# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for subdirectory (monorepo) action subpath validation.

Covers the GitHub GraphQL API path, and the validator orchestration for both
the API and Git validation methods, ensuring that a subdirectory action with a
valid base repo + ref but a bogus subpath is rejected, while a real one is
accepted -- consistently across methods and with results cached.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

from gha_workflow_linter.action_call_check import ActionCallValidator
from gha_workflow_linter.github_api import GitHubGraphQLClient
from gha_workflow_linter.models import (
    ActionCall,
    ActionCallType,
    CacheConfig,
    Config,
    GitHubAPIConfig,
    GitHubRateLimitInfo,
    ReferenceType,
    ValidationError,
    ValidationMethod,
    ValidationResult,
)

# ---------------------------------------------------------------------------
# GitHub GraphQL API path
# ---------------------------------------------------------------------------


def _make_client() -> GitHubGraphQLClient:
    # Deliberately not a real GitHub token shape (no ``ghp_`` prefix) so secret
    # scanning does not flag it; GitHubAPIConfig does not validate token form.
    return GitHubGraphQLClient(GitHubAPIConfig(token="fake-test-token"))


@pytest.mark.asyncio
async def test_subpaths_graphql_batch_valid_and_invalid() -> None:
    """A real subpath resolves; a bogus subpath does not."""
    client = _make_client()

    # sp_0 -> github/codeql-action/init (valid: action.yml present)
    # sp_1 -> github/codeql-action/not-real (bogus: nothing resolves)
    response = {
        "data": {
            "sp_0": {
                "sp_0_c0": {"__typename": "Blob"},
                "sp_0_c1": None,
                "sp_0_c2": {"__typename": "Tree"},
            },
            "sp_1": {
                "sp_1_c0": None,
                "sp_1_c1": None,
                "sp_1_c2": None,
            },
        }
    }

    with patch.object(
        client, "_execute_graphql_query", return_value=response
    ) as mock_execute:
        results = await client._validate_subpaths_graphql_batch(
            [
                ("github/codeql-action/init", "v3"),
                ("github/codeql-action/not-real", "v3"),
            ]
        )

    assert results[("github/codeql-action/init", "v3")] is True
    assert results[("github/codeql-action/not-real", "v3")] is False

    # The generated query targets the base repo and probes the subpath at ref.
    query = mock_execute.call_args[0][0]
    assert 'repository(owner: "github", name: "codeql-action")' in query
    assert "v3:init/action.yml" in query
    assert "v3:not-real/action.yml" in query
    # The subpath must never leak into the repository name.
    assert 'name: "codeql-action/init"' not in query


@pytest.mark.asyncio
async def test_subpaths_graphql_batch_directory_fallback() -> None:
    """A directory that exists without action metadata still validates."""
    client = _make_client()

    response = {
        "data": {
            "sp_0": {
                "sp_0_c0": None,
                "sp_0_c1": None,
                # Only the directory itself resolves (fallback candidate).
                "sp_0_c2": {"__typename": "Tree"},
            }
        }
    }

    with patch.object(client, "_execute_graphql_query", return_value=response):
        results = await client._validate_subpaths_graphql_batch(
            [("owner/repo/tools", "v1")]
        )

    assert results[("owner/repo/tools", "v1")] is True


@pytest.mark.asyncio
async def test_validate_subpaths_batch_uses_and_populates_cache() -> None:
    """Repeated subpath checks are served from the in-memory cache."""
    client = _make_client()

    call_count = {"n": 0}

    async def fake_batch(
        batch: list[tuple[str, str]],
    ) -> dict[tuple[str, str], bool]:
        call_count["n"] += 1
        return dict.fromkeys(batch, True)

    with patch.object(
        client, "_validate_subpaths_graphql_batch", side_effect=fake_batch
    ):
        first = await client.validate_subpaths_batch(
            [("github/codeql-action/init", "v3")]
        )
        # Second call for the same (repo_key, ref) should hit the cache.
        second = await client.validate_subpaths_batch(
            [("github/codeql-action/init", "v3")]
        )

    assert first == {("github/codeql-action/init", "v3"): True}
    assert second == {("github/codeql-action/init", "v3"): True}
    assert call_count["n"] == 1
    assert client.api_stats.cache_hits >= 1


def test_graphql_string_literal_escapes_special_characters() -> None:
    """Quotes and backslashes are escaped to keep the query well-formed."""
    escaped = GitHubGraphQLClient._graphql_string_literal('a"b\\c')
    assert escaped == 'a\\"b\\\\c'


@pytest.mark.asyncio
async def test_subpaths_graphql_batch_unexpected_error_propagates() -> None:
    """An unexpected (non-API) error re-raises instead of returning False.

    A non-data failure (e.g. a response-parsing bug) must not be reported as a
    bogus subpath; it propagates so the validator can abort the run.
    """
    client = _make_client()

    with (
        patch.object(
            client,
            "_execute_graphql_query",
            side_effect=ValueError("boom"),
        ),
        pytest.raises(ValueError, match="boom"),
    ):
        await client._validate_subpaths_graphql_batch(
            [("github/codeql-action/init", "v3")]
        )


@pytest.mark.asyncio
async def test_validate_subpaths_batch_unexpected_error_not_cached() -> None:
    """An unexpected error propagates and is never cached as a bogus False.

    Caching ``False`` for an internal failure would poison the subpath cache
    for the rest of the run and permanently mask a real subpath. The error
    must propagate (so the validator aborts) and leave the cache untouched.
    """
    client = _make_client()

    async def boom(
        _batch: list[tuple[str, str]],
    ) -> dict[tuple[str, str], bool]:
        raise ValueError("unexpected")

    with (
        patch.object(
            client, "_validate_subpaths_graphql_batch", side_effect=boom
        ),
        pytest.raises(ValueError, match="unexpected"),
    ):
        await client.validate_subpaths_batch(
            [("github/codeql-action/init", "v3")]
        )

    # Nothing was cached, so a later run re-checks rather than serving a
    # benefit-of-the-doubt or bogus result.
    assert client._subpath_cache == {}
    assert client.api_stats.failed_calls == 1


# ---------------------------------------------------------------------------
# Validator orchestration (both methods)
# ---------------------------------------------------------------------------


def _subdir_action() -> ActionCall:
    return ActionCall(
        raw_line="uses: github/codeql-action/init@v3",
        line_number=1,
        organization="github",
        repository="codeql-action/init",
        reference="v3",
        reference_type=ReferenceType.TAG,
        call_type=ActionCallType.ACTION,
        comment=None,
    )


def _plain_action() -> ActionCall:
    return ActionCall(
        raw_line="uses: actions/checkout@v4",
        line_number=2,
        organization="actions",
        repository="checkout",
        reference="v4",
        reference_type=ReferenceType.TAG,
        call_type=ActionCallType.ACTION,
        comment=None,
    )


def _validator() -> ActionCallValidator:
    config = Config(
        require_pinned_sha=False,
        cache=CacheConfig(enabled=False),
    )
    validator = ActionCallValidator(config)
    validator._validation_method = ValidationMethod.GITHUB_API
    return validator


def _api_client_mock(stats_owner: ActionCallValidator) -> AsyncMock:
    """Build an AsyncMock GitHub client with sync stat accessors.

    ``get_api_stats`` and ``get_rate_limit_info`` are synchronous methods on
    the real client, so they must not be left as coroutine-returning
    AsyncMocks.
    """
    client = AsyncMock()
    client.get_api_stats = Mock(return_value=stats_owner.api_stats)
    client.get_rate_limit_info = Mock(return_value=GitHubRateLimitInfo())
    return client


@pytest.mark.asyncio
async def test_validator_api_rejects_bogus_subpath() -> None:
    """API method: valid base repo + ref but bogus subpath -> INVALID_PATH."""
    validator = _validator()

    repo_key = "github/codeql-action/not-real"
    client = _api_client_mock(validator)
    client.validate_repositories_batch.return_value = {repo_key: True}
    client.validate_references_batch.return_value = {(repo_key, "v3"): True}
    client.validate_subpaths_batch.return_value = {(repo_key, "v3"): False}
    validator._github_client = client

    action_call = _subdir_action().model_copy(
        update={"repository": "codeql-action/not-real"}
    )
    action_calls = {Path("wf.yml"): {1: action_call}}

    errors = await validator._perform_validation(
        action_calls, use_github_api=True
    )

    assert len(errors) == 1
    assert errors[0].result == ValidationResult.INVALID_PATH
    # Only the subdirectory action triggers a subpath check.
    client.validate_subpaths_batch.assert_awaited_once()


@pytest.mark.asyncio
async def test_validator_api_accepts_real_subpath() -> None:
    """API method: a real subpath at a valid ref validates as VALID."""
    validator = _validator()

    repo_key = "github/codeql-action/init"
    client = _api_client_mock(validator)
    client.validate_repositories_batch.return_value = {repo_key: True}
    client.validate_references_batch.return_value = {(repo_key, "v3"): True}
    client.validate_subpaths_batch.return_value = {(repo_key, "v3"): True}
    validator._github_client = client

    action_calls = {Path("wf.yml"): {1: _subdir_action()}}

    errors = await validator._perform_validation(
        action_calls, use_github_api=True
    )

    assert errors == []


@pytest.mark.asyncio
async def test_validator_plain_action_skips_subpath_check() -> None:
    """A plain owner/repo action never triggers subpath validation."""
    validator = _validator()

    client = _api_client_mock(validator)
    client.validate_repositories_batch.return_value = {"actions/checkout": True}
    client.validate_references_batch.return_value = {
        ("actions/checkout", "v4"): True
    }
    validator._github_client = client

    action_calls = {Path("wf.yml"): {2: _plain_action()}}

    errors = await validator._perform_validation(
        action_calls, use_github_api=True
    )

    assert errors == []
    client.validate_subpaths_batch.assert_not_called()


@pytest.mark.asyncio
async def test_validator_git_rejects_bogus_subpath() -> None:
    """Git method: a bogus subpath maps to INVALID_PATH consistently."""
    validator = _validator()
    validator._validation_method = ValidationMethod.GIT

    repo_key = "github/codeql-action/not-real"
    client = AsyncMock()
    client.validate_repositories_batch.return_value = {
        repo_key: ValidationResult.VALID
    }
    client.validate_references_batch.return_value = {
        (repo_key, "v3"): ValidationResult.VALID
    }
    client.validate_subpaths_batch.return_value = {
        (repo_key, "v3"): ValidationResult.INVALID_PATH
    }
    validator._git_client = client

    action_call = _subdir_action().model_copy(
        update={"repository": "codeql-action/not-real"}
    )
    action_calls = {Path("wf.yml"): {1: action_call}}

    errors = await validator._perform_validation(
        action_calls, use_github_api=False
    )

    assert len(errors) == 1
    assert errors[0].result == ValidationResult.INVALID_PATH
    client.validate_subpaths_batch.assert_awaited_once()


@pytest.mark.asyncio
async def test_validator_git_network_error_not_treated_as_bogus() -> None:
    """Git method: a transient subpath error does not flag a bogus path."""
    validator = _validator()
    validator._validation_method = ValidationMethod.GIT

    repo_key = "github/codeql-action/init"
    client = AsyncMock()
    client.validate_repositories_batch.return_value = {
        repo_key: ValidationResult.VALID
    }
    client.validate_references_batch.return_value = {
        (repo_key, "v3"): ValidationResult.VALID
    }
    # A NETWORK_ERROR result must be given the benefit of the doubt.
    client.validate_subpaths_batch.return_value = {
        (repo_key, "v3"): ValidationResult.NETWORK_ERROR
    }
    validator._git_client = client

    action_calls = {Path("wf.yml"): {1: _subdir_action()}}

    errors = await validator._perform_validation(
        action_calls, use_github_api=False
    )

    assert errors == []


@pytest.mark.asyncio
async def test_validator_git_inconclusive_subpath_not_cached() -> None:
    """Git method: an inconclusive subpath check is not cached as VALID.

    A transient failure (NETWORK_ERROR) is given the benefit of the doubt for
    the current run, but must be excluded from the cache so the next run
    retries instead of persisting a false VALID that masks a bogus subpath. A
    conclusively-valid subpath alongside it is still cached.
    """
    validator = _validator()
    validator._validation_method = ValidationMethod.GIT

    valid_key = "github/codeql-action/init"
    incon_key = "github/codeql-action/analyze"

    client = AsyncMock()
    client.validate_repositories_batch.return_value = {
        valid_key: ValidationResult.VALID,
        incon_key: ValidationResult.VALID,
    }
    client.validate_references_batch.return_value = {
        (valid_key, "v3"): ValidationResult.VALID,
        (incon_key, "v3"): ValidationResult.VALID,
    }
    client.validate_subpaths_batch.return_value = {
        (valid_key, "v3"): ValidationResult.VALID,
        (incon_key, "v3"): ValidationResult.NETWORK_ERROR,
    }
    validator._git_client = client

    # Spy on cache reads/writes.
    cache = Mock()
    cache.get_batch.return_value = (
        {},
        [(valid_key, "v3"), (incon_key, "v3")],
    )
    cache.stats.hits = 0
    validator._cache = cache

    init_call = _subdir_action()
    analyze_call = _subdir_action().model_copy(
        update={"repository": "codeql-action/analyze", "line_number": 2}
    )
    action_calls = {Path("wf.yml"): {1: init_call, 2: analyze_call}}

    errors = await validator._perform_validation(
        action_calls, use_github_api=False
    )

    # Neither surfaces an error this run (inconclusive gets the benefit of
    # the doubt).
    assert errors == []

    # Only the conclusively-valid subpath is cached; the inconclusive one is
    # excluded so it can be retried.
    cache.put_batch.assert_called_once()
    stored_keys = {
        (repo, ref) for repo, ref, *_ in cache.put_batch.call_args[0][0]
    }
    assert (valid_key, "v3") in stored_keys
    assert (incon_key, "v3") not in stored_keys


def test_invalid_path_error_message_and_summary() -> None:
    """INVALID_PATH has a human-readable message and its own summary counter."""
    validator = _validator()

    message = validator._get_error_message(ValidationResult.INVALID_PATH)
    assert "path" in message.lower()

    error = ValidationError(
        file_path=Path("wf.yml"),
        action_call=_subdir_action(),
        result=ValidationResult.INVALID_PATH,
        error_message=message,
    )
    summary = validator.get_validation_summary(
        [error], total_calls=1, unique_calls=1
    )
    assert summary["invalid_paths"] == 1
    assert summary["invalid_references"] == 0
