# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests that an annotated tag-object pin is *reported* as such.

``ValidationResult.ANNOTATED_TAG_SHA`` was already produced by the Git
backend, but the validator flattened every reference verdict to a boolean
before combining results, so the user saw the generic "Invalid branch, tag,
or commit SHA". These tests pin the reporting path end to end: the specific
verdict survives, it carries the peeled commit to use instead, and both
validation backends agree on the verdict and the message.

Mocking happens at the client boundary — ``git ls-remote`` output for the
Git backend, GraphQL responses for the API backend — so the real client
code, including the peel capture, is exercised.
"""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
from typing import Any
from unittest.mock import Mock

import pytest

from gha_workflow_linter.git_refs import AnnotatedTagPeel
from gha_workflow_linter.git_validator import GitValidationClient
from gha_workflow_linter.github_api import GitHubGraphQLClient
from gha_workflow_linter.models import (
    ActionCall,
    ActionCallType,
    CacheConfig,
    Config,
    GitConfig,
    ReferenceType,
    ValidationError,
    ValidationMethod,
    ValidationResult,
)
from gha_workflow_linter.validator import ActionCallValidator
from gha_workflow_linter.validator_findings import (
    ReferenceFinding,
    specific_ref_result,
)

# Real output from ``git ls-remote`` against
# git@github.com:lfreleng-actions/.github.git. v0.12.2 is an annotated tag,
# so it is advertised twice: the tag object, then the commit it peels to.
TAG_NAME = "v0.12.2"
TAG_OBJECT_SHA = "8f363565e79650362c3359ee23b6d6fd295866ee"
PEELED_COMMIT_SHA = "bf6642f68d58c1b81bbe993e676d6cc339ac3654"
UNKNOWN_SHA = "1234567890abcdef1234567890abcdef12345678"
BRANCH_COMMIT_SHA = "0000111122223333444455556666777788889999"

LS_REMOTE_OUTPUT = (
    f"{BRANCH_COMMIT_SHA}\trefs/heads/main\n"
    f"{TAG_OBJECT_SHA}\trefs/tags/{TAG_NAME}\n"
    f"{PEELED_COMMIT_SHA}\trefs/tags/{TAG_NAME}^{{}}\n"
)

ORGANIZATION = "lfreleng-actions"
REPOSITORY = "test-action"
REPO_KEY = f"{ORGANIZATION}/{REPOSITORY}"

# What ``object(oid: ...)`` resolves to for each fixture SHA. GitHub returns
# null for a SHA the repository does not contain.
GRAPHQL_OBJECTS: dict[str, dict[str, Any]] = {
    TAG_OBJECT_SHA: {
        "__typename": "Tag",
        "name": TAG_NAME,
        "target": {"oid": PEELED_COMMIT_SHA},
    },
    PEELED_COMMIT_SHA: {
        "__typename": "Commit",
        "oid": PEELED_COMMIT_SHA,
    },
    BRANCH_COMMIT_SHA: {
        "__typename": "Commit",
        "oid": BRANCH_COMMIT_SHA,
    },
}

_OBJECT_ALIAS_RE = re.compile(r"(\w+): object\(oid: \"([0-9a-fA-F]+)\"\)")
_REPO_ALIAS_RE = re.compile(r"(repo_\d+): repository\(")


# ---------------------------------------------------------------------------
# Fixtures / doubles
# ---------------------------------------------------------------------------


class FakeCompleted:
    """Minimal stand-in for ``subprocess.CompletedProcess``."""

    def __init__(self, stdout: str, returncode: int = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = ""


def _patch_ls_remote(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub ``subprocess.run`` with the fixture ls-remote output.

    Args:
        monkeypatch: pytest monkeypatch fixture
    """

    def fake_run(_cmd: list[str], **_kwargs: object) -> FakeCompleted:
        return FakeCompleted(LS_REMOTE_OUTPUT)

    monkeypatch.setattr(subprocess, "run", fake_run)


async def _fake_graphql_query(query: str) -> dict[str, Any]:
    """Answer a GraphQL query from the fixture data.

    Args:
        query: The generated GraphQL document.

    Returns:
        A response body shaped like GitHub's, covering both the repository
        existence query and the commit-SHA object query.
    """
    if "object(oid:" in query:
        objects = {
            alias: GRAPHQL_OBJECTS.get(sha)
            for alias, sha in _OBJECT_ALIAS_RE.findall(query)
        }
        return {"data": {"repository": objects}}

    return {
        "data": {
            alias: {"id": alias, "name": REPOSITORY}
            for alias in _REPO_ALIAS_RE.findall(query)
        }
    }


def _action_call(reference: str) -> ActionCall:
    """Build an action call pinned to the given reference.

    Args:
        reference: The SHA the workflow line pins.

    Returns:
        An ``ActionCall`` as the scanner would produce for that line.
    """
    return ActionCall(
        raw_line=f"uses: {REPO_KEY}@{reference} # {TAG_NAME}",
        line_number=42,
        organization=ORGANIZATION,
        repository=REPOSITORY,
        reference=reference,
        reference_type=ReferenceType.COMMIT_SHA,
        call_type=ActionCallType.ACTION,
        comment=f"# {TAG_NAME}",
    )


def _peel() -> AnnotatedTagPeel:
    """Build the peel behind the fixture tag object.

    Returns:
        The ``AnnotatedTagPeel`` for ``v0.12.2``.
    """
    return AnnotatedTagPeel(tag=TAG_NAME, commit_sha=PEELED_COMMIT_SHA)


def _validator(cache_dir: Path | None = None) -> ActionCallValidator:
    """Build a validator with caching disabled unless a directory is given.

    Args:
        cache_dir: Directory for an enabled cache, or None to disable it.

    Returns:
        A validator with no backend client attached yet.
    """
    cache = (
        CacheConfig(enabled=True, cache_dir=cache_dir)
        if cache_dir is not None
        else CacheConfig(enabled=False)
    )
    return ActionCallValidator(Config(require_pinned_sha=False, cache=cache))


async def _validate_with_git(
    monkeypatch: pytest.MonkeyPatch,
    reference: str,
    cache_dir: Path | None = None,
    validator: ActionCallValidator | None = None,
) -> list[ValidationError]:
    """Run a full validation of one pinned reference via the Git backend.

    Args:
        monkeypatch: pytest monkeypatch fixture
        reference: The SHA the workflow pins.
        cache_dir: Optional cache directory (enables caching).
        validator: Optional pre-built validator to reuse.

    Returns:
        The validation errors produced for the single action call.
    """
    _patch_ls_remote(monkeypatch)
    validator = validator or _validator(cache_dir)
    validator._validation_method = ValidationMethod.GIT
    validator._git_client = GitValidationClient(GitConfig())

    return await validator._perform_validation(
        {Path("wf.yaml"): {42: _action_call(reference)}},
        use_github_api=False,
    )


async def _validate_with_api(
    monkeypatch: pytest.MonkeyPatch,
    reference: str,
    cache_dir: Path | None = None,
    validator: ActionCallValidator | None = None,
) -> list[ValidationError]:
    """Run a full validation of one pinned reference via the API backend.

    Args:
        monkeypatch: pytest monkeypatch fixture
        reference: The SHA the workflow pins.
        cache_dir: Optional cache directory (enables caching).
        validator: Optional pre-built validator to reuse.

    Returns:
        The validation errors produced for the single action call.
    """
    validator = validator or _validator(cache_dir)
    validator._validation_method = ValidationMethod.GITHUB_API
    client = GitHubGraphQLClient(validator.config.github_api)
    monkeypatch.setattr(client, "_execute_graphql_query", _fake_graphql_query)
    validator._github_client = client

    return await validator._perform_validation(
        {Path("wf.yaml"): {42: _action_call(reference)}},
        use_github_api=True,
    )


# ---------------------------------------------------------------------------
# The core regression: the specific verdict reaches the user
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_git_backend_reports_annotated_tag_sha_not_invalid_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pinned tag-object SHA is ANNOTATED_TAG_SHA, not INVALID_REFERENCE.

    The validator used to flatten the reference verdict to a boolean, so
    this precise, actionable result was replaced by the generic one.
    """
    errors = await _validate_with_git(monkeypatch, TAG_OBJECT_SHA)

    assert len(errors) == 1
    assert errors[0].result is ValidationResult.ANNOTATED_TAG_SHA


@pytest.mark.asyncio
async def test_git_backend_message_names_tag_and_peeled_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The message carries the remediation, not just the diagnosis."""
    errors = await _validate_with_git(monkeypatch, TAG_OBJECT_SHA)

    message = errors[0].error_message or ""
    assert PEELED_COMMIT_SHA in message
    assert TAG_NAME in message
    # The tag-object SHA is what the user already has; it is the commit
    # that is missing from the report.
    assert "annotated tag object" in message


@pytest.mark.asyncio
async def test_git_backend_peeled_commit_validates_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real commit SHA still passes; the split only rejects tag objects."""
    errors = await _validate_with_git(monkeypatch, PEELED_COMMIT_SHA)

    assert errors == []


@pytest.mark.asyncio
async def test_git_backend_unknown_sha_stays_invalid_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A SHA the remote never advertises keeps the generic verdict."""
    errors = await _validate_with_git(monkeypatch, UNKNOWN_SHA)

    assert len(errors) == 1
    assert errors[0].result is ValidationResult.INVALID_REFERENCE
    assert errors[0].error_message == "Invalid branch, tag, or commit SHA"


# ---------------------------------------------------------------------------
# Backend parity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_backend_reports_annotated_tag_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The API backend recognises and peels a tag object too."""
    errors = await _validate_with_api(monkeypatch, TAG_OBJECT_SHA)

    assert len(errors) == 1
    assert errors[0].result is ValidationResult.ANNOTATED_TAG_SHA
    message = errors[0].error_message or ""
    assert PEELED_COMMIT_SHA in message
    assert TAG_NAME in message


@pytest.mark.asyncio
async def test_backends_agree_on_annotated_tag_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both backends return the same verdict and the same message.

    Which backend runs depends only on whether a token happens to be
    available, so a disagreement here is a defect by construction.
    """
    git_errors = await _validate_with_git(monkeypatch, TAG_OBJECT_SHA)
    api_errors = await _validate_with_api(monkeypatch, TAG_OBJECT_SHA)

    assert git_errors[0].result is api_errors[0].result
    assert git_errors[0].error_message == api_errors[0].error_message


@pytest.mark.asyncio
async def test_backends_agree_on_valid_and_unknown_shas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Parity is not limited to the tag-object case."""
    assert await _validate_with_git(monkeypatch, PEELED_COMMIT_SHA) == []
    assert await _validate_with_api(monkeypatch, PEELED_COMMIT_SHA) == []

    git_errors = await _validate_with_git(monkeypatch, UNKNOWN_SHA)
    api_errors = await _validate_with_api(monkeypatch, UNKNOWN_SHA)

    assert git_errors[0].result is api_errors[0].result
    assert git_errors[0].error_message == api_errors[0].error_message


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_annotated_tag_sha_is_cached(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The verdict is definite, so it belongs in the cache.

    Unlike a network failure, nothing about it is transient: the same tag
    object will still not be a commit on the next run.
    """
    validator = _validator(tmp_path)
    put_batch = Mock()
    monkeypatch.setattr(validator._cache, "put_batch", put_batch)

    await _validate_with_git(monkeypatch, TAG_OBJECT_SHA, validator=validator)

    put_batch.assert_called_once()
    entries = put_batch.call_args[0][0]
    assert len(entries) == 1
    repo, ref, result, _api_call_type, _method, message = entries[0]
    assert (repo, ref) == (REPO_KEY, TAG_OBJECT_SHA)
    assert result is ValidationResult.ANNOTATED_TAG_SHA
    assert PEELED_COMMIT_SHA in (message or "")


def test_transient_reference_failure_is_not_cached() -> None:
    """An infrastructure failure must not persist as a verdict.

    Caching a network error as INVALID_REFERENCE would turn a blip into a
    sticky false failure; the next run must re-check it instead.
    """
    validator = _validator()
    flaky_sha = BRANCH_COMMIT_SHA

    entries = validator._build_cache_entries(
        refs_to_validate=[
            (REPO_KEY, TAG_OBJECT_SHA),
            (REPO_KEY, flaky_sha),
        ],
        inconclusive_subpaths=set(),
        repo_results={REPO_KEY: True},
        ref_results={
            (REPO_KEY, TAG_OBJECT_SHA): False,
            (REPO_KEY, flaky_sha): False,
        },
        subpath_results={},
        use_github_api=False,
        ref_findings={
            (REPO_KEY, TAG_OBJECT_SHA): ReferenceFinding(
                result=ValidationResult.ANNOTATED_TAG_SHA,
                peel=_peel(),
            ),
            (REPO_KEY, flaky_sha): ReferenceFinding(
                result=ValidationResult.NETWORK_ERROR
            ),
        },
    )

    cached_refs = {ref: result for _repo, ref, result, *_rest in entries}
    assert cached_refs == {TAG_OBJECT_SHA: ValidationResult.ANNOTATED_TAG_SHA}


@pytest.mark.asyncio
async def test_cached_annotated_tag_sha_survives_a_cache_hit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A replayed cache entry keeps the specific verdict and message.

    The peel is not persisted, so the rendered message is what the cache
    carries; the result must not degrade to INVALID_REFERENCE.
    """
    fresh = await _validate_with_git(
        monkeypatch, TAG_OBJECT_SHA, cache_dir=tmp_path
    )

    validator = _validator(tmp_path)
    validator._cache.put(
        REPO_KEY,
        TAG_OBJECT_SHA,
        ValidationResult.ANNOTATED_TAG_SHA,
        "git",
        ValidationMethod.GIT,
        fresh[0].error_message,
    )

    def _explode(_cmd: list[str], **_kwargs: object) -> FakeCompleted:
        raise AssertionError("cache hit must not reach the network")

    monkeypatch.setattr(subprocess, "run", _explode)
    validator._validation_method = ValidationMethod.GIT
    validator._git_client = GitValidationClient(GitConfig())

    errors = await validator._perform_validation(
        {Path("wf.yaml"): {42: _action_call(TAG_OBJECT_SHA)}},
        use_github_api=False,
    )

    assert len(errors) == 1
    assert errors[0].result is ValidationResult.ANNOTATED_TAG_SHA
    assert errors[0].error_message == fresh[0].error_message


class TestInfrastructureResultsSurvive:
    """Transient failures must not masquerade as invalid references.

    ``specific_ref_result`` previously collapsed every non-specific
    finding to ``INVALID_REFERENCE``, so a per-repository network error
    or timeout told the reader their reference was wrong when the check
    had simply not run, and left the summary's ``network_errors`` and
    ``timeouts`` counters unreachable.
    """

    @pytest.mark.parametrize(
        "result",
        [ValidationResult.NETWORK_ERROR, ValidationResult.TIMEOUT],
    )
    def test_infrastructure_results_pass_through(
        self, result: ValidationResult
    ) -> None:
        finding = ReferenceFinding(result=result)

        assert specific_ref_result(finding) is result

    def test_annotated_tag_still_specific(self) -> None:
        finding = ReferenceFinding(result=ValidationResult.ANNOTATED_TAG_SHA)

        assert (
            specific_ref_result(finding) is ValidationResult.ANNOTATED_TAG_SHA
        )

    def test_missing_finding_is_generic(self) -> None:
        assert specific_ref_result(None) is ValidationResult.INVALID_REFERENCE

    def test_unrelated_result_stays_generic(self) -> None:
        """A repository-level verdict must not leak into ref reporting."""
        finding = ReferenceFinding(result=ValidationResult.INVALID_REPOSITORY)

        assert (
            specific_ref_result(finding) is ValidationResult.INVALID_REFERENCE
        )
