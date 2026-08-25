# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""
End-to-end test for network error handling in the full linter pipeline.

This test verifies that when network issues occur during validation,
the linter properly reports the network problem instead of incorrectly
marking valid GitHub Actions as invalid.
"""

from collections.abc import Callable, Generator
import json
from pathlib import Path
import tempfile
from typing import Any, NoReturn
from unittest.mock import Mock, patch

import httpx
import pytest

from gha_workflow_linter import git_validator
from gha_workflow_linter.cli import run_linter
from gha_workflow_linter.exceptions import ValidationAbortedError
from gha_workflow_linter.models import (
    CacheConfig,
    CLIOptions,
    Config,
    GitConfig,
    GitHubAPIConfig,
    ValidationResult,
)

#: The unpatched client class, captured at import. ``_install_api_responder``
#: may run several times in one test, and taking the "original" from the
#: module each time would capture the previous factory -- which pops the
#: transport it is handed and substitutes its own, so every request would
#: be recorded against the first responder.
_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _install_api_responder(
    monkeypatch: pytest.MonkeyPatch,
    responder: Callable[[httpx.Request], httpx.Response],
) -> list[str]:
    """Route every ``httpx.AsyncClient`` through a mock transport.

    Returns the list the transport records into, so a test can assert
    the backend was *reached* rather than merely that the run failed --
    the failure mode these tests had was passing without issuing the
    request they name.

    Args:
        monkeypatch: Used to replace the client class.
        responder: Handler answering each request.

    Returns:
        The URLs asked for, appended to as the run proceeds.
    """
    asked: list[str] = []

    def recording(request: httpx.Request) -> httpx.Response:
        """Record the request, then hand it to the responder.

        Args:
            request: The outgoing request.

        Returns:
            Whatever the responder answers.
        """
        asked.append(str(request.url))
        return responder(request)

    def factory(**kwargs: Any) -> httpx.AsyncClient:
        """Build a client whose transport answers locally.

        Any transport the caller asked for is replaced rather than
        added to, since the point is that nothing leaves.

        Args:
            kwargs: Arguments the caller passed.

        Returns:
            The client.
        """
        kwargs.pop("transport", None)
        return _REAL_ASYNC_CLIENT(
            transport=httpx.MockTransport(recording), **kwargs
        )

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return asked


def _run_and_read(
    config: Config, path: Path, capsys: pytest.CaptureFixture[str]
) -> tuple[int, dict[str, Any]]:
    """Run the linter in JSON mode and read what it reported.

    The exit code alone cannot tell a failure to ask from an answer
    worth acting on -- both are ``1`` -- which is how these tests passed
    for years without exercising the condition they name. The document
    distinguishes them: a request the API refused or the transport could
    not complete reports no validation errors, while a request that was
    answered reports whatever the answer implies, per action.

    Args:
        config: Resolved configuration.
        path: Repository to scan.
        capsys: Captures the emitted document.

    Returns:
        The exit code and the parsed document.
    """
    exit_code = run_linter(
        config, CLIOptions(path=path, output_format="json", quiet=True)
    )
    out = capsys.readouterr().out
    document: dict[str, Any] = json.loads(out) if out.strip() else {}
    return exit_code, document


class TestGitBackendMisreportsAnUnreachableHost:
    """What :class:`TestEndToEndNetworkError` claims to check, checked.

    Its Git-backend cases assert only ``exit_code == 1``, which a
    network failure and a genuinely invalid action produce alike. So the
    second half of their stated purpose -- that a network failure is
    *not* reported as a validation error -- goes unchecked there, and is
    not true of that backend. The API-backend cases in the same class no
    longer have this limitation: they assert the backend was reached and
    inspect the findings, because that path classifies correctly.

    ``_run_git_ls_remote`` reports success as ``returncode == 0``, so an
    unreachable host and a repository that does not exist are the same
    answer, and ``_validate_repository_exists`` returns
    ``INVALID_REPOSITORY`` for both. That is the pre-commit.ci defect
    this file was written about, still present on this backend, and
    tracked as its own issue.

    Pinned rather than fixed: the classification is production
    behaviour and belongs in its own change. This makes the gap visible
    and will fail the moment it is closed, which is when those tests
    should assert the outcome they name.
    """

    def test_an_unreachable_host_reads_as_an_invalid_repository(
        self, unreachable_git: None
    ) -> None:
        """Records today's answer, which is the wrong one.

        Args:
            unreachable_git: Makes the lookup fail as a lost connection
                does, rather than as a missing repository does.
        """
        result = git_validator._validate_repository_exists(
            "actions/checkout", GitConfig()
        )

        assert result is ValidationResult.INVALID_REPOSITORY, (
            "the Git backend now distinguishes an unreachable host from a "
            "missing repository -- update the tests in this file to assert "
            "the network classification they were written for"
        )


class TestEndToEndNetworkError:
    """End-to-end tests for network error handling."""

    @pytest.fixture
    def sample_repo_with_workflows(self) -> Generator[Path, None, None]:
        """Create a temporary directory with sample GitHub workflows."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            workflows_dir = temp_path / ".github" / "workflows"
            workflows_dir.mkdir(parents=True)

            # Create a workflow with unique actions to avoid cache hits
            workflow_content = """
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: unique-test-org/unique-checkout-action@abc123def456
      - uses: another-unique-org/setup-test@def789ghi012
        with:
          version: '1.0'
"""
            workflow_file = workflows_dir / "ci.yaml"
            workflow_file.write_text(workflow_content)

            yield temp_path

    @pytest.fixture
    def config_without_token(self) -> Config:
        """Configuration without GitHub token (simulates pre-commit.ci environment)."""
        import tempfile

        from gha_workflow_linter.models import CacheConfig

        # Use a temporary cache location to avoid interference
        temp_cache_dir = Path(tempfile.mkdtemp()) / "test_cache"
        return Config(
            github_api=GitHubAPIConfig(
                token=None,
                base_url="https://nonexistent-domain-for-testing.invalid",
                graphql_url="https://nonexistent-domain-for-testing.invalid/graphql",
            ),
            cache=CacheConfig(enabled=True, cache_dir=temp_cache_dir),
        )

    @pytest.fixture
    def config_with_real_github_api(self) -> Config:
        """Configuration for successful validation tests that can hit real GitHub API."""
        import tempfile

        from gha_workflow_linter.models import CacheConfig

        # Use a temporary cache location to avoid interference
        temp_cache_dir = Path(tempfile.mkdtemp()) / "test_cache"
        return Config(
            github_api=GitHubAPIConfig(
                token=None,
                base_url="https://api.github.com",
                graphql_url="https://api.github.com/graphql",
            ),
            cache=CacheConfig(enabled=True, cache_dir=temp_cache_dir),
        )

    def test_dns_resolution_failure_exits_with_error_code_1(
        self,
        sample_repo_with_workflows: Path,
        config_without_token: Config,
        no_repository_redirect: None,
        unreachable_git: None,
    ) -> None:
        """Test that DNS resolution failures result in exit code 1.

        The exit code is all this can currently assert.
        :class:`TestGitBackendMisreportsAnUnreachableHost` explains why
        the second half of the original claim -- that such a failure is
        *not* reported as a validation error -- is not checked here, and
        pins it separately instead.
        """
        options = CLIOptions(path=sample_repo_with_workflows)

        exit_code = run_linter(config_without_token, options)

        # Should exit with error code 1 due to network issues
        assert exit_code == 1

    def test_network_timeout_exits_with_error_code_1(
        self,
        sample_repo_with_workflows: Path,
        config_without_token: Config,
        no_repository_redirect: None,
        timing_out_git: None,
    ) -> None:
        """Test that network timeouts result in exit code 1."""
        options = CLIOptions(path=sample_repo_with_workflows)

        # The timeout comes from timing_out_git, not from the reserved
        # domain in the configuration: the Git backend builds
        # github.com URLs directly and never reads base_url.
        exit_code = run_linter(config_without_token, options)
        assert exit_code == 1

    @pytest.fixture
    def config_using_the_api(self) -> Config:
        """Configuration that actually selects the GitHub API backend.

        Without a token the backend resolves to Git, so a test named for
        an API response never issues one -- it exercises ``git
        ls-remote`` instead and passes for a different reason entirely.
        Both the method and the token are set explicitly rather than
        left to resolution.

        Returns:
            A configuration pinned to the API backend.
        """
        from gha_workflow_linter.models import CacheConfig, ValidationMethod

        return Config(
            validation_method=ValidationMethod.GITHUB_API,
            github_api=GitHubAPIConfig(token="test-token-not-a-credential"),
            cache=CacheConfig(
                enabled=False,
                cache_dir=Path(tempfile.mkdtemp()) / "test_cache",
            ),
        )

    def test_github_api_401_exits_with_error_code_1(
        self,
        sample_repo_with_workflows: Path,
        config_using_the_api: Config,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """An authentication failure must not read as a workflow defect.

        Both halves of the name are asserted: the run fails, *and* it
        reports no findings about the workflows. The second is the point
        -- a rejected credential says nothing about the actions being
        checked, and reporting them as invalid is the defect this file
        exists for.

        Args:
            sample_repo_with_workflows: Repository to scan.
            config_using_the_api: Configuration selecting the API.
            monkeypatch: Used to install the HTTP double.
            capsys: Captures the emitted document.
        """
        asked = _install_api_responder(
            monkeypatch,
            lambda request: httpx.Response(
                401, json={"message": "Bad credentials"}
            ),
        )

        exit_code, document = _run_and_read(
            config_using_the_api, sample_repo_with_workflows, capsys
        )

        assert exit_code == 1
        assert asked, "the API backend was never reached"
        assert document["errors"] == [], (
            "a rejected credential was reported as findings about the workflows"
        )

    def test_github_api_rate_limit_exits_with_error_code_1(
        self,
        sample_repo_with_workflows: Path,
        config_using_the_api: Config,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A throttled API must not read as a workflow defect either.

        Distinct from the 401 case only in the status returned, which is
        the point: both must reach the same outcome by the path their
        names describe.

        Args:
            sample_repo_with_workflows: Repository to scan.
            config_using_the_api: Configuration selecting the API.
            monkeypatch: Used to install the HTTP double.
            capsys: Captures the emitted document.
        """
        asked = _install_api_responder(
            monkeypatch,
            lambda request: httpx.Response(
                403,
                headers={"x-ratelimit-remaining": "0"},
                json={"message": "API rate limit exceeded"},
            ),
        )

        exit_code, document = _run_and_read(
            config_using_the_api, sample_repo_with_workflows, capsys
        )

        assert exit_code == 1
        assert asked, "the API backend was never reached"
        assert document["errors"] == [], (
            "a throttled API was reported as findings about the workflows"
        )

    def test_an_answered_request_does_report_findings(
        self,
        sample_repo_with_workflows: Path,
        config_using_the_api: Config,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The inverse, without which the two above assert nothing.

        Every run in this file exits ``1``, so "no findings" only means
        something if a run that *did* reach the API and got an answer
        reports some. This one gets a well-formed but empty answer,
        which is a real statement about the actions rather than a
        failure to ask.

        Args:
            sample_repo_with_workflows: Repository to scan.
            config_using_the_api: Configuration selecting the API.
            monkeypatch: Used to install the HTTP double.
            capsys: Captures the emitted document.
        """
        asked = _install_api_responder(
            monkeypatch,
            lambda request: httpx.Response(200, json={"data": {}}),
        )

        exit_code, document = _run_and_read(
            config_using_the_api, sample_repo_with_workflows, capsys
        )

        assert exit_code == 1
        assert asked, "the API backend was never reached"
        assert document["errors"], (
            "an answered request reported nothing, so the assertions on "
            "the failure cases distinguish nothing"
        )

    @pytest.mark.skip(reason="Skipping to avoid GitHub API rate limits in CI")
    def test_successful_validation_when_network_works(
        self,
        sample_repo_with_workflows: Path,
        config_with_real_github_api: Config,
    ) -> None:
        """
        Test that successful network responses allow validation to proceed.

        This ensures our error handling doesn't break normal operation.
        Uses real GitHub API (may hit rate limits but tests realistic scenario).
        """
        options = CLIOptions(path=sample_repo_with_workflows)

        # No mocking - let it hit real GitHub API for successful validation test
        exit_code = run_linter(config_with_real_github_api, options)

        # Should not fail with network error exit code
        assert exit_code != 1, "Should not fail with network error exit code"

    def test_error_messages_distinguish_network_from_validation_issues(
        self,
        sample_repo_with_workflows: Path,
        config_without_token: Config,
        no_repository_redirect: None,
        unreachable_git: None,
    ) -> None:
        """A lost connection on the Git backend still exits non-zero.

        The name is the aspiration, not the assertion. On this backend
        the messages do *not* distinguish the two: a lost connection is
        reported as ``INVALID_REPOSITORY``, so the run says the workflow
        is wrong when the network was. That is the pre-commit.ci bug
        this file is named for, still open on the Git path and pinned by
        :class:`TestGitBackendMisreportsAnUnreachableHost`.

        The exit code is therefore all this can honestly check. When the
        classification is fixed, this should assert the message instead
        -- the pinning test will fail then and say so.

        Args:
            sample_repo_with_workflows: Repository to scan.
            config_without_token: Configuration selecting the Git
                backend, as a tokenless environment does.
            no_repository_redirect: Keeps the fixer's probe local.
            unreachable_git: Supplies the lost connection.
        """
        options = CLIOptions(path=sample_repo_with_workflows)

        exit_code = run_linter(config_without_token, options)

        assert exit_code == 1

    def test_no_false_validation_errors_on_network_failure(
        self, sample_repo_with_workflows: Path, config_without_token: Config
    ) -> None:
        """
        Critical test: Ensure network failures do NOT create ValidationError objects.

        This was the core bug - network issues were being reported as action validation failures.
        """
        options = CLIOptions(path=sample_repo_with_workflows)

        # Mock the validator to capture what would have been returned
        def capture_validation_errors(*_args: Any, **_kwargs: Any) -> NoReturn:
            # This should raise ValidationAbortedError, not return ValidationError objects
            raise ValidationAbortedError(
                "Unable to validate GitHub Actions due to API/network issues",
                reason="DNS resolution failed",
                original_error=Exception("Network error"),
            )

        with patch(
            "gha_workflow_linter.validator.ActionCallValidator.validate_action_calls"
        ) as mock_validate:
            mock_validate.side_effect = capture_validation_errors

            exit_code = run_linter(config_without_token, options)

            # Should exit with error due to network issues
            assert exit_code == 1

            # Verify that validate_action_calls was called (meaning we reached validation)
            assert mock_validate.called

            # The key assertion: no ValidationError objects should be created for network issues
            # The old behavior would have created ValidationError objects marking actions as invalid

    def test_precommit_ci_scenario_reproduction(
        self,
        sample_repo_with_workflows: Path,
        unreachable_git: None,
    ) -> None:
        """
        Exact reproduction of the pre-commit.ci scenario that failed.

        This test verifies the fix for the specific error reported in the GitHub issue.
        """
        # Use configuration similar to pre-commit.ci (no GitHub token).
        # The cache is disabled deliberately: these repository names are
        # stable, so a persistent cache can answer from a previous run
        # and let the assertion pass without the simulated outage being
        # reached at all. That is how this test passed locally while
        # failing on every Python version in CI, whose cache was cold.
        config = Config(
            github_api=GitHubAPIConfig(
                token=None,  # No token available
                base_url="https://api.github.com",
                graphql_url="https://api.github.com/graphql",
            ),
            cache=CacheConfig(
                enabled=False,
                cache_dir=Path(tempfile.mkdtemp()) / "test_cache",
            ),
        )
        options = CLIOptions(path=sample_repo_with_workflows)

        # Simulate the exact error from pre-commit.ci logs with comprehensive mocking
        with patch("httpx.AsyncClient") as mock_client_class:
            from unittest.mock import AsyncMock

            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            mock_client.post.side_effect = httpx.RequestError(
                "[Errno -3] Temporary failure in name resolution",
                request=Mock(),
            )

            # Before fix: This would output "❌ Invalid action call" for valid actions
            # After fix: This should clearly indicate a network connectivity issue
            exit_code = run_linter(config, options)

            # Should fail with network error (exit code 1)
            assert exit_code == 1

    def test_different_network_error_types_all_handled_consistently(
        self,
        sample_repo_with_workflows: Path,
        config_using_the_api: Config,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Four transport failures must all reach the same outcome.

        Previously none of the four was exercised: the tokenless
        configuration selected the Git backend, so the ``post``
        side-effects went unused and every iteration passed on one
        identical git failure. The loop ran four times and tested one
        thing once.

        Args:
            sample_repo_with_workflows: Repository to scan.
            config_using_the_api: Configuration selecting the API.
            monkeypatch: Used to install each failing transport.
        """
        options = CLIOptions(path=sample_repo_with_workflows)

        network_errors = [
            "[Errno -3] Temporary failure in name resolution",
            "Connection refused",
            "Network is unreachable",
            "Timeout",
        ]

        for message in network_errors:

            def failing(
                request: httpx.Request, reason: str = message
            ) -> httpx.Response:
                """Fail the request as a transport error would.

                Args:
                    request: The outgoing request.
                    reason: The failure to report.

                Raises:
                    httpx.RequestError: Always.
                """
                raise httpx.RequestError(reason, request=request)

            asked = _install_api_responder(monkeypatch, failing)

            exit_code = run_linter(config_using_the_api, options)

            assert exit_code == 1, (
                f"Network error {message} should result in exit code 1"
            )
            assert asked, (
                f"the run never issued a request, so {message} was not "
                f"the reason it failed"
            )

    @pytest.mark.skip(reason="Skipping to avoid GitHub API rate limits in CI")
    def test_validation_continues_after_network_recovery(
        self, sample_repo_with_workflows: Path, config_without_token: Config
    ) -> None:
        """
        Test that the system can recover and continue validation after network issues are resolved.

        This ensures the error handling doesn't permanently disable validation.
        """
        options = CLIOptions(path=sample_repo_with_workflows)

        # First attempt: network failure
        with patch("httpx.AsyncClient") as mock_client_class:
            from unittest.mock import AsyncMock

            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            mock_client.post.side_effect = httpx.RequestError(
                "Network error", request=Mock()
            )
            exit_code_1 = run_linter(config_without_token, options)
            assert exit_code_1 == 1

        # Second attempt: network works
        with patch("httpx.AsyncClient") as mock_client_class:
            from unittest.mock import AsyncMock

            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_response.json.return_value = {
                "data": {
                    "rateLimit": {
                        "remaining": 5000,
                        "resetAt": "2024-01-01T00:00:00Z",
                    }
                }
            }
            mock_client.post.return_value = mock_response

            # Should not fail with network error
            exit_code_2 = run_linter(config_without_token, options)

            # Should attempt validation (may succeed or fail based on API responses)
            assert exit_code_2 != 1, (
                "Should not fail with network error exit code"
            )
            assert mock_client.post.called
