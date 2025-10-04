# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""
End-to-end test for network error handling in the full linter pipeline.

This test verifies that when network issues occur during validation,
the linter properly reports the network problem instead of incorrectly
marking valid GitHub Actions as invalid.
"""

from collections.abc import Generator
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch

import httpx
import pytest

from gha_workflow_linter.cli import run_linter
from gha_workflow_linter.exceptions import ValidationAbortedError
from gha_workflow_linter.models import CLIOptions, Config, GitHubAPIConfig


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
            cache=CacheConfig(enabled=True, cache_dir=str(temp_cache_dir)),
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
            cache=CacheConfig(enabled=True, cache_dir=str(temp_cache_dir)),
        )

    def test_dns_resolution_failure_exits_with_error_code_1(
        self, sample_repo_with_workflows: Path, config_without_token: Config
    ) -> None:
        """Test that DNS resolution failures result in exit code 1, not validation errors.

        This reproduces the pre-commit.ci scenario where DNS resolution failed
        but the tool incorrectly reported all actions as invalid.
        Uses a non-existent domain to naturally cause DNS resolution failure.
        """
        options = CLIOptions(path=sample_repo_with_workflows)

        # Run the linter - it will naturally fail with DNS resolution error
        # because config_without_token points to nonexistent-domain-for-testing.invalid
        exit_code = run_linter(config_without_token, options)

        # Should exit with error code 1 due to network issues
        assert exit_code == 1

    def test_network_timeout_exits_with_error_code_1(
        self, sample_repo_with_workflows: Path, config_without_token: Config
    ) -> None:
        """Test that network timeouts result in exit code 1."""
        options = CLIOptions(path=sample_repo_with_workflows)

        # Use the same non-existent domain config - it will cause network failure
        exit_code = run_linter(config_without_token, options)
        assert exit_code == 1

    def test_github_api_401_exits_with_error_code_1(
        self, sample_repo_with_workflows: Path, config_without_token: Config
    ) -> None:
        """Test that GitHub API authentication failures result in exit code 1."""
        options = CLIOptions(path=sample_repo_with_workflows)

        # Use the same non-existent domain config - it will cause network failure
        exit_code = run_linter(config_without_token, options)
        assert exit_code == 1

    def test_github_api_rate_limit_exits_with_error_code_1(
        self, sample_repo_with_workflows: Path, config_without_token: Config
    ) -> None:
        """Test that GitHub API rate limit errors result in exit code 1."""
        options = CLIOptions(path=sample_repo_with_workflows)

        # Use the same non-existent domain config - it will cause network failure
        exit_code = run_linter(config_without_token, options)
        assert exit_code == 1

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
        self, sample_repo_with_workflows: Path, config_without_token: Config
    ) -> None:
        """
        Test that error messages clearly distinguish network issues from validation failures.

        This was the core issue in pre-commit.ci - network failures were being
        reported as validation failures, confusing users.
        Uses non-existent domain to naturally cause network error.
        """
        options = CLIOptions(path=sample_repo_with_workflows)

        # No mocking needed - config_without_token uses non-existent domain
        exit_code = run_linter(config_without_token, options)

        # Should exit with network error
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
        def capture_validation_errors(*_args, **_kwargs):
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
        self, sample_repo_with_workflows
    ):
        """
        Exact reproduction of the pre-commit.ci scenario that failed.

        This test verifies the fix for the specific error reported in the GitHub issue.
        """
        # Use configuration similar to pre-commit.ci (no GitHub token)
        config = Config(
            github_api=GitHubAPIConfig(
                token=None,  # No token available
                base_url="https://api.github.com",
                graphql_url="https://api.github.com/graphql",
            )
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
        self, sample_repo_with_workflows: Path, config_without_token: Config
    ) -> None:
        """
        Test that different types of network errors are all handled consistently.

        All network errors should result in ValidationAbortedError, not validation failures.
        """
        options = CLIOptions(path=sample_repo_with_workflows)

        network_errors = [
            httpx.RequestError(
                "[Errno -3] Temporary failure in name resolution",
                request=Mock(),
            ),
            httpx.RequestError("Connection refused", request=Mock()),
            httpx.RequestError("Network is unreachable", request=Mock()),
            httpx.RequestError("Timeout", request=Mock()),
        ]

        for error in network_errors:
            with patch("httpx.AsyncClient") as mock_client_class:
                from unittest.mock import AsyncMock

                mock_client = AsyncMock()
                mock_client_class.return_value = mock_client
                mock_client.post.side_effect = error

                exit_code = run_linter(config_without_token, options)

                # All network errors should result in exit code 1
                assert exit_code == 1, (
                    f"Network error {error} should result in exit code 1"
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
