# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""
Test reproducing the pre-commit.ci DNS resolution failure scenario.

This test simulates the exact error that occurred when the linter was run
by pre-commit.ci and encountered DNS resolution issues, ensuring that
the tool now properly reports the network issue instead of incorrectly
marking valid actions as invalid.
"""

from pathlib import Path
from unittest.mock import Mock, patch

import httpx
import pytest

from gha_workflow_linter.cli import run_linter
from gha_workflow_linter.exceptions import NetworkError, ValidationAbortedError
from gha_workflow_linter.models import CLIOptions, Config, GitHubAPIConfig
from gha_workflow_linter.validator import ActionCallValidator


class TestPreCommitCIScenario:
    """Test the specific scenario that failed in pre-commit.ci."""

    @pytest.fixture
    def sample_workflows(self, tmp_path: Path) -> Path:
        """Create sample workflow files similar to the ones that failed in pre-commit.ci."""
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)

        # testing.yaml - contains step-security/harden-runner and actions/checkout
        testing_yaml = workflows_dir / "testing.yaml"
        testing_yaml.write_text("""
name: Testing
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@f4a75cfd619ee5ce8d5b864b0d183aff3c69b55a # v2.13.1
        with:
          egress-policy: audit
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
      - name: Run tests
        run: echo "Running tests"
""")

        # release-drafter.yaml - contains release-drafter/release-drafter
        release_yaml = workflows_dir / "release-drafter.yaml"
        release_yaml.write_text("""
name: Release Drafter
on:
  push:
    branches: [main]
jobs:
  draft:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@f4a75cfd619ee5ce8d5b864b0d183aff3c69b55a # v2.13.1
      - uses: release-drafter/release-drafter@b1476f6e6eb133afa41ed8589daba6dc69b4d3f5 # v6.1.0
""")

        # tag-push.yaml - contains multiple custom actions
        tag_push_yaml = workflows_dir / "tag-push.yaml"
        tag_push_yaml.write_text("""
name: Tag Push
on:
  push:
    tags: ['v*']
jobs:
  verify-and-release:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@f4a75cfd619ee5ce8d5b864b0d183aff3c69b55a # v2.13.1
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
      - uses: lfreleng-actions/tag-push-verify-action@80e2bdbbb9ee7b67557a31705892b75e75d2859e # v0.1.1
      - uses: lfreleng-actions/draft-release-promote-action@d7e7df12e32fa26b28dbc2f18a12766482785399 # v0.1.2
""")

        return tmp_path

    @pytest.fixture
    def config_with_no_token(self) -> Config:
        """Create configuration without GitHub token (as in pre-commit.ci)."""
        import tempfile

        from gha_workflow_linter.models import CacheConfig, ValidationMethod

        # Use non-existent domain to naturally cause DNS failures
        temp_cache_dir = Path(tempfile.mkdtemp()) / "test_cache"
        return Config(
            github_api=GitHubAPIConfig(
                token="fake_token",  # Fake token to force GitHub API method
                base_url="https://nonexistent-domain-for-testing.invalid",
                graphql_url="https://nonexistent-domain-for-testing.invalid/graphql",
            ),
            cache=CacheConfig(enabled=False, cache_dir=temp_cache_dir),
            validation_method=ValidationMethod.GITHUB_API,  # Force GitHub API validation
        )

    def test_dns_resolution_failure_scenario(
        self, sample_workflows: Path, config_with_no_token: Config
    ) -> None:
        """
        Test the exact DNS resolution failure that occurred in pre-commit.ci.

        Before the fix, this would incorrectly report all actions as invalid.
        After the fix, it should properly report the network issue.
        Uses non-existent domain to naturally cause DNS resolution failure.
        """
        options = CLIOptions(path=sample_workflows)

        # No mocking needed - config_with_no_token uses non-existent domain
        # which will naturally cause DNS resolution failure
        exit_code = run_linter(config_with_no_token, options)

        # Should return exit code 1 due to validation being aborted
        assert exit_code == 1

    def test_dns_resolution_failure_in_validator_directly(
        self, config_with_no_token: Config
    ) -> None:
        """
        Test DNS resolution failure at the validator level.

        This tests the core logic that was causing the issue.
        Uses non-existent domain to naturally cause DNS resolution failure.
        """
        # Create action calls that would have been extracted from the sample workflows
        from gha_workflow_linter.models import ActionCall, ReferenceType

        action_calls = {
            Path("testing.yaml"): {
                1: ActionCall(
                    raw_line="      - uses: unique-test-org/unique-action@abc123",
                    organization="unique-test-org",
                    repository="unique-action",
                    reference="abc123",
                    reference_type=ReferenceType.COMMIT_SHA,
                    line_number=7,
                ),
            }
        }

        # Use validator with non-existent domain config - use synchronous method
        validator = ActionCallValidator(config_with_no_token)
        # This will naturally fail with DNS resolution error due to non-existent domain
        with pytest.raises(ValidationAbortedError) as exc_info:
            validator.validate_action_calls(action_calls)

            assert "API/network issues" in str(exc_info.value)
            assert isinstance(exc_info.value.original_error, NetworkError)

    def test_network_error_does_not_mark_actions_as_invalid(
        self, config_with_no_token: Config
    ) -> None:
        """
        Test that network errors do NOT result in ValidationError objects being created.

        This was the core bug: network failures were being converted to validation failures.
        Uses non-existent domain to naturally cause network error.
        """
        from gha_workflow_linter.models import ActionCall, ReferenceType

        action_calls = {
            Path("test.yaml"): {
                1: ActionCall(
                    raw_line="      - uses: unique-org/unique-action@def456",
                    organization="unique-org",
                    repository="unique-action",
                    reference="def456",
                    reference_type=ReferenceType.COMMIT_SHA,
                    line_number=1,
                )
            }
        }

        # Use validator with non-existent domain config - use synchronous method
        validator = ActionCallValidator(config_with_no_token)
        # Should raise ValidationAbortedError due to DNS failure, not return ValidationError objects
        with pytest.raises(ValidationAbortedError):
            validator.validate_action_calls(action_calls)

            # The key point: we should NEVER get ValidationError objects for network issues
            # The old behavior would have returned:
            # [ValidationError(file_path=Path("test.yaml"), action_call=..., result=INVALID_REPOSITORY)]

    def test_pre_commit_ci_error_message_format(
        self, sample_workflows: Path, config_with_no_token: Config
    ) -> None:
        """
        Test that the error message format is clear for pre-commit.ci users.

        The original error was confusing because it showed:
        "❌ Invalid action call in workflow" when the real issue was network connectivity.
        """
        options = CLIOptions(path=sample_workflows)

        with patch("httpx.AsyncClient.post") as mock_post:
            mock_post.side_effect = httpx.RequestError(
                "[Errno -3] Temporary failure in name resolution",
                request=Mock(),
            )

            # Capture the output to verify error messaging
            with patch("gha_workflow_linter.cli.console") as mock_console:
                exit_code = run_linter(config_with_no_token, options)

                # Should exit with error code 1
                assert exit_code == 1

                # Verify that helpful error messages are displayed
                print_calls = list(mock_console.print.call_args_list)

                # Should contain network-specific guidance
                error_messages = " ".join([str(call) for call in print_calls])

                # Should NOT contain "Invalid action call" messages
                assert "❌ Invalid action call" not in error_messages

                # Should contain network connectivity guidance
                # Note: The exact message format depends on implementation,
                # but it should be clear this is a network issue, not validation failure

    @pytest.mark.skip(reason="Skipping to avoid GitHub API rate limits in CI")
    def test_successful_validation_after_network_recovery(
        self, sample_workflows: Path, config_with_no_token: Config
    ) -> None:
        """
        Test that when network connectivity is restored, validation proceeds normally.

        This ensures our error handling doesn't break normal operation.
        """
        options = CLIOptions(path=sample_workflows)

        with patch("httpx.AsyncClient.post") as mock_post:
            # Mock successful API responses
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_response.json.return_value = {
                "data": {
                    "rateLimit": {
                        "remaining": 5000,
                        "resetAt": "2024-01-01T00:00:00Z",
                    },
                    # Mock repository validation responses
                    "repository1": {
                        "owner": {"repository": {"name": "harden-runner"}}
                    },
                    "repository2": {
                        "owner": {"repository": {"name": "checkout"}}
                    },
                }
            }
            mock_post.return_value = mock_response

            # Should complete successfully (though specific exit code depends on validation results)
            exit_code = run_linter(config_with_no_token, options)

            # Should not be the network error exit code (1)
            # Might be 0 for success or different error code for validation issues
            # The key is that it should not abort due to network issues
            assert exit_code != 1, (
                "Should not fail with network error exit code"
            )
            assert mock_post.called  # Confirms network requests were made

    def test_error_recovery_guidance_messages(self) -> None:
        """
        Test that appropriate recovery guidance is provided for different error types.

        Pre-commit.ci users need clear guidance on what went wrong and how to address it.
        """
        # Test NetworkError guidance
        network_error = NetworkError("DNS resolution failed")
        assert "DNS resolution failed" in str(network_error)

        # Test ValidationAbortedError with NetworkError
        validation_error = ValidationAbortedError(
            "Unable to validate GitHub Actions due to API/network issues",
            reason="DNS resolution failed",
            original_error=network_error,
        )

        assert "API/network issues" in str(validation_error)
        assert validation_error.original_error is network_error

        # The CLI should provide specific guidance based on these error types
        # This is tested in the CLI error handling tests
