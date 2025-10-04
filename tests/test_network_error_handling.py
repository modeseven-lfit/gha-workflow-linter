# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""
Tests for network error handling scenarios.

This module tests that the linter properly handles network connectivity issues,
GitHub API errors, and other external failures without incorrectly marking
valid actions as invalid.
"""

from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import httpx
import pytest

from gha_workflow_linter.exceptions import (
    AuthenticationError,
    GitHubAPIError,
    NetworkError,
    RateLimitError,
    TemporaryAPIError,
    ValidationAbortedError,
)
from gha_workflow_linter.github_api import GitHubGraphQLClient
from gha_workflow_linter.models import (
    ActionCall,
    Config,
    GitHubAPIConfig,
    ReferenceType,
)
from gha_workflow_linter.validator import ActionCallValidator


class TestNetworkErrorHandling:
    """Test network error handling in GitHub API client."""

    @pytest.fixture
    def config(self) -> Config:
        """Create test configuration."""
        return Config(
            github_api=GitHubAPIConfig(
                token="test-token",
                base_url="https://api.github.com",
                graphql_url="https://api.github.com/graphql",
            )
        )

    @pytest.mark.asyncio
    async def test_dns_resolution_failure_raises_network_error(
        self, config: Config
    ) -> None:
        """Test that DNS resolution failures raise NetworkError."""
        with patch("httpx.AsyncClient.post") as mock_post:
            # Simulate DNS resolution failure
            mock_post.side_effect = httpx.RequestError(
                "Temporary failure in name resolution", request=Mock()
            )

            async with GitHubGraphQLClient(config.github_api) as github_client:
                with pytest.raises(NetworkError) as exc_info:
                    await github_client._execute_graphql_query(
                        "query { viewer { login } }"
                    )

                assert exc_info.value.original_error is not None

    @pytest.mark.asyncio
    async def test_connection_failure_raises_network_error(
        self, config: Config
    ) -> None:
        """Test that connection failures raise NetworkError."""
        with patch("httpx.AsyncClient.post") as mock_post:
            # Simulate connection failure
            mock_post.side_effect = httpx.ConnectError(
                "Connection refused", request=Mock()
            )

            async with GitHubGraphQLClient(config.github_api) as github_client:
                with pytest.raises(NetworkError) as exc_info:
                    await github_client._execute_graphql_query(
                        "query { viewer { login } }"
                    )

                assert "Network connection failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_timeout_raises_network_error(self, config: Config) -> None:
        """Test that timeouts raise NetworkError."""
        with patch("httpx.AsyncClient.post") as mock_post:
            # Simulate timeout
            mock_post.side_effect = httpx.TimeoutException(
                "Request timeout", request=Mock()
            )

            async with GitHubGraphQLClient(config.github_api) as github_client:
                with pytest.raises(NetworkError) as exc_info:
                    await github_client._execute_graphql_query(
                        "query { viewer { login } }"
                    )

                assert "Network request timed out" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_401_raises_authentication_error(
        self, config: Config
    ) -> None:
        """Test that HTTP 401 raises AuthenticationError."""
        with patch("httpx.AsyncClient.post") as mock_post:
            # Mock 401 response
            mock_response = Mock()
            mock_response.status_code = 401
            mock_response.text = "Bad credentials"
            mock_response.headers = {}
            mock_post.return_value = mock_response

            async with GitHubGraphQLClient(config.github_api) as github_client:
                with pytest.raises(AuthenticationError) as exc_info:
                    await github_client._execute_graphql_query(
                        "query { viewer { login } }"
                    )

                assert "authentication failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_403_rate_limit_raises_rate_limit_error(
        self, config: Config
    ) -> None:
        """Test that HTTP 403 with rate limit message raises RateLimitError."""
        with patch("httpx.AsyncClient.post") as mock_post:
            # Mock 403 response with rate limit message
            mock_response = Mock()
            mock_response.status_code = 403
            mock_response.text = "API rate limit exceeded"
            mock_response.headers = {}
            mock_post.return_value = mock_response

            async with GitHubGraphQLClient(config.github_api) as github_client:
                with pytest.raises(RateLimitError) as exc_info:
                    await github_client._execute_graphql_query(
                        "query { viewer { login } }"
                    )

                assert "rate limit exceeded" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_429_raises_rate_limit_error(self, config: Config) -> None:
        """Test that HTTP 429 raises RateLimitError."""
        with patch("httpx.AsyncClient.post") as mock_post:
            # Mock 429 response
            mock_response = Mock()
            mock_response.status_code = 429
            mock_response.text = "API rate limit exceeded"
            mock_response.headers = {}
            mock_post.return_value = mock_response

            async with GitHubGraphQLClient(config.github_api) as github_client:
                with pytest.raises(RateLimitError):
                    await github_client._execute_graphql_query(
                        "query { viewer { login } }"
                    )

    @pytest.mark.asyncio
    async def test_500_raises_temporary_api_error(self, config: Config) -> None:
        """Test that HTTP 500+ raises TemporaryAPIError."""
        with patch("httpx.AsyncClient.post") as mock_post:
            # Mock 500 response
            mock_response = Mock()
            mock_response.status_code = 500
            mock_response.text = "Internal server error"
            mock_response.headers = {}
            mock_post.return_value = mock_response

            async with GitHubGraphQLClient(config.github_api) as github_client:
                with pytest.raises(TemporaryAPIError) as exc_info:
                    await github_client._execute_graphql_query(
                        "query { viewer { login } }"
                    )

                assert exc_info.value.status_code == 500
                assert "server error" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_graphql_rate_limit_error_raises_rate_limit_error(
        self, config: Config
    ) -> None:
        """Test that GraphQL rate limit errors raise RateLimitError."""
        with patch("httpx.AsyncClient.post") as mock_post:
            # Mock successful HTTP response with GraphQL rate limit error
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_response.json.return_value = {
                "errors": [{"message": "API rate limit exceeded for user"}]
            }
            mock_post.return_value = mock_response

            async with GitHubGraphQLClient(config.github_api) as github_client:
                with pytest.raises(RateLimitError) as exc_info:
                    await github_client._execute_graphql_query(
                        "query { viewer { login } }"
                    )

                assert "rate limit exceeded" in str(exc_info.value)


class TestValidatorErrorHandling:
    """Test error handling in the validator."""

    @pytest.fixture
    def config(self) -> Config:
        """Create test configuration with caching disabled."""
        from gha_workflow_linter.models import CacheConfig

        return Config(
            github_api=GitHubAPIConfig(
                token="test-token",
                base_url="https://api.github.com",
                graphql_url="https://api.github.com/graphql",
            ),
            cache=CacheConfig(enabled=False),
        )

    @pytest.fixture
    def action_calls(self) -> dict[Path, dict[int, ActionCall]]:
        """Create test action calls."""
        return {
            Path("test.yaml"): {
                1: ActionCall(
                    raw_line="      - uses: actions/checkout@v4",
                    organization="actions",
                    repository="checkout",
                    reference="v4",
                    reference_type=ReferenceType.TAG,
                    line_number=1,
                )
            }
        }

    @pytest.mark.asyncio
    async def test_network_error_during_validation_raises_validation_aborted(
        self, config: Config, action_calls: dict[Path, dict[int, ActionCall]]
    ) -> None:
        """Test that network errors during validation raise ValidationAbortedError."""
        async with ActionCallValidator(config) as validator:
            # Mock the GitHub client to raise a network error
            with patch.object(validator, "_github_client") as mock_client:
                mock_client.validate_repositories_batch.side_effect = (
                    NetworkError("DNS resolution failed")
                )

                with pytest.raises(ValidationAbortedError) as exc_info:
                    await validator.validate_action_calls_async(action_calls)

                assert "API/network issues" in str(exc_info.value)
                assert isinstance(exc_info.value.original_error, NetworkError)

    @pytest.mark.asyncio
    async def test_rate_limit_error_during_validation_raises_validation_aborted(
        self, config: Config, action_calls: dict[Path, dict[int, ActionCall]]
    ) -> None:
        """Test that rate limit errors during validation raise ValidationAbortedError."""
        async with ActionCallValidator(config) as validator:
            # Mock the GitHub client to raise a rate limit error
            with patch.object(validator, "_github_client") as mock_client:
                mock_client.validate_repositories_batch.side_effect = (
                    RateLimitError("GitHub API rate limit exceeded")
                )

                with pytest.raises(ValidationAbortedError) as exc_info:
                    await validator.validate_action_calls_async(action_calls)

                assert "API/network issues" in str(exc_info.value)
                assert isinstance(exc_info.value.original_error, RateLimitError)

    @pytest.mark.asyncio
    async def test_authentication_error_during_validation_raises_validation_aborted(
        self, config: Config, action_calls: dict[Path, dict[int, ActionCall]]
    ) -> None:
        """Test that authentication errors during validation raise ValidationAbortedError."""
        async with ActionCallValidator(config) as validator:
            # Mock the GitHub client to raise an authentication error
            with patch.object(validator, "_github_client") as mock_client:
                mock_client.validate_repositories_batch.side_effect = (
                    AuthenticationError("GitHub API authentication failed")
                )

                with pytest.raises(ValidationAbortedError) as exc_info:
                    await validator.validate_action_calls_async(action_calls)

                assert "API/network issues" in str(exc_info.value)
                assert isinstance(
                    exc_info.value.original_error, AuthenticationError
                )

    @pytest.mark.asyncio
    async def test_network_error_during_reference_validation_raises_validation_aborted(
        self, config: Config, action_calls: dict[Path, dict[int, ActionCall]]
    ) -> None:
        """Test that network errors during reference validation raise ValidationAbortedError."""
        async with ActionCallValidator(config) as validator:
            # Mock the GitHub client - first call succeeds, second call fails
            with patch.object(validator, "_github_client") as mock_client:
                # Repository validation succeeds
                async def mock_repo_validation(*_args, **_kwargs):
                    return {"actions/checkout": True}  # Repository exists

                mock_client.validate_repositories_batch = mock_repo_validation

                # Reference validation fails with network error
                mock_client.validate_references_batch.side_effect = (
                    NetworkError("Network timeout during reference validation")
                )

                with pytest.raises(ValidationAbortedError) as exc_info:
                    await validator.validate_action_calls_async(action_calls)

                assert "API/network issues" in str(exc_info.value)
                assert isinstance(exc_info.value.original_error, NetworkError)

    def test_validation_aborted_error_propagates_through_sync_method(
        self, config: Config, action_calls: dict[Path, dict[int, ActionCall]]
    ) -> None:
        """Test that ValidationAbortedError properly propagates through synchronous validation method."""
        validator = ActionCallValidator(config)

        # Mock the async method to raise ValidationAbortedError
        async def mock_validate_async(*_args: Any, **_kwargs: Any) -> None:
            raise ValidationAbortedError(
                "Unable to validate GitHub Actions due to API/network issues",
                reason="Network connection failed",
                original_error=NetworkError("Connection failed"),
            )

        with patch.object(
            validator,
            "validate_action_calls_async",
            side_effect=mock_validate_async,
        ):
            with pytest.raises(ValidationAbortedError) as exc_info:
                validator.validate_action_calls(action_calls)

            assert "API/network issues" in str(exc_info.value)
            assert isinstance(exc_info.value.original_error, NetworkError)


class TestCLIErrorHandling:
    """Test CLI error handling for network issues."""

    @pytest.fixture
    def mock_validator_with_network_error(
        self, tmp_path: Path
    ) -> ActionCallValidator:
        """Create a validator that raises network errors."""
        validator = Mock()
        validator.validate_action_calls.side_effect = ValidationAbortedError(
            "Unable to validate GitHub Actions due to API/network issues",
            reason="DNS resolution failed",
            original_error=NetworkError("DNS resolution failed"),
        )
        return validator

    @pytest.fixture
    def mock_validator_with_auth_error(
        self, tmp_path: Path
    ) -> ActionCallValidator:
        """Create a validator that raises authentication errors."""
        validator = Mock()
        validator.validate_action_calls.side_effect = ValidationAbortedError(
            "Unable to validate GitHub Actions due to API/network issues",
            reason="GitHub API authentication failed",
            original_error=AuthenticationError(
                "GitHub API authentication failed"
            ),
        )
        return validator

    def test_network_error_returns_exit_code_1(
        self, mock_validator_with_network_error: ActionCallValidator
    ) -> None:
        """Test that network errors result in exit code 1."""
        from gha_workflow_linter.cli import run_linter
        from gha_workflow_linter.models import (
            ActionCall,
            CLIOptions,
            Config,
            ReferenceType,
        )

        config = Config()
        options = CLIOptions(path=Path("."))

        # Create mock workflow calls to trigger validation
        mock_workflow_calls = {
            Path("test.yaml"): {
                1: ActionCall(
                    raw_line="- uses: actions/checkout@v4",
                    line_number=1,
                    organization="actions",
                    repository="checkout",
                    reference="v4",
                    reference_type=ReferenceType.TAG,
                )
            }
        }

        with patch(
            "gha_workflow_linter.cli.ActionCallValidator"
        ) as mock_validator_class:
            mock_validator_class.return_value = (
                mock_validator_with_network_error
            )
            with patch(
                "gha_workflow_linter.cli.WorkflowScanner"
            ) as mock_scanner_class:
                mock_scanner = Mock()
                mock_scanner.scan_directory.return_value = mock_workflow_calls
                mock_scanner.get_scan_summary.return_value = {
                    "total_files": 1,
                    "total_calls": 1,
                    "action_calls": 1,
                    "workflow_calls": 0,
                }
                mock_scanner_class.return_value = mock_scanner

                exit_code = run_linter(config, options)

        assert exit_code == 1

    def test_auth_error_returns_exit_code_1(
        self, mock_validator_with_auth_error: ActionCallValidator
    ) -> None:
        """Test that authentication errors result in exit code 1."""
        from gha_workflow_linter.cli import run_linter
        from gha_workflow_linter.models import (
            ActionCall,
            CLIOptions,
            Config,
            ReferenceType,
        )

        config = Config()
        options = CLIOptions(path=Path("."))

        # Create mock workflow calls to trigger validation
        mock_workflow_calls = {
            Path("test.yaml"): {
                1: ActionCall(
                    raw_line="- uses: actions/checkout@v4",
                    line_number=1,
                    organization="actions",
                    repository="checkout",
                    reference="v4",
                    reference_type=ReferenceType.TAG,
                )
            }
        }

        with patch(
            "gha_workflow_linter.cli.ActionCallValidator"
        ) as mock_validator_class:
            mock_validator_class.return_value = mock_validator_with_auth_error
            with patch(
                "gha_workflow_linter.cli.WorkflowScanner"
            ) as mock_scanner_class:
                mock_scanner = Mock()
                mock_scanner.scan_directory.return_value = mock_workflow_calls
                mock_scanner.get_scan_summary.return_value = {
                    "total_files": 1,
                    "total_calls": 1,
                    "action_calls": 1,
                    "workflow_calls": 0,
                }
                mock_scanner_class.return_value = mock_scanner

                exit_code = run_linter(config, options)

        assert exit_code == 1


class TestErrorClassification:
    """Test that errors are properly classified and don't result in false validation failures."""

    def test_network_error_vs_invalid_action_distinction(self):
        """Test that we can distinguish between network errors and genuinely invalid actions."""
        # Network error should raise NetworkError
        network_error = NetworkError("DNS resolution failed")
        assert isinstance(network_error, NetworkError)
        assert "DNS resolution failed" in str(network_error)

        # Invalid action should be handled as validation result, not exception
        # This is tested in the GitHub API client's handling of GraphQL "not found" errors

    def test_validation_aborted_error_contains_proper_context(self):
        """Test that ValidationAbortedError contains proper context for debugging."""
        original_error = NetworkError("Connection timeout")
        validation_error = ValidationAbortedError(
            "Unable to validate GitHub Actions due to API/network issues",
            reason="Connection timeout",
            original_error=original_error,
        )

        assert (
            validation_error.message
            == "Unable to validate GitHub Actions due to API/network issues"
        )
        assert validation_error.reason == "Connection timeout"
        assert validation_error.original_error is original_error
        assert "Connection timeout" in str(validation_error)

    def test_github_api_error_hierarchy(self):
        """Test that GitHub API errors follow proper inheritance hierarchy."""
        # Base GitHub API error
        api_error = GitHubAPIError("API failed", status_code=400)
        assert isinstance(api_error, GitHubAPIError)
        assert api_error.status_code == 400

        # Authentication error
        auth_error = AuthenticationError()
        assert isinstance(auth_error, GitHubAPIError)
        assert isinstance(auth_error, AuthenticationError)

        # Rate limit error
        rate_error = RateLimitError()
        assert isinstance(rate_error, GitHubAPIError)
        assert isinstance(rate_error, RateLimitError)

        # Temporary API error
        temp_error = TemporaryAPIError("Server error", status_code=500)
        assert isinstance(temp_error, GitHubAPIError)
        assert isinstance(temp_error, TemporaryAPIError)
        assert temp_error.status_code == 500
