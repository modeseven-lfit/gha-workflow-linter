# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Simple tests for exceptions module to improve coverage."""

from __future__ import annotations

import pytest

from gha_workflow_linter.exceptions import (
    AuthenticationError,
    ConfigurationError,
    GitHubAPIError,
    NetworkError,
    RateLimitError,
    TemporaryAPIError,
    ValidationAbortedError,
    ValidationError,
)


class TestValidationError:
    """Test the ValidationError base class."""

    def test_init_basic(self) -> None:
        """Test ValidationError initialization."""
        error = ValidationError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)

    def test_inheritance(self) -> None:
        """Test ValidationError inheritance."""
        error = ValidationError("Test")
        assert isinstance(error, Exception)
        assert isinstance(error, ValidationError)


class TestNetworkError:
    """Test the NetworkError class."""

    def test_init_message_only(self) -> None:
        """Test NetworkError with message only."""
        error = NetworkError("Connection failed")
        assert error.message == "Connection failed"
        assert error.original_error is None
        assert str(error) == "Connection failed"

    def test_init_with_original_error(self) -> None:
        """Test NetworkError with original error."""
        original = ConnectionError("DNS resolution failed")
        error = NetworkError("Network timeout", original)
        assert error.message == "Network timeout"
        assert error.original_error is original
        assert str(error) == "Network timeout"

    def test_inheritance(self) -> None:
        """Test NetworkError inheritance."""
        error = NetworkError("Test")
        assert isinstance(error, ValidationError)
        assert isinstance(error, NetworkError)


class TestGitHubAPIError:
    """Test the GitHubAPIError class."""

    def test_init_message_only(self) -> None:
        """Test GitHubAPIError with message only."""
        error = GitHubAPIError("API unavailable")
        assert error.message == "API unavailable"
        assert error.status_code is None
        assert error.original_error is None
        assert str(error) == "API unavailable"

    def test_init_with_status_code(self) -> None:
        """Test GitHubAPIError with status code."""
        error = GitHubAPIError("Server error", 500)
        assert error.message == "Server error"
        assert error.status_code == 500
        assert str(error) == "Server error"

    def test_init_with_original_error(self) -> None:
        """Test GitHubAPIError with original error."""
        original = ValueError("Invalid JSON")
        error = GitHubAPIError("Parse error", 400, original)
        assert error.message == "Parse error"
        assert error.status_code == 400
        assert error.original_error is original

    def test_inheritance(self) -> None:
        """Test GitHubAPIError inheritance."""
        error = GitHubAPIError("Test")
        assert isinstance(error, ValidationError)
        assert isinstance(error, GitHubAPIError)


class TestAuthenticationError:
    """Test the AuthenticationError class."""

    def test_init_default_message(self) -> None:
        """Test AuthenticationError with default message."""
        error = AuthenticationError()
        assert error.message == "GitHub API authentication failed"
        assert error.status_code == 401
        assert str(error) == "GitHub API authentication failed"

    def test_init_custom_message(self) -> None:
        """Test AuthenticationError with custom message."""
        error = AuthenticationError("Invalid token provided")
        assert error.message == "Invalid token provided"
        assert error.status_code == 401
        assert str(error) == "Invalid token provided"

    def test_inheritance(self) -> None:
        """Test AuthenticationError inheritance."""
        error = AuthenticationError()
        assert isinstance(error, ValidationError)
        assert isinstance(error, GitHubAPIError)
        assert isinstance(error, AuthenticationError)


class TestRateLimitError:
    """Test the RateLimitError class."""

    def test_init_default_message(self) -> None:
        """Test RateLimitError with default message."""
        error = RateLimitError()
        assert error.message == "GitHub API rate limit exceeded"
        assert error.status_code == 429
        assert str(error) == "GitHub API rate limit exceeded"

    def test_init_custom_message(self) -> None:
        """Test RateLimitError with custom message."""
        error = RateLimitError("Rate limit hit, try again later")
        assert error.message == "Rate limit hit, try again later"
        assert error.status_code == 429
        assert str(error) == "Rate limit hit, try again later"

    def test_inheritance(self) -> None:
        """Test RateLimitError inheritance."""
        error = RateLimitError()
        assert isinstance(error, ValidationError)
        assert isinstance(error, GitHubAPIError)
        assert isinstance(error, RateLimitError)


class TestTemporaryAPIError:
    """Test the TemporaryAPIError class."""

    def test_init_message_only(self) -> None:
        """Test TemporaryAPIError with message only."""
        error = TemporaryAPIError("Temporary service unavailable")
        assert error.message == "Temporary service unavailable"
        assert error.status_code is None
        assert error.original_error is None

    def test_init_with_status_code(self) -> None:
        """Test TemporaryAPIError with status code."""
        error = TemporaryAPIError("Service timeout", 503)
        assert error.message == "Service timeout"
        assert error.status_code == 503

    def test_init_with_original_error(self) -> None:
        """Test TemporaryAPIError with original error."""
        original = TimeoutError("Request timeout")
        error = TemporaryAPIError("API timeout", 504, original)
        assert error.message == "API timeout"
        assert error.status_code == 504
        assert error.original_error is original

    def test_inheritance(self) -> None:
        """Test TemporaryAPIError inheritance."""
        error = TemporaryAPIError("Test")
        assert isinstance(error, ValidationError)
        assert isinstance(error, GitHubAPIError)
        assert isinstance(error, TemporaryAPIError)


class TestValidationAbortedError:
    """Test the ValidationAbortedError class."""

    def test_init_basic(self) -> None:
        """Test ValidationAbortedError initialization."""
        error = ValidationAbortedError("Validation stopped", "User cancelled")
        assert error.message == "Validation stopped"
        assert error.reason == "User cancelled"
        assert error.original_error is None
        assert str(error) == "Validation stopped: User cancelled"

    def test_init_with_original_error(self) -> None:
        """Test ValidationAbortedError with original error."""
        original = RuntimeError("User interrupt")
        error = ValidationAbortedError("Aborted", "Signal received", original)
        assert error.message == "Aborted"
        assert error.reason == "Signal received"
        assert error.original_error is original
        assert str(error) == "Aborted: Signal received"

    def test_inheritance(self) -> None:
        """Test ValidationAbortedError inheritance."""
        error = ValidationAbortedError("Test", "Reason")
        assert isinstance(error, ValidationError)
        assert isinstance(error, ValidationAbortedError)


class TestConfigurationError:
    """Test the ConfigurationError class."""

    def test_init_basic(self) -> None:
        """Test ConfigurationError initialization."""
        error = ConfigurationError("Invalid configuration")
        assert str(error) == "Invalid configuration"

    def test_inheritance(self) -> None:
        """Test ConfigurationError inheritance."""
        error = ConfigurationError("Test")
        assert isinstance(error, Exception)
        assert isinstance(error, ConfigurationError)
        # Should not inherit from ValidationError
        assert not isinstance(error, ValidationError)


class TestErrorExceptionHandling:
    """Test error exception handling scenarios."""

    def test_raise_and_catch_network_error(self) -> None:
        """Test raising and catching NetworkError."""
        with pytest.raises(NetworkError) as exc_info:
            raise NetworkError("Test network error")

        assert exc_info.value.message == "Test network error"

    def test_raise_and_catch_authentication_error(self) -> None:
        """Test raising and catching AuthenticationError."""
        with pytest.raises(AuthenticationError) as exc_info:
            raise AuthenticationError("Bad token")

        assert exc_info.value.message == "Bad token"
        assert exc_info.value.status_code == 401

    def test_catch_base_validation_error(self) -> None:
        """Test catching derived errors as ValidationError."""
        with pytest.raises(ValidationError):
            raise NetworkError("Network issue")

        with pytest.raises(ValidationError):
            raise GitHubAPIError("API issue")

        with pytest.raises(ValidationError):
            raise AuthenticationError("Auth issue")

    def test_exception_error_chaining(self) -> None:
        """Test exception chaining with original errors."""
        original_error = ConnectionError("DNS failed")
        network_error = NetworkError("Connection issue", original_error)

        assert network_error.original_error is original_error
        assert isinstance(network_error.original_error, ConnectionError)
