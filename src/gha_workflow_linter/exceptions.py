# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""
Custom exceptions for the GitHub Actions Workflow Linter.

This module defines exception classes that provide more granular error handling,
particularly for network connectivity and API access issues.
"""

from typing import Optional


class ValidationError(Exception):
    """Base class for validation errors."""

    pass


class NetworkError(ValidationError):
    """Raised when network connectivity issues prevent validation."""

    def __init__(
        self, message: str, original_error: Optional[Exception] = None
    ):
        self.message = message
        self.original_error = original_error
        super().__init__(message)


class GitHubAPIError(ValidationError):
    """Raised when GitHub API returns an error or is inaccessible."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        original_error: Optional[Exception] = None,
    ):
        self.message = message
        self.status_code = status_code
        self.original_error = original_error
        super().__init__(message)


class AuthenticationError(GitHubAPIError):
    """Raised when GitHub API authentication fails."""

    def __init__(self, message: str = "GitHub API authentication failed"):
        super().__init__(message, status_code=401)


class RateLimitError(GitHubAPIError):
    """Raised when GitHub API rate limit is exceeded."""

    def __init__(self, message: str = "GitHub API rate limit exceeded"):
        super().__init__(message, status_code=429)


class TemporaryAPIError(GitHubAPIError):
    """Raised for temporary API issues that might resolve with retry."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        original_error: Optional[Exception] = None,
    ):
        self.message = message
        self.status_code = status_code
        self.original_error = original_error
        super().__init__(message, status_code, original_error)


class ValidationAbortedError(ValidationError):
    """Raised when validation must be aborted due to external factors."""

    def __init__(
        self,
        message: str,
        reason: str,
        original_error: Optional[Exception] = None,
    ):
        self.message = message
        self.reason = reason
        self.original_error = original_error
        super().__init__(f"{message}: {reason}")


class GitError(ValidationError):
    """Raised when Git operations fail."""

    def __init__(
        self, message: str, original_error: Optional[Exception] = None
    ):
        self.message = message
        self.original_error = original_error
        super().__init__(message)


class RepositoryNotFoundError(ValidationError):
    """Raised when a repository cannot be found or accessed."""

    def __init__(self, repository: str, message: Optional[str] = None):
        self.repository = repository
        if message is None:
            message = f"Repository not found: {repository}"
        super().__init__(message)


class ReferenceNotFoundError(ValidationError):
    """Raised when a Git reference cannot be found."""

    def __init__(
        self, repository: str, reference: str, message: Optional[str] = None
    ):
        self.repository = repository
        self.reference = reference
        if message is None:
            message = f"Reference '{reference}' not found in repository '{repository}'"
        super().__init__(message)


class ConfigurationError(Exception):
    """Raised when there's an issue with configuration."""

    pass
