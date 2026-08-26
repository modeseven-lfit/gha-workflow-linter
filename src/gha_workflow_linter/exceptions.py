# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""
Custom exceptions for the GitHub Actions Workflow Linter.

This module defines exception classes that provide more granular error handling,
particularly for network connectivity and API access issues.
"""


class ValidationError(Exception):
    """Base class for validation errors."""

    pass


class NetworkError(ValidationError):
    """Raised when network connectivity issues prevent validation."""

    def __init__(self, message: str, original_error: Exception | None = None):
        self.message = message
        self.original_error = original_error
        super().__init__(message)


class GitHubAPIError(ValidationError):
    """Raised when GitHub API returns an error or is inaccessible."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        original_error: Exception | None = None,
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
        status_code: int | None = None,
        original_error: Exception | None = None,
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
        original_error: Exception | None = None,
    ):
        self.message = message
        self.reason = reason
        self.original_error = original_error
        super().__init__(f"{message}: {reason}")


class GitError(ValidationError):
    """Raised when Git operations fail."""

    def __init__(self, message: str, original_error: Exception | None = None):
        self.message = message
        self.original_error = original_error
        super().__init__(message)


class GitInconclusiveError(GitError):
    """Raised when git produced no answer about the repository.

    Distinct from its parent because the two mean opposite things about
    the workflow being checked. A remote that answers "no such
    repository" has told us something; a lookup that produced no answer
    has told us nothing, and reporting the second as a finding blames
    the workflow for a problem elsewhere.

    Every layer that turns a failure into a result must let this one
    past, so it can surface as ``NETWORK_ERROR`` rather than as
    ``INVALID_REPOSITORY`` or ``INVALID_REFERENCE``. Which of the two
    subclasses it is does not matter there -- only to the user, who is
    told what to do about it.
    """


class GitUnreachableError(GitInconclusiveError):
    """Raised when git could not reach the remote at all.

    The connection is the fault: a name that would not resolve, a route
    that was not there, a session refused or dropped. This is the one
    the user can act on by checking the network.
    """


class GitUnusableError(GitInconclusiveError):
    """Raised when git itself could not produce an answer.

    An absent or unexecutable ``git``, or one killed part way through by
    the out-of-memory killer or a cancelled job. The remote is just as
    unheard from as with its sibling, so the layers above treat the two
    alike -- but the advice differs, and telling someone with no ``git``
    to check their DNS would send them looking in the wrong place.
    """


class RepositoryNotFoundError(ValidationError):
    """Raised when a repository cannot be found or accessed."""

    def __init__(self, repository: str, message: str | None = None):
        self.repository = repository
        if message is None:
            message = f"Repository not found: {repository}"
        super().__init__(message)


class ReferenceNotFoundError(ValidationError):
    """Raised when a Git reference cannot be found."""

    def __init__(
        self, repository: str, reference: str, message: str | None = None
    ):
        self.repository = repository
        self.reference = reference
        if message is None:
            message = f"Reference '{reference}' not found in repository '{repository}'"
        super().__init__(message)


class ConfigurationError(Exception):
    """Raised when there's an issue with configuration."""

    pass
