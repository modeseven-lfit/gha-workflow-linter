# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Pydantic models for gha-workflow-linter configuration and data structures."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LogLevel(str, Enum):
    """Available log levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ValidationResult(str, Enum):
    """Result of action call validation."""

    VALID = "valid"
    INVALID_REPOSITORY = "invalid_repository"
    INVALID_REFERENCE = "invalid_reference"
    INVALID_SYNTAX = "invalid_syntax"
    NETWORK_ERROR = "network_error"
    TIMEOUT = "timeout"
    NOT_PINNED_TO_SHA = "not_pinned_to_sha"


class ActionCallType(str, Enum):
    """Type of action call detected."""

    ACTION = "action"
    WORKFLOW = "workflow"
    UNKNOWN = "unknown"


class ReferenceType(str, Enum):
    """Type of Git reference."""

    COMMIT_SHA = "commit_sha"
    TAG = "tag"
    BRANCH = "branch"
    UNKNOWN = "unknown"


class ActionCall(BaseModel):  # type: ignore[misc]
    """Represents a GitHub Actions call found in a workflow."""

    model_config = ConfigDict(frozen=True)

    raw_line: str = Field(..., description="The original line from workflow")
    line_number: int = Field(..., description="Line number in the file")
    organization: str = Field(..., description="GitHub organization name")
    repository: str = Field(..., description="Repository name")
    reference: str = Field(..., description="Git reference (tag/branch/sha)")
    comment: str | None = Field(None, description="Trailing comment")
    call_type: ActionCallType = Field(
        ActionCallType.UNKNOWN, description="Type of action call"
    )
    reference_type: ReferenceType = Field(
        ReferenceType.UNKNOWN, description="Type of reference"
    )

    @field_validator("organization")  # type: ignore[misc]
    @classmethod
    def validate_organization(cls, v: str) -> str:
        """Validate GitHub organization name."""
        if not v:
            raise ValueError("Organization name cannot be empty")
        if len(v) > 39:
            raise ValueError("Organization name cannot exceed 39 characters")
        if v.startswith("-") or v.endswith("-"):
            raise ValueError("Organization name cannot start or end with hyphen")
        if "--" in v:
            raise ValueError("Organization name cannot contain consecutive hyphens")
        if not re.match(r"^[A-Za-z0-9-]+$", v):
            raise ValueError(
                "Organization name can only contain alphanumeric characters "
                "and hyphens"
            )
        return v

    @field_validator("repository")  # type: ignore[misc]
    @classmethod
    def validate_repository(cls, v: str) -> str:
        """Validate GitHub repository name."""
        if not v:
            raise ValueError("Repository name cannot be empty")
        # Allow repository names with paths for workflow calls
        if not re.match(r"^[A-Za-z0-9._/-]+$", v):
            raise ValueError(
                "Repository name contains invalid characters"
            )
        return v

    def __str__(self) -> str:
        """String representation of the action call."""
        return f"{self.organization}/{self.repository}@{self.reference}"


class ValidationError(BaseModel):  # type: ignore[misc]
    """Represents a validation error for an action call."""

    model_config = ConfigDict(frozen=True)

    file_path: Path = Field(..., description="Path to the workflow file")
    action_call: ActionCall = Field(..., description="The invalid action call")
    result: ValidationResult = Field(..., description="Validation result")
    error_message: str | None = Field(None, description="Detailed error")

    def __str__(self) -> str:
        """String representation of the validation error."""
        return (
            f"❌ Invalid action call in workflow: {self.file_path}\n"
            f"- {self.action_call.raw_line.strip()} [{self.result.value}]"
        )


class ScanResult(BaseModel):  # type: ignore[misc]
    """Results of scanning workflows."""

    model_config = ConfigDict(frozen=True)

    total_workflows: int = Field(0, description="Total workflows scanned")
    total_action_calls: int = Field(0, description="Total action calls found")
    valid_calls: int = Field(0, description="Number of valid calls")
    errors: list[ValidationError] = Field(
        default_factory=list, description="Validation errors"
    )

    @property
    def invalid_calls(self) -> int:
        """Number of invalid calls."""
        return len(self.errors)

    @property
    def success_rate(self) -> float:
        """Success rate as percentage."""
        if self.total_action_calls == 0:
            return 100.0
        return (self.valid_calls / self.total_action_calls) * 100




class NetworkConfig(BaseModel):  # type: ignore[misc]
    """Network-related configuration."""

    timeout_seconds: int = Field(30, description="Network request timeout")
    max_retries: int = Field(3, description="Maximum retry attempts")
    retry_delay_seconds: float = Field(1.0, description="Delay between retries")
    rate_limit_delay_seconds: float = Field(0.1, description="Rate limit delay")


class GitConfig(BaseModel):  # type: ignore[misc]
    """Git operations configuration."""

    timeout_seconds: int = Field(30, description="Git command timeout")
    use_ssh_agent: bool = Field(True, description="Use SSH agent for authentication")


class GitHubAPIConfig(BaseModel):  # type: ignore[misc]
    """GitHub API configuration."""

    base_url: str = Field("https://api.github.com", description="GitHub API base URL")
    graphql_url: str = Field("https://api.github.com/graphql", description="GitHub GraphQL API URL")
    token: str | None = Field(
        default=None,
        description="GitHub API token (overrides GITHUB_TOKEN env var)"
    )
    max_repositories_per_query: int = Field(100, description="Max repos per GraphQL query")
    max_references_per_query: int = Field(100, description="Max refs per GraphQL query")
    rate_limit_threshold: int = Field(1000, description="Remaining requests threshold")
    rate_limit_reset_buffer: int = Field(60, description="Buffer seconds before rate limit reset")


class APICallStats(BaseModel):  # type: ignore[misc]
    """API call statistics tracking."""

    total_calls: int = Field(0, description="Total API calls made")
    graphql_calls: int = Field(0, description="GraphQL API calls")
    rest_calls: int = Field(0, description="REST API calls")
    git_calls: int = Field(0, description="Git ls-remote calls")
    cache_hits: int = Field(0, description="Cache hits")
    rate_limit_delays: int = Field(0, description="Rate limit induced delays")
    failed_calls: int = Field(0, description="Failed API calls")

    def increment_total(self) -> None:
        """Increment total call counter."""
        self.total_calls += 1

    def increment_graphql(self) -> None:
        """Increment GraphQL call counter."""
        self.graphql_calls += 1
        self.increment_total()

    def increment_rest(self) -> None:
        """Increment REST call counter."""
        self.rest_calls += 1
        self.increment_total()

    def increment_git(self) -> None:
        """Increment Git call counter."""
        self.git_calls += 1
        self.increment_total()

    def increment_cache_hit(self) -> None:
        """Increment cache hit counter."""
        self.cache_hits += 1

    def increment_rate_limit_delay(self) -> None:
        """Increment rate limit delay counter."""
        self.rate_limit_delays += 1

    def increment_failed_call(self) -> None:
        """Increment failed call counter."""
        self.failed_calls += 1


class GitHubRateLimitInfo(BaseModel):  # type: ignore[misc]
    """GitHub API rate limit information."""

    limit: int = Field(5000, description="Rate limit maximum")
    remaining: int = Field(5000, description="Remaining requests")
    reset_at: int = Field(0, description="Rate limit reset timestamp")
    used: int = Field(0, description="Used requests")


class Config(BaseModel):  # type: ignore[misc]
    """Main configuration model."""

    model_config = ConfigDict()

    log_level: LogLevel = Field(LogLevel.INFO, description="Logging level")
    parallel_workers: int = Field(4, description="Number of parallel workers")
    scan_extensions: list[str] = Field(
        default_factory=lambda: [".yml", ".yaml"],
        description="Workflow file extensions to scan"
    )
    exclude_patterns: list[str] = Field(
        default_factory=list,
        description="Patterns to exclude from scanning"
    )
    require_pinned_sha: bool = Field(
        True,
        description="Require all actions to be pinned to commit SHAs"
    )

    network: NetworkConfig = Field(
        default_factory=lambda: NetworkConfig(), description="Network configuration"
    )
    git: GitConfig = Field(
        default_factory=lambda: GitConfig(), description="Git operations configuration"
    )
    github_api: GitHubAPIConfig = Field(
        default_factory=lambda: GitHubAPIConfig(), description="GitHub API configuration"
    )

    @property
    def effective_github_token(self) -> str | None:
        """Get effective GitHub token from config or environment."""
        import os
        return self.github_api.token or os.getenv("GITHUB_TOKEN")

    @field_validator("parallel_workers")  # type: ignore[misc]
    @classmethod
    def validate_parallel_workers(cls, v: int) -> int:
        """Validate parallel worker count."""
        if v < 1:
            raise ValueError("Parallel workers must be at least 1")
        if v > 32:
            raise ValueError("Parallel workers cannot exceed 32")
        return v


class CLIOptions(BaseModel):  # type: ignore[misc]
    """CLI command options."""

    path: Path = Field(Path.cwd(), description="Path to scan")
    config_file: Path | None = Field(None, description="Config file path")
    verbose: bool = Field(False, description="Verbose output")
    quiet: bool = Field(False, description="Quiet mode")
    output_format: str = Field("text", description="Output format")
    fail_on_error: bool = Field(True, description="Exit with error on failures")
    parallel: bool = Field(True, description="Enable parallel processing")
    require_pinned_sha: bool = Field(True, description="Require SHA pinning")

    @field_validator("path")  # type: ignore[misc]
    @classmethod
    def validate_path(cls, v: Path) -> Path:
        """Validate that path exists."""
        if not v.exists():
            raise ValueError(f"Path does not exist: {v}")
        return v.resolve()
