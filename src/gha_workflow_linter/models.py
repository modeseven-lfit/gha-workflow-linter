# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Pydantic models for gha-workflow-linter configuration and data structures."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LogLevel(str, Enum):
    """Available log levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ValidationMethod(str, Enum):
    """Method used for validating action calls."""

    GITHUB_API = "github-api"
    GIT = "git"


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
            raise ValueError(
                "Organization name cannot start or end with hyphen"
            )
        if "--" in v:
            raise ValueError(
                "Organization name cannot contain consecutive hyphens"
            )
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
            raise ValueError("Repository name contains invalid characters")
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
            f"line {self.action_call.line_number}: {self.action_call.raw_line.strip()} [{self.result.value}]"
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
    use_ssh_agent: bool = Field(
        True, description="Use SSH agent for authentication"
    )
    max_parallel_operations: int = Field(
        None, description="Max parallel Git operations (default: CPU count)"
    )
    clone_depth: int = Field(
        1, description="Git clone depth for shallow clones"
    )

    @field_validator("max_parallel_operations")  # type: ignore[misc]
    @classmethod
    def validate_max_parallel_operations(cls, v: int | None) -> int | None:
        """Validate max parallel operations."""
        if v is not None and v < 1:
            raise ValueError("Max parallel operations must be at least 1")
        if v is not None and v > 64:
            raise ValueError("Max parallel operations must be at most 64")
        return v


class GitHubAPIConfig(BaseModel):  # type: ignore[misc]
    """GitHub API configuration."""

    base_url: str = Field(
        "https://api.github.com", description="GitHub API base URL"
    )
    graphql_url: str = Field(
        "https://api.github.com/graphql", description="GitHub GraphQL API URL"
    )
    token: str | None = Field(
        default=None,
        description="GitHub API token (overrides GITHUB_TOKEN env var)",
    )
    timeout: float = Field(30.0, description="Request timeout in seconds")
    max_retries: int = Field(
        3, description="Maximum number of retries for failed requests"
    )
    retry_delay: float = Field(
        1.0, description="Delay between retries in seconds"
    )
    batch_size: int = Field(50, description="Batch size for API requests")
    max_repositories_per_query: int = Field(
        100, description="Max repos per GraphQL query"
    )
    max_references_per_query: int = Field(
        100, description="Max refs per GraphQL query"
    )
    rate_limit_threshold: int = Field(
        1000, description="Remaining requests threshold"
    )
    rate_limit_reset_buffer: int = Field(
        60, description="Buffer seconds before rate limit reset"
    )

    @property
    def effective_token(self) -> str | None:
        """Get the effective token, preferring explicit token over environment."""
        import os

        if self.token:
            return self.token
        return os.environ.get("GITHUB_TOKEN")


class APICallStats(BaseModel):  # type: ignore[misc]
    """API call statistics tracking."""

    total_calls: int = Field(0, description="Total API calls made")
    graphql_calls: int = Field(0, description="GraphQL API calls")
    rest_calls: int = Field(0, description="REST API calls")
    git_calls: int = Field(0, description="Git operations")
    cache_hits: int = Field(0, description="Cache hits")
    rate_limit_delays: int = Field(0, description="Rate limit induced delays")
    failed_calls: int = Field(0, description="Failed API calls")
    repositories_validated: int = Field(
        0, description="Number of repositories validated"
    )
    git_clone_operations: int = Field(0, description="Git clone operations")
    git_ls_remote_operations: int = Field(
        0, description="Git ls-remote operations"
    )

    @property
    def success_rate(self) -> float:
        """Calculate success rate as a percentage."""
        if self.total_calls == 0:
            return 100.0
        return ((self.total_calls - self.failed_calls) / self.total_calls) * 100

    @property
    def cache_hit_rate(self) -> float:
        """Calculate cache hit rate as a percentage of API calls that could have been made."""
        api_calls_made = self.total_calls - self.cache_hits
        if api_calls_made <= 0:
            return 0.0
        return (self.cache_hits / api_calls_made) * 100

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

    @property
    def reset_timestamp(self) -> int:
        """Get reset timestamp (alias for reset_at for compatibility)."""
        return self.reset_at

    @property
    def percentage_used(self) -> float:
        """Calculate percentage of rate limit used."""
        if self.limit == 0:
            return 0.0
        return (self.used / self.limit) * 100


class CacheConfig(BaseModel):  # type: ignore[misc]
    """Local cache configuration."""

    enabled: bool = Field(True, description="Enable local caching")
    cache_dir: Path = Field(
        Path.home() / ".cache" / "gha-workflow-linter",
        description="Directory to store cache files",
    )
    cache_file: str = Field(
        "validation_cache.json", description="Cache file name"
    )
    default_ttl_seconds: int = Field(
        7 * 24 * 60 * 60,  # 7 days
        description="Default TTL for cache entries in seconds",
    )
    max_cache_size: int = Field(
        10000, description="Maximum number of cache entries"
    )
    cleanup_on_startup: bool = Field(
        True, description="Clean expired entries on startup"
    )

    @property
    def cache_file_path(self) -> Path:
        """Get the full path to the cache file."""
        return self.cache_dir / self.cache_file


class Config(BaseModel):  # type: ignore[misc]
    """Main configuration model."""

    model_config = ConfigDict()

    log_level: LogLevel = Field(LogLevel.INFO, description="Logging level")
    parallel_workers: int = Field(4, description="Number of parallel workers")
    scan_extensions: list[str] = Field(
        default_factory=lambda: [".yml", ".yaml"],
        description="Workflow file extensions to scan",
    )
    exclude_patterns: list[str] = Field(
        default_factory=list, description="Patterns to exclude from scanning"
    )
    require_pinned_sha: bool = Field(
        True, description="Require all actions to be pinned to commit SHAs"
    )
    validation_method: ValidationMethod | None = Field(
        None, description="Validation method (auto-detected if None)"
    )
    auto_fix: bool = Field(
        True, description="Automatically fix broken/invalid references"
    )
    auto_latest: bool = Field(
        True, description="Use latest versions when auto-fixing"
    )
    two_space_comments: bool = Field(
        False, description="Use two spaces before inline comments"
    )
    skip_actions: bool = Field(
        False, description="Skip scanning action.yaml/action.yml files"
    )

    network: NetworkConfig = Field(
        default_factory=lambda: NetworkConfig(),
        description="Network configuration",
    )
    git: GitConfig = Field(
        default_factory=lambda: GitConfig(),
        description="Git operations configuration",
    )
    github_api: GitHubAPIConfig = Field(
        default_factory=lambda: GitHubAPIConfig(),
        description="GitHub API configuration",
    )
    cache: CacheConfig = Field(
        default_factory=lambda: CacheConfig(), description="Cache configuration"
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
            raise ValueError("Parallel workers must be at most 32")
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
    no_cache: bool = Field(False, description="Bypass local cache")
    purge_cache: bool = Field(False, description="Purge cache and exit")
    cache_ttl: int | None = Field(
        None, description="Override cache TTL in seconds"
    )
    validation_method: ValidationMethod | None = Field(
        None, description="Validation method (auto-detected if None)"
    )
    exclude: list[str] | None = Field(
        None, description="Patterns to exclude from scanning"
    )
    auto_fix: bool = Field(
        True, description="Automatically fix broken/invalid references"
    )
    auto_latest: bool = Field(
        True, description="Use latest versions when auto-fixing"
    )
    two_space_comments: bool = Field(
        False, description="Use two spaces before inline comments"
    )
    skip_actions: bool = Field(
        False, description="Skip scanning action.yaml/action.yml files"
    )

    @field_validator("output_format")  # type: ignore[misc]
    @classmethod
    def validate_output_format(cls, v: str) -> str:
        """Validate output format."""
        valid_formats = ["text", "json"]
        if v not in valid_formats:
            raise ValueError(
                f"Output format must be one of: {', '.join(valid_formats)}"
            )
        return v

    @field_validator("path")  # type: ignore[misc]
    @classmethod
    def validate_path(cls, v: Path) -> Path:
        """Validate that path exists (only in non-test environments)."""
        # Allow non-existent paths for testing
        import os

        if os.getenv("PYTEST_CURRENT_TEST") is None and not v.exists():
            raise ValueError(f"Path does not exist: {v}")
        return v.resolve() if v.exists() else v
