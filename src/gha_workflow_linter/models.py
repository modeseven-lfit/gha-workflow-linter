# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Pydantic models for gha-workflow-linter configuration and data structures."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
import re

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

from .system_utils import get_default_workers


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
    INVALID_PATH = "invalid_path"
    INVALID_SYNTAX = "invalid_syntax"
    NETWORK_ERROR = "network_error"
    TIMEOUT = "timeout"
    NOT_PINNED_TO_SHA = "not_pinned_to_sha"
    TEST_REFERENCE = "test_reference"
    ANNOTATED_TAG_SHA = "annotated_tag_sha"


class Severity(str, Enum):
    """Reporting severity for a linter finding.

    Severity governs presentation. Whether a finding fails the run is
    decided by its :class:`Category` together with the relevant
    ``--verify-*`` flag; see :mod:`gha_workflow_linter.exit_codes`.
    """

    ERROR = "error"
    WARNING = "warning"
    NOTICE = "notice"


class Category(str, Enum):
    """Whether a finding reports breakage, staleness, or a failed check.

    ``DEFECT`` findings are wrong *now* and always count towards the exit
    code. ``CURRENCY`` findings are correct but could be newer, and are
    advisory unless the caller opts in with a ``--verify-*`` flag.
    ``INFRASTRUCTURE`` means the check itself could not run, which must
    never be silently reported as a pass.
    """

    DEFECT = "defect"
    CURRENCY = "currency"
    INFRASTRUCTURE = "infrastructure"


# Classification of every validation result. Results absent from this
# mapping (only VALID) are not findings at all.
_RESULT_CATEGORIES: dict[ValidationResult, Category] = {
    ValidationResult.INVALID_REPOSITORY: Category.DEFECT,
    ValidationResult.INVALID_REFERENCE: Category.DEFECT,
    ValidationResult.INVALID_PATH: Category.DEFECT,
    ValidationResult.INVALID_SYNTAX: Category.DEFECT,
    ValidationResult.ANNOTATED_TAG_SHA: Category.DEFECT,
    ValidationResult.NOT_PINNED_TO_SHA: Category.CURRENCY,
    ValidationResult.TEST_REFERENCE: Category.CURRENCY,
    ValidationResult.NETWORK_ERROR: Category.INFRASTRUCTURE,
    ValidationResult.TIMEOUT: Category.INFRASTRUCTURE,
}


def result_category(result: ValidationResult) -> Category | None:
    """Return the category of a validation result.

    Args:
        result: The validation result to classify.

    Returns:
        The finding category, or None when the result is not a finding
        (that is, ``ValidationResult.VALID``).
    """
    return _RESULT_CATEGORIES.get(result)


class AllowListFindingKind(str, Enum):
    """What is wrong with a detected allow-list pin.

    ``STALE`` and ``UNPINNED`` are currency findings: the pin works, but
    a newer allow-list exists. The remainder are defects that are wrong
    now. Only currency findings may be silenced by an
    ``allow-list-pin-ok`` directive, because that directive asserts "this
    pin is deliberately at this version" -- a statement about currency,
    not about correctness.
    """

    STALE = "stale"
    UNPINNED = "unpinned"
    COMMENT_MISMATCH = "comment_mismatch"
    UNRESOLVABLE = "unresolvable"
    INVALID_SPEC = "invalid_spec"


#: Finding kinds an ``allow-list-pin-ok`` directive may silence. A pin
#: whose comment lies, whose SHA does not exist, or whose spec is
#: malformed is broken regardless of intent, so those are never
#: suppressible.
SUPPRESSIBLE_ALLOW_LIST_KINDS: frozenset[AllowListFindingKind] = frozenset(
    {
        AllowListFindingKind.STALE,
        AllowListFindingKind.UNPINNED,
    }
)


_ALLOW_LIST_CATEGORIES: dict[AllowListFindingKind, Category] = {
    AllowListFindingKind.STALE: Category.CURRENCY,
    AllowListFindingKind.UNPINNED: Category.CURRENCY,
    AllowListFindingKind.COMMENT_MISMATCH: Category.DEFECT,
    AllowListFindingKind.UNRESOLVABLE: Category.DEFECT,
    AllowListFindingKind.INVALID_SPEC: Category.DEFECT,
}


def allow_list_category(kind: AllowListFindingKind) -> Category:
    """Return the category of an allow-list finding kind.

    Args:
        kind: The finding kind to classify.

    Returns:
        The finding category.
    """
    return _ALLOW_LIST_CATEGORIES[kind]


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


class ActionCall(BaseModel):
    """Represents a GitHub Actions call found in a workflow."""

    model_config = ConfigDict(frozen=True)

    raw_line: str = Field(..., description="The original line from workflow")
    line_number: int = Field(..., description="Line number in the file")
    organization: str = Field(..., description="GitHub organization name")
    repository: str = Field(..., description="Repository name")
    reference: str = Field(..., description="Git reference (tag/branch/sha)")
    comment: str | None = Field(default=None, description="Trailing comment")
    call_type: ActionCallType = Field(
        default=ActionCallType.UNKNOWN, description="Type of action call"
    )
    reference_type: ReferenceType = Field(
        default=ReferenceType.UNKNOWN, description="Type of reference"
    )

    @field_validator("organization")
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

    @field_validator("repository")
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


class ValidationError(BaseModel):
    """Represents a validation error for an action call."""

    model_config = ConfigDict(frozen=True)

    file_path: Path = Field(..., description="Path to the workflow file")
    action_call: ActionCall = Field(..., description="The invalid action call")
    result: ValidationResult = Field(..., description="Validation result")
    error_message: str | None = Field(
        default=None, description="Detailed error"
    )

    def __str__(self) -> str:
        """String representation of the validation error."""
        return (
            f"Invalid action call in workflow: {self.file_path} ❌\n"
            f"line {self.action_call.line_number}: {self.action_call.raw_line.strip()} [{self.result.value}]"
        )


class ScanResult(BaseModel):
    """Results of scanning workflows."""

    model_config = ConfigDict(frozen=True)

    total_workflows: int = Field(
        default=0, description="Total workflows scanned"
    )
    total_action_calls: int = Field(
        default=0, description="Total action calls found"
    )
    valid_calls: int = Field(default=0, description="Number of valid calls")
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


class NetworkConfig(BaseModel):
    """Network-related configuration."""

    timeout_seconds: int = Field(
        default=30, description="Network request timeout"
    )
    max_retries: int = Field(default=3, description="Maximum retry attempts")
    retry_delay_seconds: float = Field(
        default=1.0, description="Delay between retries"
    )
    rate_limit_delay_seconds: float = Field(
        default=0.1, description="Rate limit delay"
    )


class GitConfig(BaseModel):
    """Git operations configuration."""

    timeout_seconds: int = Field(default=30, description="Git command timeout")
    use_ssh_agent: bool = Field(
        default=True, description="Use SSH agent for authentication"
    )
    max_parallel_operations: int | None = Field(
        default=None,
        description="Max parallel Git operations (default: CPU count)",
    )
    clone_depth: int = Field(
        default=1, description="Git clone depth for shallow clones"
    )

    @field_validator("max_parallel_operations")
    @classmethod
    def validate_max_parallel_operations(cls, v: int | None) -> int | None:
        """Validate max parallel operations."""
        if v is not None and v < 1:
            raise ValueError("Max parallel operations must be at least 1")
        if v is not None and v > 64:
            raise ValueError("Max parallel operations must be at most 64")
        return v


class GitHubAPIConfig(BaseModel):
    """GitHub API configuration."""

    base_url: str = Field(
        default="https://api.github.com", description="GitHub API base URL"
    )
    graphql_url: str = Field(
        default="https://api.github.com/graphql",
        description="GitHub GraphQL API URL",
    )
    token: str | None = Field(
        default=None,
        description="GitHub API token (overrides GITHUB_TOKEN env var)",
    )
    timeout: float = Field(
        default=30.0, description="Request timeout in seconds"
    )
    max_retries: int = Field(
        default=3, description="Maximum number of retries for failed requests"
    )
    retry_delay: float = Field(
        default=1.0, description="Delay between retries in seconds"
    )
    batch_size: int = Field(
        default=50, description="Batch size for API requests"
    )
    max_repositories_per_query: int = Field(
        default=100, description="Max repos per GraphQL query"
    )
    max_references_per_query: int = Field(
        default=100, description="Max refs per GraphQL query"
    )
    rate_limit_threshold: int = Field(
        default=1000, description="Remaining requests threshold"
    )
    rate_limit_reset_buffer: int = Field(
        default=60, description="Buffer seconds before rate limit reset"
    )

    @property
    def effective_token(self) -> str | None:
        """Get the effective token, preferring explicit token over environment."""
        import os

        if self.token:
            return self.token
        return os.environ.get("GITHUB_TOKEN")


class APICallStats(BaseModel):
    """API call statistics tracking."""

    total_calls: int = Field(default=0, description="Total API calls made")
    graphql_calls: int = Field(default=0, description="GraphQL API calls")
    rest_calls: int = Field(default=0, description="REST API calls")
    git_calls: int = Field(default=0, description="Git operations")
    cache_hits: int = Field(default=0, description="Cache hits")
    rate_limit_delays: int = Field(
        default=0, description="Rate limit induced delays"
    )
    failed_calls: int = Field(default=0, description="Failed API calls")
    repositories_validated: int = Field(
        default=0, description="Number of repositories validated"
    )
    git_clone_operations: int = Field(
        default=0, description="Git clone operations"
    )
    git_ls_remote_operations: int = Field(
        default=0, description="Git ls-remote operations"
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


class GitHubRateLimitInfo(BaseModel):
    """GitHub API rate limit information."""

    limit: int = Field(default=5000, description="Rate limit maximum")
    remaining: int = Field(default=5000, description="Remaining requests")
    reset_at: int = Field(default=0, description="Rate limit reset timestamp")
    used: int = Field(default=0, description="Used requests")

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


class CacheConfig(BaseModel):
    """Local cache configuration."""

    enabled: bool = Field(default=True, description="Enable local caching")
    cache_dir: Path = Field(
        default=Path.home() / ".cache" / "gha-workflow-linter",
        description="Directory to store cache files",
    )
    cache_file: str = Field(
        default="validation_cache.json", description="Cache file name"
    )
    default_ttl_seconds: int = Field(
        default=7 * 24 * 60 * 60,  # 7 days
        description="Default TTL for cache entries in seconds",
    )
    max_cache_size: int = Field(
        default=10000, description="Maximum number of cache entries"
    )
    cleanup_on_startup: bool = Field(
        default=True, description="Clean expired entries on startup"
    )

    @property
    def cache_file_path(self) -> Path:
        """Get the full path to the cache file."""
        return self.cache_dir / self.cache_file


class AllowListConfig(BaseModel):
    """Configuration for harden-runner allow-list pin checking.

    Allow-list pins are an ``lfreleng-actions`` convention rather than
    GitHub-native syntax, so the check is advisory by default: it reports
    stale pins but never changes the exit code. ``verify`` opts in to
    enforcement.
    """

    enabled: bool = Field(
        default=True,
        description="Detect harden-runner allow-list pins",
    )
    verify: bool = Field(
        default=False,
        description=(
            "Treat stale allow-list pins as errors and exit with the "
            "ALLOW_LIST_STALE status"
        ),
    )
    update: bool = Field(
        default=False,
        description=(
            "Rewrite stale allow-list pins in place. Suppressed pins are "
            "never rewritten"
        ),
    )
    show_suppressed: bool = Field(
        default=False,
        description=(
            "Report suppressed pins as notices. Never affects the exit code"
        ),
    )
    org: str = Field(
        default="",
        description=(
            "Workflow organisation used to resolve the '@<sha>' shorthand. "
            "When empty the tool infers it from GITHUB_REPOSITORY_OWNER, "
            "then the 'upstream' git remote, then 'origin'"
        ),
    )
    filename: str = Field(
        default="allow_list.txt",
        description=(
            "Conventional allow-list filename, used by the recogniser for "
            "scalars whose key name gives no clue. There is deliberately no "
            "per-consumer registry: every consumer shares one grammar, one "
            "host repository, and one staleness condition"
        ),
    )
    key_patterns: list[str] = Field(
        default_factory=lambda: [
            "*allow_list*",
            "*allowlist*",
            "*allow-list*",
        ],
        description=(
            "Key-name patterns recognised as allow-list coordinates in "
            "workflow_call input defaults and reusable-workflow 'with' blocks"
        ),
    )
    extra_globs: list[str] = Field(
        default_factory=lambda: [
            "examples/**/*.yaml",
            "examples/**/*.yml",
        ],
        description=(
            "Extra globs scanned only by the allow-list checker. Example "
            "caller workflows live outside .github/workflows and are "
            "otherwise not discovered"
        ),
    )


class Config(BaseModel):
    """Main configuration model."""

    # populate_by_name lets update_actions be set by its own name as well
    # as through the deprecated auto_latest alias.
    model_config = ConfigDict(populate_by_name=True)

    log_level: LogLevel = Field(
        default=LogLevel.INFO, description="Logging level"
    )
    parallel_workers: int = Field(
        default_factory=get_default_workers,
        description="Number of parallel workers (auto-detects based on CPU count)",
    )
    scan_extensions: list[str] = Field(
        default_factory=lambda: [".yml", ".yaml"],
        description="Workflow file extensions to scan",
    )
    exclude_patterns: list[str] = Field(
        default_factory=list, description="Patterns to exclude from scanning"
    )
    require_pinned_sha: bool = Field(
        default=True,
        description="Require all actions to be pinned to commit SHAs",
    )
    validation_method: ValidationMethod | None = Field(
        default=None, description="Validation method (auto-detected if None)"
    )
    auto_fix: bool = Field(
        default=True, description="Automatically fix broken/invalid references"
    )
    update_actions: bool = Field(
        default=False,
        validation_alias=AliasChoices("update_actions", "auto_latest"),
        description=(
            "Update action calls to the latest release when auto-fixing. "
            "The former name 'auto_latest' still loads and is deprecated"
        ),
    )
    allow_prerelease: bool = Field(
        default=False,
        description="Allow prerelease versions when finding latest versions",
    )
    two_space_comments: bool = Field(
        default=True, description="Use two spaces before inline comments"
    )
    skip_actions: bool = Field(
        default=False, description="Skip scanning action.yaml/action.yml files"
    )
    fix_test_calls: bool = Field(
        default=False,
        description="Enable action call fixes with test-related keywords in comments (e.g., test, testing)",
    )
    cooldown_days: int = Field(
        default=0,
        ge=0,
        description=(
            "Minimum number of days an action release must have been "
            "available before it is eligible for an update (0 disables "
            "the cooldown)"
        ),
    )

    # pydantic BaseModel subclasses with all-defaulted fields require no
    # arguments (keyword args are still accepted), but basedpyright reports
    # reportArgumentType when such classes are used as Field default_factory
    # values. Suppress that one diagnostic on the factory references.
    network: NetworkConfig = Field(
        default_factory=NetworkConfig,
        description="Network configuration",
    )
    git: GitConfig = Field(
        default_factory=GitConfig,
        description="Git operations configuration",
    )
    github_api: GitHubAPIConfig = Field(
        default_factory=GitHubAPIConfig,
        description="GitHub API configuration",
    )
    cache: CacheConfig = Field(
        default_factory=CacheConfig,
        description="Cache configuration",
    )
    allow_list: AllowListConfig = Field(
        default_factory=AllowListConfig,
        description="Allow-list pin checking configuration",
    )

    @property
    def effective_github_token(self) -> str | None:
        """Get effective GitHub token from config or environment."""
        import os

        return self.github_api.token or os.getenv("GITHUB_TOKEN")

    @field_validator("parallel_workers")
    @classmethod
    def validate_parallel_workers(cls, v: int) -> int:
        """Validate parallel worker count."""
        if v < 1:
            raise ValueError("Parallel workers must be at least 1")
        if v > 32:
            raise ValueError("Parallel workers must be at most 32")
        return v


class CLIOptions(BaseModel):
    """CLI command options."""

    path: Path = Field(default=Path.cwd(), description="Path to scan")
    config_file: Path | None = Field(
        default=None, description="Config file path"
    )
    verbose: bool = Field(default=False, description="Verbose output")
    quiet: bool = Field(default=False, description="Quiet mode")
    output_format: str = Field(default="text", description="Output format")
    fail_on_error: bool = Field(
        default=True, description="Exit with error on failures"
    )
    parallel: bool = Field(
        default=True, description="Enable parallel processing"
    )
    require_pinned_sha: bool = Field(
        default=True, description="Require SHA pinning"
    )
    no_cache: bool = Field(default=False, description="Bypass local cache")
    cache_ttl: int | None = Field(
        default=None, description="Override cache TTL in seconds"
    )
    validation_method: ValidationMethod | None = Field(
        default=None, description="Validation method (auto-detected if None)"
    )
    exclude: list[str] | None = Field(
        default=None, description="Patterns to exclude from scanning"
    )
    auto_fix: bool | None = Field(
        default=None, description="Automatically fix broken/invalid references"
    )
    update_actions: bool | None = Field(
        default=None,
        description="Update action calls to the latest release",
    )
    allow_prerelease: bool | None = Field(
        default=None,
        description="Allow prerelease versions when finding latest versions",
    )
    two_space_comments: bool | None = Field(
        default=None, description="Use two spaces before inline comments"
    )
    skip_actions: bool | None = Field(
        default=None, description="Skip scanning action.yaml/action.yml files"
    )
    fix_test_calls: bool | None = Field(
        default=None, description="Fix action calls with test comments"
    )
    cooldown: int | None = Field(
        default=None,
        ge=0,
        description=(
            "Minimum days a release must be available before updating "
            "(falls back to Dependabot config, then 0)"
        ),
    )
    files: list[str] | None = Field(
        default=None, description="Specific files to scan (supports wildcards)"
    )
    verify_actions: bool = Field(
        default=False,
        description=(
            "Treat outdated action calls as errors and exit with the "
            "ACTIONS_OUTDATED status"
        ),
    )
    allow_list: bool | None = Field(
        default=None, description="Enable allow-list pin detection"
    )
    verify_allow_list: bool = Field(
        default=False,
        description="Treat stale allow-list pins as errors",
    )
    update_allow_list: bool = Field(
        default=False,
        description="Rewrite stale allow-list pins in place",
    )
    show_suppressed: bool = Field(
        default=False,
        description="Report suppressed allow-list pins as notices",
    )
    allow_list_org: str | None = Field(
        default=None,
        description="Workflow organisation for '@<sha>' shorthand resolution",
    )

    @field_validator("output_format")
    @classmethod
    def validate_output_format(cls, v: str) -> str:
        """Validate output format."""
        valid_formats = ["text", "json"]
        if v not in valid_formats:
            raise ValueError(
                f"Output format must be one of: {', '.join(valid_formats)}"
            )
        return v

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: Path) -> Path:
        """Validate that path exists (only in non-test environments)."""
        # Allow non-existent paths for testing
        import os

        if os.getenv("PYTEST_CURRENT_TEST") is None and not v.exists():
            raise ValueError(f"Path does not exist: {v}")
        return v.resolve() if v.exists() else v
