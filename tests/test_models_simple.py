# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Simple tests for models module to improve coverage."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from gha_workflow_linter.models import (
    ActionCall,
    ActionCallType,
    APICallStats,
    CacheConfig,
    CLIOptions,
    Config,
    GitConfig,
    GitHubAPIConfig,
    GitHubRateLimitInfo,
    LogLevel,
    NetworkConfig,
    ReferenceType,
    ScanResult,
    ValidationError,
    ValidationResult,
)


class TestEnums:
    """Test enum classes."""

    def test_log_level_values(self) -> None:
        """Test LogLevel enum values."""
        assert LogLevel.DEBUG.value == "DEBUG"
        assert LogLevel.INFO.value == "INFO"
        assert LogLevel.WARNING.value == "WARNING"
        assert LogLevel.ERROR.value == "ERROR"
        assert LogLevel.CRITICAL.value == "CRITICAL"

    def test_validation_result_values(self) -> None:
        """Test ValidationResult enum values."""
        assert ValidationResult.VALID.value == "valid"
        assert ValidationResult.INVALID_REPOSITORY.value == "invalid_repository"
        assert ValidationResult.INVALID_REFERENCE.value == "invalid_reference"
        assert ValidationResult.INVALID_SYNTAX.value == "invalid_syntax"
        assert ValidationResult.NETWORK_ERROR.value == "network_error"
        assert ValidationResult.TIMEOUT.value == "timeout"
        assert ValidationResult.NOT_PINNED_TO_SHA.value == "not_pinned_to_sha"

    def test_action_call_type_values(self) -> None:
        """Test ActionCallType enum values."""
        assert ActionCallType.ACTION.value == "action"
        assert ActionCallType.WORKFLOW.value == "workflow"
        assert ActionCallType.UNKNOWN.value == "unknown"

    def test_reference_type_values(self) -> None:
        """Test ReferenceType enum values."""
        assert ReferenceType.COMMIT_SHA.value == "commit_sha"
        assert ReferenceType.TAG.value == "tag"
        assert ReferenceType.BRANCH.value == "branch"
        assert ReferenceType.UNKNOWN.value == "unknown"


class TestActionCall:
    """Test ActionCall model."""

    def test_init_basic(self) -> None:
        """Test ActionCall initialization."""
        call = ActionCall(
            raw_line="uses: actions/checkout@v4",
            line_number=10,
            organization="actions",
            repository="actions/checkout",
            reference="v4",
        )

        assert call.raw_line == "uses: actions/checkout@v4"
        assert call.line_number == 10
        assert call.organization == "actions"
        assert call.repository == "actions/checkout"
        assert call.reference == "v4"
        assert call.comment is None

    def test_init_with_comment(self) -> None:
        """Test ActionCall initialization with comment."""
        call = ActionCall(
            raw_line="uses: actions/checkout@v4 # Get code",
            line_number=5,
            organization="actions",
            repository="actions/checkout",
            reference="v4",
            comment="# Get code",
        )

        assert call.comment == "# Get code"

    def test_frozen_model(self) -> None:
        """Test that ActionCall is frozen."""
        call = ActionCall(
            raw_line="uses: actions/checkout@v4",
            line_number=10,
            organization="actions",
            repository="actions/checkout",
            reference="v4",
        )

        # Should raise error when trying to modify
        with pytest.raises(ValueError):  # ValidationError from pydantic
            call.line_number = 20


class TestValidationError:
    """Test ValidationError model."""

    def test_init_basic(self) -> None:
        """Test ValidationError initialization."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@v4",
            line_number=10,
            organization="actions",
            repository="actions/checkout",
            reference="v4",
        )

        error = ValidationError(
            file_path=Path("test.yml"),
            action_call=action_call,
            result=ValidationResult.INVALID_REPOSITORY,
        )

        assert error.file_path == Path("test.yml")
        assert error.action_call is action_call
        assert error.result == ValidationResult.INVALID_REPOSITORY
        assert error.error_message is None

    def test_init_with_error_message(self) -> None:
        """Test ValidationError with error message."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@v4",
            line_number=10,
            organization="actions",
            repository="actions/checkout",
            reference="v4",
        )

        error = ValidationError(
            file_path=Path("test.yml"),
            action_call=action_call,
            result=ValidationResult.NETWORK_ERROR,
            error_message="Connection timeout",
        )

        assert error.error_message == "Connection timeout"

    def test_str_representation(self) -> None:
        """Test string representation of ValidationError."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@v4",
            line_number=10,
            organization="actions",
            repository="actions/checkout",
            reference="v4",
        )

        error = ValidationError(
            file_path=Path("test.yml"),
            action_call=action_call,
            result=ValidationResult.INVALID_REPOSITORY,
        )

        str_repr = str(error)
        assert "test.yml" in str_repr
        assert "actions/checkout" in str_repr
        assert "line 10" in str_repr


class TestScanResult:
    """Test ScanResult model."""

    def test_init_defaults(self) -> None:
        """Test ScanResult with default values."""
        result = ScanResult()

        assert result.total_workflows == 0
        assert result.total_action_calls == 0
        assert result.valid_calls == 0
        assert result.errors == []

    def test_init_with_values(self) -> None:
        """Test ScanResult with specific values."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@v4",
            line_number=10,
            organization="actions",
            repository="actions/checkout",
            reference="v4",
        )

        error = ValidationError(
            file_path=Path("test.yml"),
            action_call=action_call,
            result=ValidationResult.INVALID_REPOSITORY,
        )

        result = ScanResult(
            total_workflows=5,
            total_action_calls=20,
            valid_calls=18,
            errors=[error],
        )

        assert result.total_workflows == 5
        assert result.total_action_calls == 20
        assert result.valid_calls == 18
        assert len(result.errors) == 1

    def test_success_rate_property(self) -> None:
        """Test success_rate property calculation."""
        result = ScanResult(total_action_calls=10, valid_calls=8)

        assert result.success_rate == 80.0

    def test_success_rate_no_calls(self) -> None:
        """Test success_rate with no calls."""
        result = ScanResult()
        assert result.success_rate == 100.0


class TestNetworkConfig:
    """Test NetworkConfig model."""

    def test_init_defaults(self) -> None:
        """Test NetworkConfig with default values."""
        config = NetworkConfig()

        assert config.timeout_seconds == 30
        assert config.max_retries == 3
        assert config.retry_delay_seconds == 1.0
        assert config.rate_limit_delay_seconds == 0.1

    def test_init_custom_values(self) -> None:
        """Test NetworkConfig with custom values."""
        config = NetworkConfig(
            timeout_seconds=60,
            max_retries=5,
            retry_delay_seconds=2.0,
            rate_limit_delay_seconds=0.5,
        )

        assert config.timeout_seconds == 60
        assert config.max_retries == 5
        assert config.retry_delay_seconds == 2.0
        assert config.rate_limit_delay_seconds == 0.5


class TestGitConfig:
    """Test GitConfig model."""

    def test_init_defaults(self) -> None:
        """Test GitConfig with default values."""
        config = GitConfig()

        assert config.timeout_seconds == 30
        assert config.use_ssh_agent is True

    def test_init_custom_values(self) -> None:
        """Test GitConfig with custom values."""
        config = GitConfig(timeout_seconds=45, use_ssh_agent=False)

        assert config.timeout_seconds == 45
        assert config.use_ssh_agent is False


class TestGitHubAPIConfig:
    """Test GitHubAPIConfig model."""

    def test_init_defaults(self) -> None:
        """Test GitHubAPIConfig with default values."""
        config = GitHubAPIConfig()

        assert config.base_url == "https://api.github.com"
        assert config.graphql_url == "https://api.github.com/graphql"
        assert config.token is None
        assert config.max_repositories_per_query == 100
        assert config.max_references_per_query == 100

    def test_init_with_token(self) -> None:
        """Test GitHubAPIConfig with token."""
        config = GitHubAPIConfig(token="ghp_test_token")
        assert config.token == "ghp_test_token"

    def test_effective_token_from_token(self) -> None:
        """Test effective_token property with explicit token."""
        config = GitHubAPIConfig(token="explicit_token")
        assert config.effective_token == "explicit_token"

    def test_effective_token_from_env(self) -> None:
        """Test effective_token property from environment."""
        config = GitHubAPIConfig()

        with patch.dict("os.environ", {"GITHUB_TOKEN": "env_token"}):
            assert config.effective_token == "env_token"

    def test_effective_token_none(self) -> None:
        """Test effective_token property when no token available."""
        config = GitHubAPIConfig()

        with patch.dict("os.environ", {}, clear=True):
            assert config.effective_token is None


class TestAPICallStats:
    """Test APICallStats model."""

    def test_init_defaults(self) -> None:
        """Test APICallStats with default values."""
        stats = APICallStats()

        assert stats.total_calls == 0
        assert stats.graphql_calls == 0
        assert stats.rest_calls == 0
        assert stats.git_calls == 0
        assert stats.cache_hits == 0
        assert stats.rate_limit_delays == 0
        assert stats.failed_calls == 0

    def test_success_rate_property(self) -> None:
        """Test success_rate property calculation."""
        stats = APICallStats(total_calls=100, failed_calls=10)

        assert stats.success_rate == 90.0

    def test_success_rate_no_calls(self) -> None:
        """Test success_rate with no calls."""
        stats = APICallStats()
        assert stats.success_rate == 100.0

    def test_cache_hit_rate_property(self) -> None:
        """Test cache_hit_rate property calculation."""
        stats = APICallStats(total_calls=50, cache_hits=20)

        # Cache hit rate should be hits / (total - cache_hits) * 100
        expected_rate = (20 / (50 - 20)) * 100
        assert stats.cache_hit_rate == expected_rate

    def test_cache_hit_rate_no_api_calls(self) -> None:
        """Test cache_hit_rate with no API calls."""
        stats = APICallStats(cache_hits=10)
        assert stats.cache_hit_rate == 0.0


class TestGitHubRateLimitInfo:
    """Test GitHubRateLimitInfo model."""

    def test_init_defaults(self) -> None:
        """Test GitHubRateLimitInfo with default values."""
        info = GitHubRateLimitInfo()

        assert info.limit == 5000
        assert info.remaining == 5000
        assert info.reset_at == 0
        assert info.used == 0

    def test_percentage_used_property(self) -> None:
        """Test percentage_used property calculation."""
        info = GitHubRateLimitInfo(limit=5000, used=1000)

        assert info.percentage_used == 20.0

    def test_percentage_used_zero_limit(self) -> None:
        """Test percentage_used with zero limit."""
        info = GitHubRateLimitInfo(limit=0, used=0)
        assert info.percentage_used == 0.0


class TestCacheConfig:
    """Test CacheConfig model."""

    def test_init_defaults(self) -> None:
        """Test CacheConfig with default values."""
        config = CacheConfig()

        assert config.enabled is True
        assert config.cache_file == "validation_cache.json"
        assert config.default_ttl_seconds == 7 * 24 * 60 * 60  # 7 days
        assert config.max_cache_size == 10000
        assert config.cleanup_on_startup is True

    def test_cache_file_path_property(self) -> None:
        """Test cache_file_path property."""
        config = CacheConfig()

        path = config.cache_file_path
        assert isinstance(path, Path)
        assert path.name == "validation_cache.json"


class TestConfig:
    """Test Config model."""

    def test_init_defaults(self) -> None:
        """Test Config with default values."""
        config = Config()

        assert config.log_level == LogLevel.INFO
        assert config.parallel_workers == 4
        assert config.scan_extensions == [".yml", ".yaml"]
        assert config.exclude_patterns == []
        assert isinstance(config.network, NetworkConfig)
        assert isinstance(config.git, GitConfig)
        assert isinstance(config.github_api, GitHubAPIConfig)
        assert isinstance(config.cache, CacheConfig)

    def test_validate_parallel_workers_valid(self) -> None:
        """Test parallel workers validation with valid values."""
        config = Config(parallel_workers=8)
        assert config.parallel_workers == 8

    def test_validate_parallel_workers_invalid_low(self) -> None:
        """Test parallel workers validation with too low value."""
        with pytest.raises(ValueError, match="at least 1"):
            Config(parallel_workers=0)

    def test_validate_parallel_workers_invalid_high(self) -> None:
        """Test parallel workers validation with too high value."""
        with pytest.raises(ValueError, match="at most 32"):
            Config(parallel_workers=50)


class TestCLIOptions:
    """Test CLIOptions model."""

    def test_init_defaults(self) -> None:
        """Test CLIOptions with default values."""
        options = CLIOptions()

        assert options.path == Path.cwd()
        assert options.config_file is None
        assert options.verbose is False
        assert options.quiet is False
        assert options.output_format == "text"
        assert options.fail_on_error is True
        assert options.parallel is True
        assert options.require_pinned_sha is True

    def test_init_custom_values(self) -> None:
        """Test CLIOptions with custom values."""
        custom_path = Path("/tmp/test")
        config_path = Path("config.yaml")

        options = CLIOptions(
            path=custom_path,
            config_file=config_path,
            verbose=True,
            quiet=False,
            output_format="json",
            fail_on_error=False,
            parallel=False,
            require_pinned_sha=False,
        )

        assert options.path == custom_path
        assert options.config_file == config_path
        assert options.verbose is True
        assert options.output_format == "json"
        assert options.fail_on_error is False
        assert options.parallel is False
        assert options.require_pinned_sha is False
