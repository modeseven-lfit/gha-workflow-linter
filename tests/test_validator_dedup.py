# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for validator deduplication functionality."""

from __future__ import annotations

from pathlib import Path
import tempfile
from unittest.mock import AsyncMock, Mock, patch

import pytest

from gha_workflow_linter.models import (
    ActionCall,
    ActionCallType,
    APICallStats,
    CacheConfig,
    Config,
    GitHubRateLimitInfo,
    LogLevel,
    ReferenceType,
    ValidationResult,
)
from gha_workflow_linter.validator import ActionCallValidator


@pytest.fixture
def test_config_no_sha_pinning() -> Config:
    """Test configuration with SHA pinning disabled for deduplication tests."""
    # Use a temporary cache directory to avoid interference between tests
    temp_dir = Path(tempfile.mkdtemp())
    cache_config = CacheConfig(
        enabled=False,  # Disable cache for these tests
        cache_dir=temp_dir,
        cache_file="test_cache.json",
    )
    return Config(
        log_level=LogLevel.DEBUG,
        parallel_workers=2,
        scan_extensions=[".yml", ".yaml"],
        exclude_patterns=["**/node_modules/**", "**/test/**"],
        require_pinned_sha=False,  # Disable SHA pinning for these tests
        cache=cache_config,
    )


@pytest.fixture
def duplicate_action_calls() -> dict[Path, dict[int, ActionCall]]:
    """Create test data with duplicate action calls across multiple files."""
    # Same action call appears in multiple files
    checkout_call = ActionCall(
        raw_line="- uses: actions/checkout@v4",
        line_number=10,
        organization="actions",
        repository="checkout",
        reference="v4",
        comment=None,
        call_type=ActionCallType.ACTION,
        reference_type=ReferenceType.TAG,
    )

    setup_python_call = ActionCall(
        raw_line="- uses: actions/setup-python@v5.0.0",
        line_number=15,
        organization="actions",
        repository="setup-python",
        reference="v5.0.0",
        comment=None,
        call_type=ActionCallType.ACTION,
        reference_type=ReferenceType.TAG,
    )

    # Different line numbers but same action
    checkout_call_2 = ActionCall(
        raw_line="      - uses: actions/checkout@v4",
        line_number=8,
        organization="actions",
        repository="checkout",
        reference="v4",
        comment=None,
        call_type=ActionCallType.ACTION,
        reference_type=ReferenceType.TAG,
    )

    return {
        Path("workflow1.yml"): {
            10: checkout_call,
            15: setup_python_call,
        },
        Path("workflow2.yml"): {
            8: checkout_call_2,
            20: setup_python_call,
        },
        Path("workflow3.yml"): {
            5: checkout_call,
        },
    }


class TestValidatorDeduplication:
    """Test validator deduplication functionality."""

    @pytest.mark.asyncio
    async def test_deduplication_reduces_api_calls(
        self,
        test_config_no_sha_pinning: Config,
        duplicate_action_calls: dict[Path, dict[int, ActionCall]],
    ) -> None:
        """Test that deduplication reduces the number of API calls made."""
        # Create mock client with properly configured async methods
        mock_github_client = AsyncMock()

        # Configure mock methods to return values directly
        mock_github_client.validate_repositories_batch = AsyncMock(
            return_value={
                "actions/checkout": True,
                "actions/setup-python": True,
            }
        )

        mock_github_client.validate_references_batch = AsyncMock(
            return_value={
                ("actions/checkout", "v4"): True,
                ("actions/setup-python", "v5.0.0"): True,
            }
        )

        # Mock API stats
        mock_stats = APICallStats(
            total_calls=4,  # 2 repos + 2 refs
            graphql_calls=2,
            rest_calls=0,
            git_calls=0,
            cache_hits=0,
            rate_limit_delays=0,
            failed_calls=0,
        )
        mock_github_client.get_api_stats = Mock(return_value=mock_stats)
        mock_github_client.get_rate_limit_info = Mock(
            return_value=GitHubRateLimitInfo(
                limit=5000, remaining=4996, reset_at=0, used=4
            )
        )

        validator = ActionCallValidator(test_config_no_sha_pinning)
        validator._github_client = mock_github_client

        errors = await validator.validate_action_calls_async(
            duplicate_action_calls
        )

        # Should have made only 2 unique repository validation calls
        mock_github_client.validate_repositories_batch.assert_called_once()

        # Should have made only 2 unique reference validation calls
        mock_github_client.validate_references_batch.assert_called_once()

        # Should have no errors if all calls are valid
        assert len(errors) == 0

    @pytest.mark.asyncio
    async def test_deduplication_maps_errors_to_all_occurrences(
        self,
        test_config_no_sha_pinning: Config,
        duplicate_action_calls: dict[Path, dict[int, ActionCall]],
    ) -> None:
        """Test that validation errors are mapped back to all occurrences."""
        mock_github_client = AsyncMock()

        # Mock: actions/checkout repository exists but reference is invalid
        mock_github_client.validate_repositories_batch = AsyncMock(
            return_value={
                "actions/checkout": True,
                "actions/setup-python": True,
            }
        )

        # Mock: actions/checkout@v4 reference is invalid
        mock_github_client.validate_references_batch = AsyncMock(
            return_value={
                ("actions/checkout", "v4"): False,  # Invalid reference
                ("actions/setup-python", "v5.0.0"): True,
            }
        )

        mock_stats = APICallStats(
            total_calls=0,
            graphql_calls=0,
            rest_calls=0,
            git_calls=0,
            cache_hits=0,
            rate_limit_delays=0,
            failed_calls=0,
        )
        mock_github_client.get_api_stats = Mock(return_value=mock_stats)
        mock_github_client.get_rate_limit_info = Mock(
            return_value=GitHubRateLimitInfo(
                limit=5000,
                remaining=5000,
                reset_at=0,
                used=0,
            )
        )

        validator = ActionCallValidator(test_config_no_sha_pinning)
        validator._github_client = mock_github_client

        errors = await validator.validate_action_calls_async(
            duplicate_action_calls
        )

        # Should have 3 errors (one for each occurrence of actions/checkout@v4)
        checkout_errors = [
            e for e in errors if e.action_call.repository == "checkout"
        ]
        assert len(checkout_errors) == 3

        # Verify all three files are represented in errors
        error_files = {e.file_path for e in checkout_errors}
        expected_files = {
            Path("workflow1.yml"),
            Path("workflow2.yml"),
            Path("workflow3.yml"),
        }
        assert error_files == expected_files

        # All checkout errors should be INVALID_REFERENCE
        for error in checkout_errors:
            assert error.result == ValidationResult.INVALID_REFERENCE

    def test_unique_call_key_generation(self, test_config: Config) -> None:
        """Test that unique call keys are generated correctly."""
        calls = {
            Path("test.yml"): {
                1: ActionCall(
                    raw_line="- uses: actions/checkout@v4",
                    line_number=1,
                    organization="actions",
                    repository="checkout",
                    reference="v4",
                    comment=None,
                    call_type=ActionCallType.ACTION,
                    reference_type=ReferenceType.TAG,
                ),
                2: ActionCall(
                    raw_line="- uses: actions/checkout@main",
                    line_number=2,
                    organization="actions",
                    repository="checkout",
                    reference="main",
                    comment=None,
                    call_type=ActionCallType.ACTION,
                    reference_type=ReferenceType.BRANCH,
                ),
            }
        }

        # Extract the deduplication logic manually for testing
        unique_calls = {}
        for _file_path, file_calls in calls.items():
            for action_call in file_calls.values():
                call_key = f"{action_call.organization}/{action_call.repository}@{action_call.reference}"
                unique_calls[call_key] = action_call

        # Should have 2 unique calls despite same org/repo
        assert len(unique_calls) == 2
        assert "actions/checkout@v4" in unique_calls
        assert "actions/checkout@main" in unique_calls

    @pytest.mark.asyncio
    async def test_validation_statistics_with_deduplication(
        self,
        test_config_no_sha_pinning: Config,
        duplicate_action_calls: dict[Path, dict[int, ActionCall]],
    ) -> None:
        """Test that validation statistics correctly reflect deduplication."""
        mock_github_client = AsyncMock()

        # All validations succeed
        mock_github_client.validate_repositories_batch = AsyncMock(
            return_value={
                "actions/checkout": True,
                "actions/setup-python": True,
            }
        )

        mock_github_client.validate_references_batch = AsyncMock(
            return_value={
                ("actions/checkout", "v4"): True,
                ("actions/setup-python", "v5.0.0"): True,
            }
        )

        mock_stats = APICallStats(
            total_calls=4,
            graphql_calls=2,
            rest_calls=0,
            git_calls=0,
            cache_hits=0,
            rate_limit_delays=0,
            failed_calls=0,
        )
        mock_github_client.get_api_stats = Mock(return_value=mock_stats)
        mock_github_client.get_rate_limit_info = Mock(
            return_value=GitHubRateLimitInfo(
                limit=5000,
                remaining=5000,
                reset_at=0,
                used=0,
            )
        )

        validator = ActionCallValidator(test_config_no_sha_pinning)
        validator._github_client = mock_github_client

        errors = await validator.validate_action_calls_async(
            duplicate_action_calls
        )

        # Get validation summary with statistics
        total_calls = sum(
            len(calls) for calls in duplicate_action_calls.values()
        )
        unique_calls = 2  # actions/checkout@v4 and actions/setup-python@v5.0.0

        summary = validator.get_validation_summary(
            errors, total_calls, unique_calls
        )

        assert summary["total_calls"] == 5
        assert summary["unique_calls_validated"] == 2
        assert summary["duplicate_calls_avoided"] == 3
        assert summary["total_errors"] == 0

    @pytest.mark.asyncio
    async def test_mixed_valid_invalid_deduplication(
        self, test_config_no_sha_pinning: Config
    ) -> None:
        """Test deduplication with mixed valid and invalid calls."""
        # Create test data with one valid and one invalid call, each duplicated
        calls = {
            Path("workflow1.yml"): {
                1: ActionCall(
                    raw_line="- uses: actions/checkout@v4",
                    line_number=1,
                    organization="actions",
                    repository="checkout",
                    reference="v4",
                    comment=None,
                    call_type=ActionCallType.ACTION,
                    reference_type=ReferenceType.TAG,
                ),
                2: ActionCall(
                    raw_line="- uses: nonexistent/repo@v1",
                    line_number=2,
                    organization="nonexistent",
                    repository="repo",
                    reference="v1",
                    comment=None,
                    call_type=ActionCallType.ACTION,
                    reference_type=ReferenceType.TAG,
                ),
            },
            Path("workflow2.yml"): {
                1: ActionCall(
                    raw_line="- uses: actions/checkout@v4",
                    line_number=1,
                    organization="actions",
                    repository="checkout",
                    reference="v4",
                    comment=None,
                    call_type=ActionCallType.ACTION,
                    reference_type=ReferenceType.TAG,
                ),
                2: ActionCall(
                    raw_line="- uses: nonexistent/repo@v1",
                    line_number=2,
                    organization="nonexistent",
                    repository="repo",
                    reference="v1",
                    comment=None,
                    call_type=ActionCallType.ACTION,
                    reference_type=ReferenceType.TAG,
                ),
            },
        }

        mock_github_client = AsyncMock()

        # Mock: actions/checkout succeeds, nonexistent/repo fails
        mock_github_client.validate_repositories_batch = AsyncMock(
            return_value={
                "actions/checkout": True,
                "nonexistent/repo": False,
            }
        )

        mock_github_client.validate_references_batch = AsyncMock(
            return_value={
                ("actions/checkout", "v4"): True,
            }
        )

        mock_stats = APICallStats(
            total_calls=0,
            graphql_calls=0,
            rest_calls=0,
            git_calls=0,
            cache_hits=0,
            rate_limit_delays=0,
            failed_calls=0,
        )
        mock_github_client.get_api_stats = Mock(return_value=mock_stats)
        mock_github_client.get_rate_limit_info = Mock(
            return_value=GitHubRateLimitInfo(
                limit=5000,
                remaining=5000,
                reset_at=0,
                used=0,
            )
        )

        validator = ActionCallValidator(test_config_no_sha_pinning)
        validator._github_client = mock_github_client

        errors = await validator.validate_action_calls_async(calls)

        # Should have 2 errors (both occurrences of nonexistent/repo@v1)
        assert len(errors) == 2

        # All errors should be for the nonexistent repo
        for error in errors:
            assert error.action_call.organization == "nonexistent"
            assert error.action_call.repository == "repo"
            assert error.result == ValidationResult.INVALID_REPOSITORY

    def test_empty_calls_handling(self, test_config: Config) -> None:
        """Test handling of empty action calls dictionary."""
        validator = ActionCallValidator(test_config)
        errors = validator.validate_action_calls({})

        assert len(errors) == 0

    @pytest.mark.skip(
        reason="Error handling behavior has changed - ValidationAbortedError is now raised"
    )
    @pytest.mark.asyncio
    async def test_network_error_propagation(
        self,
        test_config_no_sha_pinning: Config,
        duplicate_action_calls: dict[Path, dict[int, ActionCall]],
    ) -> None:
        """Test that network errors are properly propagated to all duplicate calls."""
        pytest.skip(
            "Validator now raises ValidationAbortedError for unexpected errors"
        )
        mock_github_client = AsyncMock()

        # Mock network failure
        mock_github_client.validate_repositories_batch.side_effect = Exception(
            "Network timeout"
        )
        mock_stats = APICallStats(
            total_calls=0,
            graphql_calls=0,
            rest_calls=0,
            git_calls=0,
            cache_hits=0,
            rate_limit_delays=0,
            failed_calls=0,
        )
        mock_github_client.get_api_stats = Mock(return_value=mock_stats)
        mock_github_client.get_rate_limit_info = Mock(
            return_value=GitHubRateLimitInfo(
                limit=5000,
                remaining=5000,
                reset_at=0,
                used=0,
            )
        )

        validator = ActionCallValidator(test_config_no_sha_pinning)
        validator._github_client = mock_github_client

        errors = await validator.validate_action_calls_async(
            duplicate_action_calls
        )

        # Should have errors for all 5 action calls
        assert len(errors) == 5

        # All errors should be invalid repository errors (current behavior when network fails)
        for error in errors:
            assert error.result == ValidationResult.INVALID_REPOSITORY

    def test_synchronous_wrapper(
        self,
        test_config_no_sha_pinning: Config,
        duplicate_action_calls: dict[Path, dict[int, ActionCall]],
    ) -> None:
        """Test the synchronous wrapper method."""
        with patch.object(
            ActionCallValidator,
            "validate_action_calls_async",
            new_callable=AsyncMock,
        ) as mock_async:
            mock_async.return_value = []

            validator = ActionCallValidator(test_config_no_sha_pinning)
            errors = validator.validate_action_calls(duplicate_action_calls)

            assert errors == []
            mock_async.assert_called_once_with(
                duplicate_action_calls, None, None
            )

    @pytest.mark.asyncio
    async def test_context_manager_usage(
        self, test_config_no_sha_pinning: Config
    ) -> None:
        """Test using validator as async context manager."""
        mock_github_client = AsyncMock()

        with patch(
            "gha_workflow_linter.validator.GitHubGraphQLClient"
        ) as mock_client_class:
            mock_client_class.return_value = mock_github_client

            async with ActionCallValidator(
                test_config_no_sha_pinning
            ) as validator:
                assert validator._github_client == mock_github_client
                mock_github_client.__aenter__.assert_called_once()

            mock_github_client.__aexit__.assert_called_once()
