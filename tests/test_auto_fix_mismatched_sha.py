# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for mismatched SHA fix and invalid reference with comment version."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from gha_workflow_linter.auto_fix import AutoFixer
from gha_workflow_linter.models import (
    ActionCall,
    CacheConfig,
    Config,
    GitHubAPIConfig,
    LogLevel,
    ReferenceType,
    ValidationError,
    ValidationMethod,
    ValidationResult,
)


class TestMismatchedShaFix:
    """Test cases for fixing mismatched SHAs without upgrading versions."""

    @pytest.fixture
    def config(self) -> Config:
        """Create a test config with auto_fix enabled but auto_latest disabled."""
        return Config(
            log_level=LogLevel.DEBUG,
            parallel_workers=2,
            require_pinned_sha=True,
            auto_fix=True,
            update_actions=False,  # Should not upgrade to latest
            two_space_comments=True,
            skip_actions=False,
            fix_test_calls=False,
            validation_method=ValidationMethod.GITHUB_API,
            cache=CacheConfig(enabled=False),
            github_api=GitHubAPIConfig(token="test-token"),
        )

    @pytest.mark.asyncio
    async def test_invalid_reference_fixes_to_comment_version_not_latest(
        self, config: Config, tmp_path: Path
    ) -> None:
        """Test that INVALID_REFERENCE with comment is fixed to comment version, not upgraded to latest."""
        # Create a workflow file with an invalid SHA (triggers INVALID_REFERENCE)
        workflow_content = """
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: release-drafter/release-drafter@0000000000000000000000000000000000000000  # v6.1.0
"""
        workflow_file = tmp_path / "test.yaml"
        workflow_file.write_text(workflow_content)

        # Create action call representing the invalid SHA
        action_call = ActionCall(
            organization="release-drafter",
            repository="release-drafter",
            reference="0000000000000000000000000000000000000000",
            reference_type=ReferenceType.COMMIT_SHA,
            comment="v6.1.0",
            raw_line="      - uses: release-drafter/release-drafter@0000000000000000000000000000000000000000  # v6.1.0",
            line_number=7,
        )

        # Create validation error for invalid reference
        validation_error = ValidationError(
            file_path=workflow_file,
            action_call=action_call,
            result=ValidationResult.INVALID_REFERENCE,
            error_message="Invalid reference",
        )

        # Mock the AutoFixer methods
        with (
            patch.object(
                AutoFixer, "_get_latest_versions_batch"
            ) as mock_latest,
            patch.object(AutoFixer, "_get_shas_batch") as mock_shas,
            patch.object(
                AutoFixer, "_detect_repository_redirect"
            ) as mock_redirect,
        ):
            # Latest version is v6.1.1 (but we should NOT upgrade to it)
            mock_latest.return_value = {
                "release-drafter/release-drafter": (
                    "v6.1.1",
                    "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",
                )
            }

            # SHA map includes the correct SHA for v6.1.0
            mock_shas.return_value = {
                (
                    "release-drafter/release-drafter",
                    "v6.1.0",
                ): "b1476f6e6eb133afa41ed8589daba6dc69b4d3f5",
                (
                    "release-drafter/release-drafter",
                    "v6.1.1",
                ): "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",
            }

            # No redirect
            mock_redirect.return_value = None

            async with AutoFixer(config, base_path=tmp_path) as auto_fixer:
                all_calls = {workflow_file: {7: action_call}}

                fixed_files, _, _ = await auto_fixer.fix_validation_errors(
                    [validation_error], all_calls, check_for_updates=False
                )

                # Verify the fix was applied
                assert workflow_file in fixed_files
                assert len(fixed_files[workflow_file]) > 0

                change = fixed_files[workflow_file][0]
                assert change["line_number"] == "7"

                # Should fix to v6.1.0 SHA, NOT upgrade to v6.1.1
                assert (
                    "b1476f6e6eb133afa41ed8589daba6dc69b4d3f5"
                    in change["new_line"]
                )
                assert "v6.1.0" in change["new_line"]
                assert "v6.1.1" not in change["new_line"]

    @pytest.mark.asyncio
    async def test_true_mismatched_sha_fixes_to_comment_version(
        self, config: Config, tmp_path: Path
    ) -> None:
        """Test that a valid SHA that doesn't match its comment version gets fixed to the comment version."""
        # Create a workflow file with a valid but mismatched SHA
        # (SHA exists but points to wrong version)
        workflow_content = """
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: release-drafter/release-drafter@267d2e0268deae5d44f3ba5029dd4d6e85f9d52d  # v6.1.0
"""
        workflow_file = tmp_path / "test.yaml"
        workflow_file.write_text(workflow_content)

        # Create action call with valid SHA but wrong version comment
        # The SHA 267d2e... is actually for v6.1.1, but comment says v6.1.0
        action_call = ActionCall(
            organization="release-drafter",
            repository="release-drafter",
            reference="267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",  # This is v6.1.1's SHA
            reference_type=ReferenceType.COMMIT_SHA,
            comment="v6.1.0",  # But comment says v6.1.0
            raw_line="      - uses: release-drafter/release-drafter@267d2e0268deae5d44f3ba5029dd4d6e85f9d52d  # v6.1.0",
            line_number=7,
        )

        # No validation error - the SHA is valid, just mismatched with comment
        # This tests the has_mismatched_sha detection logic

        with (
            patch.object(
                AutoFixer, "_get_latest_versions_batch"
            ) as mock_latest,
            patch.object(AutoFixer, "_get_shas_batch") as mock_shas,
            patch.object(
                AutoFixer, "_detect_repository_redirect"
            ) as mock_redirect,
        ):
            # Latest version is v6.1.1
            mock_latest.return_value = {
                "release-drafter/release-drafter": (
                    "v6.1.1",
                    "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",
                )
            }

            # SHA map shows correct SHAs for each version
            mock_shas.return_value = {
                (
                    "release-drafter/release-drafter",
                    "v6.1.0",
                ): "b1476f6e6eb133afa41ed8589daba6dc69b4d3f5",  # Correct SHA for v6.1.0
                (
                    "release-drafter/release-drafter",
                    "v6.1.1",
                ): "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",  # Correct SHA for v6.1.1
            }

            mock_redirect.return_value = None

            async with AutoFixer(config, base_path=tmp_path) as auto_fixer:
                all_calls = {workflow_file: {7: action_call}}

                # Pass empty validation errors since this is not a validation error case
                fixed_files, _, _ = await auto_fixer.fix_validation_errors(
                    [], all_calls, check_for_updates=False
                )

                # Verify the fix was applied
                assert workflow_file in fixed_files
                assert len(fixed_files[workflow_file]) > 0

                change = fixed_files[workflow_file][0]
                assert change["line_number"] == "7"

                # Should fix to v6.1.0 SHA (matching the comment), NOT keep v6.1.1 SHA
                assert (
                    "b1476f6e6eb133afa41ed8589daba6dc69b4d3f5"
                    in change["new_line"]
                )
                assert "v6.1.0" in change["new_line"]
                # Should NOT have the v6.1.1 SHA
                assert (
                    "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d"
                    not in change["new_line"]
                )

    @pytest.mark.asyncio
    async def test_mismatched_sha_with_check_for_updates_respects_comment_version(
        self, config: Config, tmp_path: Path
    ) -> None:
        """Test that mismatched SHA respects comment version even when check_for_updates=True."""
        config.update_actions = True

        # Create a workflow file with a valid but mismatched SHA
        workflow_content = """
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: release-drafter/release-drafter@267d2e0268deae5d44f3ba5029dd4d6e85f9d52d  # v6.1.0
"""
        workflow_file = tmp_path / "test.yaml"
        workflow_file.write_text(workflow_content)

        # Create action call with valid SHA but wrong version comment
        action_call = ActionCall(
            organization="release-drafter",
            repository="release-drafter",
            reference="267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",  # This is v6.1.1's SHA
            reference_type=ReferenceType.COMMIT_SHA,
            comment="v6.1.0",  # But comment says v6.1.0
            raw_line="      - uses: release-drafter/release-drafter@267d2e0268deae5d44f3ba5029dd4d6e85f9d52d  # v6.1.0",
            line_number=7,
        )

        with (
            patch.object(
                AutoFixer, "_get_latest_versions_batch"
            ) as mock_latest,
            patch.object(AutoFixer, "_get_shas_batch") as mock_shas,
            patch.object(
                AutoFixer, "_detect_repository_redirect"
            ) as mock_redirect,
        ):
            # Latest version is v6.1.1 (but should NOT upgrade to it)
            mock_latest.return_value = {
                "release-drafter/release-drafter": (
                    "v6.1.1",
                    "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",
                )
            }

            # SHA map shows correct SHAs for each version
            mock_shas.return_value = {
                (
                    "release-drafter/release-drafter",
                    "v6.1.0",
                ): "b1476f6e6eb133afa41ed8589daba6dc69b4d3f5",
                (
                    "release-drafter/release-drafter",
                    "v6.1.1",
                ): "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",
            }

            mock_redirect.return_value = None

            async with AutoFixer(config, base_path=tmp_path) as auto_fixer:
                all_calls = {workflow_file: {7: action_call}}

                # Pass empty validation errors and check_for_updates=True
                fixed_files, _, _ = await auto_fixer.fix_validation_errors(
                    [], all_calls, check_for_updates=True
                )

                # Verify the fix was applied
                assert workflow_file in fixed_files
                assert len(fixed_files[workflow_file]) > 0

                change = fixed_files[workflow_file][0]
                assert change["line_number"] == "7"

                # Should fix to v6.1.0 SHA (matching the comment), NOT upgrade to v6.1.1
                # even though check_for_updates=True
                assert (
                    "b1476f6e6eb133afa41ed8589daba6dc69b4d3f5"
                    in change["new_line"]
                )
                assert "v6.1.0" in change["new_line"]
                # Should NOT upgrade to v6.1.1
                assert "v6.1.1" not in change["new_line"]
                assert (
                    "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d"
                    not in change["new_line"]
                )

    @pytest.mark.asyncio
    async def test_invalid_ref_with_comment_respects_comment_version(
        self, config: Config, tmp_path: Path
    ) -> None:
        """Test that INVALID_REFERENCE with comment uses comment version even with check_for_updates."""
        config.update_actions = True

        workflow_content = """
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: release-drafter/release-drafter@0000000000000000000000000000000000000000  # v6.1.0
"""
        workflow_file = tmp_path / "test.yaml"
        workflow_file.write_text(workflow_content)

        action_call = ActionCall(
            organization="release-drafter",
            repository="release-drafter",
            reference="0000000000000000000000000000000000000000",
            reference_type=ReferenceType.COMMIT_SHA,
            comment="v6.1.0",
            raw_line="      - uses: release-drafter/release-drafter@0000000000000000000000000000000000000000  # v6.1.0",
            line_number=7,
        )

        validation_error = ValidationError(
            file_path=workflow_file,
            action_call=action_call,
            result=ValidationResult.INVALID_REFERENCE,
            error_message="Invalid reference",
        )

        with (
            patch.object(
                AutoFixer, "_get_latest_versions_batch"
            ) as mock_latest,
            patch.object(AutoFixer, "_get_shas_batch") as mock_shas,
            patch.object(
                AutoFixer, "_detect_repository_redirect"
            ) as mock_redirect,
            patch.object(
                AutoFixer, "_get_commit_sha_for_reference"
            ) as mock_get_sha,
        ):
            mock_latest.return_value = {
                "release-drafter/release-drafter": (
                    "v6.1.1",
                    "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",
                )
            }

            mock_shas.return_value = {
                (
                    "release-drafter/release-drafter",
                    "v6.1.0",
                ): "b1476f6e6eb133afa41ed8589daba6dc69b4d3f5",
                (
                    "release-drafter/release-drafter",
                    "v6.1.1",
                ): "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",
            }

            mock_get_sha.return_value = {
                "sha": "b1476f6e6eb133afa41ed8589daba6dc69b4d3f5",
                "type": "tag",
            }
            mock_redirect.return_value = None

            async with AutoFixer(config, base_path=tmp_path) as auto_fixer:
                all_calls = {workflow_file: {7: action_call}}

                fixed_files, _, _ = await auto_fixer.fix_validation_errors(
                    [validation_error], all_calls, check_for_updates=True
                )

                assert workflow_file in fixed_files
                assert len(fixed_files[workflow_file]) > 0

                change = fixed_files[workflow_file][0]

                # INVALID_REFERENCE with comment prioritizes comment version, not latest
                assert (
                    "b1476f6e6eb133afa41ed8589daba6dc69b4d3f5"
                    in change["new_line"]
                )
                assert "v6.1.0" in change["new_line"]


class TestInvalidReferenceWithCommentVersion:
    """Test cases for prioritizing comment version when fixing invalid references."""

    @pytest.fixture
    def config(self) -> Config:
        """Create a test config."""
        return Config(
            log_level=LogLevel.DEBUG,
            parallel_workers=2,
            require_pinned_sha=True,
            auto_fix=True,
            update_actions=False,
            two_space_comments=True,
            skip_actions=False,
            fix_test_calls=False,
            validation_method=ValidationMethod.GITHUB_API,
            cache=CacheConfig(enabled=False),
            github_api=GitHubAPIConfig(token="test-token"),
        )

    @pytest.mark.asyncio
    async def test_invalid_ref_uses_comment_version_first(
        self, config: Config, tmp_path: Path
    ) -> None:
        """Test that invalid reference uses version from comment as first priority."""
        workflow_content = """
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: release-drafter/release-drafter@invalid_sha_here  # v6.1.0
"""
        workflow_file = tmp_path / "test.yaml"
        workflow_file.write_text(workflow_content)

        action_call = ActionCall(
            organization="release-drafter",
            repository="release-drafter",
            reference="invalid_sha_here",
            reference_type=ReferenceType.COMMIT_SHA,
            comment="v6.1.0",
            raw_line="      - uses: release-drafter/release-drafter@invalid_sha_here  # v6.1.0",
            line_number=7,
        )

        validation_error = ValidationError(
            file_path=workflow_file,
            action_call=action_call,
            result=ValidationResult.INVALID_REFERENCE,
            error_message="Invalid reference",
        )

        with (
            patch.object(
                AutoFixer, "_get_latest_versions_batch"
            ) as mock_latest,
            patch.object(AutoFixer, "_get_shas_batch") as mock_shas,
            patch.object(
                AutoFixer, "_detect_repository_redirect"
            ) as mock_redirect,
            patch.object(
                AutoFixer, "_get_commit_sha_for_reference"
            ) as mock_get_sha,
        ):
            # Latest is v6.1.1
            mock_latest.return_value = {
                "release-drafter/release-drafter": (
                    "v6.1.1",
                    "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",
                )
            }

            # SHA map for v6.1.0 (from comment)
            mock_shas.return_value = {
                (
                    "release-drafter/release-drafter",
                    "v6.1.0",
                ): "b1476f6e6eb133afa41ed8589daba6dc69b4d3f5",
                (
                    "release-drafter/release-drafter",
                    "v6.1.1",
                ): "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",
            }

            # Return SHA for v6.1.0 when requested
            mock_get_sha.return_value = {
                "sha": "b1476f6e6eb133afa41ed8589daba6dc69b4d3f5",
                "type": "tag",
            }

            mock_redirect.return_value = None

            async with AutoFixer(config, base_path=tmp_path) as auto_fixer:
                all_calls = {workflow_file: {7: action_call}}

                fixed_files, _, _ = await auto_fixer.fix_validation_errors(
                    [validation_error], all_calls, check_for_updates=False
                )

                assert workflow_file in fixed_files
                assert len(fixed_files[workflow_file]) > 0

                change = fixed_files[workflow_file][0]

                # Should use v6.1.0 from comment, not upgrade to v6.1.1
                assert (
                    "b1476f6e6eb133afa41ed8589daba6dc69b4d3f5"
                    in change["new_line"]
                )
                assert "v6.1.0" in change["new_line"]
                assert "v6.1.1" not in change["new_line"]

    @pytest.mark.asyncio
    async def test_invalid_ref_without_comment_uses_fallback(
        self, config: Config, tmp_path: Path
    ) -> None:
        """Test that invalid reference without comment uses fallback reference."""
        workflow_content = """
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: release-drafter/release-drafter@invalid_sha_here
"""
        workflow_file = tmp_path / "test.yaml"
        workflow_file.write_text(workflow_content)

        action_call = ActionCall(
            organization="release-drafter",
            repository="release-drafter",
            reference="invalid_sha_here",
            reference_type=ReferenceType.COMMIT_SHA,
            comment=None,  # No comment to use
            raw_line="      - uses: release-drafter/release-drafter@invalid_sha_here",
            line_number=7,
        )

        validation_error = ValidationError(
            file_path=workflow_file,
            action_call=action_call,
            result=ValidationResult.INVALID_REFERENCE,
            error_message="Invalid reference",
        )

        with (
            patch.object(
                AutoFixer, "_get_latest_versions_batch"
            ) as mock_latest,
            patch.object(AutoFixer, "_get_shas_batch") as mock_shas,
            patch.object(
                AutoFixer, "_detect_repository_redirect"
            ) as mock_redirect,
            patch.object(AutoFixer, "_find_valid_reference") as mock_find_valid,
            patch.object(
                AutoFixer, "_get_commit_sha_for_reference"
            ) as mock_get_sha,
        ):
            mock_latest.return_value = {
                "release-drafter/release-drafter": (
                    "v6.1.1",
                    "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",
                )
            }

            mock_shas.return_value = {
                (
                    "release-drafter/release-drafter",
                    "v6.1.1",
                ): "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",
            }

            # Fallback finds v6.1.1
            mock_find_valid.return_value = "v6.1.1"
            mock_get_sha.return_value = {
                "sha": "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",
                "type": "tag",
            }
            mock_redirect.return_value = None

            async with AutoFixer(config, base_path=tmp_path) as auto_fixer:
                all_calls = {workflow_file: {7: action_call}}

                fixed_files, _, _ = await auto_fixer.fix_validation_errors(
                    [validation_error], all_calls, check_for_updates=False
                )

                assert workflow_file in fixed_files
                assert len(fixed_files[workflow_file]) > 0

                change = fixed_files[workflow_file][0]

                # Without comment, uses fallback which found v6.1.1
                assert (
                    "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d"
                    in change["new_line"]
                )

    @pytest.mark.asyncio
    async def test_invalid_ref_with_non_version_comment_uses_fallback(
        self, config: Config, tmp_path: Path
    ) -> None:
        """Test that invalid reference with non-version comment uses fallback."""
        workflow_content = """
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: release-drafter/release-drafter@invalid_sha_here  # some comment
"""
        workflow_file = tmp_path / "test.yaml"
        workflow_file.write_text(workflow_content)

        action_call = ActionCall(
            organization="release-drafter",
            repository="release-drafter",
            reference="invalid_sha_here",
            reference_type=ReferenceType.COMMIT_SHA,
            comment="some comment",  # Not a version
            raw_line="      - uses: release-drafter/release-drafter@invalid_sha_here  # some comment",
            line_number=7,
        )

        validation_error = ValidationError(
            file_path=workflow_file,
            action_call=action_call,
            result=ValidationResult.INVALID_REFERENCE,
            error_message="Invalid reference",
        )

        with (
            patch.object(
                AutoFixer, "_get_latest_versions_batch"
            ) as mock_latest,
            patch.object(AutoFixer, "_get_shas_batch") as mock_shas,
            patch.object(
                AutoFixer, "_detect_repository_redirect"
            ) as mock_redirect,
            patch.object(AutoFixer, "_find_valid_reference") as mock_find_valid,
            patch.object(
                AutoFixer, "_get_commit_sha_for_reference"
            ) as mock_get_sha,
        ):
            mock_latest.return_value = {
                "release-drafter/release-drafter": (
                    "v6.1.1",
                    "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",
                )
            }

            mock_shas.return_value = {
                (
                    "release-drafter/release-drafter",
                    "v6.1.1",
                ): "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",
            }

            # Fallback mechanism finds v6.1.1
            mock_find_valid.return_value = "v6.1.1"
            mock_get_sha.return_value = {
                "sha": "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d",
                "type": "tag",
            }
            mock_redirect.return_value = None

            async with AutoFixer(config, base_path=tmp_path) as auto_fixer:
                all_calls = {workflow_file: {7: action_call}}

                fixed_files, _, _ = await auto_fixer.fix_validation_errors(
                    [validation_error], all_calls, check_for_updates=False
                )

                assert workflow_file in fixed_files
                assert len(fixed_files[workflow_file]) > 0

                change = fixed_files[workflow_file][0]

                # Comment is not a version, so uses fallback
                assert (
                    "267d2e0268deae5d44f3ba5029dd4d6e85f9d52d"
                    in change["new_line"]
                )
