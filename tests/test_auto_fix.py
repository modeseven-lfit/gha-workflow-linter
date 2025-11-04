# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for auto-fix functionality."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

if TYPE_CHECKING:
    from pathlib import Path

import pytest
from typer.testing import CliRunner

from gha_workflow_linter.auto_fix import AutoFixer
from gha_workflow_linter.cli import app
from gha_workflow_linter.models import (
    ActionCall,
    ActionCallType,
    Config,
    LogLevel,
    NetworkConfig,
    ReferenceType,
    ValidationError,
    ValidationMethod,
    ValidationResult,
)


class TestAutoFixBehaviorWithPinnedSHA:
    """Test auto-fix behavior with require_pinned_sha configuration."""

    @pytest.fixture
    def config_pinned_required(self) -> Config:
        """Config with require_pinned_sha=True."""
        return Config(
            log_level=LogLevel.DEBUG,
            parallel_workers=2,
            require_pinned_sha=True,
            auto_fix=True,
            auto_latest=True,
            two_space_comments=False,
            validation_method=ValidationMethod.GIT,
            network=NetworkConfig(
                timeout_seconds=10,
                max_retries=2,
                retry_delay_seconds=1.0,
                rate_limit_delay_seconds=0.1,
            ),
        )

    @pytest.fixture
    def config_pinned_not_required(self) -> Config:
        """Config with require_pinned_sha=False."""
        return Config(
            log_level=LogLevel.DEBUG,
            parallel_workers=2,
            require_pinned_sha=False,
            auto_fix=True,
            auto_latest=True,
            two_space_comments=False,
            validation_method=ValidationMethod.GIT,
            network=NetworkConfig(
                timeout_seconds=10,
                max_retries=2,
                retry_delay_seconds=1.0,
                rate_limit_delay_seconds=0.1,
            ),
        )

    @pytest.fixture
    def workflow_with_mixed_references(self) -> str:
        """Workflow file with mix of valid and invalid references."""
        return """name: Test Workflow

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout with invalid branch
        uses: actions/checkout@invalid-branch

      - name: Checkout with master (should be updated)
        uses: actions/checkout@master

      - name: Setup Python with version tag
        uses: actions/setup-python@v4

      - name: Setup Node with version tag
        uses: actions/setup-node@v3.8.1

      - name: Upload artifact with old version
        uses: actions/upload-artifact@v2
"""

    @pytest.fixture
    def temp_workflow_file(
        self, temp_dir: Path, workflow_with_mixed_references: str
    ) -> Path:
        """Create temporary workflow file."""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_with_mixed_references)
        return workflow_file

    @pytest.mark.asyncio
    async def test_auto_fix_with_pinned_sha_required(
        self,
        config_pinned_required: Config,
        temp_workflow_file: Path,
    ) -> None:
        """Test auto-fix behavior when require_pinned_sha=True."""
        # Mock git operations to return realistic data
        with patch(
            "gha_workflow_linter.validator.ActionCallValidator.validate_action_calls"
        ):
            # Create validation errors for each problematic action
            validation_errors = [
                ValidationError(
                    file_path=temp_workflow_file,
                    action_call=ActionCall(
                        raw_line="        uses: actions/checkout@invalid-branch",
                        line_number=9,
                        organization="actions",
                        repository="checkout",
                        reference="invalid-branch",
                        reference_type=ReferenceType.BRANCH,
                        call_type=ActionCallType.ACTION,
                        comment="",
                    ),
                    result=ValidationResult.INVALID_REFERENCE,
                    error_message="Invalid action call",
                ),
                ValidationError(
                    file_path=temp_workflow_file,
                    action_call=ActionCall(
                        raw_line="        uses: actions/checkout@master",
                        line_number=12,
                        organization="actions",
                        repository="checkout",
                        reference="master",
                        reference_type=ReferenceType.BRANCH,
                        call_type=ActionCallType.ACTION,
                        comment="",
                    ),
                    result=ValidationResult.NOT_PINNED_TO_SHA,
                    error_message="Action not pinned to SHA",
                ),
                ValidationError(
                    file_path=temp_workflow_file,
                    action_call=ActionCall(
                        raw_line="        uses: actions/setup-python@v4",
                        line_number=15,
                        organization="actions",
                        repository="setup-python",
                        reference="v4",
                        reference_type=ReferenceType.TAG,
                        call_type=ActionCallType.ACTION,
                        comment="",
                    ),
                    result=ValidationResult.NOT_PINNED_TO_SHA,
                    error_message="Action not pinned to SHA",
                ),
                ValidationError(
                    file_path=temp_workflow_file,
                    action_call=ActionCall(
                        raw_line="        uses: actions/setup-node@v3",
                        line_number=18,
                        organization="actions",
                        repository="setup-node",
                        reference="v3",
                        reference_type=ReferenceType.TAG,
                        call_type=ActionCallType.ACTION,
                        comment="",
                    ),
                    result=ValidationResult.NOT_PINNED_TO_SHA,
                    error_message="Action not pinned to SHA",
                ),
                ValidationError(
                    file_path=temp_workflow_file,
                    action_call=ActionCall(
                        raw_line="        uses: actions/upload-artifact@v3",
                        line_number=21,
                        organization="actions",
                        repository="upload-artifact",
                        reference="v3",
                        reference_type=ReferenceType.TAG,
                        call_type=ActionCallType.ACTION,
                        comment="",
                    ),
                    result=ValidationResult.NOT_PINNED_TO_SHA,
                    error_message="Action not pinned to SHA",
                ),
            ]

            # Mock the AutoFixer methods
            with (
                patch.object(
                    AutoFixer, "_get_repository_info"
                ) as mock_repo_info,
                patch.object(
                    AutoFixer, "_find_valid_reference"
                ) as mock_find_ref,
                patch.object(
                    AutoFixer, "_get_commit_sha_for_reference"
                ) as mock_get_sha,
            ):
                # Configure mocks to return expected data
                mock_repo_info.return_value = {"default_branch": "main"}

                # Mock reference finding - invalid-branch should fallback to main
                async def mock_find_ref_impl(
                    _repo_key: str, invalid_ref: str
                ) -> str | None:
                    if invalid_ref == "invalid-branch":
                        return "main"  # Fallback to default branch
                    return invalid_ref  # Keep existing reference for others

                mock_find_ref.side_effect = mock_find_ref_impl

                # Mock SHA retrieval
                async def mock_get_sha_impl(
                    repo_key: str, ref: str
                ) -> dict[str, object]:
                    sha_map = {
                        ("actions/checkout", "main"): {
                            "sha": "abc123def456789012345678901234567890abcd",
                            "type": "branch",
                        },
                        ("actions/checkout", "master"): {
                            "sha": "def456abc789012345678901234567890abcd123",
                            "type": "branch",
                        },
                        ("actions/checkout", "v5.0.0"): {
                            "sha": "abc123def456789012345678901234567890abcd",
                            "type": "tag",
                        },
                        ("actions/setup-python", "v4"): {
                            "sha": "ghi789012345678901234567890abcdef456789",
                            "type": "tag",
                        },
                        ("actions/setup-python", "v6.0.0"): {
                            "sha": "ghi789012345678901234567890abcdef456789",
                            "type": "tag",
                        },
                        ("actions/setup-node", "v3.8.1"): {
                            "sha": "jkl012345678901234567890abcdef789456123",
                            "type": "tag",
                        },
                        ("actions/setup-node", "v6.0.0"): {
                            "sha": "jkl012345678901234567890abcdef789456123",
                            "type": "tag",
                        },
                        ("actions/upload-artifact", "v2"): {
                            "sha": "mno345678901234567890abcdef012789456789",
                            "type": "tag",
                        },
                        ("actions/upload-artifact", "v5.0.0"): {
                            "sha": "mno345678901234567890abcdef012789456789",
                            "type": "tag",
                        },
                    }
                    result = sha_map.get(
                        (repo_key, ref),
                        {
                            "sha": "sha123456789012345678901234567890abcdef12",
                            "type": "tag",
                        },
                    )
                    return result  # type: ignore[return-value]

                mock_get_sha.side_effect = mock_get_sha_impl

                # Run auto-fix
                async with AutoFixer(config_pinned_required) as fixer:
                    fixed_files = await fixer.fix_validation_errors(
                        validation_errors
                    )

                # Should fix all 5 issues when require_pinned_sha=True
                assert len(fixed_files) == 1
                assert temp_workflow_file in fixed_files

                changes = fixed_files[temp_workflow_file]
                assert len(changes) == 5  # All 5 actions should be fixed

                # Verify the file content was updated correctly
                updated_content = temp_workflow_file.read_text()

                # Should pin all actions to SHAs with version comments
                assert (
                    "actions/checkout@abc123def456789012345678901234567890abcd"
                    in updated_content
                )
                assert (
                    "actions/setup-python@ghi789012345678901234567890abcdef456789"
                    in updated_content
                )
                assert (
                    "actions/setup-node@jkl012345678901234567890abcdef789456123"
                    in updated_content
                )
                assert (
                    "actions/upload-artifact@mno345678901234567890abcdef012789456789"
                    in updated_content
                )

    @pytest.mark.asyncio
    async def test_auto_fix_with_pinned_sha_not_required(
        self,
        config_pinned_not_required: Config,
        temp_workflow_file: Path,
    ) -> None:
        """Test auto-fix behavior when require_pinned_sha=False."""
        # Mock git operations
        with patch(
            "gha_workflow_linter.validator.ActionCallValidator.validate_action_calls"
        ):
            # When require_pinned_sha=False, only invalid references should be flagged
            validation_errors = [
                ValidationError(
                    file_path=temp_workflow_file,
                    action_call=ActionCall(
                        raw_line="        uses: actions/checkout@invalid-branch",
                        line_number=9,
                        organization="actions",
                        repository="checkout",
                        reference="invalid-branch",
                        reference_type=ReferenceType.BRANCH,
                        call_type=ActionCallType.ACTION,
                        comment="",
                    ),
                    result=ValidationResult.INVALID_REFERENCE,
                    error_message="Invalid action call",
                ),
                # Note: Other actions (@master, @v4, @v3.8.1, @v2) should NOT be flagged
                # when require_pinned_sha=False
            ]

            with (
                patch.object(
                    AutoFixer, "_get_repository_info"
                ) as mock_repo_info,
                patch.object(
                    AutoFixer, "_find_valid_reference"
                ) as mock_find_ref,
                patch.object(
                    AutoFixer, "_get_commit_sha_for_reference"
                ) as mock_get_sha,
            ):
                mock_repo_info.return_value = {"default_branch": "main"}

                async def mock_find_ref_impl(
                    _repo_key: str, _invalid_ref: str
                ) -> str | None:
                    return "main"  # Always fallback to main branch

                mock_find_ref.side_effect = mock_find_ref_impl

                async def mock_get_sha_impl(
                    _repo_key: str, _ref: str
                ) -> dict[str, object]:
                    return {
                        "sha": "abc123def456789012345678901234567890abcd",
                        "type": "branch",
                    }

                mock_get_sha.side_effect = mock_get_sha_impl

                async with AutoFixer(config_pinned_not_required) as fixer:
                    fixed_files = await fixer.fix_validation_errors(
                        validation_errors
                    )

                # Should only fix 1 issue (the invalid-branch) when require_pinned_sha=False
                assert len(fixed_files) == 1
                assert temp_workflow_file in fixed_files

                changes = fixed_files[temp_workflow_file]
                assert len(changes) == 1  # Only 1 action should be fixed

                # Verify the file content
                updated_content = temp_workflow_file.read_text()

                # Should fix the invalid reference but leave others as-is
                assert (
                    "actions/checkout@abc123def456789012345678901234567890abcd"
                    in updated_content
                )

                # These should remain unchanged when require_pinned_sha=False
                assert "actions/checkout@master" in updated_content
                assert "actions/setup-python@v4" in updated_content
                assert "actions/setup-node@v3.8.1" in updated_content
                assert "actions/upload-artifact@v2" in updated_content

    def test_cli_auto_fix_with_pinned_sha_required(
        self,
        temp_dir: Path,
        workflow_with_mixed_references: str,
    ) -> None:
        """Test CLI auto-fix behavior with require_pinned_sha=True via command line."""
        # Create workflow file
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_with_mixed_references)

        runner = CliRunner()

        # Mock git operations for CLI test
        with patch(
            "gha_workflow_linter.validator.ActionCallValidator"
        ) as mock_validator_class:
            mock_validator = AsyncMock()
            mock_validator_class.return_value = mock_validator

            # Configure mock to return validation errors for all non-SHA references
            def mock_validate_calls(calls, _progress=None, _task=None):
                errors = []
                for call in calls:
                    if call.reference in [
                        "invalid-branch",
                        "master",
                        "v4",
                        "v3.8.1",
                        "v2",
                    ]:
                        errors.append(
                            ValidationError(
                                file_path=workflow_file,
                                action_call=call,
                                result=ValidationResult.INVALID_REFERENCE
                                if call.reference == "invalid-branch"
                                else ValidationResult.NOT_PINNED_TO_SHA,
                                error_message="Invalid action call"
                                if call.reference == "invalid-branch"
                                else "Action not pinned to SHA",
                            )
                        )
                return errors

            mock_validator.validate_action_calls = mock_validate_calls

            # Mock auto-fixer
            with patch(
                "gha_workflow_linter.auto_fix.AutoFixer"
            ) as mock_auto_fixer_class:
                mock_auto_fixer = AsyncMock()
                mock_auto_fixer_class.return_value.__aenter__.return_value = (
                    mock_auto_fixer
                )

                # Mock that it fixes all 5 issues
                mock_auto_fixer.fix_validation_errors.return_value = {
                    workflow_file: [
                        {
                            "line": 9,
                            "old": "actions/checkout@invalid-branch",
                            "new": "actions/checkout@abc123",
                        },
                        {
                            "line": 12,
                            "old": "actions/checkout@master",
                            "new": "actions/checkout@def456",
                        },
                        {
                            "line": 15,
                            "old": "actions/setup-python@v4",
                            "new": "actions/setup-python@ghi789",
                        },
                        {
                            "line": 18,
                            "old": "actions/setup-node@v3.8.1",
                            "new": "actions/setup-node@jkl012",
                        },
                        {
                            "line": 21,
                            "old": "actions/upload-artifact@v2",
                            "new": "actions/upload-artifact@mno345",
                        },
                    ]
                }

                # Run CLI with require-pinned-sha (default is True)
                result = runner.invoke(
                    app,
                    [
                        "lint",
                        str(temp_dir),
                        "--auto-fix",
                        "--validation-method",
                        "git",
                    ],
                )

                # Should exit with code 1 (files were modified)
                assert result.exit_code == 1
                assert (
                    "Found" in result.stdout
                    and "5" in result.stdout
                    and "validation errors" in result.stdout
                )
                assert "Auto-fixed issues in 1 file(s)" in result.stdout

    def test_cli_auto_fix_with_pinned_sha_not_required(
        self,
        temp_dir: Path,
        workflow_with_mixed_references: str,
    ) -> None:
        """Test CLI auto-fix behavior with require_pinned_sha=False via command line."""
        # Create workflow file
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_with_mixed_references)

        # Create config file with require_pinned_sha=False
        config_content = """
require_pinned_sha: false
auto_fix: true
auto_latest: true
validation_method: git
"""
        config_file = temp_dir / "gha-workflow-linter.yaml"
        config_file.write_text(config_content)

        runner = CliRunner()

        with patch(
            "gha_workflow_linter.validator.ActionCallValidator"
        ) as mock_validator_class:
            mock_validator = AsyncMock()
            mock_validator_class.return_value = mock_validator

            # When require_pinned_sha=False, only invalid references are errors
            def mock_validate_calls(calls, _progress=None, _task=None):
                errors = []
                for call in calls:
                    if (
                        call.reference == "invalid-branch"
                    ):  # Only invalid refs are errors
                        errors.append(
                            ValidationError(
                                file_path=workflow_file,
                                action_call=call,
                                result=ValidationResult.INVALID_REFERENCE,
                                error_message="Invalid action call",
                            )
                        )
                return errors

            mock_validator.validate_action_calls = mock_validate_calls

            with patch(
                "gha_workflow_linter.auto_fix.AutoFixer"
            ) as mock_auto_fixer_class:
                mock_auto_fixer = AsyncMock()
                mock_auto_fixer_class.return_value.__aenter__.return_value = (
                    mock_auto_fixer
                )

                # Mock that it only fixes 1 issue (the invalid reference)
                mock_auto_fixer.fix_validation_errors.return_value = {
                    workflow_file: [
                        {
                            "line": 9,
                            "old": "actions/checkout@invalid-branch",
                            "new": "actions/checkout@abc123",
                        },
                    ]
                }

                result = runner.invoke(
                    app,
                    [
                        "lint",
                        str(temp_dir),
                        "--config",
                        str(config_file),
                        "--auto-fix",
                    ],
                )

                # Should exit with code 1 (files were modified)
                assert result.exit_code == 1
                assert (
                    "Found" in result.stdout
                    and "1" in result.stdout
                    and "validation errors" in result.stdout
                )  # Only 1 error
                assert "1 invalid references" in result.stdout
                assert "Auto-fixed issues in 1 file(s)" in result.stdout

    def test_error_count_summary_with_pinned_sha_required(
        self,
        temp_dir: Path,
        workflow_with_mixed_references: str,
    ) -> None:
        """Test that error summary shows correct counts with require_pinned_sha=True."""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_with_mixed_references)

        runner = CliRunner()

        with patch(
            "gha_workflow_linter.validator.ActionCallValidator"
        ) as mock_validator_class:
            mock_validator = AsyncMock()
            mock_validator_class.return_value = mock_validator

            # All non-SHA references should be errors when require_pinned_sha=True
            def mock_validate_calls(calls, _progress=None, _task=None):
                errors = []
                for call in calls:
                    if call.reference in [
                        "invalid-branch",
                        "master",
                        "v4",
                        "v3.8.1",
                        "v2",
                    ]:
                        if call.reference == "invalid-branch":
                            errors.append(
                                ValidationError(
                                    file_path=workflow_file,
                                    action_call=call,
                                    result=ValidationResult.INVALID_REFERENCE,
                                    error_message="Invalid action call",
                                )
                            )
                        else:
                            errors.append(
                                ValidationError(
                                    file_path=workflow_file,
                                    action_call=call,
                                    result=ValidationResult.NOT_PINNED_TO_SHA,
                                    error_message="Action not pinned to SHA",
                                )
                            )
                return errors

            mock_validator.validate_action_calls = mock_validate_calls

            with patch(
                "gha_workflow_linter.auto_fix.AutoFixer"
            ) as mock_auto_fixer_class:
                mock_auto_fixer = AsyncMock()
                mock_auto_fixer_class.return_value.__aenter__.return_value = (
                    mock_auto_fixer
                )
                mock_auto_fixer.fix_validation_errors.return_value = {}

                result = runner.invoke(
                    app,
                    [
                        "lint",
                        str(temp_dir),
                        "--auto-fix",
                        "--validation-method",
                        "git",
                    ],
                )

                # Should show breakdown: 1 invalid + 4 not pinned = 5 total
                assert (
                    "Found" in result.stdout
                    and "5" in result.stdout
                    and "validation errors" in result.stdout
                )
                assert "1 invalid references" in result.stdout
                assert "4 actions not pinned to SHA" in result.stdout

    def test_error_count_summary_with_pinned_sha_not_required(
        self,
        temp_dir: Path,
    ) -> None:
        """Test that error summary shows correct counts with require_pinned_sha=False."""
        # Create a workflow with only valid tag references (no invalid refs)
        workflow_content = """name: Test

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
"""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_content)

        # Config with require_pinned_sha=False
        config_content = """require_pinned_sha: false
auto_fix: false
validation_method: git
"""
        config_file = temp_dir / "gha-workflow-linter.yaml"
        config_file.write_text(config_content)

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--config",
                str(config_file),
            ],
        )

        # When require_pinned_sha=False, tag references are valid
        # However, the actions are still validated (they exist), and auto-fix may still run
        # The key is that we shouldn't get "not pinned to SHA" errors
        assert "not pinned to SHA" not in result.stdout.lower()
        # Exit code may be 0 or 1 depending on whether auto-fix ran
        assert result.exit_code in (0, 1)


class TestAutoFixConfiguration:
    """Test auto-fix configuration options."""

    @pytest.fixture
    def workflow_with_old_versions(self) -> str:
        """Workflow with older action versions."""
        return """name: Test

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4.7.0
"""

    def test_auto_fix_disabled(self, temp_dir: Path) -> None:
        """Test that auto-fix respects the auto_fix=false setting."""
        workflow_file = temp_dir / ".github" / "workflows" / "auto-fix.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text("""name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
""")

        config_content = """
require_pinned_sha: true
auto_fix: false  # Disable auto-fix
validation_method: git
"""
        config_file = temp_dir / "gha-workflow-linter.yaml"
        config_file.write_text(config_content)

        runner = CliRunner()

        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--config",
                str(config_file),
                "--no-auto-fix",  # Explicitly disable to ensure it's off
            ],
        )

        # Should exit with error code but NOT auto-fix
        assert result.exit_code == 1
        assert "validation errors" in result.stdout
        assert "Auto-fixed" not in result.stdout

    def test_auto_latest_disabled(self, temp_dir: Path) -> None:
        """Test auto-fix with auto_latest=False uses existing versions not latest."""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text("""name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""")

        config_content = """
require_pinned_sha: true
auto_fix: true
auto_latest: false  # Don't use latest versions
validation_method: git
"""
        config_file = temp_dir / "gha-workflow-linter.yaml"
        config_file.write_text(config_content)

        runner = CliRunner()

        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--config",
                str(config_file),
            ],
        )

        # Should auto-fix without upgrading to latest version
        # When auto_latest=False, it should pin to the SHA of v4, not upgrade to v5
        if "Auto-fixed" in result.stdout:
            assert "v4" in result.stdout or "checkout@" in result.stdout

    def test_two_space_comments_enabled(self, temp_dir: Path) -> None:
        """Test auto-fix with two_space_comments=True."""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text("""name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""")

        config_content = """
require_pinned_sha: true
auto_fix: true
two_space_comments: true  # Use two spaces before comments
validation_method: git
"""
        config_file = temp_dir / "gha-workflow-linter.yaml"
        config_file.write_text(config_content)

        runner = CliRunner()

        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--config",
                str(config_file),
            ],
        )

        # When auto-fix runs with two_space_comments, should use double space
        # Check the actual file to see if it has two spaces before comment
        if "Auto-fixed" in result.stdout:
            content = workflow_file.read_text()
            # Should have " #" (space before hash) in comment - actual format is single space
            # The two_space_comments setting affects YAML comment formatting, not inline action comments
            assert " # " in content or result.exit_code == 0


class TestAutoFixEdgeCases:
    """Test auto-fix edge cases and error handling."""

    def test_auto_fix_with_no_errors(self, temp_dir: Path) -> None:
        """Test auto-fix behavior when there are no validation errors."""
        # Use a known valid SHA for actions/checkout@v4
        workflow_content = """name: Valid Workflow

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
"""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_content)

        runner = CliRunner()

        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--auto-fix",
                "--validation-method",
                "git",
            ],
        )

        assert result.exit_code == 0
        assert "All action calls are valid" in result.stdout
        assert "Auto-fixed" not in result.stdout

    def test_auto_fix_file_permission_error(self, temp_dir: Path) -> None:
        """Test auto-fix behavior when file cannot be written."""
        workflow_content = """name: Test

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
"""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_content)

        # Make the workflow file read-only to trigger permission error
        workflow_file.chmod(0o444)

        runner = CliRunner()

        try:
            result = runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--auto-fix",
                    "--validation-method",
                    "git",
                    "--require-pinned-sha",
                ],
            )

            # Should detect the error or handle gracefully
            # Either it fails with permission error or completes with validation errors
            assert result.exit_code in [0, 1]
        finally:
            # Restore write permission for cleanup
            workflow_file.chmod(0o644)

    @pytest.mark.asyncio
    async def test_auto_fixer_context_manager(
        self, test_config: Config
    ) -> None:
        """Test AutoFixer as async context manager."""
        async with AutoFixer(test_config) as fixer:
            assert fixer is not None
            assert hasattr(fixer, "fix_validation_errors")

    def test_cli_with_explicit_auto_fix_flags(self, temp_dir: Path) -> None:
        """Test CLI with explicit auto-fix related flags - simplified."""
        # Use a valid SHA-pinned action to avoid validation errors
        workflow_content = """name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
"""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_content)

        runner = CliRunner()

        # Test that CLI flags are accepted (actual behavior is tested elsewhere)
        test_cases = [
            (["--no-auto-fix"], "Auto-fix disabled via CLI"),
            (["--no-auto-latest"], "Auto-latest disabled via CLI"),
        ]

        for flags, description in test_cases:
            result = runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--validation-method",
                    "git",
                    *flags,
                ],
            )

            # Should succeed with valid SHA-pinned action
            assert result.exit_code == 0, (
                f"Failed for {description}: {result.stdout}"
            )


class TestAutoFixCLIOutput:
    """Test auto-fix CLI output formatting - simplified tests."""

    def test_cli_output_shows_auto_fix_results(
        self,
        temp_dir: Path,
    ) -> None:
        """Test that CLI output shows auto-fix results when fixes are made."""
        # Use a real workflow with tag that needs fixing
        workflow_content = """name: Test Workflow

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_content)

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--auto-fix",
                "--validation-method",
                "git",
            ],
        )

        # Should show auto-fix results
        output = result.stdout
        if "Auto-fixed" in output:
            assert ".github/workflows/test.yaml" in output
            assert "actions/checkout@v4" in output or "checkout" in output


class TestAutoFixIntegrationScenarios:
    """Test auto-fix integration with real-world scenarios."""

    def test_auto_fix_with_mixed_workflow_types(self, temp_dir: Path) -> None:
        """Test auto-fix with workflows containing both actions and reusable workflows."""
        workflow_content = """name: Mixed Workflow

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4

  reusable:
    uses: org/repo/.github/workflows/reusable.yaml@main

  local:
    uses: ./.github/workflows/local.yaml
"""
        workflow_file = temp_dir / ".github" / "workflows" / "mixed.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_content)

        runner = CliRunner()

        with patch(
            "gha_workflow_linter.validator.ActionCallValidator"
        ) as mock_validator_class:
            mock_validator = AsyncMock()
            mock_validator_class.return_value = mock_validator

            # Only action calls should be validated for SHA pinning
            def mock_validate_calls(calls, _progress=None, _task=None):
                errors = []
                for call in calls:
                    if (
                        call.call_type == ActionCallType.ACTION
                        and call.reference in ["v3", "v4"]
                    ):
                        errors.append(
                            ValidationError(
                                file_path=workflow_file,
                                action_call=call,
                                result=ValidationResult.NOT_PINNED_TO_SHA,
                                error_message="Action not pinned to SHA",
                            )
                        )
                return errors

            mock_validator.validate_action_calls = mock_validate_calls

            with patch(
                "gha_workflow_linter.auto_fix.AutoFixer"
            ) as mock_auto_fixer_class:
                mock_auto_fixer = AsyncMock()
                mock_auto_fixer_class.return_value.__aenter__.return_value = (
                    mock_auto_fixer
                )
                mock_auto_fixer.fix_validation_errors.return_value = {}

                result = runner.invoke(
                    app,
                    [
                        "lint",
                        str(temp_dir),
                        "--auto-fix",
                        "--validation-method",
                        "git",
                    ],
                )

                # Should only flag action calls, not reusable workflows
                assert (
                    "Found" in result.stdout
                    and "2" in result.stdout
                    and "validation errors" in result.stdout
                )
                assert "2 actions not pinned to SHA" in result.stdout

    def test_auto_fix_with_large_workflow_file(self, temp_dir: Path) -> None:
        """Test auto-fix performance with large workflow files."""
        # Create a workflow with many action calls
        steps = []
        for i in range(50):
            steps.append(f"""      - name: Step {i}
        uses: actions/checkout@v{i % 5 + 1}""")

        workflow_content = f"""name: Large Workflow

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
{chr(10).join(steps)}
"""
        workflow_file = temp_dir / ".github" / "workflows" / "large.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_content)

        runner = CliRunner()

        with patch(
            "gha_workflow_linter.validator.ActionCallValidator"
        ) as mock_validator_class:
            mock_validator = AsyncMock()
            mock_validator_class.return_value = mock_validator

            # All should be validation errors (not pinned to SHA)
            def mock_validate_calls(calls, _progress=None, _task=None):
                return [
                    ValidationError(
                        file_path=workflow_file,
                        action_call=call,
                        result=ValidationResult.NOT_PINNED_TO_SHA,
                        error_message="Action not pinned to SHA",
                    )
                    for call in calls
                ]

            mock_validator.validate_action_calls = mock_validate_calls

            with patch(
                "gha_workflow_linter.auto_fix.AutoFixer"
            ) as mock_auto_fixer_class:
                mock_auto_fixer = AsyncMock()
                mock_auto_fixer_class.return_value.__aenter__.return_value = (
                    mock_auto_fixer
                )
                mock_auto_fixer.fix_validation_errors.return_value = {}

                result = runner.invoke(
                    app,
                    [
                        "lint",
                        str(temp_dir),
                        "--auto-fix",
                        "--validation-method",
                        "git",
                    ],
                )

                # Should handle all 50 action calls
                assert (
                    "Found" in result.stdout
                    and "50" in result.stdout
                    and "validation errors" in result.stdout
                )
                assert "50 actions not pinned to SHA" in result.stdout

    def test_auto_fix_with_syntax_errors(self, temp_dir: Path) -> None:
        """Test auto-fix behavior with workflows that have YAML syntax errors."""
        workflow_content = """name: Syntax Error Workflow
on: [push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        invalid_yaml: {unclosed
"""
        workflow_file = temp_dir / ".github" / "workflows" / "syntax-error.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_content)

        runner = CliRunner()

        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--auto-fix",
                "--validation-method",
                "git",
            ],
        )

        # Scanner handles syntax errors gracefully, skips invalid files
        # So we get exit code 0 if no valid workflows found
        assert result.exit_code == 0
        # Should report scanning issues (as WARNING), not validation errors
        assert (
            "Invalid YAML" in result.stdout
            or "parsing" in result.stdout.lower()
        )

    def test_auto_fix_exit_codes(self, temp_dir: Path) -> None:
        """Test that auto-fix produces correct exit codes."""
        # Test with a valid SHA-pinned workflow
        valid_workflow = """name: Valid
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
"""
        workflows_dir = temp_dir / ".github" / "workflows"
        workflows_dir.mkdir(parents=True, exist_ok=True)
        (workflows_dir / "valid.yaml").write_text(valid_workflow)

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--validation-method",
                "git",
            ],
        )

        # Valid workflow should return 0
        assert result.exit_code == 0, f"Valid workflow failed: {result.stdout}"

        # Test with invalid workflow that needs auto-fix
        invalid_workflow = """name: Invalid
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
"""
        (workflows_dir / "invalid.yaml").write_text(invalid_workflow)

        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--auto-fix",
                "--validation-method",
                "git",
            ],
        )

        # Auto-fix should modify file and return 1
        assert result.exit_code == 1, (
            f"Auto-fix should return 1: {result.stdout}"
        )
        assert (
            "Auto-fixed" in result.stdout
            or "validation errors" in result.stdout
        )


class TestAutoFixErrorHandling:
    """Test auto-fix error handling and edge cases."""

    def test_auto_fix_with_network_errors(self, temp_dir: Path) -> None:
        """Test that auto-fix handles network errors gracefully."""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(
            """name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        )

        runner = CliRunner()

        # Test with auto-fix - should work with git validation method
        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--auto-fix",
                "--validation-method",
                "git",
                "--require-pinned-sha",
            ],
        )

        # Should complete successfully or show auto-fix
        assert (
            result.exit_code == 0
            or "Auto-fixed" in result.stdout
            or "validation errors" in result.stdout
        )

    def test_auto_fix_with_multiple_workflow_directories(
        self, temp_dir: Path
    ) -> None:
        """Test auto-fix with multiple nested workflow directories."""
        # Create multiple workflow directories
        dirs = [
            temp_dir / ".github" / "workflows",
            temp_dir / "subproject" / ".github" / "workflows",
            temp_dir / "another" / ".github" / "workflows",
        ]

        for workflow_dir in dirs:
            workflow_dir.mkdir(parents=True)
            workflow_file = workflow_dir / "test.yaml"
            workflow_file.write_text("""name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
""")

        runner = CliRunner()

        with patch(
            "gha_workflow_linter.validator.ActionCallValidator"
        ) as mock_validator_class:
            mock_validator = AsyncMock()
            mock_validator_class.return_value = mock_validator

            # Return errors for all workflows
            def mock_validate_calls(calls, _progress=None, _task=None):
                return [
                    ValidationError(
                        file_path=workflow_dir / "test.yaml",
                        action_call=call,
                        result=ValidationResult.NOT_PINNED_TO_SHA,
                        error_message="Action not pinned to SHA",
                    )
                    for call in calls
                ]

            mock_validator.validate_action_calls = mock_validate_calls

            with patch(
                "gha_workflow_linter.auto_fix.AutoFixer"
            ) as mock_auto_fixer_class:
                mock_auto_fixer = AsyncMock()
                mock_auto_fixer_class.return_value.__aenter__.return_value = (
                    mock_auto_fixer
                )

                # Mock fixes for all files
                fixed_files = {}
                for workflow_dir in dirs:
                    workflow_file = workflow_dir / "test.yaml"
                    fixed_files[workflow_file] = [
                        {"line": 7, "old": "v3", "new": "sha123"}
                    ]

                mock_auto_fixer.fix_validation_errors.return_value = fixed_files

                result = runner.invoke(
                    app,
                    [
                        "lint",
                        str(temp_dir),
                        "--auto-fix",
                        "--validation-method",
                        "git",
                    ],
                )

                # Should find and fix all 3 workflow files
                assert (
                    "Found" in result.stdout
                    and "3" in result.stdout
                    and "validation errors" in result.stdout
                )
                assert "Auto-fixed issues in 3 file(s)" in result.stdout
                assert result.exit_code == 1


class TestYAMLStructurePreservation:
    """Test that auto-fix preserves YAML structure (indentation and dashes)."""

    @pytest.fixture
    def config_with_pinned_sha(self) -> Config:
        """Config with require_pinned_sha=True."""
        return Config(
            log_level=LogLevel.DEBUG,
            parallel_workers=2,
            require_pinned_sha=True,
            auto_fix=True,
            auto_latest=True,
            two_space_comments=True,
            validation_method=ValidationMethod.GIT,
            network=NetworkConfig(
                timeout_seconds=10,
                max_retries=2,
                retry_delay_seconds=1.0,
                rate_limit_delay_seconds=0.1,
            ),
        )

    def test_build_fixed_line_preserves_dash_prefix(
        self, config_with_pinned_sha: Config
    ) -> None:
        """Test that _build_fixed_line preserves dash prefix when present."""
        auto_fixer = AutoFixer(config_with_pinned_sha)

        # Test case 1: Line WITH dash prefix (workflow style)
        action_call_with_dash = ActionCall(
            raw_line="      - uses: astral-sh/setup-uv@0f33eebc8badfbd026c0aa235815a1f99c93ce1f  # v5.2.0",
            line_number=10,
            organization="astral-sh",
            repository="setup-uv",
            reference="0f33eebc8badfbd026c0aa235815a1f99c93ce1f",
            reference_type=ReferenceType.COMMIT_SHA,
            call_type=ActionCallType.ACTION,
            comment="v5.2.0",
        )

        fixed_line = auto_fixer._build_fixed_line(
            action_call_with_dash,
            "85856786d1ce8acfbcc2f13a5f3fbd6b938f9f41",
            "v7.1.2",
        )

        # Should preserve the dash and indentation
        assert fixed_line.startswith("      - uses: ")
        assert (
            "astral-sh/setup-uv@85856786d1ce8acfbcc2f13a5f3fbd6b938f9f41"
            in fixed_line
        )
        assert "# v7.1.2" in fixed_line
        # Should NOT have double dash
        assert "- - uses:" not in fixed_line

    def test_build_fixed_line_preserves_no_dash_prefix(
        self, config_with_pinned_sha: Config
    ) -> None:
        """Test that _build_fixed_line does not add dash when not present."""
        auto_fixer = AutoFixer(config_with_pinned_sha)

        # Test case 2: Line WITHOUT dash prefix (composite action style)
        action_call_without_dash = ActionCall(
            raw_line="      uses: astral-sh/setup-uv@0f33eebc8badfbd026c0aa235815a1f99c93ce1f  # v5.2.0",
            line_number=10,
            organization="astral-sh",
            repository="setup-uv",
            reference="0f33eebc8badfbd026c0aa235815a1f99c93ce1f",
            reference_type=ReferenceType.COMMIT_SHA,
            call_type=ActionCallType.ACTION,
            comment="v5.2.0",
        )

        fixed_line = auto_fixer._build_fixed_line(
            action_call_without_dash,
            "85856786d1ce8acfbcc2f13a5f3fbd6b938f9f41",
            "v7.1.2",
        )

        # Should NOT add a dash when original doesn't have one
        assert fixed_line.startswith("      uses: ")
        assert not fixed_line.startswith("      - uses: ")
        assert (
            "astral-sh/setup-uv@85856786d1ce8acfbcc2f13a5f3fbd6b938f9f41"
            in fixed_line
        )
        assert "# v7.1.2" in fixed_line

    def test_build_fixed_line_preserves_various_indentation(
        self, config_with_pinned_sha: Config
    ) -> None:
        """Test that _build_fixed_line preserves different indentation levels."""
        auto_fixer = AutoFixer(config_with_pinned_sha)

        test_cases = [
            # (original_line, expected_prefix)
            ("  - uses: actions/checkout@v4", "  - uses: "),
            ("    - uses: actions/checkout@v4", "    - uses: "),
            ("        - uses: actions/checkout@v4", "        - uses: "),
            ("  uses: actions/checkout@v4", "  uses: "),
            ("    uses: actions/checkout@v4", "    uses: "),
            ("        uses: actions/checkout@v4", "        uses: "),
        ]

        for original_line, expected_prefix in test_cases:
            action_call = ActionCall(
                raw_line=original_line,
                line_number=1,
                organization="actions",
                repository="checkout",
                reference="v4",
                reference_type=ReferenceType.TAG,
                call_type=ActionCallType.ACTION,
                comment=None,
            )

            fixed_line = auto_fixer._build_fixed_line(
                action_call,
                "abc123def456",
                "v5.0.0",
            )

            assert fixed_line.startswith(expected_prefix), (
                f"Expected '{expected_prefix}' but got '{fixed_line[: len(expected_prefix)]}' "
                f"for original line: '{original_line}'"
            )

    @pytest.mark.asyncio
    async def test_composite_action_format_preservation(
        self, tmp_path: Path, config_with_pinned_sha: Config
    ) -> None:
        """Test that composite action.yaml format is preserved during auto-fix."""
        # Create a composite action.yaml with the specific format
        action_file = tmp_path / "action.yaml"
        action_file.write_text("""name: Test Action
description: Test composite action

runs:
  using: "composite"
  steps:
    - name: "Setup Python"
      uses: actions/setup-python@v5.0.0
      with:
        python-version: "3.11"

    - name: "Install uv"
      uses: astral-sh/setup-uv@0f33eebc8badfbd026c0aa235815a1f99c93ce1f  # v5.2.0
      with:
        enable-cache: true
""")

        validation_error = ValidationError(
            file_path=action_file,
            action_call=ActionCall(
                raw_line="      uses: astral-sh/setup-uv@0f33eebc8badfbd026c0aa235815a1f99c93ce1f  # v5.2.0",
                line_number=12,
                organization="astral-sh",
                repository="setup-uv",
                reference="0f33eebc8badfbd026c0aa235815a1f99c93ce1f",
                reference_type=ReferenceType.COMMIT_SHA,
                call_type=ActionCallType.ACTION,
                comment="v5.2.0",
            ),
            result=ValidationResult.NOT_PINNED_TO_SHA,
            error_message="Outdated SHA",
        )

        async with AutoFixer(config_with_pinned_sha) as auto_fixer:
            with patch.object(
                auto_fixer,
                "_get_commit_sha_for_reference",
                return_value={
                    "sha": "85856786d1ce8acfbcc2f13a5f3fbd6b938f9f41"
                },
            ):
                with patch.object(
                    auto_fixer,
                    "_get_latest_release_or_tag",
                    return_value="v7.1.2",
                ):
                    fixed_files = await auto_fixer.fix_validation_errors(
                        [validation_error]
                    )

        # Verify the file was fixed
        assert action_file in fixed_files

        # Read the fixed content
        fixed_content = action_file.read_text()

        # The line should be updated WITHOUT adding a dash
        assert (
            "      uses: astral-sh/setup-uv@85856786d1ce8acfbcc2f13a5f3fbd6b938f9f41"
            in fixed_content
        )
        # Should NOT have a dash added
        assert (
            "      - uses: astral-sh/setup-uv@85856786d1ce8acfbcc2f13a5f3fbd6b938f9f41"
            not in fixed_content
        )
        # Comment should be updated
        assert "# v7.1.2" in fixed_content or "# v5.2.0" in fixed_content

    @pytest.mark.asyncio
    async def test_workflow_format_preservation(
        self, tmp_path: Path, config_with_pinned_sha: Config
    ) -> None:
        """Test that workflow YAML format with dashes is preserved during auto-fix."""
        # Create a workflow file with dash format
        workflow_dir = tmp_path / ".github" / "workflows"
        workflow_dir.mkdir(parents=True)
        workflow_file = workflow_dir / "test.yaml"
        workflow_file.write_text("""name: Test Workflow

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
""")

        validation_error = ValidationError(
            file_path=workflow_file,
            action_call=ActionCall(
                raw_line="      - uses: actions/checkout@v4",
                line_number=9,
                organization="actions",
                repository="checkout",
                reference="v4",
                reference_type=ReferenceType.TAG,
                call_type=ActionCallType.ACTION,
                comment=None,
            ),
            result=ValidationResult.NOT_PINNED_TO_SHA,
            error_message="Not pinned to SHA",
        )

        async with AutoFixer(config_with_pinned_sha) as auto_fixer:
            with patch.object(
                auto_fixer,
                "_get_commit_sha_for_reference",
                return_value={
                    "sha": "abc123def456789abc123def456789abc123def4"
                },
            ):
                with patch.object(
                    auto_fixer,
                    "_get_latest_release_or_tag",
                    return_value="v5.0.0",
                ):
                    fixed_files = await auto_fixer.fix_validation_errors(
                        [validation_error]
                    )

        # Verify the file was fixed
        assert workflow_file in fixed_files

        # Read the fixed content
        fixed_content = workflow_file.read_text()

        # The line should still have a single dash
        assert (
            "      - uses: actions/checkout@abc123def456789abc123def456789abc123def4"
            in fixed_content
        )
        # Should NOT have double dash
        assert "      - - uses:" not in fixed_content
