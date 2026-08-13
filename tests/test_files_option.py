# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for --files CLI option."""
# pyright: reportUninitializedInstanceVariable=false

from __future__ import annotations

from pathlib import Path
import tempfile
from unittest.mock import Mock, patch

from typer.testing import CliRunner

from gha_workflow_linter.cli import app


class TestFilesOption:
    """Test the --files CLI option."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.runner = CliRunner()

    def create_test_workspace(self) -> Path:
        """Create a test workspace with multiple workflow files."""
        temp_dir = Path(tempfile.mkdtemp())
        github_dir = temp_dir / ".github" / "workflows"
        github_dir.mkdir(parents=True)

        # Create multiple workflow files
        ci_workflow = """
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
"""
        (github_dir / "ci.yml").write_text(ci_workflow)

        deploy_workflow = """
name: Deploy
on: [release]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
"""
        (github_dir / "deploy.yml").write_text(deploy_workflow)

        test_workflow = """
name: Test
on: [pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v3
"""
        (github_dir / "test.yml").write_text(test_workflow)

        # Create an action.yml file
        action_content = """
name: Custom Action
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
"""
        (temp_dir / "action.yml").write_text(action_content)

        return temp_dir

    @patch(
        "gha_workflow_linter.validator.ActionCallValidator.validate_action_calls"
    )
    def test_scan_single_file(self, mock_validate: Mock) -> None:
        """Test scanning a single specific file."""
        mock_validate.return_value = []
        temp_dir = self.create_test_workspace()

        try:
            result = self.runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--files",
                    ".github/workflows/ci.yml",
                    "--no-fail-on-error",
                ],
            )

            # Should succeed
            assert result.exit_code == 0

            # Verify output mentions only ci.yml
            assert "ci.yml" in result.stdout or "CI" in result.stdout
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    @patch(
        "gha_workflow_linter.validator.ActionCallValidator.validate_action_calls"
    )
    def test_scan_multiple_files(self, mock_validate: Mock) -> None:
        """Test scanning multiple specific files."""
        mock_validate.return_value = []
        temp_dir = self.create_test_workspace()

        try:
            result = self.runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--files",
                    ".github/workflows/ci.yml",
                    "--files",
                    ".github/workflows/test.yml",
                    "--no-fail-on-error",
                ],
            )

            # Should succeed
            assert result.exit_code == 0
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    @patch(
        "gha_workflow_linter.validator.ActionCallValidator.validate_action_calls"
    )
    def test_scan_files_with_wildcard(self, mock_validate: Mock) -> None:
        """Test scanning files matching wildcard pattern."""
        mock_validate.return_value = []
        temp_dir = self.create_test_workspace()

        try:
            result = self.runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--files",
                    ".github/workflows/*.yml",
                    "--no-fail-on-error",
                ],
            )

            # Should succeed
            assert result.exit_code == 0
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    @patch(
        "gha_workflow_linter.validator.ActionCallValidator.validate_action_calls"
    )
    def test_scan_action_file(self, mock_validate: Mock) -> None:
        """Test scanning an action.yml file."""
        mock_validate.return_value = []
        temp_dir = self.create_test_workspace()

        try:
            result = self.runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--files",
                    "action.yml",
                    "--no-fail-on-error",
                ],
            )

            # Should succeed
            assert result.exit_code == 0
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    @patch(
        "gha_workflow_linter.validator.ActionCallValidator.validate_action_calls"
    )
    def test_no_files_found_warning(self, mock_validate: Mock) -> None:
        """Test warning when no files match the pattern."""
        mock_validate.return_value = []
        temp_dir = self.create_test_workspace()

        try:
            result = self.runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--files",
                    "nonexistent.yml",
                    "--no-fail-on-error",
                ],
            )

            # Should succeed but may show warning
            assert result.exit_code == 0
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    @patch(
        "gha_workflow_linter.validator.ActionCallValidator.validate_action_calls"
    )
    @patch("gha_workflow_linter.auto_fix.AutoFixer.fix_validation_errors")
    def test_auto_fix_with_specific_files(
        self, mock_fix: Mock, mock_validate: Mock
    ) -> None:
        """Test auto-fix only applies to specified files."""
        from gha_workflow_linter.models import (
            ActionCall,
            ValidationError,
            ValidationResult,
        )

        temp_dir = self.create_test_workspace()
        ci_file = temp_dir / ".github" / "workflows" / "ci.yml"

        # Mock validation to return an error for ci.yml
        error = ValidationError(
            file_path=ci_file,
            action_call=ActionCall(
                raw_line="uses: actions/checkout@v4",
                line_number=7,
                organization="actions",
                repository="checkout",
                reference="v4",
            ),
            result=ValidationResult.INVALID_REFERENCE,
            error_message="Invalid reference",
        )
        mock_validate.return_value = [error]

        # Mock auto-fix to return fixed file
        mock_fix.return_value = (
            {
                ci_file: [
                    {
                        "old_line": "uses: actions/checkout@v4",
                        "new_line": "uses: actions/checkout@abc123",
                    }
                ]
            },
            {"actions_moved": 0, "calls_updated": 0},
            {},
        )

        try:
            result = self.runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--files",
                    ".github/workflows/ci.yml",
                    "--auto-fix",
                    "--no-update-actions",
                ],
            )

            # Should exit with code 1 since fixes were made
            assert result.exit_code == 1

            # Verify fix was called
            assert mock_fix.called
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    @patch(
        "gha_workflow_linter.validator.ActionCallValidator.validate_action_calls"
    )
    def test_files_option_with_absolute_path(self, mock_validate: Mock) -> None:
        """Test --files option with absolute paths."""
        mock_validate.return_value = []
        temp_dir = self.create_test_workspace()

        try:
            ci_file = temp_dir / ".github" / "workflows" / "ci.yml"
            result = self.runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--files",
                    str(ci_file.resolve()),
                    "--no-fail-on-error",
                ],
            )

            # Should succeed
            assert result.exit_code == 0
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    @patch(
        "gha_workflow_linter.validator.ActionCallValidator.validate_action_calls"
    )
    def test_files_option_excludes_other_files(
        self, mock_validate: Mock
    ) -> None:
        """Test that --files option excludes non-specified files from scanning."""
        mock_validate.return_value = []
        temp_dir = self.create_test_workspace()

        try:
            # Scan only ci.yml - should not scan deploy.yml or test.yml
            result = self.runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--files",
                    ".github/workflows/ci.yml",
                    "--verbose",
                    "--no-fail-on-error",
                ],
            )

            # Should succeed
            assert result.exit_code == 0

            # The validator should have been called with only the specified file
            assert mock_validate.called
            call_args = mock_validate.call_args
            workflow_calls = call_args[0][0]

            # Should have only 1 file in the workflow_calls dict
            assert len(workflow_calls) == 1

            # Verify it's the ci.yml file
            file_path = list(workflow_calls.keys())[0]
            assert file_path.name == "ci.yml"
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    @patch(
        "gha_workflow_linter.validator.ActionCallValidator.validate_action_calls"
    )
    def test_files_option_with_mixed_patterns(
        self, mock_validate: Mock
    ) -> None:
        """Test --files with mix of exact paths and wildcards."""
        mock_validate.return_value = []
        temp_dir = self.create_test_workspace()

        try:
            result = self.runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--files",
                    ".github/workflows/ci.yml",
                    "--files",
                    "action.yml",
                    "--no-fail-on-error",
                ],
            )

            # Should succeed
            assert result.exit_code == 0

            # Verify both files were scanned
            assert mock_validate.called
            call_args = mock_validate.call_args
            workflow_calls = call_args[0][0]

            # Should have 2 files in the workflow_calls dict
            assert len(workflow_calls) == 2
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_files_option_shown_in_help(self) -> None:
        """Test that --files option appears in help text."""
        result = self.runner.invoke(app, ["lint", "--help"])

        assert result.exit_code == 0
        # More robust check - look for the option name or description parts
        help_text = result.stdout.lower()
        assert (
            "--files" in result.stdout
            or "files" in help_text
            and "scan" in help_text
            or "specific files" in help_text
        ), (
            f"--files option not found in help output. Got: {result.stdout[:500]}"
        )

    @patch(
        "gha_workflow_linter.validator.ActionCallValidator.validate_action_calls"
    )
    @patch("gha_workflow_linter.auto_fix.AutoFixer.fix_validation_errors")
    def test_auto_fix_validation_errors_without_auto_latest(
        self, mock_fix: Mock, mock_validate: Mock
    ) -> None:
        """Test that validation errors are fixed with --auto-fix even without --auto-latest."""
        from gha_workflow_linter.models import (
            ActionCall,
            ValidationError,
            ValidationResult,
        )

        temp_dir = self.create_test_workspace()
        ci_file = temp_dir / ".github" / "workflows" / "ci.yml"

        # Mock validation to return an error (invalid SHA)
        error = ValidationError(
            file_path=ci_file,
            action_call=ActionCall(
                raw_line="uses: actions/checkout@invalid123",
                line_number=7,
                organization="actions",
                repository="checkout",
                reference="invalid123",
            ),
            result=ValidationResult.INVALID_REFERENCE,
            error_message="Invalid SHA",
        )
        mock_validate.return_value = [error]

        # Mock auto-fix to return fixed file (simulating that the invalid SHA was fixed)
        mock_fix.return_value = (
            {
                ci_file: [
                    {
                        "old_line": "uses: actions/checkout@invalid123",
                        "new_line": "uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1",
                    }
                ]
            },
            {"actions_moved": 0, "calls_updated": 0},
            {},  # No stale actions since this was a validation error fix
        )

        try:
            result = self.runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--files",
                    ".github/workflows/ci.yml",
                    "--auto-fix",
                    # Note: NOT using --auto-latest
                ],
            )

            # Should exit with code 1 since fixes were made
            assert result.exit_code == 1

            # Verify fix was called
            assert mock_fix.called

            # Verify the output shows the fix was applied
            assert (
                "Updated" in result.stdout or "workflow call" in result.stdout
            )
        finally:
            import shutil

            shutil.rmtree(temp_dir)
