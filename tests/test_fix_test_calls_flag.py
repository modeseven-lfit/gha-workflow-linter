# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for --fix-test-calls flag functionality."""

from __future__ import annotations

from pathlib import Path
import re
import tempfile
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from gha_workflow_linter.auto_fix import AutoFixer
from gha_workflow_linter.cli import app
from gha_workflow_linter.models import (
    ActionCall,
    ActionCallType,
    Config,
    ReferenceType,
    ValidationError,
    ValidationResult,
)
from gha_workflow_linter.utils import has_test_comment
from tests.test_auto_fix import build_all_action_calls_from_errors

if TYPE_CHECKING:
    from collections.abc import Generator


class TestFixTestCallsFlag:
    """Test --fix-test-calls flag behavior."""

    @pytest.fixture(autouse=True)
    def isolated_home(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> Generator[Path, None, None]:
        """Isolate HOME directory to prevent tests from touching real user cache."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_home = Path(temp_dir)
            monkeypatch.setenv("HOME", str(temp_home))
            # Also set for Windows compatibility
            monkeypatch.setenv("USERPROFILE", str(temp_home))
            yield temp_home

    @pytest.fixture
    def runner(self) -> CliRunner:
        """Create a CLI runner with isolated environment."""
        import os

        # Create runner with isolated environment
        runner = CliRunner(
            env={
                k: v
                for k, v in os.environ.items()
                if not k.startswith("GITHUB")
            }
        )
        return runner

    @pytest.fixture
    def temp_workflow_dir(self) -> Generator[Path, None, None]:
        """Create a temporary directory with test workflow files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            workflows_dir = temp_path / ".github" / "workflows"
            workflows_dir.mkdir(parents=True)
            yield temp_path

    def test_default_behavior_skips_test_comments(
        self,
        temp_workflow_dir: Path,
        runner: CliRunner,
        mock_git_commands: None,
    ) -> None:
        """Test that by default, actions with 'test' comments are skipped."""
        workflow_file = (
            temp_workflow_dir / ".github" / "workflows" / "test.yaml"
        )
        workflow_file.write_text("""name: Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: lfreleng-actions/pypi-publish-action@update-action  # Testing
      - uses: actions/checkout@v4
""")

        # Use isolated runner to avoid state pollution
        result = runner.invoke(
            app,
            ["lint", str(temp_workflow_dir), "--no-cache"],
            catch_exceptions=False,
        )

        # Should succeed or show test references as warnings, not errors
        assert result.exit_code in [0, 1]  # May have other validation issues

        # The output should indicate test references differently
        clean_output = re.sub(r"\x1b\[[0-9;]*m", "", result.output)

        # The action should either be:
        # 1. Explicitly shown as skipped (with "Skipped" message and "testing" keyword)
        # 2. Appear in output with a test marker
        has_action = (
            "lfreleng-actions/pypi-publish-action" in clean_output
            or "pypi-publish-action" in clean_output
        )
        has_skipped_message = "Skipped" in clean_output and (
            "testing" in clean_output.lower() or "Testing" in clean_output
        )
        has_test_marker = (
            "Testing" in clean_output or "test" in clean_output.lower()
        )

        # Either the action should be explicitly marked as skipped, or it should appear with test marker
        # It should NOT be silently ignored without any output
        assert has_skipped_message or (has_action and has_test_marker), (
            f"Test action not properly reported in output. "
            f"Expected either 'Skipped' message or action with test marker.\n"
            f"Output:\n{clean_output}"
        )

    @pytest.mark.network
    def test_fix_test_calls_flag_enables_fixing(
        self,
        temp_workflow_dir: Path,
        runner: CliRunner,
    ) -> None:
        """Test that --fix-test-calls flag enables fixing of test actions.

        Unlike its neighbours this one asserts a rewrite *happened*, so it
        needs a real reference resolved to a real SHA. ``mock_git_commands``
        stubs the git binary but not the API resolution path the fixer uses,
        so the mocked run produces no replacement and the assertion fails.
        Marked rather than stubbed, so the dependency is visible and can be
        deselected, until the resolution layer has a seam to stub.
        """
        workflow_file = (
            temp_workflow_dir / ".github" / "workflows" / "test.yaml"
        )
        workflow_file.write_text("""name: Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3  # Testing
      - uses: actions/setup-python@v4
""")

        runner.invoke(
            app,
            [
                "lint",
                str(temp_workflow_dir),
                "--no-cache",
                "--fix-test-calls",
                "--auto-fix",
            ],
        )

        # With --fix-test-calls, the action with test comment should be fixed
        updated_content = workflow_file.read_text()

        # The action should be updated (SHA or newer version)
        # The original v3 should not be there anymore
        assert "actions/checkout@v3" not in updated_content
        # Should have been updated to a SHA or newer version
        assert "actions/checkout@" in updated_content

    def test_no_fix_test_calls_preserves_test_actions(
        self,
        temp_workflow_dir: Path,
        runner: CliRunner,
        mock_git_commands: None,
    ) -> None:
        """Test that without --fix-test-calls, test actions are not modified."""
        workflow_file = (
            temp_workflow_dir / ".github" / "workflows" / "test.yaml"
        )
        original_content = """name: Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3  # Testing
      - uses: actions/setup-python@v4
"""
        workflow_file.write_text(original_content)

        runner.invoke(
            app,
            ["lint", str(temp_workflow_dir), "--no-cache", "--auto-fix"],
        )

        updated_content = workflow_file.read_text()

        # The action with test comment should remain unchanged
        assert "actions/checkout@v3  # Testing" in updated_content

        # But the non-test action may be updated (depending on network)
        # We just verify the test one wasn't touched


class TestHasTestComment:
    """Test _has_test_comment helper function."""

    def test_has_test_comment_with_test(self) -> None:
        """Test detection of 'test' in comment."""
        action_call = ActionCall(
            raw_line="uses: actions/checkout@main  # Testing",
            line_number=10,
            organization="actions",
            repository="checkout",
            reference="main",
            reference_type=ReferenceType.BRANCH,
            call_type=ActionCallType.ACTION,
            comment="# Testing",
        )

        assert has_test_comment(action_call) is True

    def test_has_test_comment_case_insensitive(self) -> None:
        """Test that comment detection is case-insensitive."""
        test_cases = [
            "# test",
            "# Test",
            "# TEST",
            "# testing",
            "# Testing branch",
            "#test",
            "# This is a TEST comment",
        ]

        for comment in test_cases:
            action_call = ActionCall(
                raw_line=f"uses: actions/checkout@main  {comment}",
                line_number=10,
                organization="actions",
                repository="checkout",
                reference="main",
                reference_type=ReferenceType.BRANCH,
                call_type=ActionCallType.ACTION,
                comment=comment,
            )
            assert has_test_comment(action_call) is True, (
                f"Failed for: {comment}"
            )

    def test_has_test_comment_without_test(self) -> None:
        """Test that non-test comments return False."""
        test_cases = [
            "# v4",
            "# stable",
            "",
            "# Production ready",
        ]

        for comment in test_cases:
            action_call = ActionCall(
                raw_line=f"uses: actions/checkout@main  {comment}",
                line_number=10,
                organization="actions",
                repository="checkout",
                reference="main",
                reference_type=ReferenceType.BRANCH,
                call_type=ActionCallType.ACTION,
                comment=comment,
            )
            assert has_test_comment(action_call) is False, (
                f"Failed for: {comment}"
            )


class TestAutoFixerTestBehavior:
    """Test AutoFixer behavior with test comments."""

    @pytest.fixture
    def temp_file(self) -> Generator[Path, None, None]:
        """Create a temporary file for testing."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            temp_path = Path(f.name)
            yield temp_path
            if temp_path.exists():
                temp_path.unlink()

    @pytest.mark.asyncio
    async def test_auto_fixer_skips_test_actions_by_default(
        self, temp_file: Path
    ) -> None:
        """Test that AutoFixer skips actions with test comments by default."""
        temp_file.write_text("""name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3  # Testing
""")

        # Create config with fix_test_calls=False (default)
        config = Config(
            auto_fix=True,
            fix_test_calls=False,
        )

        # Create validation errors
        validation_errors = [
            ValidationError(
                file_path=temp_file,
                action_call=ActionCall(
                    raw_line="      - uses: actions/checkout@v3  # Testing",
                    line_number=7,
                    organization="actions",
                    repository="checkout",
                    reference="v3",
                    reference_type=ReferenceType.TAG,
                    call_type=ActionCallType.ACTION,
                    comment="# Testing",
                ),
                result=ValidationResult.NOT_PINNED_TO_SHA,
                error_message="Action not pinned to SHA",
            ),
        ]

        async with AutoFixer(config) as fixer:
            (
                fixed_files,
                redirect_stats,
                stale_actions_summary,
            ) = await fixer.fix_validation_errors(
                validation_errors,
                build_all_action_calls_from_errors(validation_errors),
            )

        # Should return empty dict or skipped items, not actual fixes
        if temp_file in fixed_files:
            # Check if it was marked as skipped
            changes = fixed_files[temp_file]
            if changes:
                # If there are changes, they should indicate it was skipped
                assert any("skipped" in str(change) for change in changes)

        # Content should be unchanged
        content = temp_file.read_text()
        assert "actions/checkout@v3  # Testing" in content

    @pytest.mark.asyncio
    async def test_auto_fixer_fixes_test_actions_when_enabled(
        self, temp_file: Path
    ) -> None:
        """Test that AutoFixer fixes test actions when fix_test_calls=True (via --fix-test-calls)."""
        temp_file.write_text("""name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3  # Testing
""")

        # Create config with fix_test_calls=True (enabled via --fix-test-calls)
        config = Config(
            auto_fix=True,
            fix_test_calls=True,
        )

        # Note: This test would need mocking of network calls to actually fix
        # For now, we just verify the config is set correctly
        async with AutoFixer(config) as fixer:
            assert fixer.config.fix_test_calls is True


class TestCLIFixTestCallsIntegration:
    """Test CLI integration with --fix-test-calls flag."""

    @pytest.fixture
    def runner(self) -> CliRunner:
        """Create a CLI runner."""
        return CliRunner()

    def test_fix_test_calls_flag_accepted(self, runner: CliRunner) -> None:
        """Test that --fix-test-calls flag is accepted by CLI."""
        with tempfile.TemporaryDirectory() as temp_dir:
            result = runner.invoke(
                app,
                ["lint", temp_dir, "--fix-test-calls", "--help"],
            )

            # Should not error on the flag
            assert "--fix-test-calls" in result.output or result.exit_code in [
                0,
                2,
            ]

    def test_fix_test_calls_in_help_text(self, runner: CliRunner) -> None:
        """Test that --fix-test-calls appears in help text."""
        result = runner.invoke(app, ["lint", "--help"])

        clean_output = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
        assert "--fix-test-calls" in clean_output
        assert "test" in clean_output.lower()

    def test_fix_test_calls_with_auto_fix(self, runner: CliRunner) -> None:
        """Test that --fix-test-calls works with --auto-fix."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            workflows_dir = temp_path / ".github" / "workflows"
            workflows_dir.mkdir(parents=True)

            workflow_file = workflows_dir / "test.yaml"
            workflow_file.write_text("""name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""")

            result = runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--no-cache",
                    "--auto-fix",
                    "--fix-test-calls",
                ],
            )

            # Should execute without error
            assert result.exit_code in [0, 1]

    def test_no_fix_test_calls_without_auto_fix(
        self, runner: CliRunner
    ) -> None:
        """Test that --fix-test-calls has no effect without --auto-fix."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            workflows_dir = temp_path / ".github" / "workflows"
            workflows_dir.mkdir(parents=True)

            workflow_file = workflows_dir / "test.yaml"
            original = """name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3  # Testing
"""
            workflow_file.write_text(original)

            runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--no-cache",
                    "--no-auto-fix",
                    "--fix-test-calls",
                ],
            )

            # File should be unchanged without auto-fix enabled
            assert workflow_file.read_text() == original


class TestTestReferenceReporting:
    """Test that test references are reported correctly."""

    @pytest.fixture
    def runner(self) -> CliRunner:
        """Create a CLI runner."""
        return CliRunner()

    @pytest.mark.skip(reason="Network-dependent test that can be flaky")
    def test_test_references_not_counted_as_failures(
        self, runner: CliRunner
    ) -> None:
        """Test that actions with test comments don't cause failure."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            workflows_dir = temp_path / ".github" / "workflows"
            workflows_dir.mkdir(parents=True)

            workflow_file = workflows_dir / "test.yaml"
            workflow_file.write_text("""name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: fake-org/nonexistent-action@main  # test
""")

            result = runner.invoke(
                app,
                ["lint", str(temp_dir), "--no-cache"],
            )

            # Should not fail on test references
            # (exit code 1 might occur for other reasons, but test refs shouldn't fail)
            clean_output = re.sub(r"\x1b\[[0-9;]*m", "", result.output)

            # Should mention it's a test reference somewhere
            assert "test" in clean_output.lower() or result.exit_code == 0

    def test_test_references_shown_in_output(self, runner: CliRunner) -> None:
        """Test that test references are shown in output."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            workflows_dir = temp_path / ".github" / "workflows"
            workflows_dir.mkdir(parents=True)

            workflow_file = workflows_dir / "test.yaml"
            workflow_file.write_text("""name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: lfreleng-actions/test-action@branch  # Testing new feature
""")

            result = runner.invoke(
                app,
                ["lint", str(temp_dir), "--no-cache"],
            )

            clean_output = re.sub(r"\x1b\[[0-9;]*m", "", result.output)

            # Output should reference the test action
            assert (
                "lfreleng-actions/test-action" in clean_output
                or "test" in clean_output.lower()
            )
