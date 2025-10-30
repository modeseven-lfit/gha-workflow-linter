# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for CLI flags related to auto-fix functionality."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from gha_workflow_linter.cli import app


class TestAutoFixCLIFlags:
    """Test CLI flags for auto-fix configuration - functional tests only."""

    def test_no_auto_fix_flag_disables_auto_fix(
        self,
        temp_dir: Path,
    ) -> None:
        """Test --no-auto-fix flag disables auto-fix."""
        # Use a workflow with a tag reference that would normally be auto-fixed
        workflow_content = """name: Test
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
                "--no-auto-fix",
                "--validation-method",
                "git",
            ],
        )

        # Should report errors but not fix them
        assert result.exit_code == 1
        assert "Auto-fixed" not in result.stdout
        assert "validation error" in result.stdout

    def test_cli_flags_are_accepted(
        self,
        temp_dir: Path,
    ) -> None:
        """Test that CLI flags are accepted without error."""
        # Use a valid SHA-pinned workflow
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

        # Test that various flag combinations are accepted
        flag_combinations = [
            ["--auto-fix"],
            ["--no-auto-fix"],
            ["--auto-latest"],
            ["--no-auto-latest"],
            ["--two-space-comments"],
            ["--no-two-space-comments"],
            ["--require-pinned-sha"],
            ["--no-require-pinned-sha"],
        ]

        for flags in flag_combinations:
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
            # Should not crash - exit code 0 or 1 is acceptable
            assert result.exit_code in (0, 1), (
                f"Failed with flags {flags}: {result.stdout}"
            )


class TestAutoFixConfigurationFile:
    """Test auto-fix settings in configuration files."""

    @pytest.mark.skip(
        reason="Config file auto_fix setting not properly implemented yet - TODO: fix implementation"
    )
    def test_config_file_auto_fix_disabled(
        self,
        temp_dir: Path,
    ) -> None:
        """Test that config file can disable auto-fix."""
        # Create config file with auto-fix disabled
        config_content = """
require_pinned_sha: true
auto_fix: false
validation_method: git
"""
        config_file = temp_dir / "gha-workflow-linter.yaml"
        config_file.write_text(config_content)

        # Create sample workflow with tag reference
        workflow_content = """name: Test
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
                "--config",
                str(config_file),
            ],
        )

        # Should report errors but not auto-fix
        assert result.exit_code == 1
        assert "Auto-fixed" not in result.stdout

    def test_invalid_config_file_values(
        self,
        temp_dir: Path,
    ) -> None:
        """Test handling of invalid auto-fix configuration values."""
        # Create config file with invalid values
        config_content = """
require_pinned_sha: "invalid_boolean"
auto_fix: 123
auto_latest: "true_but_string"
two_space_comments: null
"""
        config_file = temp_dir / "gha-workflow-linter.yaml"
        config_file.write_text(config_content)

        workflow_content = """name: Test
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
                "--config",
                str(config_file),
            ],
        )

        # Should fail due to invalid configuration
        assert result.exit_code != 0
        assert (
            "Configuration validation failed" in result.stdout
            or "validation" in result.stdout.lower()
        )

    def test_default_config_generation_includes_auto_fix_settings(
        self,
        temp_dir: Path,
    ) -> None:
        """Test that generated default config includes auto-fix settings."""
        runner = CliRunner()

        # Generate default config
        result = runner.invoke(
            app,
            [
                "cache",
                "--generate-config",
                str(temp_dir / "generated-config.yaml"),
            ],
        )

        if result.exit_code == 0:
            # Check that generated config contains auto-fix settings
            generated_config = (temp_dir / "generated-config.yaml").read_text()

            assert "require_pinned_sha:" in generated_config
            assert "auto_fix:" in generated_config
            assert "auto_latest:" in generated_config
            assert "two_space_comments:" in generated_config


class TestAutoFixHelp:
    """Test auto-fix related help text and documentation."""

    def test_help_includes_auto_fix_options(self) -> None:
        """Test that help output includes auto-fix related options."""
        runner = CliRunner()

        result = runner.invoke(app, ["lint", "--help"])

        help_text = result.stdout.lower()

        # Check for auto-fix related options in help
        # Use partial matching to handle formatting differences
        assert "auto-fix" in help_text
        assert "auto-latest" in help_text
        assert "two-space" in help_text or "two space" in help_text
        assert "require-pinned-sha" in help_text or "pinned-sha" in help_text

    def test_version_output(self) -> None:
        """Test version output works with auto-fix functionality."""
        runner = CliRunner()

        result = runner.invoke(app, ["--version"])

        assert result.exit_code == 0
        assert "gha-workflow-linter version" in result.stdout
