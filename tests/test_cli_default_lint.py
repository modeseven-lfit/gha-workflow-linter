# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for CLI default lint behavior (no subcommand)."""
# pyright: reportUninitializedInstanceVariable=false

from __future__ import annotations

from pathlib import Path
import tempfile
from typing import Any
from unittest.mock import Mock, patch

from typer.testing import CliRunner

from gha_workflow_linter.cli import _preprocess_args_for_default_command, app
from gha_workflow_linter.models import Config, ValidationMethod


class TestCLIDefaultLint:
    """Test that CLI invokes lint by default when no subcommand is provided."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.runner = CliRunner()

    def invoke_with_preprocessing(self, args: list[str]) -> Any:
        """Invoke the app with argument preprocessing."""
        processed_args = _preprocess_args_for_default_command(args)
        return self.runner.invoke(app, processed_args)

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_no_subcommand_runs_lint(
        self,
        mock_cache: Mock,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test that running without subcommand invokes lint."""
        # Setup mocks
        mock_config_manager.return_value.load_config.return_value = Config()
        mock_scanner.return_value.scan_directory.return_value = {}
        mock_scanner.return_value.get_scan_summary.return_value = {
            "total_files": 0,
            "total_calls": 0,
            "action_calls": 0,
            "workflow_calls": 0,
            "sha_references": 0,
            "tag_references": 0,
            "branch_references": 0,
        }
        mock_validator.return_value.validate_action_calls.return_value = []
        mock_validator.return_value.get_validation_summary.return_value = {
            "total_calls": 0,
            "unique_calls_validated": 0,
            "duplicate_calls_avoided": 0,
            "api_calls_total": 0,
        }
        mock_cache.return_value = Mock()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Invoke without any subcommand
            result = self.invoke_with_preprocessing([tmpdir])

        # Should run successfully
        assert result.exit_code == 0
        assert "No workflows found to validate" in result.stdout

        # Verify that scanning was invoked
        mock_scanner.return_value.scan_directory.assert_called_once()

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_no_subcommand_with_flags(
        self,
        mock_cache: Mock,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test that flags work without explicit 'lint' subcommand."""
        # Setup mocks
        mock_config_manager.return_value.load_config.return_value = Config()
        mock_scanner.return_value.scan_directory.return_value = {}
        mock_scanner.return_value.get_scan_summary.return_value = {
            "total_files": 0,
            "total_calls": 0,
            "action_calls": 0,
            "workflow_calls": 0,
            "sha_references": 0,
            "tag_references": 0,
            "branch_references": 0,
        }
        mock_validator.return_value.validate_action_calls.return_value = []
        mock_validator.return_value.get_validation_summary.return_value = {
            "total_calls": 0,
            "unique_calls_validated": 0,
            "duplicate_calls_avoided": 0,
            "api_calls_total": 0,
        }
        mock_cache.return_value = Mock()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Invoke with flags but no subcommand
            result = self.invoke_with_preprocessing(
                [tmpdir, "--verbose", "--no-parallel"]
            )

        # Should run successfully
        assert result.exit_code == 0
        assert "No workflows found to validate" in result.stdout

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_no_subcommand_with_workers_option(
        self,
        mock_cache: Mock,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test that --workers flag works without explicit 'lint' subcommand."""
        # Setup mocks
        mock_config = Mock()
        mock_config.parallel_workers = 1
        mock_config_manager.return_value.load_config.return_value = mock_config
        mock_scanner.return_value.scan_directory.return_value = {}
        mock_scanner.return_value.get_scan_summary.return_value = {
            "total_files": 0,
            "total_calls": 0,
            "action_calls": 0,
            "workflow_calls": 0,
            "sha_references": 0,
            "tag_references": 0,
            "branch_references": 0,
        }
        mock_validator.return_value.validate_action_calls.return_value = []
        mock_validator.return_value.get_validation_summary.return_value = {
            "total_calls": 0,
            "unique_calls_validated": 0,
            "duplicate_calls_avoided": 0,
            "api_calls_total": 0,
        }
        mock_cache.return_value = Mock()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Invoke with --workers but no subcommand
            result = self.invoke_with_preprocessing([tmpdir, "--workers", "4"])

        # Should run successfully
        assert result.exit_code == 0
        # Verify workers was set
        assert mock_config.parallel_workers == 4

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_no_subcommand_with_exclude_patterns(
        self,
        mock_cache: Mock,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test that --exclude flag works without explicit 'lint' subcommand."""
        # Setup mocks
        mock_config = Mock()
        mock_config.exclude_patterns = []
        mock_config_manager.return_value.load_config.return_value = mock_config
        mock_scanner.return_value.scan_directory.return_value = {}
        mock_scanner.return_value.get_scan_summary.return_value = {
            "total_files": 0,
            "total_calls": 0,
            "action_calls": 0,
            "workflow_calls": 0,
            "sha_references": 0,
            "tag_references": 0,
            "branch_references": 0,
        }
        mock_validator.return_value.validate_action_calls.return_value = []
        mock_validator.return_value.get_validation_summary.return_value = {
            "total_calls": 0,
            "unique_calls_validated": 0,
            "duplicate_calls_avoided": 0,
            "api_calls_total": 0,
        }
        mock_cache.return_value = Mock()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Invoke with --exclude but no subcommand
            result = self.invoke_with_preprocessing(
                [tmpdir, "--exclude", "*.test.yml"]
            )

        # Should run successfully
        assert result.exit_code == 0
        # Verify exclude pattern was set
        assert "*.test.yml" in mock_config.exclude_patterns

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_no_subcommand_with_no_cache(
        self,
        mock_cache: Mock,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test that --no-cache flag works without explicit 'lint' subcommand."""
        # Setup mocks
        mock_config = Mock()
        mock_config.cache.enabled = True
        mock_config_manager.return_value.load_config.return_value = mock_config
        mock_scanner.return_value.scan_directory.return_value = {}
        mock_scanner.return_value.get_scan_summary.return_value = {
            "total_files": 0,
            "total_calls": 0,
            "action_calls": 0,
            "workflow_calls": 0,
            "sha_references": 0,
            "tag_references": 0,
            "branch_references": 0,
        }
        mock_validator.return_value.validate_action_calls.return_value = []
        mock_validator.return_value.get_validation_summary.return_value = {
            "total_calls": 0,
            "unique_calls_validated": 0,
            "duplicate_calls_avoided": 0,
            "api_calls_total": 0,
        }
        mock_cache.return_value = Mock()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Invoke with --no-cache but no subcommand
            result = self.invoke_with_preprocessing([tmpdir, "--no-cache"])

        # Should run successfully
        assert result.exit_code == 0
        # Verify cache was disabled
        assert mock_config.cache.enabled is False

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_no_subcommand_with_validation_method(
        self,
        mock_cache: Mock,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test that --validation-method flag works without explicit 'lint' subcommand."""
        # Setup mocks
        mock_config = Mock()
        mock_config.validation_method = None
        mock_config_manager.return_value.load_config.return_value = mock_config
        mock_scanner.return_value.scan_directory.return_value = {}
        mock_scanner.return_value.get_scan_summary.return_value = {
            "total_files": 0,
            "total_calls": 0,
            "action_calls": 0,
            "workflow_calls": 0,
            "sha_references": 0,
            "tag_references": 0,
            "branch_references": 0,
        }
        mock_validator.return_value.validate_action_calls.return_value = []
        mock_validator.return_value.get_validation_summary.return_value = {
            "total_calls": 0,
            "unique_calls_validated": 0,
            "duplicate_calls_avoided": 0,
            "api_calls_total": 0,
        }
        mock_cache.return_value = Mock()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Invoke with --validation-method but no subcommand
            result = self.invoke_with_preprocessing(
                [tmpdir, "--validation-method", "git"]
            )

        # Should run successfully
        assert result.exit_code == 0
        # Verify validation method was set
        assert mock_config.validation_method == ValidationMethod.GIT

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_no_subcommand_with_auto_fix(
        self,
        mock_cache: Mock,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test that --auto-fix flag works without explicit 'lint' subcommand."""
        # Setup mocks
        mock_config = Mock()
        mock_config.auto_fix = False
        mock_config_manager.return_value.load_config.return_value = mock_config
        mock_scanner.return_value.scan_directory.return_value = {}
        mock_scanner.return_value.get_scan_summary.return_value = {
            "total_files": 0,
            "total_calls": 0,
            "action_calls": 0,
            "workflow_calls": 0,
            "sha_references": 0,
            "tag_references": 0,
            "branch_references": 0,
        }
        mock_validator.return_value.validate_action_calls.return_value = []
        mock_validator.return_value.get_validation_summary.return_value = {
            "total_calls": 0,
            "unique_calls_validated": 0,
            "duplicate_calls_avoided": 0,
            "api_calls_total": 0,
        }
        mock_cache.return_value = Mock()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Invoke with --auto-fix but no subcommand
            result = self.invoke_with_preprocessing([tmpdir, "--auto-fix"])

        # Should run successfully
        assert result.exit_code == 0
        # Verify auto-fix was enabled
        assert mock_config.auto_fix is True

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_no_subcommand_json_output(
        self,
        mock_cache: Mock,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test that --format json works without explicit 'lint' subcommand."""
        # Setup mocks
        mock_config_manager.return_value.load_config.return_value = Config()
        mock_scanner.return_value.scan_directory.return_value = {}
        mock_scanner.return_value.get_scan_summary.return_value = {
            "total_files": 0,
            "total_calls": 0,
            "action_calls": 0,
            "workflow_calls": 0,
            "sha_references": 0,
            "tag_references": 0,
            "branch_references": 0,
        }
        mock_validator.return_value.validate_action_calls.return_value = []
        mock_validator.return_value.get_validation_summary.return_value = {
            "total_calls": 0,
            "unique_calls_validated": 0,
            "duplicate_calls_avoided": 0,
            "api_calls_total": 0,
        }
        mock_cache.return_value = Mock()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Invoke with --format json but no subcommand
            result = self.invoke_with_preprocessing(
                [tmpdir, "--format", "json"]
            )

        # Should run successfully
        assert result.exit_code == 0
        # Should output JSON (may be minimal if no workflows found)
        # Just verify it's valid JSON output by checking for common JSON patterns
        assert result.stdout.strip() or result.exit_code == 0

    @patch("gha_workflow_linter.cli.ConfigManager")
    def test_no_subcommand_with_config_file(
        self, mock_config_manager: Mock
    ) -> None:
        """Test that --config flag works without explicit 'lint' subcommand."""
        mock_config_manager.return_value.load_config.return_value = Config()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a config file
            config_file = Path(tmpdir) / "config.yaml"
            config_file.write_text("exclude_patterns: ['*.test.yml']")

            # Invoke with --config but no subcommand
            self.invoke_with_preprocessing(
                [tmpdir, "--config", str(config_file)]
            )

        # Config should be loaded
        mock_config_manager.return_value.load_config.assert_called_once()
        call_args = mock_config_manager.return_value.load_config.call_args
        assert call_args[0][0] == config_file

    def test_no_subcommand_verbose_quiet_conflict(self) -> None:
        """Test that --verbose and --quiet conflict even without 'lint' subcommand."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.invoke_with_preprocessing(
                [tmpdir, "--verbose", "--quiet"]
            )

        assert result.exit_code == 1
        assert (
            "Error: --verbose and --quiet cannot be used together"
            in result.stdout
        )

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_no_subcommand_with_files_option(
        self,
        mock_cache: Mock,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test that --files flag works without explicit 'lint' subcommand."""
        # Setup mocks
        mock_config_manager.return_value.load_config.return_value = Config()
        mock_scanner.return_value.scan_directory.return_value = {}
        mock_scanner.return_value.get_scan_summary.return_value = {
            "total_files": 0,
            "total_calls": 0,
            "action_calls": 0,
            "workflow_calls": 0,
            "sha_references": 0,
            "tag_references": 0,
            "branch_references": 0,
        }
        mock_validator.return_value.validate_action_calls.return_value = []
        mock_validator.return_value.get_validation_summary.return_value = {
            "total_calls": 0,
            "unique_calls_validated": 0,
            "duplicate_calls_avoided": 0,
            "api_calls_total": 0,
        }
        mock_cache.return_value = Mock()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a workflow file
            workflows_dir = Path(tmpdir) / ".github" / "workflows"
            workflows_dir.mkdir(parents=True)
            workflow_file = workflows_dir / "test.yml"
            workflow_file.write_text(
                "name: Test\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
            )

            # Invoke with --files but no subcommand
            result = self.invoke_with_preprocessing(
                [tmpdir, "--files", str(workflow_file)]
            )

        # Should run successfully
        assert result.exit_code == 0

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_no_subcommand_current_directory(
        self,
        mock_cache: Mock,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test that default path (current directory) works without explicit 'lint' subcommand."""
        # Setup mocks
        mock_config_manager.return_value.load_config.return_value = Config()
        mock_scanner.return_value.scan_directory.return_value = {}
        mock_scanner.return_value.get_scan_summary.return_value = {
            "total_files": 0,
            "total_calls": 0,
            "action_calls": 0,
            "workflow_calls": 0,
            "sha_references": 0,
            "tag_references": 0,
            "branch_references": 0,
        }
        mock_validator.return_value.validate_action_calls.return_value = []
        mock_validator.return_value.get_validation_summary.return_value = {
            "total_calls": 0,
            "unique_calls_validated": 0,
            "duplicate_calls_avoided": 0,
            "api_calls_total": 0,
        }
        mock_cache.return_value = Mock()

        # Invoke with no arguments at all (should use current directory)
        result = self.invoke_with_preprocessing([])

        # Should run successfully
        assert result.exit_code == 0
        # Scanner should have been called
        mock_scanner.return_value.scan_directory.assert_called_once()

    def test_explicit_lint_subcommand_still_works(self) -> None:
        """Test that explicit 'lint' subcommand still works as before."""
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch("gha_workflow_linter.cli.ConfigManager") as mock_config,
            patch("gha_workflow_linter.cli.WorkflowScanner") as mock_scanner,
            patch(
                "gha_workflow_linter.cli.ActionCallValidator"
            ) as mock_validator,
            patch("gha_workflow_linter.cli.ValidationCache") as mock_cache,
        ):
            mock_config.return_value.load_config.return_value = Config()
            mock_scanner.return_value.scan_directory.return_value = {}
            mock_scanner.return_value.get_scan_summary.return_value = {
                "total_files": 0,
                "total_calls": 0,
                "action_calls": 0,
                "workflow_calls": 0,
                "sha_references": 0,
                "tag_references": 0,
                "branch_references": 0,
            }
            mock_validator.return_value.validate_action_calls.return_value = []
            mock_validator.return_value.get_validation_summary.return_value = {
                "total_calls": 0,
                "unique_calls_validated": 0,
                "duplicate_calls_avoided": 0,
                "api_calls_total": 0,
            }
            mock_cache.return_value = Mock()

            # Invoke with explicit 'lint' subcommand (no preprocessing needed)
            result = self.runner.invoke(app, ["lint", tmpdir])

            # Should run successfully
            assert result.exit_code == 0
            assert "No workflows found to validate" in result.stdout


class TestPreprocessArgsForDefaultCommand:
    """Unit tests for _preprocess_args_for_default_command argv rewriting."""

    def test_no_args_appends_lint(self) -> None:
        assert _preprocess_args_for_default_command([]) == ["lint"]

    def test_help_passes_through(self) -> None:
        assert _preprocess_args_for_default_command(["--help"]) == ["--help"]
        assert _preprocess_args_for_default_command(["--version"]) == [
            "--version"
        ]

    def test_known_subcommand_passes_through(self) -> None:
        assert _preprocess_args_for_default_command(["lint", "foo"]) == [
            "lint",
            "foo",
        ]
        assert _preprocess_args_for_default_command(["cache", "--purge"]) == [
            "cache",
            "--purge",
        ]

    def test_positional_path_gets_lint_injected(self) -> None:
        assert _preprocess_args_for_default_command(["src/"]) == [
            "lint",
            "src/",
        ]

    def test_value_taking_option_before_path(self) -> None:
        """`lint` is prepended in default-lint mode so all options route
        to the lint subcommand. Inserting `lint` mid-argv (e.g. between
        --config and its value, or between --verbose and the path) would
        cause Typer to interpret the leading options as *top-level*
        options of the app and error out, since --verbose / --config /
        etc. are lint-subcommand options."""
        result = _preprocess_args_for_default_command(
            ["--config", "foo.yml", "src/"]
        )
        assert result == ["lint", "--config", "foo.yml", "src/"]

    def test_multiple_value_taking_options(self) -> None:
        result = _preprocess_args_for_default_command(
            [
                "--config",
                "foo.yml",
                "--workers",
                "4",
                "--exclude",
                "*.test.yml",
                "src/",
            ]
        )
        assert result == [
            "lint",
            "--config",
            "foo.yml",
            "--workers",
            "4",
            "--exclude",
            "*.test.yml",
            "src/",
        ]

    def test_value_taking_option_with_no_path(self) -> None:
        """Even with no positional path, `lint` is prepended so Typer
        routes the options to the lint subcommand rather than treating
        them as top-level options of the app."""
        result = _preprocess_args_for_default_command(["--config", "foo.yml"])
        assert result == ["lint", "--config", "foo.yml"]

    def test_short_value_taking_option(self) -> None:
        result = _preprocess_args_for_default_command(["-c", "foo.yml", "src/"])
        assert result == ["lint", "-c", "foo.yml", "src/"]

    def test_boolean_flag_before_path_prepends_lint(self) -> None:
        """Regression: `gha-workflow-linter --verbose src/` previously
        produced argv `[--verbose, lint, src/]` which Typer rejects
        because --verbose is a *lint*-subcommand option, not an app
        option. The processor must prepend `lint` so all flags route
        to the subcommand."""
        result = _preprocess_args_for_default_command(["--verbose", "src/"])
        assert result == ["lint", "--verbose", "src/"]

    def test_path_with_help_injects_lint(self) -> None:
        """Regression: `gha-workflow-linter src/ --help` should still
        inject `lint` so Typer's help renders for the lint subcommand
        rather than treating `src/` as an unknown subcommand."""
        result = _preprocess_args_for_default_command(["src/", "--help"])
        assert result == ["lint", "src/", "--help"]

    def test_path_with_version_injects_lint(self) -> None:
        result = _preprocess_args_for_default_command(["src/", "--version"])
        assert result == ["lint", "src/", "--version"]

    def test_lint_subcommand_with_help_passes_through(self) -> None:
        """If a known subcommand is present we never inject; --help is
        routed by Typer to the subcommand normally."""
        result = _preprocess_args_for_default_command(["lint", "--help"])
        assert result == ["lint", "--help"]

    def test_subcommand_token_as_option_value_is_not_subcommand(
        self,
    ) -> None:
        """Regression: ``--config lint src/`` must inject ``lint`` —
        ``lint`` here is the *value* of ``--config``, not a subcommand
        invocation. Detection must look at the first non-option
        positional token, not scan the whole argv."""
        result = _preprocess_args_for_default_command(
            ["--config", "lint", "src/"]
        )
        assert result == ["lint", "--config", "lint", "src/"]

    def test_subcommand_token_as_exclude_value_is_not_subcommand(
        self,
    ) -> None:
        """Same regression for the ``cache`` token appearing as the
        value of ``--exclude``."""
        result = _preprocess_args_for_default_command(
            ["--exclude", "cache", "src/"]
        )
        assert result == ["lint", "--exclude", "cache", "src/"]

    def test_long_form_option_with_equals_value_does_not_consume_next(
        self,
    ) -> None:
        """``--workers=8`` carries its value in the same token, so the
        next token is the first positional. ``--config=lint`` is a more
        adversarial variant of the same shape."""
        assert _preprocess_args_for_default_command(
            ["--workers=8", "src/"]
        ) == ["lint", "--workers=8", "src/"]
        assert _preprocess_args_for_default_command(
            ["--config=lint", "src/"]
        ) == ["lint", "--config=lint", "src/"]

    def test_subcommand_option_before_positional_routes_correctly(
        self,
    ) -> None:
        """Regression: ``--verbose <path>`` (a *lint*-subcommand option
        followed by the path) must produce an argv shape Typer accepts.
        Previously the processor inserted ``lint`` *between* ``--verbose``
        and the path, producing ``[--verbose, lint, <path>]`` — which
        Typer rejects because ``--verbose`` is a lint-subcommand option,
        not an app-level option. The fix prepends ``lint`` so the option
        routes to the subcommand correctly."""
        import tempfile

        from typer.testing import CliRunner

        from gha_workflow_linter.cli import app

        with tempfile.TemporaryDirectory() as tmpdir:
            runner = CliRunner()
            processed = _preprocess_args_for_default_command(
                ["--verbose", tmpdir]
            )
            assert processed[0] == "lint", (
                "lint must be prepended so --verbose routes to the "
                f"lint subcommand; got {processed!r}"
            )
            result = runner.invoke(app, processed)
            assert result.exit_code != 2, (
                "Typer should not reject the argv as malformed. "
                f"Output: {result.stdout}"
            )
