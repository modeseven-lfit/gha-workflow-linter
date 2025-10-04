# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for CLI interface."""

from __future__ import annotations

import logging
import os
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch

import pytest
import typer
from typer.testing import CliRunner

from gha_workflow_linter import __version__
from gha_workflow_linter.cli import (
    app,
    cache_help_callback,
    help_callback,
    main_app_help_callback,
    main_callback,
    setup_logging,
    version_callback,
)
from gha_workflow_linter.models import (
    ActionCall,
    ActionCallType,
    LogLevel,
    ReferenceType,
    ValidationError,
    ValidationResult,
)


class TestCLICallbacks:
    """Test CLI callback functions."""

    def test_help_callback_no_value(self) -> None:
        """Test help callback when value is False."""
        ctx = Mock(spec=typer.Context)
        ctx.resilient_parsing = False

        # Should not raise when value is False
        help_callback(ctx, None, False)

    def test_help_callback_resilient_parsing(self) -> None:
        """Test help callback during resilient parsing."""
        ctx = Mock(spec=typer.Context)
        ctx.resilient_parsing = True

        # Should not raise during resilient parsing
        help_callback(ctx, None, True)

    def test_help_callback_show_help(self) -> None:
        """Test help callback shows help and exits."""
        ctx = Mock(spec=typer.Context)
        ctx.resilient_parsing = False
        ctx.get_help.return_value = "Test help content"

        with pytest.raises(typer.Exit):
            help_callback(ctx, None, True)

        ctx.get_help.assert_called_once()

    def test_main_app_help_callback_no_value(self) -> None:
        """Test main app help callback when value is False."""
        ctx = Mock(spec=typer.Context)
        ctx.resilient_parsing = False

        # Should not raise when value is False
        main_app_help_callback(ctx, None, False)

    def test_main_app_help_callback_show_help(self) -> None:
        """Test main app help callback shows help and exits."""
        ctx = Mock(spec=typer.Context)
        ctx.resilient_parsing = False
        ctx.get_help.return_value = "Test help content"

        with pytest.raises(typer.Exit):
            main_app_help_callback(ctx, None, True)

        ctx.get_help.assert_called_once()

    def test_cache_help_callback_no_value(self) -> None:
        """Test cache help callback when value is False."""
        ctx = Mock(spec=typer.Context)
        ctx.resilient_parsing = False

        # Should not raise when value is False
        cache_help_callback(ctx, None, False)

    def test_cache_help_callback_show_help(self) -> None:
        """Test cache help callback shows help and exits."""
        ctx = Mock(spec=typer.Context)
        ctx.resilient_parsing = False
        ctx.get_help.return_value = "Test help content"

        with pytest.raises(typer.Exit):
            cache_help_callback(ctx, None, True)

        ctx.get_help.assert_called_once()

    def test_version_callback_false(self) -> None:
        """Test version callback when value is False."""
        # Should not raise when value is False
        version_callback(False)

    def test_version_callback_true(self) -> None:
        """Test version callback shows version and exits."""
        with pytest.raises(typer.Exit):
            version_callback(True)


class TestSetupLogging:
    """Test logging setup function."""

    def test_setup_logging_info_level(self) -> None:
        """Test setup logging with INFO level."""
        setup_logging(LogLevel.INFO, quiet=False)

        logger = logging.getLogger()
        assert logger.level == logging.INFO

    def test_setup_logging_debug_level(self) -> None:
        """Test setup logging with DEBUG level."""
        setup_logging(LogLevel.DEBUG, quiet=False)

        logger = logging.getLogger()
        assert logger.level == logging.DEBUG

    def test_setup_logging_quiet_mode(self) -> None:
        """Test setup logging in quiet mode."""
        setup_logging(LogLevel.INFO, quiet=True)

        logger = logging.getLogger()
        assert logger.level == logging.ERROR

    def test_setup_logging_httpx_suppression(self) -> None:
        """Test that httpx logging is suppressed."""
        setup_logging(LogLevel.DEBUG, quiet=False)

        httpx_logger = logging.getLogger("httpx")
        httpcore_logger = logging.getLogger("httpcore")

        assert httpx_logger.level == logging.WARNING
        assert httpcore_logger.level == logging.WARNING


class TestCLICommands:
    """Test CLI commands using CliRunner."""

    def setup_method(self) -> None:
        """Set up test fragments."""
        self.runner = CliRunner()

    def test_main_help(self) -> None:
        """Test main app help."""
        result = self.runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert __version__ in result.stdout
        assert "GitHub Actions workflow linter" in result.stdout

    def test_version_flag(self) -> None:
        """Test --version flag."""
        result = self.runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.stdout

    def test_lint_help(self) -> None:
        """Test lint command help."""
        result = self.runner.invoke(app, ["lint", "--help"])
        assert result.exit_code == 0
        assert __version__ in result.stdout
        assert "Scan GitHub Actions workflows" in result.stdout

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_lint_basic_execution(
        self,
        mock_cache: Mock,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test basic lint command execution."""
        # Setup mocks
        mock_config_manager.return_value.load_config.return_value = Mock()
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
            result = self.runner.invoke(app, ["lint", tmpdir])

        # Should not exit with error for empty results
        assert result.exit_code == 0
        assert "No workflows found to validate" in result.stdout

    def test_lint_verbose_and_quiet_conflict(self) -> None:
        """Test lint command with conflicting verbose and quiet flags."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.invoke(
                app, ["lint", tmpdir, "--verbose", "--quiet"]
            )

        assert result.exit_code == 1
        assert (
            "Error: --verbose and --quiet cannot be used together"
            in result.stdout
        )

    @patch("gha_workflow_linter.cli.ConfigManager")
    def test_lint_invalid_config_file(self, mock_config_manager: Mock) -> None:
        """Test lint command with invalid config file."""
        mock_config_manager.return_value.load_config.side_effect = ValueError(
            "Invalid config"
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "invalid.yaml"
            config_file.write_text("invalid: yaml: content")

            result = self.runner.invoke(
                app, ["lint", tmpdir, "--config", str(config_file)]
            )

        assert result.exit_code == 1
        assert "Configuration error" in result.stdout

    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_lint_purge_cache(self, mock_cache_class: Mock) -> None:
        """Test lint command with --purge-cache flag."""
        mock_cache = Mock()
        mock_cache.purge.return_value = 5  # Return a number of purged entries
        mock_cache_class.return_value = mock_cache

        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.invoke(app, ["lint", tmpdir, "--purge-cache"])

        assert result.exit_code == 0
        mock_cache.purge.assert_called_once()
        assert "Purged" in result.stdout and "cache entries" in result.stdout

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    def test_lint_scanner_error(
        self, mock_scanner: Mock, mock_config_manager: Mock
    ) -> None:
        """Test lint command with scanner error."""
        mock_config_manager.return_value.load_config.return_value = Mock()
        mock_scanner.return_value.scan_directory.side_effect = OSError(
            "Permission denied"
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.invoke(app, ["lint", tmpdir])

        assert result.exit_code == 1
        assert "Error scanning workflows" in result.stdout

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    def test_lint_with_github_token_env(
        self,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test lint command with GitHub token from environment."""
        mock_config_manager.return_value.load_config.return_value = Mock()
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

        with (
            tempfile.TemporaryDirectory() as tmpdir,
            patch.dict(os.environ, {"GITHUB_TOKEN": "test-token"}),
        ):
            result = self.runner.invoke(app, ["lint", tmpdir])

        assert result.exit_code == 0

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    def test_lint_with_github_token_flag(
        self,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test lint command with GitHub token from CLI flag."""
        mock_config_manager.return_value.load_config.return_value = Mock()
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

        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.invoke(
                app, ["lint", tmpdir, "--github-token", "test-token"]
            )

        assert result.exit_code == 0

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    def test_lint_json_output_format(
        self,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test lint command with JSON output format."""
        mock_config_manager.return_value.load_config.return_value = Mock()
        mock_scanner.return_value.scan_directory.return_value = {
            Path("workflow.yml"): {1: Mock()}
        }
        mock_scanner.return_value.get_scan_summary.return_value = {
            "total_files": 1,
            "total_calls": 1,
            "action_calls": 1,
            "workflow_calls": 0,
            "sha_references": 0,
            "tag_references": 1,
            "branch_references": 0,
        }
        mock_validator.return_value.validate_action_calls.return_value = []
        mock_validator.return_value.get_validation_summary.return_value = {
            "total_calls": 1,
            "unique_calls_validated": 1,
            "duplicate_calls_avoided": 0,
            "api_calls_total": 1,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.invoke(
                app, ["lint", tmpdir, "--format", "json"]
            )

        assert result.exit_code == 0
        # Should contain JSON output
        assert (
            '{"scan_summary":' in result.stdout
            or '"validation_summary":' in result.stdout
        )

    def test_lint_invalid_output_format(self) -> None:
        """Test lint command with invalid output format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.invoke(
                app, ["lint", tmpdir, "--format", "invalid"]
            )

        # Should fail with validation error
        assert result.exit_code == 1
        assert "Output format must be one of: text, json" in result.stdout

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    def test_lint_with_workers_option(
        self,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test lint command with workers option."""
        mock_config = Mock()
        mock_config.parallel_workers = 4
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

        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.invoke(app, ["lint", tmpdir, "--workers", "8"])

        assert result.exit_code == 0
        # Config should be updated with worker count
        assert mock_config.parallel_workers == 8

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    def test_lint_with_exclude_patterns(
        self,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test lint command with exclude patterns."""
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

        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.invoke(
                app,
                ["lint", tmpdir, "--exclude", "test*", "--exclude", "*.tmp"],
            )

        assert result.exit_code == 0
        # Config should be updated with exclude patterns
        assert "test*" in mock_config.exclude_patterns
        assert "*.tmp" in mock_config.exclude_patterns

    def test_lint_nonexistent_path(self) -> None:
        """Test lint command with nonexistent path."""
        result = self.runner.invoke(app, ["lint", "/nonexistent/path"])

        assert result.exit_code == 2  # Typer validation error
        # Just check that it exits with error code, don't rely on specific message
        # since Typer's error handling may vary between environments
        assert result.exit_code != 0

    def test_lint_file_instead_of_directory(self) -> None:
        """Test lint command with file path instead of directory."""
        with tempfile.NamedTemporaryFile() as f:
            result = self.runner.invoke(app, ["lint", f.name])

        assert result.exit_code == 2  # Typer validation error

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    def test_lint_no_parallel(
        self,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test lint command with parallel processing disabled."""
        mock_config = Mock()
        mock_config.parallel_workers = 4
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

        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.invoke(app, ["lint", tmpdir, "--no-parallel"])

        assert result.exit_code == 0
        # Should set workers to 1 when parallel is disabled
        assert mock_config.parallel_workers == 1

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    def test_lint_cache_ttl_option(
        self,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test lint command with cache TTL option."""
        mock_config_manager.return_value.load_config.return_value = Mock()
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

        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.invoke(
                app, ["lint", tmpdir, "--cache-ttl", "3600"]
            )

        assert result.exit_code == 0

    def test_lint_invalid_cache_ttl(self) -> None:
        """Test lint command with invalid cache TTL."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.invoke(
                app, ["lint", tmpdir, "--cache-ttl", "30"]
            )

        assert result.exit_code == 2  # Typer validation error
        # Just check that it exits with error code, don't rely on specific message
        # since Typer's error handling may vary between environments
        assert result.exit_code != 0

    def test_lint_invalid_workers_count(self) -> None:
        """Test lint command with invalid workers count."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Test minimum
            result = self.runner.invoke(app, ["lint", tmpdir, "--workers", "0"])
            assert result.exit_code == 2

            # Test maximum
            result = self.runner.invoke(
                app, ["lint", tmpdir, "--workers", "100"]
            )
            assert result.exit_code == 2

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    def test_lint_no_require_pinned_sha(
        self,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test lint command with --no-require-pinned-sha flag."""
        mock_config_manager.return_value.load_config.return_value = Mock()
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

        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.invoke(
                app, ["lint", tmpdir, "--no-require-pinned-sha"]
            )

        assert result.exit_code == 0

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    def test_lint_no_fail_on_error(
        self,
        mock_validator: Mock,
        mock_scanner: Mock,
        mock_config_manager: Mock,
    ) -> None:
        """Test lint command with --no-fail-on-error flag."""
        # Setup mocks to return validation errors
        mock_config_manager.return_value.load_config.return_value = Mock()
        mock_scanner.return_value.scan_directory.return_value = {
            Path("workflow.yml"): {1: Mock()}
        }
        mock_scanner.return_value.get_scan_summary.return_value = {
            "total_files": 1,
            "total_calls": 1,
            "action_calls": 1,
            "workflow_calls": 0,
            "sha_references": 0,
            "tag_references": 1,
            "branch_references": 0,
        }
        # Create a proper ValidationError object
        mock_action_call = ActionCall(
            organization="test",
            repository="test-action",
            reference="v1",
            raw_line="uses: test/test-action@v1",
            line_number=1,
            comment=None,
            call_type=ActionCallType.ACTION,
            reference_type=ReferenceType.TAG,
        )
        validation_error = ValidationError(
            file_path=Path("workflow.yml"),
            action_call=mock_action_call,
            result=ValidationResult.INVALID_REPOSITORY,
            error_message="Test error",
        )
        mock_validator.return_value.validate_action_calls.return_value = [
            validation_error
        ]
        mock_validator.return_value.get_validation_summary.return_value = {
            "total_errors": 1,
            "total_calls": 1,
            "unique_calls_validated": 1,
            "duplicate_calls_avoided": 0,
            "invalid_repositories": 1,
            "invalid_references": 0,
            "syntax_errors": 0,
            "network_errors": 0,
            "timeouts": 0,
            "not_pinned_to_sha": 0,
            "api_calls_total": 1,
            "api_calls_graphql": 1,
            "api_calls_rest": 0,
            "api_calls_git": 0,
            "cache_hits": 0,
            "rate_limit_delays": 0,
            "failed_api_calls": 0,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.runner.invoke(
                app, ["lint", tmpdir, "--no-fail-on-error"]
            )

        # Should not exit with error code even when validation fails
        assert result.exit_code == 0

    def test_main_callback_with_subcommand(self) -> None:
        """Test main callback when subcommand is invoked."""

        ctx = Mock(spec=typer.Context)
        ctx.invoked_subcommand = "lint"

        # Should not raise or do anything special
        main_callback(ctx)

    def test_main_callback_without_subcommand(self) -> None:
        """Test main callback when no subcommand is invoked."""

        ctx = Mock(spec=typer.Context)
        ctx.invoked_subcommand = None

        # Should not raise
        main_callback(ctx)
