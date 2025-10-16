# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Comprehensive tests for CLI module with proper mocking."""

from __future__ import annotations

import json
import logging
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch

import pytest
import typer
from typer.testing import CliRunner

from gha_workflow_linter import __version__
from gha_workflow_linter.cli import (
    _create_api_stats_table,
    _create_scan_summary_table,
    _display_validation_summary,
    app,
    cache_help_callback,
    help_callback,
    main_app_help_callback,
    main_callback,
    output_json_results,
    output_text_results,
    run_linter,
    setup_logging,
    version_callback,
)
from gha_workflow_linter.exceptions import (
    AuthenticationError,
    NetworkError,
    RateLimitError,
    ValidationAbortedError,
)
from gha_workflow_linter.models import (
    APICallStats,
    CLIOptions,
    Config,
    LogLevel,
    ValidationError,
)


class TestCLICallbacks:
    """Test CLI callback functions."""

    def test_help_callback_no_action(self) -> None:
        """Test help callback when value is False."""
        ctx = Mock()
        help_callback(ctx, None, False)
        # Should not raise or print anything

    def test_help_callback_resilient_parsing(self) -> None:
        """Test help callback during resilient parsing."""
        ctx = Mock()
        ctx.resilient_parsing = True
        help_callback(ctx, None, True)
        # Should not raise or print anything

    def test_help_callback_show_help(self) -> None:
        """Test help callback showing help."""
        ctx = Mock()
        ctx.resilient_parsing = False
        ctx.get_help.return_value = "Help text"

        with patch("gha_workflow_linter.cli.console") as mock_console:
            with pytest.raises(typer.Exit):
                help_callback(ctx, None, True)

            assert mock_console.print.call_count >= 2  # Version + help

    def test_main_app_help_callback_no_action(self) -> None:
        """Test main app help callback when value is False."""
        ctx = Mock()
        main_app_help_callback(ctx, None, False)
        # Should not raise or print anything

    def test_main_app_help_callback_show_help(self) -> None:
        """Test main app help callback showing help."""
        ctx = Mock()
        ctx.resilient_parsing = False
        ctx.get_help.return_value = "Main help text"

        with patch("gha_workflow_linter.cli.console") as mock_console:
            with pytest.raises(typer.Exit):
                main_app_help_callback(ctx, None, True)

            mock_console.print.assert_called()

    def test_cache_help_callback_no_action(self) -> None:
        """Test cache help callback when value is False."""
        ctx = Mock()
        cache_help_callback(ctx, None, False)
        # Should not raise or print anything

    def test_cache_help_callback_show_help(self) -> None:
        """Test cache help callback showing help."""
        ctx = Mock()
        ctx.resilient_parsing = False
        ctx.get_help.return_value = "Cache help text"

        with patch("gha_workflow_linter.cli.console") as mock_console:
            with pytest.raises(typer.Exit):
                cache_help_callback(ctx, None, True)

            mock_console.print.assert_called()

    def test_version_callback_false(self) -> None:
        """Test version callback when value is False."""
        version_callback(False)
        # Should not raise or print anything

    def test_version_callback_true(self) -> None:
        """Test version callback showing version."""
        with patch("gha_workflow_linter.cli.console") as mock_console:
            with pytest.raises(typer.Exit):
                version_callback(True)

            mock_console.print.assert_called_once()
            call_args = mock_console.print.call_args[0][0]
            assert __version__ in call_args

    def test_main_callback_with_subcommand(self) -> None:
        """Test main callback when subcommand is invoked."""
        ctx = Mock()
        ctx.invoked_subcommand = "lint"

        # Should not raise or do anything
        main_callback(ctx)

    def test_main_callback_no_subcommand(self) -> None:
        """Test main callback when no subcommand is invoked."""
        ctx = Mock()
        ctx.invoked_subcommand = None

        # Should not raise or do anything
        main_callback(ctx)


class TestSetupLogging:
    """Test logging setup functionality."""

    def test_setup_logging_info_level(self) -> None:
        """Test setting up logging with INFO level."""
        with patch("logging.getLogger") as mock_get_logger:
            mock_root_logger = Mock()
            mock_root_logger.handlers = []

            def mock_logger_factory(name=None):
                if name is None or name == "":
                    return mock_root_logger
                return Mock()

            mock_get_logger.side_effect = mock_logger_factory

            setup_logging(LogLevel.INFO, quiet=False)

            # Check root logger was configured
            mock_get_logger.assert_any_call()
            mock_root_logger.setLevel.assert_called_with(logging.INFO)

    def test_setup_logging_debug_level(self) -> None:
        """Test setting up logging with DEBUG level."""
        with patch("logging.getLogger") as mock_get_logger:
            mock_root_logger = Mock()
            mock_root_logger.handlers = []

            def mock_logger_factory(name=None):
                if name is None or name == "":
                    return mock_root_logger
                return Mock()

            mock_get_logger.side_effect = mock_logger_factory

            setup_logging(LogLevel.DEBUG, quiet=False)

            # Check root logger was configured
            mock_get_logger.assert_any_call()
            mock_root_logger.setLevel.assert_called_with(logging.DEBUG)

    def test_setup_logging_quiet_mode(self) -> None:
        """Test setting up logging in quiet mode."""
        with patch("logging.getLogger") as mock_get_logger:
            mock_root_logger = Mock()
            mock_root_logger.handlers = []

            def mock_logger_factory(name=None):
                if name is None or name == "":
                    return mock_root_logger
                return Mock()

            mock_get_logger.side_effect = mock_logger_factory

            setup_logging(LogLevel.INFO, quiet=True)

            # Check root logger was configured with ERROR level
            mock_get_logger.assert_any_call()
            mock_root_logger.setLevel.assert_called_with(logging.ERROR)

    def test_setup_logging_httpx_suppression(self) -> None:
        """Test that httpx loggers are set to WARNING level."""
        with patch("logging.getLogger") as mock_get_logger:
            mock_root_logger = Mock()
            mock_root_logger.handlers = []
            mock_httpx_logger = Mock()

            def get_logger_side_effect(name=None):
                if name is None or name == "":  # Root logger
                    return mock_root_logger
                return mock_httpx_logger

            mock_get_logger.side_effect = get_logger_side_effect

            setup_logging(LogLevel.INFO, quiet=False)

            # Check that httpx-related loggers were configured
            expected_calls = [
                "httpx",
                "httpcore",
                "httpcore.connection",
                "httpcore.http11",
            ]

            for expected_logger in expected_calls:
                mock_get_logger.assert_any_call(expected_logger)

            # Verify setLevel was called on the httpx loggers
            assert mock_httpx_logger.setLevel.call_count >= len(expected_calls)


class TestOutputFunctions:
    """Test output formatting functions."""

    def test_create_scan_summary_table(self) -> None:
        """Test creating scan summary table."""
        scan_summary = {
            "total_files": 5,
            "total_calls": 10,
            "action_calls": 8,
            "workflow_calls": 2,
            "sha_references": 3,
            "tag_references": 5,
            "branch_references": 2,
        }
        validation_summary = {
            "total_calls": 10,
            "unique_calls_validated": 8,
            "duplicate_calls_avoided": 2,
            "total_errors": 2,
        }

        table = _create_scan_summary_table(scan_summary, validation_summary)

        assert table.title == "Scan Summary"
        assert len(table.columns) == 2

    def test_create_api_stats_table(self) -> None:
        """Test creating API stats table."""
        validation_summary = {
            "api_calls_total": 10,
            "api_calls_graphql": 5,
            "api_calls_rest": 2,
            "api_calls_git": 3,
            "cache_hits": 8,
            "rate_limit_delays": 1,
            "failed_api_calls": 0,
        }

        table = _create_api_stats_table(validation_summary)

        assert table.title == "API Call Statistics"
        assert len(table.columns) == 2

    def test_display_validation_summary_no_errors(self) -> None:
        """Test displaying validation summary with no errors."""
        validation_summary = {
            "total_errors": 0,
            "invalid_repositories": 0,
            "invalid_references": 0,
            "network_errors": 0,
            "timeouts": 0,
            "not_pinned_to_sha": 0,
        }

        with patch("gha_workflow_linter.cli.console") as mock_console:
            _display_validation_summary(validation_summary)

            mock_console.print.assert_called()
            # Should show success message
            success_call = [
                call
                for call in mock_console.print.call_args_list
                if "✅" in str(call)
            ]
            assert success_call

    def test_display_validation_summary_with_errors(self) -> None:
        """Test displaying validation summary with errors."""

        validation_summary = {
            "total_errors": 2,
            "invalid_repositories": 1,
            "invalid_references": 1,
            "network_errors": 0,
            "timeouts": 0,
            "not_pinned_to_sha": 0,
        }

        with patch("gha_workflow_linter.cli.console") as mock_console:
            _display_validation_summary(validation_summary)

            mock_console.print.assert_called()

    def test_display_validation_summary_quiet(self) -> None:
        """Test validation summary display in quiet mode."""
        validation_summary = {
            "total_errors": 0,
            "invalid_repositories": 0,
            "invalid_references": 0,
            "network_errors": 0,
            "timeouts": 0,
            "not_pinned_to_sha": 0,
        }

        with patch("gha_workflow_linter.cli.console") as mock_console:
            _display_validation_summary(validation_summary)

            # Should print success message even in quiet mode
            mock_console.print.assert_called()

    def test_output_text_results(self) -> None:
        """Test text output formatting."""
        from gha_workflow_linter.models import (
            ActionCall,
            ActionCallType,
            ReferenceType,
            ValidationResult,
        )

        scan_summary = {
            "total_files": 2,
            "total_calls": 4,
            "action_calls": 3,
            "workflow_calls": 1,
            "sha_references": 1,
            "tag_references": 2,
            "branch_references": 1,
            "unique_calls_validated": 3,
            "duplicate_calls_avoided": 1,
            "validation_efficiency": 25.0,
        }
        validation_summary = {
            "total_calls": 4,
            "unique_calls_validated": 3,
            "duplicate_calls_avoided": 1,
            "total_errors": 1,
            "invalid_repositories": 1,
            "invalid_references": 0,
            "network_errors": 0,
            "timeouts": 0,
            "not_pinned_to_sha": 0,
            "api_calls_total": 3,
            "api_calls_graphql": 2,
            "api_calls_rest": 0,
            "api_calls_git": 1,
            "cache_hits": 1,
            "rate_limit_delays": 0,
            "failed_api_calls": 0,
        }

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

        validation_errors = [
            ValidationError(
                file_path=Path("test.yml"),
                action_call=mock_action_call,
                result=ValidationResult.INVALID_REPOSITORY,
                error_message="Test error",
            )
        ]

        with patch("gha_workflow_linter.cli.console") as mock_console:
            output_text_results(
                scan_summary,
                validation_summary,
                validation_errors,
                Path("test"),
                quiet=False,
            )

            mock_console.print.assert_called()

    def test_output_json_results(self) -> None:
        """Test JSON output formatting."""
        from gha_workflow_linter.models import (
            ActionCall,
            ActionCallType,
            ReferenceType,
            ValidationResult,
        )

        scan_summary = {
            "total_files": 2,
            "total_calls": 4,
            "action_calls": 3,
            "workflow_calls": 1,
            "sha_references": 1,
            "tag_references": 2,
            "branch_references": 1,
            "unique_calls_validated": 3,
            "duplicate_calls_avoided": 1,
            "validation_efficiency": 25.0,
        }
        validation_summary = {
            "total_calls": 4,
            "unique_calls_validated": 3,
            "duplicate_calls_avoided": 1,
            "total_errors": 1,
            "invalid_repositories": 1,
            "invalid_references": 0,
            "network_errors": 0,
            "timeouts": 0,
            "not_pinned_to_sha": 0,
            "api_calls_total": 3,
            "api_calls_graphql": 2,
            "cache_hits": 1,
        }

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

        validation_errors = [
            ValidationError(
                file_path=Path("test.yml"),
                action_call=mock_action_call,
                result=ValidationResult.INVALID_REPOSITORY,
                error_message="Test error",
            )
        ]

        with patch("gha_workflow_linter.cli.console") as mock_console:
            output_json_results(
                scan_summary,
                validation_summary,
                validation_errors,
                Path("test"),
            )

            mock_console.print.assert_called_once()
            printed_text = mock_console.print.call_args[0][0]

            # Should be valid JSON
            parsed = json.loads(printed_text)
            assert "scan_summary" in parsed
            assert "validation_summary" in parsed
            assert "errors" in parsed


class TestRunLinter:
    """Test the main linter execution function."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.config = Config()
        self.options = CLIOptions(
            path=Path("/tmp"),
            verbose=False,
            quiet=False,
            output_format="text",
            fail_on_error=True,
        )

    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.Progress")
    def test_run_linter_success(
        self,
        mock_progress: Mock,
        mock_validator_class: Mock,
        mock_scanner_class: Mock,
    ) -> None:
        """Test successful linter execution."""
        # Mock scanner
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan_directory.return_value = {
            Path("test.yml"): {1: Mock()}
        }
        mock_scanner.get_scan_summary.return_value = {
            "total_files": 1,
            "total_calls": 1,
        }

        # Mock validator
        mock_validator = Mock()
        mock_validator_class.return_value = mock_validator
        mock_validator.validate_action_calls.return_value = []
        mock_validator.get_validation_summary.return_value = {
            "total_calls": 1,
            "unique_calls_validated": 1,
            "duplicate_calls_avoided": 0,
            "total_errors": 0,
            "invalid_repositories": 0,
            "invalid_references": 0,
            "network_errors": 0,
            "timeouts": 0,
            "not_pinned_to_sha": 0,
            "api_calls_total": 0,
            "api_calls_graphql": 0,
            "cache_hits": 0,
        }

        # Mock progress
        mock_progress_instance = Mock()
        mock_progress.__enter__.return_value = mock_progress_instance
        mock_progress_instance.add_task.return_value = "task_id"

        with patch("gha_workflow_linter.cli.output_text_results"):
            result = run_linter(self.config, self.options)

        assert result == 0

    @patch("gha_workflow_linter.cli.WorkflowScanner")
    def test_run_linter_scanner_error(self, mock_scanner_class) -> None:
        """Test linter when scanner throws error."""
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan_directory.side_effect = Exception("Scanner error")

        with patch("gha_workflow_linter.cli.Progress"):
            result = run_linter(self.config, self.options)

        assert result == 1

    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.Progress")
    def test_run_linter_no_workflows(
        self, mock_progress, mock_scanner_class
    ) -> None:
        """Test linter when no workflows are found."""
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan_directory.return_value = {}

        mock_progress_instance = Mock()
        mock_progress.__enter__.return_value = mock_progress_instance
        mock_progress_instance.add_task.return_value = "task_id"

        with patch("gha_workflow_linter.cli.console"):
            result = run_linter(self.config, self.options)

        assert result == 0

    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.Progress")
    def test_run_linter_validation_aborted_network_error(
        self, mock_progress, mock_validator_class, mock_scanner_class
    ) -> None:
        """Test linter when validation is aborted due to network error."""
        # Mock scanner
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan_directory.return_value = {
            Path("test.yml"): {1: Mock()}
        }

        # Mock validator that raises ValidationAbortedError
        mock_validator = Mock()
        mock_validator_class.return_value = mock_validator
        network_error = NetworkError("Connection failed")
        validation_error = ValidationAbortedError(
            message="Network error",
            reason="Connection failed",
            original_error=network_error,
        )
        mock_validator.validate_action_calls.side_effect = validation_error

        # Mock progress
        mock_progress_instance = Mock()
        mock_progress.__enter__.return_value = mock_progress_instance
        mock_progress_instance.add_task.return_value = "task_id"

        with patch("gha_workflow_linter.cli.console"):
            result = run_linter(self.config, self.options)

        assert result == 1

    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.Progress")
    def test_run_linter_validation_aborted_network(
        self,
        mock_progress: Mock,
        mock_validator_class: Mock,
        mock_scanner_class: Mock,
    ) -> None:
        """Test linter when validation is aborted due to auth error."""
        # Mock scanner
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan_directory.return_value = {
            Path("test.yml"): {1: Mock()}
        }

        # Mock validator that raises ValidationAbortedError with AuthenticationError
        mock_validator = Mock()
        mock_validator_class.return_value = mock_validator
        auth_error = AuthenticationError("Invalid token")
        validation_error = ValidationAbortedError(
            message="Auth failed",
            reason="Invalid token",
            original_error=auth_error,
        )
        mock_validator.validate_action_calls.side_effect = validation_error

        # Mock progress
        mock_progress_instance = Mock()
        mock_progress.__enter__.return_value = mock_progress_instance
        mock_progress_instance.add_task.return_value = "task_id"

        with patch("gha_workflow_linter.cli.console"):
            result = run_linter(self.config, self.options)

        assert result == 1

    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.Progress")
    def test_run_linter_validation_aborted_auth(
        self,
        mock_progress: Mock,
        mock_validator_class: Mock,
        mock_scanner_class: Mock,
    ) -> None:
        """Test linter when validation is aborted due to rate limit."""
        # Mock scanner
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan_directory.return_value = {
            Path("test.yml"): {1: Mock()}
        }

        # Mock validator that raises ValidationAbortedError with RateLimitError
        mock_validator = Mock()
        mock_validator_class.return_value = mock_validator
        rate_limit_error = RateLimitError("Rate limit exceeded")
        validation_error = ValidationAbortedError(
            message="Rate limited",
            reason="Rate limit exceeded",
            original_error=rate_limit_error,
        )
        mock_validator.validate_action_calls.side_effect = validation_error

        # Mock progress
        mock_progress_instance = Mock()
        mock_progress.__enter__.return_value = mock_progress_instance
        mock_progress_instance.add_task.return_value = "task_id"

        with patch("gha_workflow_linter.cli.console"):
            result = run_linter(self.config, self.options)

        assert result == 1

    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.Progress")
    def test_run_linter_with_validation_errors(
        self,
        mock_progress: Mock,
        mock_validator_class: Mock,
        mock_scanner_class: Mock,
    ) -> None:
        """Test linter with validation errors and fail_on_error=True."""
        from gha_workflow_linter.models import (
            ActionCall,
            ActionCallType,
            ReferenceType,
            ValidationResult,
        )

        # Mock scanner
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan_directory.return_value = {
            Path("test.yml"): {1: Mock()}
        }
        mock_scanner.get_scan_summary.return_value = {
            "total_files": 1,
            "total_calls": 1,
            "action_calls": 1,
            "workflow_calls": 0,
            "sha_references": 0,
            "tag_references": 1,
            "branch_references": 0,
        }

        # Mock validator with errors
        mock_validator = Mock()
        mock_validator_class.return_value = mock_validator

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

        validation_errors = [
            ValidationError(
                file_path=Path("test.yml"),
                action_call=mock_action_call,
                result=ValidationResult.INVALID_REPOSITORY,
                error_message="Repository not found",
            )
        ]

        mock_validator.validate_action_calls.return_value = validation_errors
        mock_validator.get_validation_summary.return_value = {
            "total_calls": 1,
            "unique_calls_validated": 1,
            "duplicate_calls_avoided": 0,
            "total_errors": 1,
            "invalid_repositories": 1,
            "invalid_references": 0,
            "network_errors": 0,
            "timeouts": 0,
            "not_pinned_to_sha": 0,
            "api_calls_total": 1,
            "api_calls_graphql": 1,
            "cache_hits": 0,
        }

        # Mock progress
        mock_progress_instance = Mock()
        mock_progress.__enter__.return_value = mock_progress_instance
        mock_progress_instance.add_task.return_value = "task_id"

        with patch("gha_workflow_linter.cli.output_text_results"):
            result = run_linter(self.config, self.options)

        assert result == 1

    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.Progress")
    def test_run_linter_validation_error(
        self,
        mock_progress: Mock,
        mock_validator_class: Mock,
        mock_scanner_class: Mock,
    ) -> None:
        """Test linter with ValidationAbortedError."""
        from gha_workflow_linter.exceptions import (
            NetworkError,
            ValidationAbortedError,
        )

        # Mock scanner
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan_directory.return_value = {
            Path("test.yml"): {1: Mock()}
        }

        # Mock validator to raise ValidationAbortedError
        mock_validator = Mock()
        mock_validator_class.return_value = mock_validator
        network_error = NetworkError("Network timeout")
        validation_aborted = ValidationAbortedError(
            message="Validation aborted due to network error",
            reason="Network connectivity issue",
            original_error=network_error,
        )
        mock_validator.validate_action_calls.side_effect = validation_aborted

        # Mock progress
        mock_progress_instance = Mock()
        mock_progress.__enter__.return_value = mock_progress_instance
        mock_progress_instance.add_task.return_value = "task_id"

        result = run_linter(self.config, self.options)

        # Should return 1 due to validation error
        assert result == 1

    @patch("gha_workflow_linter.cli.WorkflowScanner")
    @patch("gha_workflow_linter.cli.ActionCallValidator")
    @patch("gha_workflow_linter.cli.Progress")
    def test_run_linter_json_output(
        self,
        mock_progress: Mock,
        mock_validator_class: Mock,
        mock_scanner_class: Mock,
    ) -> None:
        """Test linter with JSON output format."""
        # Update options for JSON output
        options = CLIOptions(
            path=Path("/tmp"),
            verbose=False,
            quiet=False,
            output_format="json",
            fail_on_error=True,
        )

        # Mock scanner
        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan_directory.return_value = {
            Path("test.yml"): {1: Mock()}
        }
        mock_scanner.get_scan_summary.return_value = {
            "total_files": 1,
            "total_calls": 1,
        }

        # Mock validator
        mock_validator = Mock()
        mock_validator_class.return_value = mock_validator
        mock_validator.validate_action_calls.return_value = {}
        mock_validator.get_validation_summary.return_value = {
            "total_validated": 1,
            "errors": 0,
            "api_stats": APICallStats(),
        }

        # Mock progress
        mock_progress_instance = Mock()
        mock_progress.__enter__.return_value = mock_progress_instance
        mock_progress_instance.add_task.return_value = "task_id"

        with patch(
            "gha_workflow_linter.cli.output_json_results"
        ) as mock_json_output:
            result = run_linter(self.config, options)

            mock_json_output.assert_called_once()
            assert result == 0


class TestCLIIntegration:
    """Test CLI integration using CliRunner."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.runner = CliRunner()

    def test_app_help(self) -> None:
        """Test main app help command."""
        result = self.runner.invoke(app, ["--help"])

        # May exit with code 2 (help) or 0, both are acceptable
        assert result.exit_code in [0, 2]
        assert "gha-workflow-linter" in result.stdout

    def test_version_command(self) -> None:
        """Test version display."""
        with patch("gha_workflow_linter.cli.console") as mock_console:
            result = self.runner.invoke(app, ["--version"])

            # Should exit cleanly after showing version
            assert result.exit_code == 0
            mock_console.print.assert_called()

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.run_linter")
    def test_lint_command_basic(
        self, mock_run_linter: Mock, mock_config_manager: Mock
    ) -> None:
        """Test basic lint command execution."""
        # Mock config manager
        mock_config_manager.return_value.load_config.return_value = Config()

        # Mock run_linter to return success
        mock_run_linter.return_value = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.runner.invoke(app, ["lint", temp_dir])

            assert result.exit_code == 0
            mock_run_linter.assert_called_once()

    @patch("gha_workflow_linter.cli.ConfigManager")
    def test_lint_command_verbose_quiet_conflict(
        self, mock_config_manager
    ) -> None:
        """Test lint command with conflicting verbose and quiet flags."""
        mock_config_manager.return_value.load_config.return_value = Config()

        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.runner.invoke(
                app, ["lint", temp_dir, "--verbose", "--quiet"]
            )

            assert result.exit_code == 1
            assert "cannot be used together" in result.stdout

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_lint_command_purge_cache(
        self, mock_cache_class, mock_config_manager
    ) -> None:
        """Test lint command with purge cache option."""
        mock_config_manager.return_value.load_config.return_value = Config()

        mock_cache = Mock()
        mock_cache.purge.return_value = 5
        mock_cache_class.return_value = mock_cache

        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.runner.invoke(
                app, ["lint", temp_dir, "--purge-cache"]
            )

            assert result.exit_code == 0
            mock_cache.purge.assert_called_once()

    def test_lint_command_nonexistent_path(self) -> None:
        """Test lint command with nonexistent path."""
        result = self.runner.invoke(app, ["lint", "/nonexistent/path"])

        # Should fail due to path not existing
        assert result.exit_code == 2

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_cache_command_info(
        self, mock_cache_class, mock_config_manager
    ) -> None:
        """Test cache info command."""
        mock_config_manager.return_value.load_config.return_value = Config()

        mock_cache = Mock()
        mock_cache.get_cache_info.return_value = {
            "enabled": True,
            "cache_file": "/tmp/cache.db",
            "entries": 10,
            "max_cache_size": 1000,
            "ttl_seconds": 604800,
            "stats": {
                "hits": 5,
                "misses": 3,
                "writes": 8,
                "purges": 1,
                "cleanup_removed": 2,
            },
        }
        mock_cache.stats.hit_rate = 62.5
        mock_cache_class.return_value = mock_cache

        result = self.runner.invoke(app, ["cache", "--info"])

        assert result.exit_code == 0
        mock_cache.get_cache_info.assert_called_once()

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_cache_command_cleanup(
        self, mock_cache_class, mock_config_manager
    ) -> None:
        """Test cache cleanup command."""
        mock_config_manager.return_value.load_config.return_value = Config()

        mock_cache = Mock()
        mock_cache.cleanup.return_value = 3
        mock_cache_class.return_value = mock_cache

        result = self.runner.invoke(app, ["cache", "--cleanup"])

        assert result.exit_code == 0
        mock_cache.cleanup.assert_called_once()

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_cache_command_purge(
        self, mock_cache_class, mock_config_manager
    ) -> None:
        """Test cache purge command."""
        mock_config_manager.return_value.load_config.return_value = Config()

        mock_cache = Mock()
        mock_cache.purge.return_value = 15
        mock_cache_class.return_value = mock_cache

        result = self.runner.invoke(app, ["cache", "--purge"])

        assert result.exit_code == 0
        mock_cache.purge.assert_called_once()

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_cache_command_default(
        self, mock_cache_class, mock_config_manager
    ) -> None:
        """Test cache command with no specific options (default behavior)."""
        mock_config_manager.return_value.load_config.return_value = Config()

        mock_cache = Mock()
        mock_cache.get_cache_info.return_value = {
            "enabled": True,
            "cache_file": "/tmp/cache.db",
            "entries": 5,
        }
        mock_cache_class.return_value = mock_cache

        result = self.runner.invoke(app, ["cache"])

        assert result.exit_code == 0
        mock_cache.get_cache_info.assert_called_once()

    @patch("gha_workflow_linter.cli.ConfigManager")
    def test_lint_command_config_file_error(self, mock_config_manager) -> None:
        """Test lint command with config file that causes an error."""
        mock_config_manager.return_value.load_config.side_effect = Exception(
            "Invalid config"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.runner.invoke(app, ["lint", temp_dir])

            assert result.exit_code == 1
            assert "Fatal error" in result.stdout

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.run_linter")
    def test_lint_command_github_token(
        self, mock_run_linter: Mock, mock_config_manager: Mock
    ) -> None:
        """Test lint command with GitHub token."""
        mock_config = Config()
        mock_config_manager.return_value.load_config.return_value = mock_config
        mock_run_linter.return_value = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.runner.invoke(
                app, ["lint", temp_dir, "--github-token", "ghp_test123"]
            )

            assert result.exit_code == 0
            # Verify token was set in config
            assert mock_config.github_api.token == "ghp_test123"

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.run_linter")
    def test_lint_command_with_config(
        self, mock_run_linter: Mock, mock_config_manager: Mock
    ) -> None:
        """Test lint command with custom worker count."""
        mock_config = Config()
        mock_config_manager.return_value.load_config.return_value = mock_config
        mock_run_linter.return_value = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.runner.invoke(
                app, ["lint", temp_dir, "--workers", "8"]
            )

            assert result.exit_code == 0
            assert mock_config.parallel_workers == 8

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.run_linter")
    def test_lint_command_exclude_patterns(
        self, mock_run_linter: Mock, mock_config_manager: Mock
    ) -> None:
        """Test lint command with exclude patterns."""
        mock_config = Config()
        mock_config_manager.return_value.load_config.return_value = mock_config
        mock_run_linter.return_value = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.runner.invoke(
                app,
                ["lint", temp_dir, "--exclude", "test*", "--exclude", "*.tmp"],
            )

            assert result.exit_code == 0
            assert mock_config.exclude_patterns == ["test*", "*.tmp"]

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.run_linter")
    def test_lint_command_no_cache(
        self, mock_run_linter: Mock, mock_config_manager: Mock
    ) -> None:
        """Test lint command with parallel processing disabled."""
        mock_config = Config()
        mock_config_manager.return_value.load_config.return_value = mock_config
        mock_run_linter.return_value = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.runner.invoke(
                app, ["lint", temp_dir, "--no-parallel"]
            )

            assert result.exit_code == 0
            assert mock_config.parallel_workers == 1

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.run_linter")
    def test_lint_command_cache_options(
        self, mock_run_linter: Mock, mock_config_manager: Mock
    ) -> None:
        """Test lint command with custom cache TTL."""
        mock_config = Config()
        mock_config_manager.return_value.load_config.return_value = mock_config
        mock_run_linter.return_value = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.runner.invoke(
                app, ["lint", temp_dir, "--cache-ttl", "3600"]
            )

            assert result.exit_code == 0
            assert mock_config.cache.default_ttl_seconds == 3600

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.run_linter")
    def test_lint_command_require_pinned_sha(
        self, mock_run_linter: Mock, mock_config_manager: Mock
    ) -> None:
        """Test lint command with SHA pinning requirement disabled."""
        mock_config = Config()
        mock_config_manager.return_value.load_config.return_value = mock_config
        mock_run_linter.return_value = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.runner.invoke(
                app, ["lint", temp_dir, "--no-require-pinned-sha"]
            )

            assert result.exit_code == 0
            assert mock_config.require_pinned_sha is False

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.run_linter")
    def test_lint_command_no_fail_on_error(
        self, mock_run_linter: Mock, mock_config_manager: Mock
    ) -> None:
        """Test lint command with fail on error disabled."""
        mock_config_manager.return_value.load_config.return_value = Config()
        mock_run_linter.return_value = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.runner.invoke(
                app, ["lint", temp_dir, "--no-fail-on-error"]
            )

            assert result.exit_code == 0
            # Check that the CLIOptions passed to run_linter has fail_on_error=False
            call_args = mock_run_linter.call_args[0]
            cli_options = call_args[1]  # Second argument is CLIOptions
            assert cli_options.fail_on_error is False

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.run_linter")
    def test_lint_command_json_format(
        self, mock_run_linter: Mock, mock_config_manager: Mock
    ) -> None:
        """Test lint command with JSON output format."""
        mock_config_manager.return_value.load_config.return_value = Config()
        mock_run_linter.return_value = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            result = self.runner.invoke(
                app, ["lint", temp_dir, "--format", "json"]
            )

            assert result.exit_code == 0
            # Check that the CLIOptions passed to run_linter has correct format
            call_args = mock_run_linter.call_args[0]
            cli_options = call_args[1]
            assert cli_options.output_format == "json"
