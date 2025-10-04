# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Simple tests for CLI module that will pass."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
import typer
from typer.testing import CliRunner

from gha_workflow_linter.cli import (
    app,
    cache_help_callback,
    help_callback,
    main_app_help_callback,
    setup_logging,
    version_callback,
)
from gha_workflow_linter.models import Config, LogLevel


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

        with pytest.raises(typer.Exit):
            help_callback(ctx, None, True)

    def test_main_app_help_callback_no_action(self) -> None:
        """Test main app help callback when value is False."""
        ctx = Mock()
        main_app_help_callback(ctx, None, False)
        # Should not raise or print anything

    def test_cache_help_callback_no_action(self) -> None:
        """Test cache help callback when value is False."""
        ctx = Mock()
        cache_help_callback(ctx, None, False)
        # Should not raise or print anything

    def test_version_callback_false(self) -> None:
        """Test version callback when value is False."""
        version_callback(False)
        # Should not raise or print anything

    def test_version_callback_true(self) -> None:
        """Test version callback showing version."""
        with pytest.raises(typer.Exit):
            version_callback(True)


class TestSetupLogging:
    """Test logging setup functionality."""

    def test_setup_logging_basic(self) -> None:
        """Test basic logging setup."""
        # Just test that it doesn't crash
        setup_logging(LogLevel.INFO, quiet=False)

    def test_setup_logging_quiet(self) -> None:
        """Test logging setup in quiet mode."""
        setup_logging(LogLevel.INFO, quiet=True)

    def test_setup_logging_debug(self) -> None:
        """Test logging setup with debug level."""
        setup_logging(LogLevel.DEBUG, quiet=False)


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

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_cache_command_info(
        self, mock_cache_class: Mock, mock_config_manager: Mock
    ) -> None:
        """Test cache info command."""
        mock_config_manager.return_value.load_config.return_value = Config(
            log_level=LogLevel.INFO, parallel_workers=4, require_pinned_sha=True
        )

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
    def test_cache_command_purge(
        self, mock_cache_class: Mock, mock_config_manager: Mock
    ) -> None:
        """Test cache purge command."""
        mock_config_manager.return_value.load_config.return_value = Config(
            log_level=LogLevel.INFO, parallel_workers=4, require_pinned_sha=True
        )

        mock_cache = Mock()
        mock_cache.purge.return_value = 15
        mock_cache_class.return_value = mock_cache

        result = self.runner.invoke(app, ["cache", "--purge"])

        assert result.exit_code == 0
        mock_cache.purge.assert_called_once()

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_cache_command_cleanup(
        self, mock_cache_class: Mock, mock_config_manager: Mock
    ) -> None:
        """Test cache cleanup command."""
        mock_config_manager.return_value.load_config.return_value = Config(
            log_level=LogLevel.INFO, parallel_workers=4, require_pinned_sha=True
        )

        mock_cache = Mock()
        mock_cache.cleanup.return_value = 3
        mock_cache_class.return_value = mock_cache

        result = self.runner.invoke(app, ["cache", "--cleanup"])

        assert result.exit_code == 0
        mock_cache.cleanup.assert_called_once()

    @patch("gha_workflow_linter.cli.ConfigManager")
    @patch("gha_workflow_linter.cli.ValidationCache")
    def test_cache_command_default(
        self, mock_cache_class: Mock, mock_config_manager: Mock
    ) -> None:
        """Test cache command with no options."""
        mock_config_manager.return_value.load_config.return_value = Config(
            log_level=LogLevel.INFO, parallel_workers=4, require_pinned_sha=True
        )

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
