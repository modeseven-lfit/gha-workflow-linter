# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for GitHub authentication utilities."""

from __future__ import annotations

import os
import subprocess
from unittest.mock import Mock, patch

import pytest
from rich.console import Console

from gha_workflow_linter.github_auth import (
    check_github_cli_available,
    get_github_cli_suggestions,
    get_github_token_with_fallback,
)


class TestGetGitHubTokenWithFallback:
    """Test get_github_token_with_fallback function."""

    def test_explicit_token_priority(self) -> None:
        """Test that explicit token has highest priority."""
        token = get_github_token_with_fallback(explicit_token="explicit_token")
        assert token == "explicit_token"

    def test_environment_token_fallback(self) -> None:
        """Test fallback to environment variable."""
        with patch.dict(os.environ, {"GITHUB_TOKEN": "env_token"}):
            token = get_github_token_with_fallback()
            assert token == "env_token"

    def test_explicit_over_environment(self) -> None:
        """Test that explicit token overrides environment."""
        with patch.dict(os.environ, {"GITHUB_TOKEN": "env_token"}):
            token = get_github_token_with_fallback(
                explicit_token="explicit_token"
            )
            assert token == "explicit_token"

    @patch("gha_workflow_linter.github_auth._get_token_from_gh_cli")
    def test_cli_fallback_success(self, mock_gh_cli: Mock) -> None:
        """Test successful GitHub CLI fallback."""
        mock_gh_cli.return_value = "cli_token"
        console = Mock(spec=Console)

        with patch.dict(os.environ, {}, clear=True):
            token = get_github_token_with_fallback(console=console)

        assert token == "cli_token"
        mock_gh_cli.assert_called_once()
        console.print.assert_any_call(
            "⚠️  No GitHub token found; attempting to obtain using GitHub CLI"
        )
        console.print.assert_any_call(
            "✅ Successfully obtained GitHub token from GitHub CLI"
        )

    @patch("gha_workflow_linter.github_auth._get_token_from_gh_cli")
    def test_cli_fallback_failure(self, mock_gh_cli: Mock) -> None:
        """Test GitHub CLI fallback failure."""
        mock_gh_cli.side_effect = subprocess.SubprocessError("CLI failed")
        console = Mock(spec=Console)

        with patch.dict(os.environ, {}, clear=True):
            token = get_github_token_with_fallback(console=console)

        assert token is None
        mock_gh_cli.assert_called_once()
        console.print.assert_any_call(
            "⚠️  No GitHub token found; attempting to obtain using GitHub CLI"
        )
        console.print.assert_any_call(
            "❌ Unable to obtain GitHub token from any source"
        )

    @patch("gha_workflow_linter.github_auth._get_token_from_gh_cli")
    def test_quiet_mode_suppresses_messages(self, mock_gh_cli: Mock) -> None:
        """Test that quiet mode suppresses console messages."""
        mock_gh_cli.return_value = "cli_token"
        console = Mock(spec=Console)

        with patch.dict(os.environ, {}, clear=True):
            token = get_github_token_with_fallback(console=console, quiet=True)

        assert token == "cli_token"
        console.print.assert_not_called()

    def test_no_console_no_messages(self) -> None:
        """Test that no console instance means no messages."""
        with (
            patch.dict(os.environ, {}, clear=True),
            patch(
                "gha_workflow_linter.github_auth._get_token_from_gh_cli"
            ) as mock_gh_cli,
        ):
            mock_gh_cli.side_effect = subprocess.SubprocessError("CLI failed")
            token = get_github_token_with_fallback()

        assert token is None


class TestGetTokenFromGHCli:
    """Test _get_token_from_gh_cli function."""

    @patch("subprocess.run")
    def test_successful_token_retrieval(self, mock_run: Mock) -> None:
        """Test successful token retrieval from GitHub CLI."""
        # Mock successful auth status check
        mock_run.side_effect = [
            Mock(returncode=0, stderr=""),  # auth status success
            Mock(
                stdout="ghp_1234567890abcdefghijklmnopqrstuvwxyz1234", stderr=""
            ),  # token output
        ]

        from gha_workflow_linter.github_auth import _get_token_from_gh_cli

        token = _get_token_from_gh_cli()
        assert token == "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"
        assert mock_run.call_count == 2

    @patch("subprocess.run")
    def test_auth_status_failure(self, mock_run: Mock) -> None:
        """Test authentication status failure."""
        mock_run.return_value = Mock(
            returncode=1, stderr="not logged into any GitHub hosts"
        )

        from gha_workflow_linter.github_auth import _get_token_from_gh_cli

        with pytest.raises(
            subprocess.SubprocessError,
            match="Not authenticated with GitHub CLI",
        ):
            _get_token_from_gh_cli()

    @patch("subprocess.run")
    def test_gh_cli_not_installed(self, mock_run: Mock) -> None:
        """Test GitHub CLI not installed."""
        mock_run.side_effect = FileNotFoundError("gh not found")

        from gha_workflow_linter.github_auth import _get_token_from_gh_cli

        with pytest.raises(
            subprocess.SubprocessError, match="GitHub CLI not installed"
        ):
            _get_token_from_gh_cli()

    @patch("subprocess.run")
    def test_token_command_timeout(self, mock_run: Mock) -> None:
        """Test timeout during token retrieval."""
        mock_run.side_effect = [
            Mock(returncode=0, stderr=""),  # auth status success
            subprocess.TimeoutExpired("gh auth token", 10),  # token timeout
        ]

        from gha_workflow_linter.github_auth import _get_token_from_gh_cli

        with pytest.raises(
            subprocess.SubprocessError, match="GitHub CLI command timed out"
        ):
            _get_token_from_gh_cli()

    @patch("subprocess.run")
    def test_invalid_token_format(self, mock_run: Mock) -> None:
        """Test invalid token format from CLI."""
        mock_run.side_effect = [
            Mock(returncode=0, stderr=""),  # auth status success
            Mock(stdout="invalid", stderr=""),  # invalid short token
        ]

        from gha_workflow_linter.github_auth import _get_token_from_gh_cli

        with pytest.raises(ValueError, match="Invalid token format"):
            _get_token_from_gh_cli()

    @patch("subprocess.run")
    def test_empty_token_output(self, mock_run: Mock) -> None:
        """Test empty token output from CLI."""
        mock_run.side_effect = [
            Mock(returncode=0, stderr=""),  # auth status success
            Mock(stdout="", stderr=""),  # empty token output
        ]

        from gha_workflow_linter.github_auth import _get_token_from_gh_cli

        with pytest.raises(ValueError, match="Invalid token format"):
            _get_token_from_gh_cli()


class TestCheckGitHubCliAvailable:
    """Test check_github_cli_available function."""

    @patch("subprocess.run")
    def test_cli_available_and_authenticated(self, mock_run: Mock) -> None:
        """Test GitHub CLI is available and authenticated."""
        mock_run.return_value = Mock(returncode=0)

        result = check_github_cli_available()
        assert result is True
        mock_run.assert_called_once_with(
            ["gh", "auth", "status"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

    @patch("subprocess.run")
    def test_cli_not_authenticated(self, mock_run: Mock) -> None:
        """Test GitHub CLI not authenticated."""
        mock_run.return_value = Mock(returncode=1)

        result = check_github_cli_available()
        assert result is False

    @patch("subprocess.run")
    def test_cli_not_installed(self, mock_run: Mock) -> None:
        """Test GitHub CLI not installed."""
        mock_run.side_effect = FileNotFoundError()

        result = check_github_cli_available()
        assert result is False

    @patch("subprocess.run")
    def test_cli_timeout(self, mock_run: Mock) -> None:
        """Test GitHub CLI command timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired("gh auth status", 5)

        result = check_github_cli_available()
        assert result is False


class TestGetGitHubCliSuggestions:
    """Test get_github_cli_suggestions function."""

    @patch("gha_workflow_linter.github_auth.check_github_cli_available")
    def test_cli_available_and_authenticated(self, mock_check: Mock) -> None:
        """Test suggestions when CLI is available and authenticated."""
        mock_check.return_value = True

        suggestions = get_github_cli_suggestions()
        assert suggestions == ["GitHub CLI is available and authenticated"]

    @patch("gha_workflow_linter.github_auth.check_github_cli_available")
    @patch("subprocess.run")
    def test_cli_installed_not_authenticated(
        self, mock_run: Mock, mock_check: Mock
    ) -> None:
        """Test suggestions when CLI is installed but not authenticated."""
        mock_check.return_value = False
        mock_run.return_value = Mock(returncode=0)  # gh --version succeeds

        suggestions = get_github_cli_suggestions()
        expected = [
            "Install and authenticate with GitHub CLI: gh auth login",
            "Or set environment variable: export GITHUB_TOKEN=ghp_xxx",
            "Or use --github-token flag with your personal access token",
        ]
        assert suggestions == expected

    @patch("gha_workflow_linter.github_auth.check_github_cli_available")
    @patch("subprocess.run")
    def test_cli_not_installed(self, mock_run: Mock, mock_check: Mock) -> None:
        """Test suggestions when CLI is not installed."""
        mock_check.return_value = False
        mock_run.side_effect = FileNotFoundError()  # gh --version fails

        suggestions = get_github_cli_suggestions()
        expected = [
            "Install GitHub CLI: https://cli.github.com/",
            "Or set environment variable: export GITHUB_TOKEN=ghp_xxx",
            "Or use --github-token flag with your personal access token",
        ]
        assert suggestions == expected

    @patch("gha_workflow_linter.github_auth.check_github_cli_available")
    @patch("subprocess.run")
    def test_cli_version_timeout(
        self, mock_run: Mock, mock_check: Mock
    ) -> None:
        """Test suggestions when CLI version check times out."""
        mock_check.return_value = False
        mock_run.side_effect = subprocess.TimeoutExpired("gh --version", 5)

        suggestions = get_github_cli_suggestions()
        expected = [
            "Install GitHub CLI: https://cli.github.com/",
            "Or set environment variable: export GITHUB_TOKEN=ghp_xxx",
            "Or use --github-token flag with your personal access token",
        ]
        assert suggestions == expected

    @patch("gha_workflow_linter.github_auth.check_github_cli_available")
    @patch("subprocess.run")
    def test_cli_version_subprocess_error(
        self, mock_run: Mock, mock_check: Mock
    ) -> None:
        """Test suggestions when CLI version check has subprocess error."""
        mock_check.return_value = False
        mock_run.side_effect = subprocess.SubprocessError("Process failed")

        suggestions = get_github_cli_suggestions()
        expected = [
            "Install GitHub CLI: https://cli.github.com/",
            "Or set environment variable: export GITHUB_TOKEN=ghp_xxx",
            "Or use --github-token flag with your personal access token",
        ]
        assert suggestions == expected

    @patch("gha_workflow_linter.github_auth.check_github_cli_available")
    @patch("subprocess.run")
    def test_cli_version_os_error(
        self, mock_run: Mock, mock_check: Mock
    ) -> None:
        """Test suggestions when CLI version check has OS error."""
        mock_check.return_value = False
        mock_run.side_effect = OSError("OS error")

        suggestions = get_github_cli_suggestions()
        expected = [
            "Install GitHub CLI: https://cli.github.com/",
            "Or set environment variable: export GITHUB_TOKEN=ghp_xxx",
            "Or use --github-token flag with your personal access token",
        ]
        assert suggestions == expected


class TestIntegration:
    """Integration tests for GitHub authentication utilities."""

    @patch("gha_workflow_linter.github_auth._get_token_from_gh_cli")
    def test_full_fallback_chain_with_cli_success(
        self, mock_gh_cli: Mock
    ) -> None:
        """Test complete fallback chain with successful CLI retrieval."""
        mock_gh_cli.return_value = "cli_token_from_fallback"
        console = Mock(spec=Console)

        # Clear environment to force CLI fallback
        with patch.dict(os.environ, {}, clear=True):
            token = get_github_token_with_fallback(console=console)

        assert token == "cli_token_from_fallback"

    def test_full_fallback_chain_failure(self) -> None:
        """Test complete fallback chain when all methods fail."""
        with (
            patch.dict(os.environ, {}, clear=True),
            patch(
                "gha_workflow_linter.github_auth._get_token_from_gh_cli"
            ) as mock_gh_cli,
        ):
            mock_gh_cli.side_effect = subprocess.SubprocessError(
                "All methods failed"
            )
            token = get_github_token_with_fallback()

        assert token is None

    @patch("gha_workflow_linter.github_auth.check_github_cli_available")
    def test_suggestions_integration(self, mock_check: Mock) -> None:
        """Test integration of suggestion system."""
        mock_check.return_value = False

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()
            suggestions = get_github_cli_suggestions()

        assert len(suggestions) == 3
        assert "Install GitHub CLI" in suggestions[0]
        assert "export GITHUB_TOKEN" in suggestions[1]
        assert "--github-token flag" in suggestions[2]
