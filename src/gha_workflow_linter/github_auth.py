# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""GitHub authentication utilities with CLI fallback support."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rich.console import Console

logger = logging.getLogger(__name__)


def get_github_token_with_fallback(
    explicit_token: str | None = None,
    *,
    console: Console | None = None,
    quiet: bool = False,
) -> str | None:
    """
    Get GitHub token with fallback to GitHub CLI.

    This function implements a multi-step approach to obtain a GitHub token:
    1. Use explicitly provided token if available
    2. Check GITHUB_TOKEN environment variable
    3. Fallback to GitHub CLI (`gh auth token`) if available

    Args:
        explicit_token: Explicitly provided token (e.g., from config or CLI)
        console: Rich console instance for user messages
        quiet: Suppress informational messages

    Returns:
        GitHub token if found, None otherwise
    """
    # Step 1: Use explicit token if provided
    if explicit_token:
        logger.debug("Using explicitly provided GitHub token")
        return explicit_token

    # Step 2: Check environment variable
    env_token = os.environ.get("GITHUB_TOKEN")
    if env_token:
        logger.debug(
            "Using GitHub token from GITHUB_TOKEN environment variable"
        )
        return env_token

    # Step 3: Try GitHub CLI fallback
    if not quiet and console:
        console.print(
            "⚠️  No GitHub token found; attempting to obtain using GitHub CLI"
        )

    try:
        cli_token = _get_token_from_gh_cli()
        if cli_token:
            if not quiet and console:
                console.print(
                    "✅ Successfully obtained GitHub token from GitHub CLI"
                )
            logger.info("Successfully obtained GitHub token from GitHub CLI")
            return cli_token
    except Exception as e:
        logger.debug(f"Failed to obtain token from GitHub CLI: {e}")

    # All methods failed
    if not quiet and console:
        console.print("❌ Unable to obtain GitHub token from any source")

    return None


def _get_token_from_gh_cli() -> str | None:
    """
    Attempt to get GitHub token using GitHub CLI.

    Returns:
        Token from GitHub CLI if successful, None otherwise

    Raises:
        subprocess.SubprocessError: If gh command fails
        FileNotFoundError: If gh CLI is not installed
    """
    try:
        # Check if gh CLI is available
        result = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True,
            text=True,
            timeout=10,  # 10 second timeout
            check=False,  # Don't raise on non-zero exit
        )

        # If auth status fails, user is not logged in
        if result.returncode != 0:
            logger.debug(f"GitHub CLI auth status failed: {result.stderr}")
            raise subprocess.CalledProcessError(
                result.returncode,
                "gh auth status",
                stderr="User not authenticated with GitHub CLI",
            )

        # Try to get the token
        token_result = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            timeout=10,  # 10 second timeout
            check=True,
        )

        token = token_result.stdout.strip()

        # Validate token format (GitHub tokens are usually 40+ characters)
        if not token or len(token) < 20:
            logger.debug(
                f"Invalid token format from GitHub CLI: {len(token) if token else 0} characters"
            )
            raise ValueError("Invalid token format from GitHub CLI")

        logger.debug(
            f"Successfully obtained {len(token)}-character token from GitHub CLI"
        )
        return token

    except FileNotFoundError:
        logger.debug("GitHub CLI (gh) not found in PATH")
        raise subprocess.SubprocessError("GitHub CLI not installed")

    except subprocess.TimeoutExpired:
        logger.debug("GitHub CLI command timed out")
        raise subprocess.SubprocessError("GitHub CLI command timed out")

    except subprocess.CalledProcessError as e:
        if (
            "not logged into" in str(e.stderr).lower()
            or "not authenticated" in str(e.stderr).lower()
        ):
            logger.debug("User not authenticated with GitHub CLI")
            raise subprocess.SubprocessError(
                "Not authenticated with GitHub CLI"
            )
        else:
            logger.debug(f"GitHub CLI command failed: {e}")
            raise subprocess.SubprocessError(f"GitHub CLI error: {e}")


def check_github_cli_available() -> bool:
    """
    Check if GitHub CLI is available and user is authenticated.

    Returns:
        True if GitHub CLI is available and authenticated, False otherwise
    """
    try:
        result = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def get_github_cli_suggestions() -> list[str]:
    """
    Get helpful suggestions for setting up GitHub authentication.

    Returns:
        List of suggestion strings for the user
    """
    suggestions = []

    # Check if gh CLI is available
    if check_github_cli_available():
        suggestions.append("GitHub CLI is available and authenticated")
    else:
        try:
            # Check if gh is installed but not authenticated
            subprocess.run(
                ["gh", "--version"], capture_output=True, timeout=5, check=True
            )
            suggestions.extend(
                [
                    "Install and authenticate with GitHub CLI: gh auth login",
                    "Or set environment variable: export GITHUB_TOKEN=ghp_xxx",
                    "Or use --github-token flag with your personal access token",
                ]
            )
        except (
            FileNotFoundError,
            subprocess.SubprocessError,
            subprocess.TimeoutExpired,
            OSError,
        ):
            suggestions.extend(
                [
                    "Install GitHub CLI: https://cli.github.com/",
                    "Or set environment variable: export GITHUB_TOKEN=ghp_xxx",
                    "Or use --github-token flag with your personal access token",
                ]
            )

    return suggestions
