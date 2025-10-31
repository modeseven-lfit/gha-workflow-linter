# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Configuration management for gha-workflow-linter."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from pydantic import ValidationError
import yaml

from .models import Config


class ConfigManager:
    """Manager for loading and validating configuration."""

    def __init__(self) -> None:
        """Initialize the configuration manager."""
        self.logger = logging.getLogger(__name__)

    def load_config(self, config_file: Path | None = None) -> Config:
        """
        Load configuration from file and environment variables.

        Args:
            config_file: Optional path to configuration file

        Returns:
            Validated Config object

        Raises:
            ValueError: If configuration is invalid
        """
        # Start with default config
        config_data: dict[str, object] = {}

        # Load from default location if no file specified
        if config_file is None:
            config_file = self._find_default_config_file()

        # Load from file if it exists
        if config_file and config_file.exists():
            self.logger.debug(f"Loading config from: {config_file}")
            config_data = self._load_config_file(config_file)
        else:
            self.logger.debug("No config file found, using defaults")

        # Create Config object (will load from environment variables)
        try:
            config = Config(**config_data)
            self.logger.debug("Configuration loaded successfully")
            return config
        except ValidationError as e:
            self.logger.error(f"Invalid configuration: {e}")
            raise ValueError(f"Configuration validation failed: {e}") from e

    def _find_default_config_file(self) -> Path | None:
        """
        Find default configuration file location.

        Returns:
            Path to config file if found, None otherwise
        """
        # Check current directory first
        for filename in [
            "gha-workflow-linter.yaml",
            "gha-workflow-linter.yml",
            ".gha-workflow-linter.yaml",
        ]:
            config_path = Path.cwd() / filename
            if config_path.exists():
                return config_path

        # Check user config directory
        config_dir = self._get_config_directory()
        if config_dir:
            for filename in ["config.yaml", "config.yml"]:
                config_path = config_dir / filename
                if config_path.exists():
                    return config_path

        return None

    def _get_config_directory(self) -> Path | None:
        """
        Get user configuration directory.

        Returns:
            Path to config directory, None if not available
        """
        # Use XDG_CONFIG_HOME if set
        xdg_config = os.environ.get("XDG_CONFIG_HOME")
        if xdg_config:
            return Path(xdg_config) / "gha-workflow-linter"

        # Use ~/.config on Unix-like systems
        home = Path.home()
        if home.exists():
            config_dir = home / ".config" / "gha-workflow-linter"
            return config_dir

        return None

    def _load_config_file(self, config_file: Path) -> dict[str, object]:
        """
        Load configuration from YAML file.

        Args:
            config_file: Path to configuration file

        Returns:
            Dictionary with configuration data

        Raises:
            ValueError: If file cannot be loaded or parsed
        """
        try:
            with open(config_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not isinstance(data, dict):
                raise ValueError(
                    "Configuration file must contain a YAML object"
                )

            return data

        except OSError as e:
            self.logger.error(f"Cannot read config file {config_file}: {e}")
            raise ValueError(f"Cannot read configuration file: {e}") from e
        except yaml.YAMLError as e:
            self.logger.error(f"Invalid YAML in config file {config_file}: {e}")
            raise ValueError(f"Invalid YAML in configuration file: {e}") from e

    def save_default_config(self, output_path: Path | None = None) -> Path:
        """
        Save default configuration to file.

        Args:
            output_path: Optional path to save config file

        Returns:
            Path where config was saved
        """
        if output_path is None:
            config_dir = self._get_config_directory()
            if config_dir is None:
                output_path = Path.cwd() / "gha-workflow-linter.yaml"
            else:
                config_dir.mkdir(parents=True, exist_ok=True)
                output_path = config_dir / "config.yaml"

        # Create default config
        default_config = Config()

        # Convert to dictionary for YAML serialization
        config_dict: dict[str, object] = {
            "log_level": default_config.log_level.value,
            "parallel_workers": default_config.parallel_workers,
            "scan_extensions": default_config.scan_extensions,
            "exclude_patterns": default_config.exclude_patterns,
            "require_pinned_sha": default_config.require_pinned_sha,
            "auto_fix": default_config.auto_fix,
            "auto_latest": default_config.auto_latest,
            "two_space_comments": default_config.two_space_comments,
            "skip_actions": default_config.skip_actions,
            "network": {
                "timeout_seconds": default_config.network.timeout_seconds,
                "max_retries": default_config.network.max_retries,
                "retry_delay_seconds": default_config.network.retry_delay_seconds,
                "rate_limit_delay_seconds": default_config.network.rate_limit_delay_seconds,
            },
            "github_api": {
                "base_url": default_config.github_api.base_url,
                "graphql_url": default_config.github_api.graphql_url,
                "max_repositories_per_query": default_config.github_api.max_repositories_per_query,
                "max_references_per_query": default_config.github_api.max_references_per_query,
                "rate_limit_threshold": default_config.github_api.rate_limit_threshold,
                "rate_limit_reset_buffer": default_config.github_api.rate_limit_reset_buffer,
            },
        }

        # Add comments for clarity
        yaml_content = f"""# gha-workflow-linter configuration file
# SPDX-License-Identifier: Apache-2.0

# Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
log_level: {config_dict["log_level"]}

# Number of parallel workers for validation (1-32)
parallel_workers: {config_dict["parallel_workers"]}

# File extensions to scan for workflows
scan_extensions:
{chr(10).join(f'  - "{ext}"' for ext in (config_dict["scan_extensions"] if isinstance(config_dict["scan_extensions"], list) else []))}

# Patterns to exclude from scanning (can be empty)
exclude_patterns: []

# Require action calls to be pinned to commit SHAs
require_pinned_sha: {config_dict["require_pinned_sha"]}

# Auto-fix broken/invalid references
auto_fix: {config_dict["auto_fix"]}

# Use latest versions when auto-fixing
auto_latest: {config_dict["auto_latest"]}

# Use two spaces before inline comments when fixing
two_space_comments: {config_dict["two_space_comments"]}

# Skip scanning action.yaml/action.yml files
skip_actions: {config_dict["skip_actions"]}

# Network configuration
network:
  # Timeout for network requests (seconds)
  timeout_seconds: {config_dict["network"]["timeout_seconds"] if isinstance(config_dict["network"], dict) else 30}

  # Maximum retry attempts for failed requests
  max_retries: {config_dict["network"]["max_retries"] if isinstance(config_dict["network"], dict) else 3}

  # Delay between retry attempts (seconds)
  retry_delay_seconds: {config_dict["network"]["retry_delay_seconds"] if isinstance(config_dict["network"], dict) else 1.0}

  # Delay between requests for rate limiting (seconds)
  rate_limit_delay_seconds: {config_dict["network"]["rate_limit_delay_seconds"] if isinstance(config_dict["network"], dict) else 0.1}

# GitHub API configuration
github_api:
  # GitHub API base URL
  base_url: {config_dict["github_api"]["base_url"] if isinstance(config_dict["github_api"], dict) else "https://api.github.com"}

  # GitHub GraphQL API URL
  graphql_url: {config_dict["github_api"]["graphql_url"] if isinstance(config_dict["github_api"], dict) else "https://api.github.com/graphql"}

  # Maximum repositories per GraphQL query
  max_repositories_per_query: {config_dict["github_api"]["max_repositories_per_query"] if isinstance(config_dict["github_api"], dict) else 100}

  # Maximum references per GraphQL query
  max_references_per_query: {config_dict["github_api"]["max_references_per_query"] if isinstance(config_dict["github_api"], dict) else 100}

  # Rate limit threshold for delays
  rate_limit_threshold: {config_dict["github_api"]["rate_limit_threshold"] if isinstance(config_dict["github_api"], dict) else 1000}

  # Buffer seconds before rate limit reset
  rate_limit_reset_buffer: {config_dict["github_api"]["rate_limit_reset_buffer"] if isinstance(config_dict["github_api"], dict) else 60}

  # GitHub API token (can also be set via GITHUB_TOKEN environment variable)
  # token: your_github_token_here
"""

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(yaml_content)

            self.logger.info(f"Default configuration saved to: {output_path}")
            return output_path

        except OSError as e:
            self.logger.error(f"Cannot write config file {output_path}: {e}")
            raise ValueError(f"Cannot write configuration file: {e}") from e

    def validate_config_file(self, config_file: Path) -> bool:
        """
        Validate configuration file without loading it.

        Args:
            config_file: Path to configuration file

        Returns:
            True if valid, False otherwise
        """
        try:
            self.load_config(config_file)
            return True
        except (ValueError, ValidationError):
            return False
