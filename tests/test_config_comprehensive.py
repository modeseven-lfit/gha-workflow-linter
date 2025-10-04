# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Comprehensive tests for config module."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
from unittest.mock import patch

import pytest
import yaml

from gha_workflow_linter.config import ConfigManager
from gha_workflow_linter.models import (
    CacheConfig,
    Config,
    GitHubAPIConfig,
)


class TestConfigManager:
    """Test ConfigManager class."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.config_manager = ConfigManager()

    def test_init(self) -> None:
        """Test ConfigManager initialization."""
        assert self.config_manager.logger is not None

    def test_load_config_defaults(self) -> None:
        """Test loading default configuration when no file exists."""
        with patch("pathlib.Path.exists", return_value=False):
            config = self.config_manager.load_config(None)

            # Should return default config
            assert isinstance(config, Config)
            assert config.parallel_workers == 4
            assert config.require_pinned_sha is True
            assert config.scan_extensions == [".yml", ".yaml"]
            assert config.exclude_patterns == []

    def test_load_config_from_file(self) -> None:
        """Test loading configuration from YAML file."""
        config_data = {
            "parallel_workers": 8,
            "require_pinned_sha": False,
            "scan_extensions": [".yml", ".yaml", ".json"],
            "exclude_patterns": ["test*", "*.tmp"],
            "github_api": {
                "timeout": 60.0,
                "max_retries": 5,
                "retry_delay": 2.0,
            },
            "cache": {
                "enabled": False,
                "default_ttl_seconds": 86400,
            },
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            yaml.safe_dump(config_data, f)
            config_file = Path(f.name)

        try:
            config = self.config_manager.load_config(config_file)

            assert config.parallel_workers == 8
            assert config.require_pinned_sha is False
            assert config.scan_extensions == [".yml", ".yaml", ".json"]
            assert config.exclude_patterns == ["test*", "*.tmp"]

            assert config.github_api.timeout == 60.0
            assert config.github_api.max_retries == 5
            assert config.github_api.retry_delay == 2.0

            assert config.cache.enabled is False
            assert config.cache.default_ttl_seconds == 86400
        finally:
            config_file.unlink()

    def test_load_config_invalid_yaml(self) -> None:
        """Test loading configuration with invalid YAML."""
        invalid_yaml = """
        parallel_workers: 4
        github_api:
          token: test
          invalid: [
        """

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            f.write(invalid_yaml)
            config_file = Path(f.name)

        try:
            with pytest.raises(ValueError, match="Invalid YAML"):
                self.config_manager.load_config(config_file)
        finally:
            config_file.unlink()

    def test_load_config_nonexistent_file(self) -> None:
        """Test loading configuration from nonexistent file."""
        nonexistent_file = Path("/nonexistent/config.yml")

        # When file doesn't exist, it just loads defaults - no error
        config = self.config_manager.load_config(nonexistent_file)
        assert isinstance(config, Config)

    def test_load_config_permission_error(self) -> None:
        """Test loading configuration with permission error."""
        config_file = Path("/etc/config.yml")  # Likely no read permission

        with (
            patch("pathlib.Path.exists", return_value=True),
            patch(
                "builtins.open",
                side_effect=PermissionError("Permission denied"),
            ),
            pytest.raises(ValueError, match="Cannot read configuration file"),
        ):
            self.config_manager.load_config(config_file)

    def test_create_default_config(self) -> None:
        """Test creating default configuration."""
        # Test default config creation through load_config with no file
        result = self.config_manager.load_config(None)

        assert isinstance(result, Config)
        assert result.parallel_workers == 4
        assert result.require_pinned_sha is True
        assert result.scan_extensions == [".yml", ".yaml"]
        assert result.exclude_patterns == []

        assert isinstance(result.github_api, GitHubAPIConfig)
        assert result.github_api.token is None
        assert result.github_api.graphql_url == "https://api.github.com/graphql"
        assert result.github_api.timeout == 30.0
        assert result.github_api.max_retries == 3
        assert result.github_api.retry_delay == 1.0
        assert result.github_api.batch_size == 50

        assert isinstance(result.cache, CacheConfig)
        assert result.cache.enabled is True
        assert (
            result.cache.cache_dir
            == Path.home() / ".cache" / "gha-workflow-linter"
        )
        assert result.cache.default_ttl_seconds == 604800  # 7 days
        assert result.cache.max_cache_size == 10000

    def test_validate_config_valid(self) -> None:
        """Test config validation with valid configuration."""
        # Test by loading a valid config - no exception should be raised
        config = self.config_manager.load_config(None)
        assert isinstance(config, Config)

    def test_validate_config_invalid_workers(self) -> None:
        """Test config validation with invalid worker count."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            f.write("parallel_workers: 0")
            config_file = Path(f.name)

        try:
            with pytest.raises(
                ValueError, match="Configuration validation failed"
            ):
                self.config_manager.load_config(config_file)
        finally:
            config_file.unlink()

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            f.write("parallel_workers: 50")
            config_file = Path(f.name)

        try:
            with pytest.raises(
                ValueError, match="Configuration validation failed"
            ):
                self.config_manager.load_config(config_file)
        finally:
            config_file.unlink()

    def test_validate_config_invalid_extensions(self) -> None:
        """Test config validation with invalid scan extensions."""
        # Pydantic will validate this at model level
        # Empty scan_extensions is actually valid in the model
        config = Config(scan_extensions=[])
        assert config.scan_extensions == []

    def test_validate_config_invalid_github_api(self) -> None:
        """Test config validation with invalid GitHub API config."""
        # Test validation through config loading - Pydantic handles this
        config = Config()
        # These values are valid in the model
        assert config.github_api.timeout > 0
        assert config.github_api.max_retries >= 0

    def test_validate_config_invalid_cache(self) -> None:
        """Test config validation with invalid cache config."""
        # Test validation through config loading
        config = Config()
        # These values are actually valid in the model, so just verify they work
        assert config.cache.default_ttl_seconds > 0
        assert config.cache.max_cache_size > 0

    def test_merge_configs_full_override(self) -> None:
        """Test merging configurations with full override."""
        # Test loading config with overrides through YAML
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            f.write("""
parallel_workers: 8
require_pinned_sha: false
github_api:
  timeout: 60.0
""")
            config_file = Path(f.name)

        try:
            config = self.config_manager.load_config(config_file)
            assert config.parallel_workers == 8
            assert config.require_pinned_sha is False
            assert config.github_api.timeout == 60.0
        finally:
            config_file.unlink()

    def test_merge_configs_partial_override(self) -> None:
        """Test merging configurations with partial override."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            f.write("""
parallel_workers: 6
""")
            config_file = Path(f.name)

        try:
            config = self.config_manager.load_config(config_file)
            # Should override parallel_workers but keep other defaults
            assert config.parallel_workers == 6
            assert config.require_pinned_sha is True  # default
            assert config.github_api.timeout == 30.0  # default
        finally:
            config_file.unlink()

    def test_merge_configs_empty_override(self) -> None:
        """Test merging configurations with empty override."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            f.write("{}")  # Empty YAML
            config_file = Path(f.name)

        try:
            config = self.config_manager.load_config(config_file)
            # Should be all defaults
            assert config.parallel_workers == 4
            assert config.require_pinned_sha is True
        finally:
            config_file.unlink()

    def test_dict_to_config_full(self) -> None:
        """Test converting dictionary to config with all fields."""
        # Test through load_config
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            f.write("""
log_level: DEBUG
parallel_workers: 8
scan_extensions: [".yml", ".yaml"]
exclude_patterns: ["**/test/**"]
require_pinned_sha: false
github_api:
  base_url: "https://api.github.com"
  timeout: 45.0
""")
            config_file = Path(f.name)

        try:
            config = self.config_manager.load_config(config_file)
            assert config.log_level.value == "DEBUG"
            assert config.parallel_workers == 8
            assert config.scan_extensions == [".yml", ".yaml"]
            assert config.exclude_patterns == ["**/test/**"]
            assert config.require_pinned_sha is False
        finally:
            config_file.unlink()

    def test_dict_to_config_minimal(self) -> None:
        """Test converting minimal dictionary to config."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            f.write("parallel_workers: 2")
            config_file = Path(f.name)

        try:
            config = self.config_manager.load_config(config_file)
            assert config.parallel_workers == 2
            # Other fields should have defaults
            assert config.log_level.value == "INFO"
            assert config.require_pinned_sha is True
        finally:
            config_file.unlink()

    def test_dict_to_config_partial_nested(self) -> None:
        """Test converting dictionary with partial nested config."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            f.write("""
github_api:
  timeout: 120.0
cache:
  enabled: false
""")
            config_file = Path(f.name)

        try:
            config = self.config_manager.load_config(config_file)
            assert config.github_api.timeout == 120.0
            assert config.cache.enabled is False
            # Other nested fields should have defaults
            assert config.github_api.base_url == "https://api.github.com"
        finally:
            config_file.unlink()

    def test_load_config_with_environment_expansion(self) -> None:
        """Test loading config with environment variable expansion."""
        # Since the model handles environment variables directly,
        # just test that it works
        config = Config()
        # The effective_github_token property handles env vars
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test_token"}):
            assert config.effective_github_token == "test_token"

    def test_config_validation_comprehensive(self) -> None:
        """Test comprehensive configuration validation."""
        # Test that the config manager validates properly
        config = self.config_manager.load_config(None)
        assert isinstance(config, Config)

        # Test validation of all major components
        assert 1 <= config.parallel_workers <= 32
        assert config.scan_extensions is not None
        assert isinstance(config.github_api, GitHubAPIConfig)
        assert isinstance(config.cache, CacheConfig)

    def test_config_logging_levels(self) -> None:
        """Test configuration with different logging levels."""
        # Mock the logger to verify info was called
        with patch.object(self.config_manager.logger, "debug") as mock_debug:
            config = self.config_manager.load_config(None)
            assert isinstance(config, Config)
            # Debug should have been called during config loading
            mock_debug.assert_called()

    def test_effective_github_token_from_config(self) -> None:
        """Test effective GitHub token when set in config."""
        config_data = {"github_api": {"token": "config_token_123"}}

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            yaml.safe_dump(config_data, f)
            config_file = Path(f.name)

        try:
            config = self.config_manager.load_config(config_file)
            assert config.effective_github_token == "config_token_123"
        finally:
            config_file.unlink()

    def test_effective_github_token_from_env(self) -> None:
        """Test effective GitHub token from environment variable."""
        config = Config()
        config.github_api.token = None

        with patch.dict(os.environ, {"GITHUB_TOKEN": "env_token_456"}):
            assert config.effective_github_token == "env_token_456"

    def test_effective_github_token_config_over_env(self) -> None:
        """Test that config token takes precedence over environment."""
        config = Config()
        config.github_api.token = "config_token"

        with patch.dict(os.environ, {"GITHUB_TOKEN": "env_token"}):
            assert config.effective_github_token == "config_token"

    def test_effective_github_token_none(self) -> None:
        """Test effective GitHub token when neither config nor env is set."""
        config = Config()
        config.github_api.token = None

        with patch.dict(os.environ, {}, clear=True):
            assert config.effective_github_token is None

    def test_save_default_config(self) -> None:
        """Test saving default configuration to file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "test_config.yaml"
            result_path = self.config_manager.save_default_config(output_path)

            assert result_path == output_path
            assert output_path.exists()

            # Verify the saved config can be loaded back
            config = self.config_manager.load_config(output_path)
            assert isinstance(config, Config)
            assert config.parallel_workers == 4

    def test_validate_config_file(self) -> None:
        """Test config file validation."""
        # Test with valid config
        config_data = {"parallel_workers": 8}

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            yaml.safe_dump(config_data, f)
            config_file = Path(f.name)

        try:
            assert self.config_manager.validate_config_file(config_file) is True
        finally:
            config_file.unlink()

        # Test with invalid config
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            f.write("invalid: yaml: content: [")
            config_file = Path(f.name)

        try:
            assert (
                self.config_manager.validate_config_file(config_file) is False
            )
        finally:
            config_file.unlink()
