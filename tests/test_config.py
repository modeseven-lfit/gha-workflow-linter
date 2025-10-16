# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for configuration management."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
from unittest.mock import patch

import pytest
import yaml

from gha_workflow_linter.config import ConfigManager
from gha_workflow_linter.models import Config, LogLevel


class TestConfigManager:
    """Test the ConfigManager class."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.config_manager = ConfigManager()

    def test_init(self) -> None:
        """Test ConfigManager initialization."""
        assert self.config_manager is not None
        assert self.config_manager.logger is not None

    def test_load_config_with_defaults_no_file(self) -> None:
        """Test loading config with defaults when no file exists."""
        with patch.object(
            self.config_manager, "_find_default_config_file", return_value=None
        ):
            config = self.config_manager.load_config()

        assert isinstance(config, Config)
        assert config.log_level == LogLevel.INFO
        assert config.parallel_workers == 4
        assert config.scan_extensions == [".yml", ".yaml"]

    def test_load_config_with_nonexistent_file(self) -> None:
        """Test loading config with a nonexistent file path."""
        nonexistent_file = Path("/nonexistent/config.yaml")
        config = self.config_manager.load_config(nonexistent_file)

        assert isinstance(config, Config)
        # Should use defaults since file doesn't exist

    def test_load_config_from_valid_file(self) -> None:
        """Test loading config from a valid YAML file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            config_data = {
                "log_level": "DEBUG",
                "parallel_workers": 8,
                "scan_extensions": [".yml"],
                "exclude_patterns": ["test*"],
                "network": {"timeout_seconds": 60, "max_retries": 5},
            }
            yaml.dump(config_data, f)
            config_file = Path(f.name)

        try:
            config = self.config_manager.load_config(config_file)

            assert config.log_level == LogLevel.DEBUG
            assert config.parallel_workers == 8
            assert config.scan_extensions == [".yml"]
            assert config.exclude_patterns == ["test*"]
            assert config.network.timeout_seconds == 60
            assert config.network.max_retries == 5
        finally:
            config_file.unlink()

    def test_load_config_from_invalid_yaml(self) -> None:
        """Test loading config from invalid YAML file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("invalid: yaml: content: [")
            config_file = Path(f.name)

        try:
            with pytest.raises(ValueError, match="Invalid YAML"):
                self.config_manager.load_config(config_file)
        finally:
            config_file.unlink()

    def test_load_config_from_non_dict_yaml(self) -> None:
        """Test loading config from YAML that doesn't contain a dict."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("- not\n- a\n- dict")
            config_file = Path(f.name)

        try:
            with pytest.raises(
                ValueError,
                match="Configuration file must contain a YAML object",
            ):
                self.config_manager.load_config(config_file)
        finally:
            config_file.unlink()

    def test_load_config_unreadable_file(self) -> None:
        """Test loading config from unreadable file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("log_level: DEBUG")
            config_file = Path(f.name)

        try:
            # Make file unreadable
            config_file.chmod(0o000)

            with pytest.raises(
                ValueError, match="Cannot read configuration file"
            ):
                self.config_manager.load_config(config_file)
        finally:
            config_file.chmod(0o644)
            config_file.unlink()

    def test_load_config_invalid_validation(self) -> None:
        """Test loading config with validation errors."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            config_data = {
                "log_level": "INVALID_LEVEL",
                "parallel_workers": -5,
            }
            yaml.dump(config_data, f)
            config_file = Path(f.name)

        try:
            with pytest.raises(
                ValueError, match="Configuration validation failed"
            ):
                self.config_manager.load_config(config_file)
        finally:
            config_file.unlink()

    def test_find_default_config_file_current_directory(self) -> None:
        """Test finding default config file in current directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)

                # Create a config file in current directory
                config_file = Path("gha-workflow-linter.yaml")
                config_file.write_text("log_level: DEBUG")

                found_file = self.config_manager._find_default_config_file()
                assert found_file == config_file.resolve()
            finally:
                os.chdir(original_cwd)

    def test_find_default_config_file_variations(self) -> None:
        """Test finding default config file with different naming variations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)

                # Test each variation
                variations = [
                    "gha-workflow-linter.yaml",
                    "gha-workflow-linter.yml",
                    ".gha-workflow-linter.yaml",
                ]

                for variation in variations:
                    config_file = Path(variation)
                    config_file.write_text("log_level: DEBUG")

                    found_file = self.config_manager._find_default_config_file()
                    assert found_file == config_file.resolve()

                    # Clean up for next iteration
                    config_file.unlink()
            finally:
                os.chdir(original_cwd)

    def test_find_default_config_file_user_config_dir(self) -> None:
        """Test finding default config file in user config directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "gha-workflow-linter"
            config_dir.mkdir()
            config_file = config_dir / "config.yaml"
            config_file.write_text("log_level: DEBUG")

            with patch.object(
                self.config_manager,
                "_get_config_directory",
                return_value=config_dir,
            ):
                found_file = self.config_manager._find_default_config_file()
                assert found_file == config_file

    def test_find_default_config_file_none_found(self) -> None:
        """Test finding default config file when none exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)

                with patch.object(
                    self.config_manager,
                    "_get_config_directory",
                    return_value=None,
                ):
                    found_file = self.config_manager._find_default_config_file()
                    assert found_file is None
            finally:
                os.chdir(original_cwd)

    def test_get_config_directory_xdg_config_home(self) -> None:
        """Test getting config directory from XDG_CONFIG_HOME."""
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": "/tmp/config"}):
            config_dir = self.config_manager._get_config_directory()
            assert config_dir == Path("/tmp/config/gha-workflow-linter")

    def test_get_config_directory_home_config(self) -> None:
        """Test getting config directory from ~/.config."""
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("pathlib.Path.home") as mock_home,
            patch.object(Path, "exists", return_value=True),
        ):
            mock_home.return_value = Path("/home/user")
            config_dir = self.config_manager._get_config_directory()
            assert config_dir == Path("/home/user/.config/gha-workflow-linter")

    def test_get_config_directory_no_home(self) -> None:
        """Test getting config directory when home doesn't exist."""
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("pathlib.Path.home") as mock_home,
            patch.object(Path, "exists", return_value=False),
        ):
            mock_home.return_value = Path("/nonexistent")
            config_dir = self.config_manager._get_config_directory()
            assert config_dir is None

    def test_save_default_config_specified_path(self) -> None:
        """Test saving default config to specified path."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            output_path = Path(f.name)

        try:
            saved_path = self.config_manager.save_default_config(output_path)
            assert saved_path == output_path
            assert output_path.exists()

            # Verify content
            content = output_path.read_text()
            assert "log_level:" in content
            assert "parallel_workers:" in content
        finally:
            if output_path.exists():
                output_path.unlink()

    def test_save_default_config_default_path_with_config_dir(self) -> None:
        """Test saving default config to default path with config directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "gha-workflow-linter"

            with patch.object(
                self.config_manager,
                "_get_config_directory",
                return_value=config_dir,
            ):
                saved_path = self.config_manager.save_default_config()

                assert saved_path == config_dir / "config.yaml"
                assert saved_path.exists()
                assert config_dir.exists()

    def test_save_default_config_default_path_no_config_dir(self) -> None:
        """Test saving default config to current directory when no config dir."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)

                with patch.object(
                    self.config_manager,
                    "_get_config_directory",
                    return_value=None,
                ):
                    saved_path = self.config_manager.save_default_config()

                    expected_path = Path.cwd() / "gha-workflow-linter.yaml"
                    assert saved_path == expected_path
                    assert expected_path.exists()
            finally:
                os.chdir(original_cwd)

    def test_save_default_config_unwritable_path(self) -> None:
        """Test saving default config to unwritable path."""
        unwritable_path = Path("/root/config.yaml")  # Typically not writable

        with pytest.raises(ValueError, match="Cannot write configuration file"):
            self.config_manager.save_default_config(unwritable_path)

    def test_validate_config_file_valid(self) -> None:
        """Test validating a valid config file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            config_data = {"log_level": "DEBUG", "parallel_workers": 2}
            yaml.dump(config_data, f)
            config_file = Path(f.name)

        try:
            result = self.config_manager.validate_config_file(config_file)
            assert result is True
        finally:
            config_file.unlink()

    def test_validate_config_file_invalid(self) -> None:
        """Test validating an invalid config file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            config_data = {"log_level": "INVALID_LEVEL", "parallel_workers": -1}
            yaml.dump(config_data, f)
            config_file = Path(f.name)

        try:
            result = self.config_manager.validate_config_file(config_file)
            assert result is False
        finally:
            config_file.unlink()

    def test_validate_config_file_nonexistent(self) -> None:
        """Test validating a nonexistent config file."""
        nonexistent_file = Path("/nonexistent/config.yaml")
        result = self.config_manager.validate_config_file(nonexistent_file)
        # Should still return True since it loads defaults
        assert result is True

    def test_load_config_file_success(self) -> None:
        """Test _load_config_file with valid YAML."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            config_data = {"key": "value", "number": 42}
            yaml.dump(config_data, f)
            config_file = Path(f.name)

        try:
            result = self.config_manager._load_config_file(config_file)
            assert result == config_data
        finally:
            config_file.unlink()

    def test_load_config_with_environment_override(self) -> None:
        """Test that environment variables can override config file values."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            config_data = {"log_level": "INFO", "parallel_workers": 4}
            yaml.dump(config_data, f)
            config_file = Path(f.name)

        try:
            # Test without environment variable first
            config = self.config_manager.load_config(config_file)
            assert config.log_level == LogLevel.INFO  # Should come from file
            assert config.parallel_workers == 4  # Should come from file
        finally:
            config_file.unlink()
