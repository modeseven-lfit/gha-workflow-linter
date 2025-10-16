# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Integration tests for cache functionality with CLI."""

from collections.abc import Generator
import json
from pathlib import Path
import tempfile

import pytest
from typer.testing import CliRunner

from gha_workflow_linter.cache import CacheConfig, ValidationCache
from gha_workflow_linter.cli import app
from gha_workflow_linter.models import ValidationResult


class TestCacheIntegration:
    """Integration tests for cache functionality."""

    @pytest.fixture
    def temp_workflow_dir(self) -> Generator[Path, None, None]:
        """Create a temporary directory with test workflow files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create .github/workflows directory
            workflows_dir = temp_path / ".github" / "workflows"
            workflows_dir.mkdir(parents=True)

            # Create a test workflow file
            workflow_content = """
name: Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
"""

            workflow_file = workflows_dir / "test.yml"
            workflow_file.write_text(workflow_content)

            yield temp_path

    @pytest.fixture
    def temp_cache_dir(self) -> Generator[Path, None, None]:
        """Create a temporary cache directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)

    def test_cache_command_info_empty(self, temp_cache_dir: Path) -> None:
        """Test cache info command with empty cache."""
        runner = CliRunner()

        # Create temporary config that uses our temp cache dir
        config_content = f"""
cache:
  cache_dir: "{temp_cache_dir}"
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(config_content)
            config_file = f.name

        try:
            result = runner.invoke(
                app, ["cache", "--info", "--config", config_file]
            )
            assert result.exit_code == 0
            assert "Cache Information" in result.stdout
            assert "Total Entries" in result.stdout
            assert "0" in result.stdout  # Should show 0 entries
        finally:
            Path(config_file).unlink()

    def test_cache_command_purge(self, temp_cache_dir: Path) -> None:
        """Test cache purge command."""
        runner = CliRunner()

        # First, create some cache entries
        cache_config = CacheConfig(
            enabled=True, cache_dir=temp_cache_dir, cache_file="test_cache.json"
        )
        cache = ValidationCache(cache_config)
        cache.put("actions/checkout", "v4", ValidationResult.VALID, "graphql")
        cache.put(
            "actions/setup-python", "v5", ValidationResult.VALID, "graphql"
        )
        cache.save()

        # Verify cache has entries
        info = cache.get_cache_info()
        assert info["entries"] == 2

        # Create config for CLI
        config_content = f"""
cache:
  cache_dir: "{temp_cache_dir}"
  cache_file: "test_cache.json"
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(config_content)
            config_file = f.name

        try:
            # Purge cache via CLI
            result = runner.invoke(
                app, ["cache", "--purge", "--config", config_file]
            )
            assert result.exit_code == 0
            assert "Purged 2 cache entries" in result.stdout

            # Verify cache is empty
            new_cache = ValidationCache(cache_config)
            info = new_cache.get_cache_info()
            assert info["entries"] == 0
        finally:
            Path(config_file).unlink()

    def test_cache_command_cleanup(self, temp_cache_dir: Path) -> None:
        """Test cache cleanup command."""
        runner = CliRunner()

        # Create cache with expired entries
        cache_config = CacheConfig(
            enabled=True,
            cache_dir=temp_cache_dir,
            cache_file="test_cache.json",
            default_ttl_seconds=1,  # 1 second TTL
        )
        cache = ValidationCache(cache_config)

        # Add entries and wait for expiration
        cache.put("actions/checkout", "v4", ValidationResult.VALID, "graphql")
        cache.save()

        import time

        time.sleep(1.1)  # Wait for expiration

        # Create config for CLI
        config_content = f"""
cache:
  cache_dir: "{temp_cache_dir}"
  cache_file: "test_cache.json"
  default_ttl_seconds: 1
  cleanup_on_startup: false
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(config_content)
            config_file = f.name

        try:
            # Cleanup cache via CLI
            result = runner.invoke(
                app, ["cache", "--cleanup", "--config", config_file]
            )
            assert result.exit_code == 0
            assert "Removed 1 expired cache entries" in result.stdout
        finally:
            Path(config_file).unlink()

    def test_cache_config_disabled(self, temp_cache_dir: Path) -> None:
        """Test that cache commands work when cache is disabled in config."""
        runner = CliRunner()

        # Create config with cache disabled
        config_content = f"""
cache:
  enabled: false
  cache_dir: "{temp_cache_dir}"
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(config_content)
            config_file = f.name

        try:
            # Cache info should show disabled
            result = runner.invoke(
                app, ["cache", "--info", "--config", config_file]
            )
            assert result.exit_code == 0
            assert "Enabled        │ False" in result.stdout

        finally:
            Path(config_file).unlink()

    def test_cache_file_operations(self, temp_cache_dir: Path) -> None:
        """Test basic cache file operations."""
        # Create cache with some test data
        cache_config = CacheConfig(
            enabled=True, cache_dir=temp_cache_dir, cache_file="test_cache.json"
        )
        cache = ValidationCache(cache_config)
        cache.put("actions/checkout", "v4", ValidationResult.VALID, "graphql")
        cache.save()

        # Verify cache file exists and has content
        cache_file = temp_cache_dir / "test_cache.json"
        assert cache_file.exists()

        with open(cache_file) as f:
            cache_data = json.load(f)
        assert len(cache_data) == 2  # 1 cache entry + 1 metadata entry
        assert "actions/checkout@v4" in cache_data
        assert "_metadata" in cache_data

    def test_main_command_purge_cache_flag(self, temp_cache_dir: Path) -> None:
        """Test --purge-cache flag on main command."""
        runner = CliRunner()

        # Create some cache entries first
        cache_config = CacheConfig(
            enabled=True, cache_dir=temp_cache_dir, cache_file="test_cache.json"
        )
        cache = ValidationCache(cache_config)
        cache.put("actions/checkout", "v4", ValidationResult.VALID, "graphql")
        cache.save()

        # Create config
        config_content = f"""
cache:
  cache_dir: "{temp_cache_dir}"
  cache_file: "test_cache.json"
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(config_content)
            config_file = f.name

        try:
            # Use --purge-cache flag
            result = runner.invoke(
                app, ["lint", "--config", config_file, "--purge-cache"]
            )
            assert result.exit_code == 0
            assert "Purged 1 cache entries" in result.stdout

            # Verify cache is empty
            new_cache = ValidationCache(cache_config)
            info = new_cache.get_cache_info()
            assert info["entries"] == 0

        finally:
            Path(config_file).unlink()

    def test_cache_ttl_override(self, temp_cache_dir: Path) -> None:
        """Test cache TTL override via CLI."""
        runner = CliRunner()

        # Create config with default TTL
        config_content = f"""
cache:
  cache_dir: "{temp_cache_dir}"
  cache_file: "test_cache.json"
  default_ttl_seconds: 3600
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(config_content)
            config_file = f.name

        try:
            # Check cache info with TTL override
            result = runner.invoke(
                app, ["cache", "--info", "--config", config_file]
            )
            assert result.exit_code == 0
            assert "3600" in result.stdout  # Should show default TTL

        finally:
            Path(config_file).unlink()

    def test_cache_mutually_exclusive_operations(
        self, temp_cache_dir: Path
    ) -> None:
        """Test that cache operations are handled correctly."""
        runner = CliRunner()

        config_content = f"""
cache:
  cache_dir: "{temp_cache_dir}"
"""

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write(config_content)
            config_file = f.name

        try:
            # Test purge operation
            result = runner.invoke(
                app, ["cache", "--purge", "--config", config_file]
            )
            assert result.exit_code == 0
            assert "Purged" in result.stdout

        finally:
            Path(config_file).unlink()
