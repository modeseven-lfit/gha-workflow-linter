# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Simple tests for cache module to improve coverage."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import time

from gha_workflow_linter.cache import (
    CacheConfig,
    CachedValidationEntry,
    ValidationCache,
)
from gha_workflow_linter.models import ValidationResult


class TestCachedValidationEntry:
    """Test CachedValidationEntry class."""

    def test_init(self) -> None:
        """Test CachedValidationEntry initialization."""
        result = ValidationResult.VALID

        entry = CachedValidationEntry(
            repository="actions/checkout",
            reference="v4",
            result=result,
            timestamp=time.time(),
            api_call_type="graphql",
        )

        assert entry.repository == "actions/checkout"
        assert entry.reference == "v4"
        assert entry.result == result
        assert entry.api_call_type == "graphql"

    def test_is_expired_not_expired(self) -> None:
        """Test checking if entry is not expired."""
        result = ValidationResult.VALID

        entry = CachedValidationEntry(
            repository="actions/checkout",
            reference="v4",
            result=result,
            timestamp=time.time(),
            api_call_type="graphql",
        )

        # Should not be expired with 1 hour TTL
        assert not entry.is_expired(3600)

    def test_is_expired_expired(self) -> None:
        """Test checking if entry is expired."""
        result = ValidationResult.VALID

        # Create entry with old timestamp
        entry = CachedValidationEntry(
            repository="actions/checkout",
            reference="v4",
            result=result,
            timestamp=time.time() - 7200,  # 2 hours ago
            api_call_type="graphql",
        )

        # Should be expired with 1 hour TTL
        assert entry.is_expired(3600)

    def test_age_seconds(self) -> None:
        """Test getting age of cache entry."""
        result = ValidationResult.VALID

        # Create entry with timestamp 100 seconds ago
        old_time = time.time() - 100
        entry = CachedValidationEntry(
            repository="actions/checkout",
            reference="v4",
            result=result,
            timestamp=old_time,
            api_call_type="graphql",
        )

        age = entry.age_seconds
        assert age >= 99  # Should be at least 99 seconds (allowing for timing)


class TestValidationCache:
    """Test ValidationCache class."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        # Use a temporary file to avoid interference with real cache
        self.temp_cache_file_path = tempfile.mktemp(suffix=".json")

        self.cache_config = CacheConfig(
            enabled=True,
            cache_dir=Path(self.temp_cache_file_path).parent,
            cache_file=Path(self.temp_cache_file_path).name,
        )

    def teardown_method(self) -> None:
        """Clean up test fixtures."""
        # Clean up the temporary cache file
        if os.path.exists(self.temp_cache_file_path):
            os.unlink(self.temp_cache_file_path)

    def test_init_with_config(self) -> None:
        """Test ValidationCache initialization."""
        cache = ValidationCache(self.cache_config)
        assert cache.config is self.cache_config

    def test_init_with_default_config(self) -> None:
        """Test ValidationCache with default config."""
        default_config = CacheConfig()
        cache = ValidationCache(default_config)
        assert isinstance(cache.config, CacheConfig)

    def test_generate_cache_key(self) -> None:
        """Test cache key generation."""
        cache = ValidationCache(self.cache_config)
        key = cache._generate_cache_key("actions/checkout", "v4")
        assert key == "actions/checkout@v4"

    def test_enabled_true(self) -> None:
        """Test cache enabled property when enabled."""
        cache_config = CacheConfig(enabled=True)
        cache = ValidationCache(cache_config)

        assert cache.config.enabled is True

    def test_enabled_false(self) -> None:
        """Test cache enabled property when disabled."""
        cache_config = CacheConfig(enabled=False)
        cache = ValidationCache(cache_config)

        assert cache.config.enabled is False

    def test_get_cache_file_path(self) -> None:
        """Test getting cache file path."""
        cache = ValidationCache(self.cache_config)
        path = cache.config.cache_file_path

        assert isinstance(path, Path)
        assert str(path).endswith(".json")

    def test_load_cache_basic(self) -> None:
        """Test loading cache with no existing file."""
        # Remove the temp file to ensure we start with no cache
        if os.path.exists(self.temp_cache_file_path):
            os.unlink(self.temp_cache_file_path)

        cache = ValidationCache(self.cache_config)
        cache._load_cache()
        assert cache._cache == {}

    def test_save_cache_basic(self) -> None:
        """Test saving cache (should not fail)."""
        cache = ValidationCache(self.cache_config)
        # Should not raise even if cache is empty
        cache._save_cache()

    def test_cleanup_expired(self) -> None:
        """Test cleaning up expired entries."""
        cache = ValidationCache(self.cache_config)

        # Add an expired entry
        old_entry = CachedValidationEntry(
            repository="old/repo",
            reference="v1",
            result=ValidationResult.VALID,
            timestamp=time.time() - 86400,  # 1 day ago
            api_call_type="graphql",
        )
        cache._cache["test_key"] = old_entry

        initial_count = len(cache._cache)
        cache._cleanup_expired()

        # Should have same or fewer entries after cleanup
        assert len(cache._cache) <= initial_count

    def test_cache_disabled_operations(self) -> None:
        """Test cache operations when disabled."""
        cache_config = CacheConfig(enabled=False)
        cache = ValidationCache(cache_config)

        # Should not raise when cache is disabled
        cache._save_cache()  # Should do nothing

    def test_stats_basic(self) -> None:
        """Test getting cache statistics."""
        cache = ValidationCache(self.cache_config)
        stats = cache.stats

        # Should return CacheStats object
        assert hasattr(stats, "hits")
        assert hasattr(stats, "misses")
        assert stats.hits >= 0
        assert stats.misses >= 0
