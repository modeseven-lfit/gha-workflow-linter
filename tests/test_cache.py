# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for the cache module."""

from collections.abc import Generator
from pathlib import Path
import tempfile
import time

import pytest

from gha_workflow_linter.cache import (
    CacheConfig,
    CachedValidationEntry,
    ValidationCache,
)
from gha_workflow_linter.models import ValidationMethod, ValidationResult


class TestCacheConfig:
    """Test CacheConfig model."""

    def test_default_config(self) -> None:
        """Test default cache configuration."""
        config = CacheConfig()

        assert config.enabled is True
        assert (
            config.cache_dir == Path.home() / ".cache" / "gha-workflow-linter"
        )
        assert config.cache_file == "validation_cache.json"
        assert config.default_ttl_seconds == 7 * 24 * 60 * 60  # 7 days
        assert config.max_cache_size == 10000
        assert config.cleanup_on_startup is True

    def test_cache_file_path(self) -> None:
        """Test cache file path property."""
        config = CacheConfig()
        expected_path = config.cache_dir / config.cache_file
        assert config.cache_file_path == expected_path

    def test_custom_config(self) -> None:
        """Test custom cache configuration."""
        custom_dir = Path("/tmp/test-cache")
        config = CacheConfig(
            enabled=False,
            cache_dir=custom_dir,
            cache_file="test_cache.json",
            default_ttl_seconds=3600,
            max_cache_size=500,
            cleanup_on_startup=False,
        )

        assert config.enabled is False
        assert config.cache_dir == custom_dir
        assert config.cache_file == "test_cache.json"
        assert config.default_ttl_seconds == 3600
        assert config.max_cache_size == 500
        assert config.cleanup_on_startup is False


class TestCachedValidationEntry:
    """Test CachedValidationEntry model."""

    def test_entry_creation(self) -> None:
        """Test creating a cache entry."""
        timestamp = time.time()
        entry = CachedValidationEntry(
            repository="owner/repo",
            reference="v1.0.0",
            result=ValidationResult.VALID,
            timestamp=timestamp,
            api_call_type="graphql",
            error_message=None,
        )

        assert entry.repository == "owner/repo"
        assert entry.reference == "v1.0.0"
        assert entry.result == ValidationResult.VALID
        assert entry.timestamp == timestamp
        assert entry.api_call_type == "graphql"
        assert entry.error_message is None

    def test_is_expired(self) -> None:
        """Test expiration checking."""
        # Create entry that's 10 seconds old
        old_timestamp = time.time() - 10
        entry = CachedValidationEntry(
            repository="owner/repo",
            reference="v1.0.0",
            result=ValidationResult.VALID,
            timestamp=old_timestamp,
            api_call_type="graphql",
        )

        # Should not be expired with 20 second TTL
        assert not entry.is_expired(20)

        # Should be expired with 5 second TTL
        assert entry.is_expired(5)

    def test_age_seconds(self) -> None:
        """Test age calculation."""
        timestamp = time.time() - 5
        entry = CachedValidationEntry(
            repository="owner/repo",
            reference="v1.0.0",
            result=ValidationResult.VALID,
            timestamp=timestamp,
            api_call_type="graphql",
        )

        age = entry.age_seconds
        assert 4.5 <= age <= 5.5  # Allow some tolerance for test execution time


class TestValidationCache:
    """Test ValidationCache functionality."""

    @pytest.fixture
    def temp_cache_config(self) -> Generator[CacheConfig, None, None]:
        """Create a temporary cache configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = CacheConfig(
                enabled=True,
                cache_dir=Path(temp_dir),
                cache_file="test_cache.json",
                default_ttl_seconds=3600,  # 1 hour
                max_cache_size=100,
                cleanup_on_startup=True,
            )
            yield config

    def test_cache_initialization(self, temp_cache_config: CacheConfig) -> None:
        """Test cache initialization."""
        cache = ValidationCache(temp_cache_config)

        assert cache.config == temp_cache_config
        assert cache.stats.hits == 0
        assert cache.stats.misses == 0
        assert cache._loaded is False

    def test_cache_disabled(self) -> None:
        """Test cache behavior when disabled."""
        config = CacheConfig(enabled=False)
        cache = ValidationCache(config)

        # Should return None for all operations
        assert cache.get("owner/repo", "v1.0.0") is None

        # Put should do nothing
        cache.put("owner/repo", "v1.0.0", ValidationResult.VALID, "graphql")
        assert cache.get("owner/repo", "v1.0.0") is None

    def test_cache_put_and_get(self, temp_cache_config: CacheConfig) -> None:
        """Test basic cache put and get operations."""
        cache = ValidationCache(temp_cache_config)

        # Initially should be a miss
        result = cache.get("owner/repo", "v1.0.0")
        assert result is None
        assert cache.stats.misses == 1

        # Store a result
        cache.put("owner/repo", "v1.0.0", ValidationResult.VALID, "graphql")
        assert cache.stats.writes == 1

        # Should now be a hit
        result = cache.get("owner/repo", "v1.0.0")
        assert result is not None
        assert result.repository == "owner/repo"
        assert result.reference == "v1.0.0"
        assert result.result == ValidationResult.VALID
        assert result.api_call_type == "graphql"
        assert cache.stats.hits == 1

    def test_cache_expiration(self, temp_cache_config: CacheConfig) -> None:
        """Test cache entry expiration."""
        # Set short TTL
        temp_cache_config = CacheConfig(
            enabled=True,
            cache_dir=temp_cache_config.cache_dir,
            cache_file="test_cache.json",
            default_ttl_seconds=1,  # 1 second
            max_cache_size=100,
        )
        cache = ValidationCache(temp_cache_config)

        # Store a result
        cache.put("owner/repo", "v1.0.0", ValidationResult.VALID, "graphql")

        # Should be available immediately
        result = cache.get("owner/repo", "v1.0.0")
        assert result is not None

        # Wait for expiration
        time.sleep(1.1)

        # Should now be expired
        result = cache.get("owner/repo", "v1.0.0")
        assert result is None
        assert cache.stats.expired == 1

    def test_cache_persistence(self, temp_cache_config: CacheConfig) -> None:
        """Test cache persistence to disk."""
        # Create first cache instance and store data
        cache1 = ValidationCache(temp_cache_config)
        cache1.put("owner/repo", "v1.0.0", ValidationResult.VALID, "graphql")
        cache1.put(
            "owner/repo2",
            "v2.0.0",
            ValidationResult.INVALID_REPOSITORY,
            "graphql",
            ValidationMethod.GITHUB_API,
            "Not found",
        )
        cache1.save()

        # Create second cache instance (should load from disk)
        cache2 = ValidationCache(temp_cache_config)

        # Should find the cached entries
        result1 = cache2.get("owner/repo", "v1.0.0")
        assert result1 is not None
        assert result1.result == ValidationResult.VALID

        result2 = cache2.get("owner/repo2", "v2.0.0")
        assert result2 is not None
        assert result2.result == ValidationResult.INVALID_REPOSITORY
        assert result2.error_message == "Not found"

    def test_cache_batch_operations(
        self, temp_cache_config: CacheConfig
    ) -> None:
        """Test batch cache operations."""
        cache = ValidationCache(temp_cache_config)

        # Store batch of results
        batch_data = [
            (
                "owner/repo1",
                "v1.0.0",
                ValidationResult.VALID,
                "graphql",
                ValidationMethod.GITHUB_API,
                None,
            ),
            (
                "owner/repo2",
                "v2.0.0",
                ValidationResult.INVALID_REPOSITORY,
                "graphql",
                ValidationMethod.GITHUB_API,
                "Not found",
            ),
            (
                "owner/repo3",
                "v3.0.0",
                ValidationResult.VALID,
                "graphql",
                ValidationMethod.GITHUB_API,
                None,
            ),
        ]
        cache.put_batch(batch_data)

        # Test batch get
        repo_refs = [
            ("owner/repo1", "v1.0.0"),
            ("owner/repo2", "v2.0.0"),
            ("owner/repo3", "v3.0.0"),
            ("owner/repo4", "v4.0.0"),  # This one should be a miss
        ]

        cached_results, cache_misses = cache.get_batch(repo_refs)

        assert len(cached_results) == 3
        assert len(cache_misses) == 1
        assert cache_misses[0] == ("owner/repo4", "v4.0.0")

        assert ("owner/repo1", "v1.0.0") in cached_results
        assert ("owner/repo2", "v2.0.0") in cached_results
        assert ("owner/repo3", "v3.0.0") in cached_results

    def test_cache_size_limit(self, temp_cache_config: CacheConfig) -> None:
        """Test cache size limit enforcement."""
        # Set small cache size
        temp_cache_config = CacheConfig(
            enabled=True,
            cache_dir=temp_cache_config.cache_dir,
            cache_file="test_cache.json",
            default_ttl_seconds=3600,
            max_cache_size=3,
        )
        cache = ValidationCache(temp_cache_config)

        # Add more entries than the limit
        for i in range(5):
            cache.put(
                f"owner/repo{i}", "v1.0.0", ValidationResult.VALID, "graphql"
            )
            time.sleep(0.01)  # Ensure different timestamps

        # Should only have 3 entries (oldest should be removed)
        cache_info = cache.get_cache_info()
        assert cache_info["entries"] == 3

        # Oldest entries should be gone
        assert cache.get("owner/repo0", "v1.0.0") is None
        assert cache.get("owner/repo1", "v1.0.0") is None

        # Newest entries should still be there
        assert cache.get("owner/repo2", "v1.0.0") is not None
        assert cache.get("owner/repo3", "v1.0.0") is not None
        assert cache.get("owner/repo4", "v1.0.0") is not None

    def test_cache_cleanup(self, temp_cache_config: CacheConfig) -> None:
        """Test cache cleanup of expired entries."""
        # Set short TTL
        temp_cache_config = CacheConfig(
            enabled=True,
            cache_dir=temp_cache_config.cache_dir,
            cache_file="test_cache.json",
            default_ttl_seconds=1,  # 1 second
            max_cache_size=100,
        )
        cache = ValidationCache(temp_cache_config)

        # Add some entries
        cache.put("owner/repo1", "v1.0.0", ValidationResult.VALID, "graphql")
        cache.put("owner/repo2", "v2.0.0", ValidationResult.VALID, "graphql")

        # Wait for expiration
        time.sleep(1.1)

        # Add a fresh entry
        cache.put("owner/repo3", "v3.0.0", ValidationResult.VALID, "graphql")

        # Cleanup should remove expired entries
        removed_count = cache.cleanup()
        assert removed_count == 2

        # Only the fresh entry should remain
        assert cache.get("owner/repo1", "v1.0.0") is None
        assert cache.get("owner/repo2", "v2.0.0") is None
        assert cache.get("owner/repo3", "v3.0.0") is not None

    def test_cache_purge(self, temp_cache_config: CacheConfig) -> None:
        """Test cache purge functionality."""
        cache = ValidationCache(temp_cache_config)

        # Add some entries
        cache.put("owner/repo1", "v1.0.0", ValidationResult.VALID, "graphql")
        cache.put("owner/repo2", "v2.0.0", ValidationResult.VALID, "graphql")
        cache.save()

        # Purge should remove all entries
        removed_count = cache.purge()
        assert removed_count == 2

        # Cache should be empty
        cache_info = cache.get_cache_info()
        assert cache_info["entries"] == 0

        # Cache file should be removed
        assert not temp_cache_config.cache_file_path.exists()

    def test_cache_info(self, temp_cache_config: CacheConfig) -> None:
        """Test cache information reporting."""
        cache = ValidationCache(temp_cache_config)

        # Empty cache info
        info = cache.get_cache_info()
        assert info["enabled"] is True
        assert info["entries"] == 0
        assert info["cache_file_exists"] is False

        # Add some entries
        cache.put("owner/repo1", "v1.0.0", ValidationResult.VALID, "graphql")
        cache.put("owner/repo2", "v2.0.0", ValidationResult.VALID, "graphql")
        cache.save()

        # Updated cache info
        info = cache.get_cache_info()
        assert info["enabled"] is True
        assert info["entries"] == 2
        assert info["cache_file_exists"] is True
        assert info["max_cache_size"] == temp_cache_config.max_cache_size
        assert info["ttl_seconds"] == temp_cache_config.default_ttl_seconds

    def test_cache_stats(self, temp_cache_config: CacheConfig) -> None:
        """Test cache statistics tracking."""
        cache = ValidationCache(temp_cache_config)

        # Initial stats
        assert cache.stats.hits == 0
        assert cache.stats.misses == 0
        assert cache.stats.writes == 0
        assert cache.stats.hit_rate == 0.0

        # Generate some activity
        cache.get("owner/repo", "v1.0.0")  # miss
        cache.put(
            "owner/repo", "v1.0.0", ValidationResult.VALID, "graphql"
        )  # write
        cache.get("owner/repo", "v1.0.0")  # hit
        cache.get("owner/repo", "v2.0.0")  # miss

        # Check updated stats
        assert cache.stats.hits == 1
        assert cache.stats.misses == 2
        assert cache.stats.writes == 1
        assert cache.stats.total_requests == 3
        assert cache.stats.hit_rate == pytest.approx(33.33, rel=1e-2)

    def test_invalid_cache_file(self, temp_cache_config: CacheConfig) -> None:
        """Test handling of invalid cache file."""
        cache = ValidationCache(temp_cache_config)

        # Create invalid JSON file
        temp_cache_config.cache_dir.mkdir(parents=True, exist_ok=True)
        with open(temp_cache_config.cache_file_path, "w") as f:
            f.write("invalid json content")

        # Should handle gracefully and start with empty cache
        result = cache.get("owner/repo", "v1.0.0")
        assert result is None
        assert cache.stats.misses == 1

    def test_cache_key_generation(self, temp_cache_config: CacheConfig) -> None:
        """Test cache key generation."""
        cache = ValidationCache(temp_cache_config)

        # Test key generation
        key1 = cache._generate_cache_key("owner/repo", "v1.0.0")
        key2 = cache._generate_cache_key("owner/repo", "v2.0.0")
        key3 = cache._generate_cache_key("other/repo", "v1.0.0")

        assert key1 == "owner/repo@v1.0.0"
        assert key2 == "owner/repo@v2.0.0"
        assert key3 == "other/repo@v1.0.0"

        # Keys should be unique
        assert key1 != key2
        assert key1 != key3
        assert key2 != key3
