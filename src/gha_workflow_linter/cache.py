# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Local caching module for gha-workflow-linter validation results."""

from __future__ import annotations

import json
import logging
from pathlib import Path
import time
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .models import ValidationResult  # noqa: TC001


class CachedValidationEntry(BaseModel):  # type: ignore[misc]
    """Represents a cached validation result entry."""

    model_config = ConfigDict(frozen=True)

    repository: str = Field(..., description="Full repository name (org/repo)")
    reference: str = Field(..., description="Git reference (tag/branch/sha)")
    result: ValidationResult = Field(..., description="Validation result")
    timestamp: float = Field(..., description="Unix timestamp when cached")
    api_call_type: str = Field(
        ..., description="Type of API call that generated this result"
    )
    error_message: str | None = Field(
        None, description="Error message if validation failed"
    )

    def is_expired(self, ttl_seconds: int) -> bool:
        """Check if the cache entry has expired."""
        return time.time() - self.timestamp > ttl_seconds

    @property
    def age_seconds(self) -> float:
        """Get the age of this cache entry in seconds."""
        return time.time() - self.timestamp


class CacheConfig(BaseModel):  # type: ignore[misc]
    """Configuration for the local cache system."""

    model_config = ConfigDict(frozen=True)

    enabled: bool = Field(True, description="Enable local caching")
    cache_dir: Path = Field(
        Path.home() / ".cache" / "gha-workflow-linter",
        description="Directory to store cache files",
    )
    cache_file: str = Field(
        "validation_cache.json", description="Cache file name"
    )
    default_ttl_seconds: int = Field(
        7 * 24 * 60 * 60,  # 7 days
        description="Default TTL for cache entries in seconds",
    )
    max_cache_size: int = Field(
        10000, description="Maximum number of cache entries"
    )
    cleanup_on_startup: bool = Field(
        True, description="Clean expired entries on startup"
    )

    @property
    def cache_file_path(self) -> Path:
        """Get the full path to the cache file."""
        return self.cache_dir / self.cache_file


class CacheStats(BaseModel):  # type: ignore[misc]
    """Statistics for cache operations."""

    hits: int = Field(0, description="Number of cache hits")
    misses: int = Field(0, description="Number of cache misses")
    expired: int = Field(0, description="Number of expired entries encountered")
    writes: int = Field(0, description="Number of cache writes")
    purges: int = Field(0, description="Number of cache purges")
    cleanup_removed: int = Field(
        0, description="Number of entries removed during cleanup"
    )

    @property
    def total_requests(self) -> int:
        """Total number of cache requests."""
        return self.hits + self.misses

    @property
    def hit_rate(self) -> float:
        """Cache hit rate as a percentage."""
        if self.total_requests == 0:
            return 0.0
        return (self.hits / self.total_requests) * 100


class ValidationCache:
    """Local cache for validation results."""

    def __init__(self, config: CacheConfig) -> None:
        """
        Initialize the validation cache.

        Args:
            config: Cache configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.stats = CacheStats()
        self._cache: dict[str, CachedValidationEntry] = {}
        self._loaded = False

    def _generate_cache_key(self, repository: str, reference: str) -> str:
        """Generate a cache key for a repository and reference."""
        return f"{repository}@{reference}"

    def _load_cache(self) -> None:
        """Load cache from disk."""
        if self._loaded or not self.config.enabled:
            return

        try:
            if not self.config.cache_file_path.exists():
                self.logger.debug(
                    "Cache file does not exist, starting with empty cache"
                )
                self._loaded = True
                return

            self.logger.debug(
                f"Loading cache from {self.config.cache_file_path}"
            )

            with open(self.config.cache_file_path, encoding="utf-8") as f:
                cache_data = json.load(f)

            # Convert JSON data back to CachedValidationEntry objects
            for key, entry_data in cache_data.items():
                try:
                    entry = CachedValidationEntry(**entry_data)
                    self._cache[key] = entry
                except Exception as e:
                    self.logger.warning(
                        f"Invalid cache entry for key {key}: {e}"
                    )

            self.logger.info(f"Loaded {len(self._cache)} entries from cache")

            # Cleanup expired entries if configured
            if self.config.cleanup_on_startup:
                self._cleanup_expired()

        except Exception as e:
            self.logger.warning(f"Failed to load cache: {e}")
            self._cache = {}

        self._loaded = True

    def _save_cache(self) -> None:
        """Save cache to disk."""
        if not self.config.enabled:
            return

        try:
            # Ensure cache directory exists
            self.config.cache_dir.mkdir(parents=True, exist_ok=True)

            # Convert cache entries to JSON-serializable format
            cache_data = {}
            for key, entry in self._cache.items():
                cache_data[key] = entry.model_dump()

            # Write to temporary file first, then rename for atomicity
            temp_file = self.config.cache_file_path.with_suffix(".tmp")
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)

            temp_file.replace(self.config.cache_file_path)
            self.logger.debug(f"Saved {len(self._cache)} entries to cache")

        except Exception as e:
            self.logger.warning(f"Failed to save cache: {e}")

    def _cleanup_expired(self) -> None:
        """Remove expired entries from cache."""
        if not self.config.enabled:
            return

        expired_keys = []

        for key, entry in self._cache.items():
            if entry.is_expired(self.config.default_ttl_seconds):
                expired_keys.append(key)

        for key in expired_keys:
            del self._cache[key]

        removed_count = len(expired_keys)
        if removed_count > 0:
            self.stats.cleanup_removed += removed_count
            self.logger.debug(f"Removed {removed_count} expired cache entries")

    def _enforce_cache_size_limit(self) -> None:
        """Ensure cache doesn't exceed maximum size."""
        if len(self._cache) <= self.config.max_cache_size:
            return

        # Remove oldest entries first
        sorted_entries = sorted(
            self._cache.items(), key=lambda x: x[1].timestamp
        )

        entries_to_remove = len(self._cache) - self.config.max_cache_size
        for i in range(entries_to_remove):
            key = sorted_entries[i][0]
            del self._cache[key]

        self.logger.debug(
            f"Removed {entries_to_remove} entries to enforce cache size limit"
        )

    def get(
        self, repository: str, reference: str
    ) -> CachedValidationEntry | None:
        """
        Get a cached validation result.

        Args:
            repository: Full repository name (org/repo)
            reference: Git reference

        Returns:
            Cached entry if found and not expired, None otherwise
        """
        if not self.config.enabled:
            return None

        self._load_cache()

        cache_key = self._generate_cache_key(repository, reference)
        entry = self._cache.get(cache_key)

        if entry is None:
            self.stats.misses += 1
            return None

        if entry.is_expired(self.config.default_ttl_seconds):
            self.stats.expired += 1
            # Remove expired entry
            del self._cache[cache_key]
            return None

        self.stats.hits += 1
        self.logger.debug(f"Cache hit for {repository}@{reference}")
        return entry

    def put(
        self,
        repository: str,
        reference: str,
        result: ValidationResult,
        api_call_type: str,
        error_message: str | None = None,
    ) -> None:
        """
        Store a validation result in the cache.

        Args:
            repository: Full repository name (org/repo)
            reference: Git reference
            result: Validation result
            api_call_type: Type of API call that generated this result
            error_message: Optional error message
        """
        if not self.config.enabled:
            return

        self._load_cache()

        cache_key = self._generate_cache_key(repository, reference)
        entry = CachedValidationEntry(
            repository=repository,
            reference=reference,
            result=result,
            timestamp=time.time(),
            api_call_type=api_call_type,
            error_message=error_message,
        )

        self._cache[cache_key] = entry
        self.stats.writes += 1

        # Enforce size limit
        self._enforce_cache_size_limit()

        self.logger.debug(
            f"Cached validation result for {repository}@{reference}: {result}"
        )

    def get_batch(
        self, repo_refs: list[tuple[str, str]]
    ) -> tuple[
        dict[tuple[str, str], CachedValidationEntry], list[tuple[str, str]]
    ]:
        """
        Get multiple cached validation results.

        Args:
            repo_refs: List of (repository, reference) tuples

        Returns:
            Tuple of (cached_results, cache_misses)
        """
        if not self.config.enabled:
            return {}, repo_refs

        cached_results = {}
        cache_misses = []

        for repo, ref in repo_refs:
            entry = self.get(repo, ref)
            if entry is not None:
                cached_results[(repo, ref)] = entry
            else:
                cache_misses.append((repo, ref))

        return cached_results, cache_misses

    def put_batch(
        self, results: list[tuple[str, str, ValidationResult, str, str | None]]
    ) -> None:
        """
        Store multiple validation results in the cache.

        Args:
            results: List of (repository, reference, result, api_call_type, error_message) tuples
        """
        if not self.config.enabled:
            return

        for repo, ref, result, api_call_type, error_message in results:
            self.put(repo, ref, result, api_call_type, error_message)

        # Save cache after batch update
        self._save_cache()

    def purge(self) -> int:
        """
        Clear all cache entries.

        Returns:
            Number of entries removed
        """
        if not self.config.enabled:
            return 0

        self._load_cache()

        removed_count = len(self._cache)
        self._cache.clear()
        self.stats.purges += 1

        # Remove cache file
        try:
            if self.config.cache_file_path.exists():
                self.config.cache_file_path.unlink()
                self.logger.info("Cache file removed")
        except Exception as e:
            self.logger.warning(f"Failed to remove cache file: {e}")

        self.logger.info(f"Purged {removed_count} cache entries")
        return removed_count

    def cleanup(self) -> int:
        """
        Remove expired entries from cache.

        Returns:
            Number of entries removed
        """
        if not self.config.enabled:
            return 0

        self._load_cache()

        before_count = len(self._cache)
        self._cleanup_expired()
        removed_count = before_count - len(self._cache)

        if removed_count > 0:
            self._save_cache()

        return removed_count

    def get_cache_info(self) -> dict[str, Any]:
        """
        Get information about the cache state.

        Returns:
            Dictionary with cache information
        """
        if not self.config.enabled:
            return {
                "enabled": False,
                "cache_file": str(self.config.cache_file_path),
                "cache_file_exists": False,
                "entries": 0,
                "expired_entries": 0,
                "oldest_entry_age": None,
                "newest_entry_age": None,
                "max_cache_size": self.config.max_cache_size,
                "ttl_seconds": self.config.default_ttl_seconds,
                "stats": self.stats.model_dump(),
            }

        self._load_cache()

        # Count expired entries
        expired_count = 0
        oldest_timestamp = None
        newest_timestamp = None

        for entry in self._cache.values():
            if entry.is_expired(self.config.default_ttl_seconds):
                expired_count += 1

            if oldest_timestamp is None or entry.timestamp < oldest_timestamp:
                oldest_timestamp = entry.timestamp

            if newest_timestamp is None or entry.timestamp > newest_timestamp:
                newest_timestamp = entry.timestamp

        return {
            "enabled": True,
            "cache_file": str(self.config.cache_file_path),
            "cache_file_exists": self.config.cache_file_path.exists(),
            "entries": len(self._cache),
            "expired_entries": expired_count,
            "oldest_entry_age": time.time() - oldest_timestamp
            if oldest_timestamp
            else None,
            "newest_entry_age": time.time() - newest_timestamp
            if newest_timestamp
            else None,
            "max_cache_size": self.config.max_cache_size,
            "ttl_seconds": self.config.default_ttl_seconds,
            "stats": self.stats.model_dump(),
        }

    def save(self) -> None:
        """Force save cache to disk."""
        if self.config.enabled and self._loaded:
            self._save_cache()
