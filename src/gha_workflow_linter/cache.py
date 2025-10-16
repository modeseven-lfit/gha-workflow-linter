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

from ._version import __version__
from .models import CacheConfig, ValidationMethod, ValidationResult  # noqa: TC001

# Re-export CacheConfig for backward compatibility
__all__ = [
    "CacheConfig",
    "CachedValidationEntry",
    "CacheStats",
    "ValidationCache",
]


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
    validation_method: ValidationMethod = Field(
        ValidationMethod.GITHUB_API, description="Validation method used"
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
    """
    Local cache for validation results with version-based invalidation.

    The cache automatically purges all entries when the tool version changes,
    ensuring that validation logic changes don't result in stale cache data.
    """

    def __init__(self, config: CacheConfig) -> None:
        """
        Initialize the validation cache.

        Args:
            config: Cache configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.stats = CacheStats(
            hits=0,
            misses=0,
            expired=0,
            writes=0,
            purges=0,
            cleanup_removed=0,
        )
        self._cache: dict[str, CachedValidationEntry] = {}
        self._cache_version: str = __version__
        self._loaded = False

    def _generate_cache_key(self, repository: str, reference: str) -> str:
        """Generate a cache key for a repository and reference."""
        return f"{repository}@{reference}"

    def _load_cache(self) -> None:
        """
        Load cache from disk with version validation.

        If the cache was created with a different version of the tool,
        it will be automatically purged to prevent validation inconsistencies.
        """
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

            # Check cache version compatibility
            cache_version = cache_data.get("_metadata", {}).get("version")
            if cache_version != __version__:
                if cache_version:
                    self.logger.info(
                        f"Cache version mismatch (cache: {cache_version}, "
                        f"current: {__version__}). Purging cache for consistency."
                    )
                else:
                    self.logger.info(
                        "Legacy cache format detected (no version info). "
                        "Purging cache for consistency."
                    )
                self._purge_cache_file()
                self._loaded = True
                return

            # Load cache entries (skip metadata)
            entry_count = 0
            for key, entry_data in cache_data.items():
                if key == "_metadata":
                    continue
                try:
                    entry = CachedValidationEntry(**entry_data)
                    self._cache[key] = entry
                    entry_count += 1
                except Exception as e:
                    self.logger.warning(
                        f"Invalid cache entry for key {key}: {e}"
                    )

            self.logger.info(
                f"Loaded {entry_count} entries from cache (version {cache_version})"
            )

            # Cleanup expired entries if configured
            if self.config.cleanup_on_startup:
                self._cleanup_expired()

        except Exception as e:
            self.logger.warning(f"Failed to load cache: {e}")
            self._cache = {}

        self._loaded = True

    def _save_cache(self) -> None:
        """
        Save cache to disk with version metadata.

        The version information is embedded in the cache file to enable
        automatic invalidation when the tool version changes.
        """
        if not self.config.enabled or not self._loaded:
            return

        try:
            # Ensure parent directory exists
            self.config.cache_file_path.parent.mkdir(
                parents=True, exist_ok=True
            )

            # Convert cache entries to JSON-serializable format
            cache_data = {
                "_metadata": {
                    "version": __version__,
                    "created_timestamp": time.time(),
                    "entry_count": len(self._cache),
                }
            }

            for key, entry in self._cache.items():
                cache_data[key] = entry.model_dump()

            # Use atomic write to prevent corruption
            temp_file = self.config.cache_file_path.with_suffix(".tmp")
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)

            temp_file.replace(self.config.cache_file_path)
            self.logger.debug(
                f"Saved {len(self._cache)} entries to cache (version {__version__})"
            )

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
        validation_method: ValidationMethod = ValidationMethod.GITHUB_API,
        error_message: str | None = None,
    ) -> None:
        """
        Store a validation result in the cache.

        Args:
            repository: Full repository name (org/repo)
            reference: Git reference
            result: Validation result
            api_call_type: Type of API call that generated this result
            validation_method: Validation method used
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
            validation_method=validation_method,
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
        self,
        results: list[
            tuple[str, str, ValidationResult, str, ValidationMethod, str | None]
        ],
    ) -> None:
        """
        Store multiple validation results in the cache.

        Args:
            results: List of (repository, reference, result, api_call_type, validation_method, error_message) tuples
        """
        if not self.config.enabled:
            return

        for (
            repo,
            ref,
            result,
            api_call_type,
            validation_method,
            error_message,
        ) in results:
            self.put(
                repo,
                ref,
                result,
                api_call_type,
                validation_method,
                error_message,
            )

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

        purged_count = len(self._cache)
        self._cache.clear()
        self.stats.purges += 1

        # Remove cache file from disk
        self._purge_cache_file()

        if purged_count > 0:
            self.logger.debug(f"Purged {purged_count} cache entries")

        return purged_count

    def _purge_cache_file(self) -> None:
        """Remove cache file from disk."""
        try:
            if self.config.cache_file_path.exists():
                self.config.cache_file_path.unlink()
                self.logger.debug("Removed cache file from disk")
        except Exception as e:
            self.logger.warning(f"Failed to remove cache file: {e}")

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
            "cache_version": self._cache_version,
            "current_version": __version__,
            "stats": self.stats.model_dump(),
        }

    def detect_suspicious_cache_patterns(self) -> dict[str, Any]:
        """
        Detect suspicious patterns in cache that might indicate invalid entries.

        This includes version mismatches, high error rates, and invalid well-known repositories.

        Returns:
            Dictionary with analysis of cache patterns
        """
        if not self.config.enabled or not self._loaded:
            return {"suspicious": False, "reason": "Cache not loaded"}

        self._load_cache()

        # Check for version mismatch first
        if self._cache_version != __version__:
            return {
                "suspicious": True,
                "reason": f"Version mismatch (cache: {self._cache_version}, current: {__version__})",
                "total_entries": len(self._cache),
                "reasons": [
                    f"Cache version {self._cache_version} != current version {__version__}"
                ],
            }

        if len(self._cache) == 0:
            return {"suspicious": False, "reason": "Empty cache"}

        total_entries = len(self._cache)
        invalid_entries = 0
        network_error_entries = 0
        timeout_entries = 0
        well_known_repos_invalid = 0

        # List of well-known GitHub Actions that should almost always be valid
        well_known_repos = {
            "actions/checkout",
            "actions/setup-node",
            "actions/setup-python",
            "actions/upload-artifact",
            "actions/download-artifact",
            "actions/cache",
            "step-security/harden-runner",
        }

        for entry in self._cache.values():
            if entry.result == ValidationResult.INVALID_REFERENCE:
                invalid_entries += 1
                # Check if this is a well-known repo that's marked invalid
                if entry.repository in well_known_repos:
                    well_known_repos_invalid += 1
            elif entry.result == ValidationResult.INVALID_REPOSITORY:
                invalid_entries += 1
                if entry.repository in well_known_repos:
                    well_known_repos_invalid += 1
            elif entry.result == ValidationResult.NETWORK_ERROR:
                network_error_entries += 1
            elif entry.result == ValidationResult.TIMEOUT:
                timeout_entries += 1

        invalid_percentage = (invalid_entries / total_entries) * 100
        well_known_invalid_percentage = (
            (well_known_repos_invalid / len(well_known_repos)) * 100
            if well_known_repos
            else 0
        )

        reasons: list[str] = []
        analysis: dict[str, Any] = {
            "suspicious": False,
            "total_entries": total_entries,
            "invalid_entries": invalid_entries,
            "invalid_percentage": invalid_percentage,
            "network_error_entries": network_error_entries,
            "timeout_entries": timeout_entries,
            "well_known_repos_invalid": well_known_repos_invalid,
            "well_known_invalid_percentage": well_known_invalid_percentage,
            "reasons": reasons,
        }

        # High percentage of invalid entries is suspicious
        if invalid_percentage > 80:
            analysis["suspicious"] = True
            reasons.append(
                f"High invalid percentage: {invalid_percentage:.1f}%"
            )

        # Well-known repos being invalid is very suspicious
        if well_known_repos_invalid > 3:
            analysis["suspicious"] = True
            reasons.append(
                f"Well-known repos marked invalid: {well_known_repos_invalid}"
            )

        # High network errors might indicate temporary issues that cached bad results
        if network_error_entries > (total_entries * 0.3):
            analysis["suspicious"] = True
            reasons.append(f"High network errors: {network_error_entries}")

        return analysis

    def auto_purge_if_suspicious(self) -> bool:
        """
        Automatically purge cache if suspicious patterns are detected.

        Returns:
            True if cache was purged, False otherwise
        """
        if not self.config.enabled:
            return False

        analysis = self.detect_suspicious_cache_patterns()

        if analysis["suspicious"]:
            self.logger.warning(
                f"Suspicious cache patterns detected: {', '.join(analysis['reasons'])}. "
                f"Auto-purging cache with {analysis['total_entries']} entries."
            )
            purged_count = self.purge()
            self.logger.info(f"Cache purged: {purged_count} entries removed")
            return True

        return False

    def save(self) -> None:
        """Force save cache to disk."""
        if self.config.enabled and self._loaded:
            self._save_cache()
