# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Local caching module for gha-workflow-linter validation results."""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from . import __version__
from .models import (  # noqa: TC001
    CacheConfig,
    ValidationMethod,
    ValidationResult,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

# Re-export CacheConfig for backward compatibility
__all__ = [
    "CacheConfig",
    "CachedValidationEntry",
    "LatestVersionEntry",
    "RepositoryRedirect",
    "CacheStats",
    "ValidationCache",
]


class RepositoryRedirect(BaseModel):
    """Represents a repository that has moved to a new location."""

    model_config = ConfigDict(frozen=True)

    old_repository: str = Field(
        ..., description="Original repository name (org/repo)"
    )
    new_repository: str = Field(
        ..., description="New repository name (org/repo)"
    )
    timestamp: float = Field(
        ..., description="Unix timestamp when redirect was discovered"
    )

    def is_expired(self, ttl_seconds: int) -> bool:
        """Check if the redirect entry has expired."""
        return time.time() - self.timestamp > ttl_seconds

    @property
    def age_seconds(self) -> float:
        """Get the age of this redirect entry in seconds."""
        return time.time() - self.timestamp


class LatestVersionEntry(BaseModel):
    """Represents a cached latest version entry for a repository."""

    model_config = ConfigDict(frozen=True)

    repository: str = Field(..., description="Full repository name (org/repo)")
    latest_tag: str = Field(..., description="Latest release/tag name")
    latest_sha: str = Field(..., description="SHA for the latest tag")
    timestamp: float = Field(..., description="Unix timestamp when cached")
    commit_tags: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Lowercased commit SHA to release tag, covering every release "
            "the resolution considered and not only the selected one. "
            "Retains the ordering information a bare (tag, sha) pair "
            "cannot carry, so a restored entry can still say whether a "
            "pinned commit is behind the cached target or ahead of it. "
            "Empty for entries written by a caller that has no such map."
        ),
    )

    def is_expired(self, ttl_seconds: int) -> bool:
        """Check if the cache entry has expired."""
        return time.time() - self.timestamp > ttl_seconds

    @property
    def age_seconds(self) -> float:
        """Get the age of this cache entry in seconds."""
        return time.time() - self.timestamp


class CachedValidationEntry(BaseModel):
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
        default=ValidationMethod.GITHUB_API,
        description="Validation method used",
    )
    error_message: str | None = Field(
        default=None, description="Error message if validation failed"
    )

    def is_expired(self, ttl_seconds: int) -> bool:
        """Check if the cache entry has expired."""
        return time.time() - self.timestamp > ttl_seconds

    @property
    def age_seconds(self) -> float:
        """Get the age of this cache entry in seconds."""
        return time.time() - self.timestamp


class CacheStats(BaseModel):
    """Statistics for cache operations."""

    hits: int = Field(default=0, description="Number of cache hits")
    misses: int = Field(default=0, description="Number of cache misses")
    expired: int = Field(
        default=0, description="Number of expired entries encountered"
    )
    writes: int = Field(default=0, description="Number of cache writes")
    purges: int = Field(default=0, description="Number of cache purges")
    cleanup_removed: int = Field(
        default=0, description="Number of entries removed during cleanup"
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


class CachePrimeReport(BaseModel):
    """Result of a one-shot ``ValidationCache.prime()`` invocation.

    The cache module never prints; the CLI layer (or any other caller)
    inspects this report after ``prime()`` returns and renders banners
    *outside* any Rich ``Progress`` / ``Live`` context.
    """

    model_config = ConfigDict(frozen=True)

    version_mismatch_purged: bool = Field(
        default=False,
        description=(
            "True iff the on-disk cache was created by a different tool "
            "version and was purged during prime()."
        ),
    )
    suspicious_patterns_purged: bool = Field(
        default=False,
        description=(
            "True iff prime() detected suspicious patterns (high error "
            "rate, etc.) in the loaded cache and purged it."
        ),
    )
    suspicious_reasons: tuple[str, ...] = Field(
        default_factory=tuple,
        description=(
            "Human-readable reasons that triggered a suspicious-patterns "
            "purge. Empty when ``suspicious_patterns_purged`` is False."
        ),
    )


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
        self._redirects: dict[str, RepositoryRedirect] = {}
        self._latest_versions: dict[str, LatestVersionEntry] = {}
        self._cache_version: str = __version__
        self._loaded = False
        # Set to True the first time _load_cache() detects a version
        # mismatch and purges the cache. Surfaced via prime() so callers
        # can render a user-facing banner before any progress UI starts.
        self._version_mismatch_purged: bool = False

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

            redirects_data = cache_data.get("redirects", {})
            for old_repo, redirect_info in redirects_data.items():
                try:
                    self._redirects[old_repo] = RepositoryRedirect(
                        **redirect_info
                    )
                except Exception as e:
                    self.logger.debug(
                        f"Failed to load redirect for {old_repo}: {e}"
                    )

            latest_versions_data = cache_data.get("latest_versions", {})
            for repo, version_info in latest_versions_data.items():
                try:
                    self._latest_versions[repo] = LatestVersionEntry(
                        **version_info
                    )
                except Exception as e:
                    self.logger.debug(
                        f"Failed to load latest version for {repo}: {e}"
                    )

            # Check cache version compatibility. Record the mismatch on
            # the instance so callers can render a banner *before* any
            # progress UI starts (printing here would interleave with an
            # active Rich Progress spinner and corrupt the line).
            #
            # Also stash the on-disk version on ``_cache_version`` so
            # ``get_cache_info()`` and ``detect_suspicious_cache_patterns``
            # reflect the actual file contents (rather than always
            # returning the current tool version, which made the
            # version-mismatch branch in those introspection APIs dead
            # code).
            metadata = cache_data.get("_metadata")
            cache_version = (
                metadata.get("version") if isinstance(metadata, dict) else None
            )
            self._cache_version = cache_version or __version__
            if cache_version != __version__:
                if cache_version:
                    self.logger.debug(
                        f"Cache version mismatch (cache: {cache_version}, "
                        f"current: {__version__}). Purging cache for consistency."
                    )
                else:
                    self.logger.debug(
                        "Legacy cache format detected (no version info). "
                        "Purging cache for consistency."
                    )
                # The redirects and latest_versions dicts may have been
                # partly populated above from the incompatible cache file
                # before the version check ran; clear them along with
                # _cache so no stale data leaks into the run.
                self._version_mismatch_purged = True
                self._cache.clear()
                self._redirects.clear()
                self._latest_versions.clear()
                self._purge_cache_file()
                # Post-purge the in-memory cache is logically a fresh
                # cache at the current tool version; reflect that in
                # introspection.
                self._cache_version = __version__
                self._loaded = True
                return

            # Load cache entries (skip metadata, redirects, and latest_versions)
            entry_count = 0
            for key, entry_data in cache_data.items():
                if key in ("_metadata", "redirects", "latest_versions"):
                    continue
                try:
                    entry = CachedValidationEntry(**entry_data)
                    self._cache[key] = entry
                    entry_count += 1
                except Exception as e:
                    self.logger.warning(
                        f"Invalid cache entry for key {key}: {e}"
                    )

            self.logger.debug(
                f"Loaded {entry_count} entries from cache (version {cache_version})"
            )

            # Cleanup expired entries if configured
            if self.config.cleanup_on_startup:
                self._cleanup_expired()

        except Exception as e:
            self.logger.warning(f"Failed to load cache: {e}")
            self._cache = {}

        self._loaded = True

    def prime(self) -> CachePrimeReport:
        """
        Eagerly load the cache from disk and run all startup-time checks.

        Performs (in order):

        1. ``_load_cache()`` — deserializes the cache file and records a
           version-mismatch purge if applicable.
        2. ``detect_suspicious_cache_patterns()`` over the loaded
           entries followed by ``purge()`` if anomalies (high error
           rate, etc.) are detected. We inline these calls (rather than
           delegating to ``auto_purge_if_suspicious()``) so the report
           can surface the specific ``reasons`` that triggered the
           purge.

        The method is UI-free; it returns a ``CachePrimeReport`` describing
        what happened so the caller can render banners *before* any Rich
        ``Progress`` / ``Live`` block opens. Subsequent calls return an
        all-False report (no further startup-time work to do).

        Idempotent: safe to call multiple times.

        Returns:
            A ``CachePrimeReport`` describing the outcomes.
        """
        if not self.config.enabled or self._loaded:
            return CachePrimeReport()

        self._load_cache()
        version_mismatch_purged = self._version_mismatch_purged

        # Suspicious-patterns check is also a startup concern. Capture
        # reasons before the purge so the caller can surface them.
        suspicious_purged = False
        suspicious_reasons: tuple[str, ...] = ()
        if not version_mismatch_purged:
            analysis = self.detect_suspicious_cache_patterns()
            if analysis.get("suspicious"):
                suspicious_reasons = tuple(analysis.get("reasons", ()))
                self.logger.warning(
                    "Suspicious cache patterns detected: "
                    f"{', '.join(suspicious_reasons)}. "
                    f"Auto-purging cache with {analysis['total_entries']} entries."
                )
                self.purge()
                suspicious_purged = True

        return CachePrimeReport(
            version_mismatch_purged=version_mismatch_purged,
            suspicious_patterns_purged=suspicious_purged,
            suspicious_reasons=suspicious_reasons,
        )

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

            # Convert cache entries to JSON-serializable format. The
            # mapping is intentionally heterogeneous (mix of metadata
            # primitives, per-entry model dumps, and nested redirect /
            # latest-version dicts), so type as Any-valued.
            cache_data: dict[str, Any] = {
                "_metadata": {
                    "version": __version__,
                    "created_timestamp": time.time(),
                    "entry_count": len(self._cache),
                    "redirect_count": len(self._redirects),
                    "latest_version_count": len(self._latest_versions),
                }
            }

            for key, entry in self._cache.items():
                cache_data[key] = entry.model_dump()

            # Add repository redirects
            if self._redirects:
                cache_data["redirects"] = {
                    old_repo: redirect.model_dump()
                    for old_repo, redirect in self._redirects.items()
                }

            # Add latest versions
            if self._latest_versions:
                cache_data["latest_versions"] = {
                    repo: version.model_dump()
                    for repo, version in self._latest_versions.items()
                }

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

        # Also clean up expired latest version entries
        expired_version_repos = []
        for repo, version_entry in self._latest_versions.items():
            if version_entry.is_expired(self.config.default_ttl_seconds):
                expired_version_repos.append(repo)

        for repo in expired_version_repos:
            del self._latest_versions[repo]

        if expired_version_repos:
            self.logger.debug(
                f"Removed {len(expired_version_repos)} expired latest version entries"
            )

    def _enforce_cache_size_limit(self) -> None:
        """Ensure cache doesn't exceed maximum size."""
        if len(self._cache) <= self.config.max_cache_size:
            return

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
        timestamps: list[float] = []

        for entry in self._cache.values():
            if entry.is_expired(self.config.default_ttl_seconds):
                expired_count += 1
            timestamps.append(entry.timestamp)

        oldest_timestamp = min(timestamps) if timestamps else None
        newest_timestamp = max(timestamps) if timestamps else None

        # Count expired latest version entries
        expired_version_count = 0
        for version_entry in self._latest_versions.values():
            if version_entry.is_expired(self.config.default_ttl_seconds):
                expired_version_count += 1

        return {
            "enabled": True,
            "cache_file": str(self.config.cache_file_path),
            "cache_file_exists": self.config.cache_file_path.exists(),
            "entries": len(self._cache),
            "expired_entries": expired_count,
            "latest_version_entries": len(self._latest_versions),
            "expired_latest_version_entries": expired_version_count,
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

    def get_redirect(self, old_repository: str) -> str | None:
        """
        Get the new repository location if it has been redirected.

        Args:
            old_repository: Original repository name (org/repo)

        Returns:
            New repository name if a redirect exists, None otherwise
        """
        if not self.config.enabled:
            return None

        self._load_cache()

        redirect = self._redirects.get(old_repository)
        if redirect:
            # Check if redirect has expired
            if redirect.is_expired(self.config.default_ttl_seconds):
                self.logger.debug(f"Redirect for {old_repository} has expired")
                del self._redirects[old_repository]
                return None

            self.logger.debug(
                f"Found redirect: {old_repository} -> {redirect.new_repository}"
            )
            return redirect.new_repository

        return None

    def put_redirect(self, old_repository: str, new_repository: str) -> None:
        """
        Record a repository redirect.

        Args:
            old_repository: Original repository name (org/repo)
            new_repository: New repository name (org/repo)
        """
        if not self.config.enabled:
            return

        self._load_cache()

        redirect = RepositoryRedirect(
            old_repository=old_repository,
            new_repository=new_repository,
            timestamp=time.time(),
        )

        self._redirects[old_repository] = redirect
        self.logger.debug(
            f"Recorded repository redirect: {old_repository} -> {new_repository}"
        )

    def get_latest_version(self, repository: str) -> tuple[str, str] | None:
        """
        Get the cached latest version for a repository.

        Args:
            repository: Repository name (org/repo)

        Returns:
            Tuple of (tag, sha) if cached and not expired, None otherwise
        """
        entry = self.get_latest_version_entry(repository)
        if entry is None:
            return None
        return (entry.latest_tag, entry.latest_sha)

    def get_latest_version_entry(
        self, repository: str
    ) -> LatestVersionEntry | None:
        """
        Get the whole cached latest-version entry for a repository.

        Callers that only need the target take :meth:`get_latest_version`.
        This exists for the one that also needs
        :attr:`LatestVersionEntry.commit_tags`, which is what tells a pin
        that is *behind* the cached target from one that is *ahead* of it.

        Args:
            repository: Repository name (org/repo)

        Returns:
            The entry if cached and not expired, None otherwise.
        """
        if not self.config.enabled:
            return None

        self._load_cache()

        version_entry = self._latest_versions.get(repository)
        if version_entry:
            # Check if entry has expired
            if version_entry.is_expired(self.config.default_ttl_seconds):
                self.logger.debug(
                    f"Latest version cache for {repository} has expired"
                )
                del self._latest_versions[repository]
                return None

            self.logger.debug(
                f"Cache hit for latest version: {repository} -> {version_entry.latest_tag}"
            )
            return version_entry

        return None

    def put_latest_version(
        self,
        repository: str,
        latest_tag: str,
        latest_sha: str,
        commit_tags: Mapping[str, str] | None = None,
    ) -> None:
        """
        Cache the latest version information for a repository.

        Args:
            repository: Repository name (org/repo)
            latest_tag: Latest release/tag name
            latest_sha: SHA for the latest tag
            commit_tags: Lowercased commit SHA to release tag for every
                release the resolution considered. Supplying it lets a
                later run place a pinned commit relative to the stored
                target instead of assuming the target is newer; a caller
                with no such map omits it.
        """
        if not self.config.enabled:
            return

        self._load_cache()

        version_entry = LatestVersionEntry(
            repository=repository,
            latest_tag=latest_tag,
            latest_sha=latest_sha,
            timestamp=time.time(),
            commit_tags=dict(commit_tags or {}),
        )

        self._latest_versions[repository] = version_entry
        self.logger.debug(
            f"Cached latest version for {repository}: {latest_tag} ({latest_sha[:8]}...)"
        )

    def save(self) -> None:
        """Force save cache to disk."""
        if self.config.enabled and self._loaded:
            self._save_cache()
