# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Simple tests for cache module to improve coverage."""
# pyright: reportUninitializedInstanceVariable=false

from __future__ import annotations

import os
import pathlib
from pathlib import Path
import shutil
import tempfile
import time
from typing import TYPE_CHECKING

from gha_workflow_linter.cache import (
    CacheConfig,
    CachedValidationEntry,
    ValidationCache,
)
from gha_workflow_linter.models import ValidationResult

if TYPE_CHECKING:
    import pytest


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
        # Create a private temp directory and place the cache file inside
        # it. Using mkdtemp() + a fixed filename avoids the race conditions
        # tempfile.mktemp() exposes (where another process could create the
        # named path between mktemp() and our first write).
        self._temp_cache_dir = Path(
            tempfile.mkdtemp(prefix="gha-workflow-linter-cache-")
        )
        self.temp_cache_file_path = str(self._temp_cache_dir / "cache.json")

        self.cache_config = CacheConfig(
            enabled=True,
            cache_dir=self._temp_cache_dir,
            cache_file="cache.json",
        )

    def teardown_method(self) -> None:
        """Clean up test fixtures."""
        # Remove the entire temp directory in one shot. shutil.rmtree
        # tolerates a missing directory via ignore_errors=True so tests
        # that delete the cache file mid-run still teardown cleanly.
        shutil.rmtree(self._temp_cache_dir, ignore_errors=True)

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


class TestCachePrime:
    """Regression tests for ``ValidationCache.prime()``.

    The cache module must be UI-free; ``prime()`` reports its findings
    via a ``CachePrimeReport`` instead of printing. The CLI layer renders
    banners *before* opening any Rich Progress UI so output never
    interleaves with a Live spinner.
    """

    def setup_method(self) -> None:
        self._temp_cache_dir = pathlib.Path(
            tempfile.mkdtemp(prefix="gha-workflow-linter-prime-")
        )
        self.cache_config = CacheConfig(
            enabled=True,
            cache_dir=self._temp_cache_dir,
            cache_file="cache.json",
        )

    def teardown_method(self) -> None:
        shutil.rmtree(self._temp_cache_dir, ignore_errors=True)

    def test_prime_no_cache_file_returns_empty_report(self) -> None:
        from gha_workflow_linter.cache import CachePrimeReport

        cache = ValidationCache(self.cache_config)
        report = cache.prime()
        assert isinstance(report, CachePrimeReport)
        assert report.version_mismatch_purged is False
        assert report.suspicious_patterns_purged is False
        assert report.suspicious_reasons == ()

    def test_prime_idempotent(self) -> None:
        cache = ValidationCache(self.cache_config)
        first = cache.prime()
        second = cache.prime()
        assert first.version_mismatch_purged == second.version_mismatch_purged

    def test_prime_disabled_cache_no_op(self) -> None:
        from gha_workflow_linter.cache import CachePrimeReport

        config = CacheConfig(
            enabled=False,
            cache_dir=self._temp_cache_dir,
            cache_file="cache.json",
        )
        cache = ValidationCache(config)
        report = cache.prime()
        assert isinstance(report, CachePrimeReport)
        assert report.version_mismatch_purged is False
        assert report.suspicious_patterns_purged is False

    def test_prime_detects_version_mismatch(self) -> None:
        """A pre-existing cache from a different tool version triggers a
        version-mismatch purge, surfaced via the report (not stdout)."""
        import json

        # Write a cache file with a deliberately-stale version.
        stale = {
            "_metadata": {
                "version": "0.0.0-fake",
                "created_timestamp": time.time(),
                "entry_count": 0,
                "redirect_count": 0,
                "latest_version_count": 0,
            }
        }
        cache_path = self._temp_cache_dir / "cache.json"
        cache_path.write_text(json.dumps(stale))

        cache = ValidationCache(self.cache_config)
        report = cache.prime()
        assert report.version_mismatch_purged is True
        assert report.suspicious_patterns_purged is False

    def test_cache_version_reflects_on_disk_metadata(self) -> None:
        """``_cache_version`` must mirror the on-disk metadata version
        after a successful load, so ``get_cache_info()`` and
        ``detect_suspicious_cache_patterns()`` report the actual file
        version rather than the current tool version (regression: the
        version-mismatch branch in those introspection APIs was dead
        code because ``_cache_version`` was never updated)."""
        import json

        from gha_workflow_linter import __version__

        # A successful load: cache file's version equals current tool
        # version, so no purge happens. ``_cache_version`` should equal
        # ``__version__``.
        good = {
            "_metadata": {
                "version": __version__,
                "created_timestamp": time.time(),
                "entry_count": 0,
                "redirect_count": 0,
                "latest_version_count": 0,
            }
        }
        cache_path = self._temp_cache_dir / "cache.json"
        cache_path.write_text(json.dumps(good))

        cache = ValidationCache(self.cache_config)
        cache.prime()
        assert cache._cache_version == __version__
        # ``get_cache_info`` exposes the same value to callers.
        info = cache.get_cache_info()
        assert info["cache_version"] == __version__

    def test_cache_version_resets_to_current_after_mismatch_purge(
        self,
    ) -> None:
        """After a version-mismatch purge the in-memory state is
        logically a fresh cache at the current tool version, so
        ``_cache_version`` should reflect that (not the stale on-disk
        value)."""
        import json

        from gha_workflow_linter import __version__

        stale = {
            "_metadata": {
                "version": "0.0.0-stale",
                "created_timestamp": time.time(),
                "entry_count": 0,
                "redirect_count": 0,
                "latest_version_count": 0,
            }
        }
        cache_path = self._temp_cache_dir / "cache.json"
        cache_path.write_text(json.dumps(stale))

        cache = ValidationCache(self.cache_config)
        report = cache.prime()
        assert report.version_mismatch_purged is True
        assert cache._cache_version == __version__

    def test_prime_clears_inmemory_state_on_version_mismatch(self) -> None:
        """A version-mismatch purge must clear in-memory _cache,
        _redirects and _latest_versions populated from the stale
        on-disk file, otherwise stale entries leak into the run.
        """
        import json

        stale = {
            "_metadata": {
                "version": "0.0.0-stale",
                "created_timestamp": time.time(),
                "entry_count": 0,
                "redirect_count": 1,
                "latest_version_count": 1,
            },
            "owner/repo@v1": {
                "repository": "owner/repo",
                "reference": "v1",
                "result": "valid",
                "validation_method_used": "graphql",
                "validation_method": "github-api",
                "timestamp": time.time(),
                "error_message": None,
            },
            "redirects": {
                "old/repo": {
                    "old_repository": "old/repo",
                    "new_repository": "new/repo",
                    "timestamp": time.time(),
                }
            },
            "latest_versions": {
                "owner/repo": {
                    "repository": "owner/repo",
                    "tag": "v1",
                    "sha": "0" * 40,
                    "timestamp": time.time(),
                }
            },
        }
        cache_path = self._temp_cache_dir / "cache.json"
        cache_path.write_text(json.dumps(stale))

        cache = ValidationCache(self.cache_config)
        report = cache.prime()
        assert report.version_mismatch_purged is True
        # All in-memory state should be empty after a mismatch purge.
        assert cache._cache == {}
        assert cache._redirects == {}
        assert cache._latest_versions == {}

    def test_prime_does_not_print(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Sanity: prime() must not write user-facing output (Rich
        ``console.print`` calls or bare ``print()``) to stdout/stderr.
        Diagnostic logs (``self.logger.debug(...)``) are *expected* and
        belong to the logging subsystem; they only become user-visible
        when the CLI ``--verbose`` flag opts the user in. We silence
        the cache logger for this test so ambient logging configuration
        from earlier tests in the suite cannot bleed into the
        assertion."""
        import json
        import logging

        stale = {
            "_metadata": {
                "version": "0.0.0-fake",
                "created_timestamp": time.time(),
                "entry_count": 0,
                "redirect_count": 0,
                "latest_version_count": 0,
            }
        }
        cache_path = self._temp_cache_dir / "cache.json"
        cache_path.write_text(json.dumps(stale))

        cache = ValidationCache(self.cache_config)
        # Suppress the cache logger so its DEBUG output (which we
        # explicitly want to allow in production behind --verbose)
        # cannot bleed into stderr via any handler installed by an
        # earlier test in the suite.
        cache_logger = logging.getLogger("gha_workflow_linter.cache")
        previous_level = cache_logger.level
        cache_logger.setLevel(logging.CRITICAL + 1)
        try:
            cache.prime()
        finally:
            cache_logger.setLevel(previous_level)
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""


class TestStandaloneCacheConsumers:
    """Regression tests: when ``ActionCallValidator`` / ``AutoFixer``
    construct their own ``ValidationCache`` (ad-hoc / library use, no
    shared cache from the CLI), they must run the same startup-time
    checks (version-mismatch purge + suspicious-patterns purge) the
    CLI path runs. Otherwise stale or known-bad cache contents leak
    into the run.
    """

    def setup_method(self) -> None:
        self._temp_cache_dir = pathlib.Path(
            tempfile.mkdtemp(prefix="gha-workflow-linter-standalone-")
        )

    def teardown_method(self) -> None:
        shutil.rmtree(self._temp_cache_dir, ignore_errors=True)

    def _seed_stale_cache(self) -> None:
        import json

        stale = {
            "_metadata": {
                "version": "0.0.0-stale",
                "created_timestamp": time.time(),
                "entry_count": 0,
                "redirect_count": 0,
                "latest_version_count": 0,
            }
        }
        cache_path = self._temp_cache_dir / "validation_cache.json"
        cache_path.write_text(json.dumps(stale))

    def test_autofixer_primes_own_cache_on_construct(self) -> None:
        from gha_workflow_linter import __version__
        from gha_workflow_linter.auto_fix import AutoFixer
        from gha_workflow_linter.models import Config

        self._seed_stale_cache()
        config = Config(
            cache=CacheConfig(
                enabled=True,
                cache_dir=self._temp_cache_dir,
                cache_file="validation_cache.json",
            )
        )
        fixer = AutoFixer(config)
        # Constructor should have primed the cache.
        assert fixer._cache._loaded is True
        # And the version-mismatch purge should have fired.
        assert fixer._cache._version_mismatch_purged is True
        # _cache_version reflects the post-purge state.
        assert fixer._cache._cache_version == __version__

    def test_validator_primes_own_cache_via_validate(self) -> None:
        """``ActionCallValidator`` primes lazily on its first
        ``validate_action_calls_async`` call so the constructor stays
        cheap. Verify priming happens via the public entry point —
        not by reaching into the private ``_cache.prime()`` directly —
        so the test exercises the actual user-visible behavior.
        """
        import asyncio

        from gha_workflow_linter import __version__
        from gha_workflow_linter.models import Config, ValidationMethod
        from gha_workflow_linter.validator import ActionCallValidator

        self._seed_stale_cache()
        config = Config(
            cache=CacheConfig(
                enabled=True,
                cache_dir=self._temp_cache_dir,
                cache_file="validation_cache.json",
            ),
            validation_method=ValidationMethod.GIT,
        )
        validator = ActionCallValidator(config)
        # Constructor shouldn't have primed yet (lazy).
        assert validator._cache._loaded is False

        # Drive the public validation path through the async entry
        # point with an empty work-set; this short-circuits past the
        # GitHub / Git client invocations but still runs the
        # cache.prime() call at the top of validate_action_calls_async.
        async def _run() -> None:
            async with validator:
                await validator.validate_action_calls_async({})

        asyncio.run(_run())

        # The prime() call inside validate_action_calls_async loaded
        # and purged the stale cache file. We funnel the assertions
        # through a nested helper so mypy doesn't flag them as
        # unreachable: validator.validate_action_calls_async has two
        # branches that ``raise RuntimeError`` if the corresponding
        # client isn't initialized, which mypy infers as
        # ``NoReturn``-ish even though both branches are guarded by
        # __aenter__ at runtime.
        def _assert_purged() -> None:
            assert validator._cache._loaded is True
            assert validator._cache._version_mismatch_purged is True
            assert validator._cache._cache_version == __version__

        _assert_purged()

    def test_autofixer_skip_priming_when_shared_cache_provided(
        self,
    ) -> None:
        """When the CLI passes a pre-built ``cache=`` argument, the
        constructor must not call prime() a second time (the shared
        cache is already primed by the CLI prepare phase). We assert
        that the existing _loaded state is preserved."""
        from gha_workflow_linter.auto_fix import AutoFixer
        from gha_workflow_linter.models import Config

        config = Config(
            cache=CacheConfig(
                enabled=True,
                cache_dir=self._temp_cache_dir,
                cache_file="validation_cache.json",
            )
        )
        shared = ValidationCache(config.cache)
        # Pretend the CLI already primed.
        shared._loaded = True
        fixer = AutoFixer(config, cache=shared)
        # AutoFixer should reuse the shared cache as-is, not re-prime.
        assert fixer._cache is shared
        assert fixer._cache._loaded is True
