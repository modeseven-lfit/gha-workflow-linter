# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for cooldown-aware version selection in the auto-fixer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
import time
from typing import TYPE_CHECKING, Any, cast

import pytest

from gha_workflow_linter import cli
from gha_workflow_linter.auto_fix import (
    AutoFixer,
)
from gha_workflow_linter.cache import ValidationCache
from gha_workflow_linter.models import CacheConfig, Config, ValidationMethod
from gha_workflow_linter.version_utils import (
    _parse_iso_datetime,
    _select_version_with_cooldown,
)

if TYPE_CHECKING:
    from pathlib import Path

    from gha_workflow_linter.github_api import GitHubGraphQLClient

NOW = datetime(2026, 6, 12, tzinfo=timezone.utc)

REPO_KEY = "actions/checkout"
# The version a previous run left in the persistent cache.
CACHED_TAG = "v4"
CACHED_SHA = "a" * 40
# The version this run resolves from a (stubbed) backend.
FRESH_TAG = "v5"
FRESH_SHA = "b" * 40


def _days_ago(days: int) -> datetime:
    return NOW - timedelta(days=days)


def _iso_days_ago(days: int) -> str:
    return _days_ago(days).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_fixer(
    cooldown_days: int, *, allow_prerelease: bool = False
) -> AutoFixer:
    """Build an AutoFixer without running its heavyweight ``__init__``.

    The cooldown selection helpers only rely on ``config`` and ``logger``,
    so we bypass the cache priming and network client setup.

    Args:
        cooldown_days: Cooldown window to apply, in days.
        allow_prerelease: Whether prereleases are eligible candidates.

    Returns:
        A fixer carrying nothing but the release policy under test.
    """
    fixer = AutoFixer.__new__(AutoFixer)
    fixer.config = Config(
        cooldown_days=cooldown_days, allow_prerelease=allow_prerelease
    )
    fixer.logger = logging.getLogger("test.cooldown")
    return fixer


def _make_batch_fixer(
    cooldown_days: int,
    cache_dir: Path,
    *,
    allow_prerelease: bool = False,
    graphql: bool = False,
) -> tuple[AutoFixer, ValidationCache]:
    """Build a fully initialised AutoFixer over a throwaway disk cache.

    Args:
        cooldown_days: Cooldown window to apply, in days.
        cache_dir: Directory backing the persistent ``ValidationCache``.
        allow_prerelease: Whether prereleases are eligible candidates.
        graphql: Whether to arm the batched GraphQL path. The client is a
            bare sentinel purely to satisfy the ``self._graphql_client``
            gate; the batch call itself is always stubbed, so no test
            reaches the network.

    Returns:
        The fixer and the cache it was handed, so tests can inspect what
        the run persisted.
    """
    config = Config(
        cooldown_days=cooldown_days,
        allow_prerelease=allow_prerelease,
        validation_method=ValidationMethod.GITHUB_API,
        cache=CacheConfig(enabled=True, cache_dir=cache_dir),
    )
    cache = ValidationCache(config.cache)
    fixer = AutoFixer(config, base_path=cache_dir, cache=cache)
    if graphql:
        fixer._graphql_client = cast("GitHubGraphQLClient", object())
    return fixer, cache


def _stub_single_lookup(
    fixer: AutoFixer,
    monkeypatch: pytest.MonkeyPatch,
    result: tuple[str, str] | None,
) -> list[str]:
    """Replace the per-repository backend lookup with a canned answer.

    Args:
        fixer: Fixer whose lookup should be stubbed.
        monkeypatch: Fixture used to patch the bound method.
        result: The ``(tag, sha)`` pair to answer with, or ``None``.

    Returns:
        A list, appended to in call order, of every repository the fixer
        could not answer from a cache and therefore queued for
        resolution.
    """
    fetched: list[str] = []

    async def fake_single(repo_key: str) -> tuple[str, str] | None:
        """Answer one repository without touching the network.

        Args:
            repo_key: Repository queued for resolution.

        Returns:
            The canned pair supplied by the caller.
        """
        fetched.append(repo_key)
        return result

    monkeypatch.setattr(fixer, "_get_latest_version_single", fake_single)
    return fetched


def _stub_graphql_lookup(
    fixer: AutoFixer,
    monkeypatch: pytest.MonkeyPatch,
    results: dict[str, tuple[str, str]],
) -> list[list[str]]:
    """Replace the batched GraphQL lookup with a canned answer.

    Args:
        fixer: Fixer whose batch lookup should be stubbed.
        monkeypatch: Fixture used to patch the bound method.
        results: The ``repo_key -> (tag, sha)`` mapping to answer with.

    Returns:
        A list, appended to in call order, of every batch the fixer could
        not answer from a cache and therefore queued for resolution.
    """
    batches: list[list[str]] = []

    async def fake_batch(repo_keys: list[str]) -> dict[str, tuple[str, str]]:
        """Answer a whole batch without touching the network.

        Args:
            repo_keys: Repositories queued for resolution.

        Returns:
            The canned mapping supplied by the caller.
        """
        batches.append(repo_keys)
        return results

    monkeypatch.setattr(fixer, "_get_latest_versions_graphql_batch", fake_batch)
    return batches


class TestParseIsoDatetime:
    """Tests for ISO-8601 timestamp parsing."""

    def test_parses_zulu_suffix(self) -> None:
        parsed = _parse_iso_datetime("2026-01-02T03:04:05Z")
        assert parsed == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    def test_parses_explicit_offset(self) -> None:
        parsed = _parse_iso_datetime("2026-01-02T03:04:05+00:00")
        assert parsed is not None
        assert parsed.tzinfo is not None

    def test_returns_none_for_empty(self) -> None:
        assert _parse_iso_datetime(None) is None
        assert _parse_iso_datetime("") is None

    def test_returns_none_for_garbage(self) -> None:
        assert _parse_iso_datetime("not-a-date") is None


class TestSelectVersionWithCooldown:
    """Tests for the cooldown selection algorithm."""

    def test_disabled_cooldown_returns_newest(self) -> None:
        candidates: list[tuple[str, str, datetime | None]] = [
            ("v3", "sha3", _days_ago(1)),
            ("v2", "sha2", _days_ago(30)),
        ]
        assert _select_version_with_cooldown(candidates, 0) == ("v3", "sha3")

    def test_negative_cooldown_returns_newest(self) -> None:
        candidates: list[tuple[str, str, datetime | None]] = [
            ("v3", "sha3", _days_ago(1))
        ]
        assert _select_version_with_cooldown(candidates, -5) == ("v3", "sha3")

    def test_skips_versions_inside_window(self) -> None:
        candidates: list[tuple[str, str, datetime | None]] = [
            ("v3", "sha3", _days_ago(2)),  # too new
            ("v2", "sha2", _days_ago(10)),  # eligible
            ("v1", "sha1", _days_ago(40)),
        ]
        assert _select_version_with_cooldown(candidates, 7, now=NOW) == (
            "v2",
            "sha2",
        )

    def test_newest_eligible_when_all_old(self) -> None:
        candidates: list[tuple[str, str, datetime | None]] = [
            ("v3", "sha3", _days_ago(8)),
            ("v2", "sha2", _days_ago(20)),
        ]
        assert _select_version_with_cooldown(candidates, 7, now=NOW) == (
            "v3",
            "sha3",
        )

    def test_boundary_exactly_at_cutoff_is_eligible(self) -> None:
        candidates: list[tuple[str, str, datetime | None]] = [
            ("v1", "sha1", _days_ago(7))
        ]
        assert _select_version_with_cooldown(candidates, 7, now=NOW) == (
            "v1",
            "sha1",
        )

    def test_returns_none_when_all_too_new(self) -> None:
        candidates: list[tuple[str, str, datetime | None]] = [
            ("v3", "sha3", _days_ago(1)),
            ("v2", "sha2", _days_ago(3)),
        ]
        assert _select_version_with_cooldown(candidates, 7, now=NOW) is None

    def test_skips_unknown_dates_under_cooldown(self) -> None:
        candidates: list[tuple[str, str, datetime | None]] = [
            ("v3", "sha3", None),  # unknown date, cannot verify
            ("v2", "sha2", _days_ago(30)),
        ]
        assert _select_version_with_cooldown(candidates, 7, now=NOW) == (
            "v2",
            "sha2",
        )

    def test_returns_none_for_empty(self) -> None:
        assert _select_version_with_cooldown([], 7) is None


class TestSelectCooldownVersionGraphql:
    """Tests for GraphQL cooldown selection wiring on the AutoFixer."""

    def test_skips_release_inside_window(self) -> None:
        fixer = _make_fixer(7)
        repo_data: dict[str, Any] = {
            "latestRelease": {
                "tagName": "v3",
                "publishedAt": _iso_days_ago(2),
                "tagCommit": {"oid": "sha3"},
            }
        }
        all_tags = [("v3", "sha3"), ("v2", "sha2")]
        tag_dates: dict[str, datetime | None] = {
            "v3": _days_ago(2),
            "v2": _days_ago(20),
        }
        assert fixer._select_cooldown_version_graphql(
            repo_data, all_tags, tag_dates, now=NOW
        ) == ("v2", "sha2")

    def test_selects_release_when_old_enough(self) -> None:
        fixer = _make_fixer(7)
        repo_data: dict[str, Any] = {
            "latestRelease": {
                "tagName": "v3",
                "publishedAt": _iso_days_ago(30),
                "tagCommit": {"oid": "sha3"},
            }
        }
        all_tags = [("v3", "sha3"), ("v2", "sha2")]
        tag_dates: dict[str, datetime | None] = {
            "v3": _days_ago(30),
            "v2": _days_ago(60),
        }
        assert fixer._select_cooldown_version_graphql(
            repo_data, all_tags, tag_dates, now=NOW
        ) == ("v3", "sha3")

    def test_prefers_more_specific_tag_for_sha(self) -> None:
        fixer = _make_fixer(7)
        repo_data: dict[str, Any] = {}
        # v8 and v8.0.0 point at the same commit; the more specific tag wins.
        all_tags = [("v8", "sha8"), ("v8.0.0", "sha8")]
        tag_dates: dict[str, datetime | None] = {
            "v8": _days_ago(30),
            "v8.0.0": _days_ago(30),
        }
        assert fixer._select_cooldown_version_graphql(
            repo_data, all_tags, tag_dates, now=NOW
        ) == ("v8.0.0", "sha8")

    def test_returns_none_when_no_tags(self) -> None:
        fixer = _make_fixer(7)
        assert (
            fixer._select_cooldown_version_graphql({}, [], {}, now=NOW) is None
        )


class TestResolveCooldownDays:
    """Tests for the CLI cooldown resolution precedence."""

    def test_explicit_flag_takes_precedence(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        # Even with a Dependabot config present, the explicit value wins.
        github_dir = tmp_path / ".github"
        github_dir.mkdir()
        (github_dir / "dependabot.yml").write_text(
            "version: 2\nupdates:\n  - package-ecosystem: github-actions\n"
            "    directory: /\n    cooldown:\n      default-days: 7\n",
            encoding="utf-8",
        )
        printed: list[str] = []
        monkeypatch.setattr(
            "gha_workflow_linter.cli.console.print",
            lambda *args, **kwargs: printed.append(str(args[0])),
        )
        result = cli._resolve_cooldown_days(
            3, tmp_path, quiet=False, output_format="text"
        )
        assert result == 3
        # No Dependabot message when the flag is explicit.
        assert printed == []

    def test_falls_back_to_dependabot(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        github_dir = tmp_path / ".github"
        github_dir.mkdir()
        (github_dir / "dependabot.yml").write_text(
            "version: 2\nupdates:\n  - package-ecosystem: github-actions\n"
            "    directory: /\n    cooldown:\n      default-days: 7\n",
            encoding="utf-8",
        )
        printed: list[str] = []
        monkeypatch.setattr(
            "gha_workflow_linter.cli.console.print",
            lambda *args, **kwargs: printed.append(str(args[0])),
        )
        result = cli._resolve_cooldown_days(
            None, tmp_path, quiet=False, output_format="text"
        )
        assert result == 7
        assert len(printed) == 1
        assert "[7]" in printed[0]
        assert "dependabot configuration" in printed[0]

    def test_defaults_to_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        printed: list[str] = []
        monkeypatch.setattr(
            "gha_workflow_linter.cli.console.print",
            lambda *args, **kwargs: printed.append(str(args[0])),
        )
        result = cli._resolve_cooldown_days(
            None, tmp_path, quiet=False, output_format="text"
        )
        assert result == 0
        assert printed == []

    def test_quiet_suppresses_message(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        github_dir = tmp_path / ".github"
        github_dir.mkdir()
        (github_dir / "dependabot.yml").write_text(
            "version: 2\nupdates:\n  - package-ecosystem: github-actions\n"
            "    directory: /\n    cooldown:\n      default-days: 7\n",
            encoding="utf-8",
        )
        printed: list[str] = []
        monkeypatch.setattr(
            "gha_workflow_linter.cli.console.print",
            lambda *args, **kwargs: printed.append(str(args[0])),
        )
        result = cli._resolve_cooldown_days(
            None, tmp_path, quiet=True, output_format="text"
        )
        assert result == 7
        assert printed == []


class TestPersistentCacheUnderReleasePolicy:
    """A non-default release policy must not share persisted versions.

    ``ValidationCache`` keys latest versions on the repository alone and
    records no policy, so an answer written by one run could be read back
    by a run whose policy would have chosen differently. Two settings
    make up that policy: a **cooldown** shifts the answer to an older
    release, and **prerelease eligibility** changes which releases are
    candidates at all. The fixer therefore bypasses the persistent cache
    entirely unless both are at their defaults, mirroring
    ``AllowListResolver.cache_usable``.

    The session cache is deliberately left alone: it lives on one
    ``AutoFixer``, which serves exactly one repository and therefore one
    policy.
    """

    @pytest.mark.parametrize(
        ("cooldown_days", "allow_prerelease", "usable"),
        [
            pytest.param(0, False, True, id="default-policy"),
            pytest.param(7, False, False, id="cooldown"),
            pytest.param(0, True, False, id="prerelease"),
            pytest.param(7, True, False, id="cooldown-and-prerelease"),
        ],
    )
    def test_only_the_default_policy_is_cacheable(
        self, cooldown_days: int, allow_prerelease: bool, usable: bool
    ) -> None:
        """Only a default-policy entry means the same to every reader."""
        fixer = _make_fixer(cooldown_days, allow_prerelease=allow_prerelease)

        assert fixer._persistent_cache_usable is usable

    @pytest.mark.asyncio
    async def test_a_cooldown_run_ignores_a_persisted_version(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The persisted v4 is passed over and the repository re-resolved."""
        fixer, cache = _make_batch_fixer(7, tmp_path)
        cache.put_latest_version(REPO_KEY, CACHED_TAG, CACHED_SHA)
        fetched = _stub_single_lookup(
            fixer, monkeypatch, (FRESH_TAG, FRESH_SHA)
        )

        results = await fixer._get_latest_versions_batch([REPO_KEY])

        assert fetched == [REPO_KEY]
        assert results == {REPO_KEY: (FRESH_TAG, FRESH_SHA)}

    @pytest.mark.asyncio
    async def test_a_cooldown_run_does_not_persist_a_resolved_version(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A version resolved per-repository stays out of the cache."""
        fixer, cache = _make_batch_fixer(7, tmp_path)
        _stub_single_lookup(fixer, monkeypatch, (FRESH_TAG, FRESH_SHA))

        results = await fixer._get_latest_versions_batch([REPO_KEY])

        assert results == {REPO_KEY: (FRESH_TAG, FRESH_SHA)}
        assert cache.get_latest_version(REPO_KEY) is None

    @pytest.mark.asyncio
    async def test_a_cooldown_run_does_not_persist_a_batched_version(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The GraphQL path suppresses its write for the same reason."""
        fixer, cache = _make_batch_fixer(7, tmp_path, graphql=True)
        batches = _stub_graphql_lookup(
            fixer, monkeypatch, {REPO_KEY: (FRESH_TAG, FRESH_SHA)}
        )

        results = await fixer._get_latest_versions_batch([REPO_KEY])

        assert batches == [[REPO_KEY]]
        assert results == {REPO_KEY: (FRESH_TAG, FRESH_SHA)}
        assert cache.get_latest_version(REPO_KEY) is None

    @pytest.mark.asyncio
    async def test_a_cooldown_run_still_uses_the_session_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Only the *persistent* cache crosses release policies.

        One ``AutoFixer`` serves one repository and therefore one
        cooldown, so a session entry cannot have been produced under a
        different policy. Guarding it too would cost a lookup per
        repository for no safety gain.
        """
        fixer, _ = _make_batch_fixer(7, tmp_path)
        fixer._latest_versions_cache[REPO_KEY] = (
            CACHED_TAG,
            CACHED_SHA,
            time.time(),
        )
        fetched = _stub_single_lookup(
            fixer, monkeypatch, (FRESH_TAG, FRESH_SHA)
        )

        results = await fixer._get_latest_versions_batch([REPO_KEY])

        assert fetched == []
        assert results == {REPO_KEY: (CACHED_TAG, CACHED_SHA)}

    @pytest.mark.asyncio
    async def test_a_prerelease_run_ignores_a_persisted_version(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A stable-only entry could hide a newer prerelease."""
        fixer, cache = _make_batch_fixer(0, tmp_path, allow_prerelease=True)
        cache.put_latest_version(REPO_KEY, CACHED_TAG, CACHED_SHA)
        fetched = _stub_single_lookup(
            fixer, monkeypatch, (FRESH_TAG, FRESH_SHA)
        )

        results = await fixer._get_latest_versions_batch([REPO_KEY])

        assert fetched == [REPO_KEY]
        assert results == {REPO_KEY: (FRESH_TAG, FRESH_SHA)}

    @pytest.mark.asyncio
    async def test_a_prerelease_run_does_not_persist_a_resolved_version(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A default run must not later consume a cached prerelease."""
        fixer, cache = _make_batch_fixer(0, tmp_path, allow_prerelease=True)
        _stub_single_lookup(fixer, monkeypatch, (FRESH_TAG, FRESH_SHA))

        results = await fixer._get_latest_versions_batch([REPO_KEY])

        assert results == {REPO_KEY: (FRESH_TAG, FRESH_SHA)}
        assert cache.get_latest_version(REPO_KEY) is None

    @pytest.mark.asyncio
    async def test_a_prerelease_run_does_not_persist_a_batched_version(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The GraphQL path suppresses its write for the same reason."""
        fixer, cache = _make_batch_fixer(
            0, tmp_path, allow_prerelease=True, graphql=True
        )
        batches = _stub_graphql_lookup(
            fixer, monkeypatch, {REPO_KEY: (FRESH_TAG, FRESH_SHA)}
        )

        results = await fixer._get_latest_versions_batch([REPO_KEY])

        assert batches == [[REPO_KEY]]
        assert results == {REPO_KEY: (FRESH_TAG, FRESH_SHA)}
        assert cache.get_latest_version(REPO_KEY) is None

    @pytest.mark.asyncio
    async def test_a_default_policy_run_reads_a_persisted_version(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression guard: the fix must not disable caching outright."""
        fixer, cache = _make_batch_fixer(0, tmp_path)
        cache.put_latest_version(REPO_KEY, CACHED_TAG, CACHED_SHA)
        fetched = _stub_single_lookup(
            fixer, monkeypatch, (FRESH_TAG, FRESH_SHA)
        )

        results = await fixer._get_latest_versions_batch([REPO_KEY])

        assert fetched == []
        assert results == {REPO_KEY: (CACHED_TAG, CACHED_SHA)}

    @pytest.mark.asyncio
    async def test_a_default_policy_run_persists_a_resolved_version(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression guard for the per-repository write site."""
        fixer, cache = _make_batch_fixer(0, tmp_path)
        _stub_single_lookup(fixer, monkeypatch, (FRESH_TAG, FRESH_SHA))

        results = await fixer._get_latest_versions_batch([REPO_KEY])

        assert results == {REPO_KEY: (FRESH_TAG, FRESH_SHA)}
        assert cache.get_latest_version(REPO_KEY) == (FRESH_TAG, FRESH_SHA)

    @pytest.mark.asyncio
    async def test_a_default_policy_run_persists_a_batched_version(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Regression guard for the GraphQL write site."""
        fixer, cache = _make_batch_fixer(0, tmp_path, graphql=True)
        _stub_graphql_lookup(
            fixer, monkeypatch, {REPO_KEY: (FRESH_TAG, FRESH_SHA)}
        )

        results = await fixer._get_latest_versions_batch([REPO_KEY])

        assert results == {REPO_KEY: (FRESH_TAG, FRESH_SHA)}
        assert cache.get_latest_version(REPO_KEY) == (FRESH_TAG, FRESH_SHA)
