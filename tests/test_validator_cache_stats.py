# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for how a validator accounts for cache hits.

A multi-repository sweep builds one
:class:`~gha_workflow_linter.cache.ValidationCache` and shares it across
every repository, which is the efficiency argument for building the mode
into the tool. The cache's hit counter is cumulative, so a validator
that reported it wholesale would credit each repository with every hit
since the sweep began -- the second repository's JSON payload claiming
the first repository's cache hits as its own.

Each validator therefore records where the counter stood when its
context was entered and reports the difference. The single-repository
case is unaffected, since the counter starts at zero there.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from gha_workflow_linter.cache import ValidationCache
from gha_workflow_linter.models import (
    ActionCall,
    ActionCallType,
    CacheConfig,
    Config,
    ReferenceType,
    ValidationMethod,
    ValidationResult,
)
from gha_workflow_linter.validator import ActionCallValidator

if TYPE_CHECKING:
    from pathlib import Path

#: A pinned call the cache can answer for without any network access.
REPOSITORY = "actions/checkout"
REFERENCE = "11bd71901bbe5b1630ceea73d27597364c9af683"


def make_config(tmp_path: Path) -> Config:
    """Build a configuration with a throwaway cache directory.

    The Git validation method is chosen so that entering the validator's
    context builds no network client.

    Args:
        tmp_path: Test-scoped directory to hold the cache file.

    Returns:
        A configuration safe to use without touching the user's cache.
    """
    return Config(
        cache=CacheConfig(cache_dir=tmp_path / "cache"),
        validation_method=ValidationMethod.GIT,
    )


def report_cache_hits(
    config: Config, cache: ValidationCache, *, hits: int
) -> int:
    """Build a validator, cause some cache hits, and read its tally.

    The baseline is taken when the context is entered and the merge
    happens on exit, so the hits are simulated in between -- which is
    where a real run's hits occur.

    Args:
        config: Configuration for the validator.
        cache: Cache to share with it.
        hits: How many cache hits to attribute to this validator.

    Returns:
        The cache hits the validator attributed to itself.
    """

    async def run() -> int:
        """Enter the validator's context and cause hits inside it.

        Returns:
            The validator's reported cache hits.
        """
        validator = ActionCallValidator(config, cache=cache)
        async with validator:
            cache.stats.hits += hits
        return validator.api_stats.cache_hits

    return asyncio.run(run())


class TestCacheHitAccounting:
    """What a validator counts as its own cache hits."""

    def test_a_fresh_cache_reports_its_own_hits(self, tmp_path: Path) -> None:
        """The single-repository case is unchanged.

        This is the guard against reporting nothing at all, which a
        wrongly-taken baseline would produce.

        Args:
            tmp_path: Supplies the cache directory.
        """
        config = make_config(tmp_path)
        cache = ValidationCache(config.cache)

        assert report_cache_hits(config, cache, hits=3) == 3

    def test_earlier_hits_are_not_claimed_by_a_later_validator(
        self, tmp_path: Path
    ) -> None:
        """A sweep's second repository reports only what it caused.

        Args:
            tmp_path: Supplies the cache directory.
        """
        config = make_config(tmp_path)
        cache = ValidationCache(config.cache)

        # The first repository of a sweep.
        assert report_cache_hits(config, cache, hits=5) == 5

        # The second, sharing the same cache, which already holds five.
        assert report_cache_hits(config, cache, hits=2) == 2

    def test_a_repository_that_hits_nothing_reports_nothing(
        self, tmp_path: Path
    ) -> None:
        """No hits of its own means none reported, not inherited ones.

        Args:
            tmp_path: Supplies the cache directory.
        """
        config = make_config(tmp_path)
        cache = ValidationCache(config.cache)

        report_cache_hits(config, cache, hits=9)

        assert report_cache_hits(config, cache, hits=0) == 0

    def test_the_shared_counter_is_left_intact(self, tmp_path: Path) -> None:
        """Accounting reads the counter; it must not reset it.

        Resetting between visits would be the other way to fix this, and
        would cost the sweep its cumulative total.

        Args:
            tmp_path: Supplies the cache directory.
        """
        config = make_config(tmp_path)
        cache = ValidationCache(config.cache)

        report_cache_hits(config, cache, hits=4)
        report_cache_hits(config, cache, hits=6)

        assert cache.stats.hits == 10

    def test_hits_before_entry_are_not_claimed(self, tmp_path: Path) -> None:
        """The baseline is taken on entry, not at construction.

        A validator may be built well before it runs, and the shared
        cache keeps serving other work in between.

        Args:
            tmp_path: Supplies the cache directory.
        """
        config = make_config(tmp_path)
        cache = ValidationCache(config.cache)
        validator = ActionCallValidator(config, cache=cache)

        # Someone else's hits, between construction and this run.
        cache.stats.hits += 7

        async def run() -> int:
            """Enter the validator and cause two hits of its own.

            Returns:
                The validator's reported cache hits.
            """
            async with validator:
                cache.stats.hits += 2
            return validator.api_stats.cache_hits

        assert asyncio.run(run()) == 2

    def test_a_second_pass_does_not_recount_the_first(
        self, tmp_path: Path
    ) -> None:
        """Re-entering one validator reports each pass separately.

        Args:
            tmp_path: Supplies the cache directory.
        """
        config = make_config(tmp_path)
        cache = ValidationCache(config.cache)
        validator = ActionCallValidator(config, cache=cache)

        async def run(hits: int) -> int:
            """Enter the validator once and cause some hits.

            Args:
                hits: Hits to attribute to this pass.

            Returns:
                The validator's cumulative reported cache hits.
            """
            async with validator:
                cache.stats.hits += hits
            return validator.api_stats.cache_hits

        assert asyncio.run(run(3)) == 3
        # The second pass adds only its own two, not the first three
        # again, so the running total is five rather than eight.
        assert asyncio.run(run(2)) == 5


class TestRealValidationPath:
    """The tally a genuine validation run produces.

    The tests above drive the counter directly, which pins the
    arithmetic but cannot see a second merge somewhere else in the run.
    One existed: the Git backend's statistics logging merged the cache
    tally as well, so a real run counted every hit twice. These tests
    validate a call the cache can already answer, so the run is
    self-contained and the reported figure has a known correct value.
    """

    @staticmethod
    def seed(cache: ValidationCache) -> None:
        """Record a validation result the cache can serve from memory.

        Args:
            cache: Cache to populate.
        """
        cache.put(
            REPOSITORY,
            REFERENCE,
            ValidationResult.VALID,
            api_call_type="test",
            validation_method=ValidationMethod.GIT,
        )

    @staticmethod
    def action_calls() -> dict[Path, dict[int, ActionCall]]:
        """Build one cached action call for the validator to check.

        Returns:
            A single call, keyed as the scanner would key it.
        """
        from pathlib import Path as _Path

        return {
            _Path(".github/workflows/build.yaml"): {
                1: ActionCall(
                    raw_line=(
                        f"      - uses: {REPOSITORY}@{REFERENCE}  # v4.2.2"
                    ),
                    line_number=1,
                    organization="actions",
                    repository="checkout",
                    reference=REFERENCE,
                    comment="# v4.2.2",
                    call_type=ActionCallType.ACTION,
                    reference_type=ReferenceType.COMMIT_SHA,
                )
            }
        }

    def validate(self, config: Config, cache: ValidationCache) -> int:
        """Validate one cached call and report the resulting tally.

        Args:
            config: Configuration for the validator.
            cache: Cache holding the answer.

        Returns:
            The cache hits the validator attributed to itself.
        """

        async def run() -> int:
            """Run a validation inside the validator's context.

            Returns:
                The validator's reported cache hits.
            """
            validator = ActionCallValidator(config, cache=cache)
            async with validator:
                await validator.validate_action_calls_async(self.action_calls())
            return validator.api_stats.cache_hits

        return asyncio.run(run())

    def test_one_cached_call_is_counted_once(self, tmp_path: Path) -> None:
        """A single cache hit is reported as one, not two.

        Args:
            tmp_path: Supplies the cache directory.
        """
        config = make_config(tmp_path)
        cache = ValidationCache(config.cache)
        self.seed(cache)

        assert self.validate(config, cache) == 1

    def test_a_later_repository_counts_only_its_own(
        self, tmp_path: Path
    ) -> None:
        """Two validations over one cache report one hit each.

        Args:
            tmp_path: Supplies the cache directory.
        """
        config = make_config(tmp_path)
        cache = ValidationCache(config.cache)
        self.seed(cache)

        assert self.validate(config, cache) == 1
        assert self.validate(config, cache) == 1
