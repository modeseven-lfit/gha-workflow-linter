# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for allow-list pin classification.

Every SHA below is real. ``lfreleng-actions/.github`` releases with
annotated tags, so the commit an allow-list pin carries at ``v0.12.2``
is the *peeled* commit ``bf6642f6...`` and never the tag object
``8f363565...``. A classifier that compared against the tag object would
report every correctly-pinned reference as stale, so the distinction is
asserted rather than assumed.

The scanner and the resolver are already covered by their own suites.
What is tested here is the join between them: which pin plus which
latest release yields which finding, at which severity, and when a
directive silences it.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import subprocess
from typing import TYPE_CHECKING, Any
from unittest import mock

import pytest

from gha_workflow_linter import allow_list_check
from gha_workflow_linter.allow_list_check import (
    ORG_ENV_VAR,
    UNKNOWN_ORG_HOST,
    UNRESOLVED_REASON,
    AllowListChecker,
    AllowListFinding,
    AllowListOutcome,
    _owner_from_remote_url,
    classify_pins,
    host_key,
    resolve_workflow_org,
)
from gha_workflow_linter.allow_list_resolver import AllowListResolver
from gha_workflow_linter.allow_list_scanner import (
    AllowListPin,
    AllowListScanner,
    CommentPosition,
    QuoteStyle,
)
from gha_workflow_linter.allow_list_spec import SpecError, resolve_spec
from gha_workflow_linter.cache import ValidationCache
from gha_workflow_linter.directives import Directive, SuppressionSource
from gha_workflow_linter.latest_release import LatestRelease
from gha_workflow_linter.models import (
    SUPPRESSIBLE_ALLOW_LIST_KINDS,
    AllowListFindingKind,
    CacheConfig,
    Category,
    Config,
    Severity,
    allow_list_category,
)
from gha_workflow_linter.version_utils import _parse_version

if TYPE_CHECKING:
    from collections.abc import Iterable

FIXTURES = Path(__file__).parent / "fixtures" / "allow_list"

WORKFLOW_ORG = "lfreleng-actions"
HOST_REPO = f"{WORKFLOW_ORG}/.github"

# v0.1.1 of lfreleng-actions/.github: the version the estate is pinned to.
STALE_SHA = "18d9c4446bea555d0783e850f6d295f844fe8f67"
STALE_TAG = "v0.1.1"

# v0.12.2, the current release. The tag is annotated, so the commit and
# the tag object have different SHAs.
CURRENT_SHA = "bf6642f68d58c1b81bbe993e676d6cc339ac3654"
CURRENT_TAG = "v0.12.2"
TAG_OBJECT_SHA = "8f363565e79650362c3359ee23b6d6fd295866ee"

LATEST = LatestRelease(tag=CURRENT_TAG, commit_sha=CURRENT_SHA)

# v0.7.0: the newest release at least seven days old while the whole
# v0.12.x series is still inside a Dependabot-style cooldown window, and
# therefore what the resolver legitimately selects as the target. Moving
# a pin from v0.12.2 to v0.7.0 would be a downgrade.
COOLDOWN_SHA = "d46590dd8f51bdd71494eb9d2afa3bade1457a62"
COOLDOWN_TAG = "v0.7.0"

#: Commit-to-tag map of the releases above, in the shape the resolver
#: surfaces on :class:`LatestRelease`. Direction is decided through this
#: rather than through the version comment, which may lie.
RELEASE_COMMITS = {
    CURRENT_SHA: CURRENT_TAG,
    COOLDOWN_SHA: COOLDOWN_TAG,
    STALE_SHA: STALE_TAG,
}

#: What a cooldown-constrained resolution yields: v0.7.0 as the target,
#: with v0.12.2 still known to be a release of the same repository.
COOLDOWN_TARGET = LatestRelease(
    tag=COOLDOWN_TAG,
    commit_sha=COOLDOWN_SHA,
    commit_tags=RELEASE_COMMITS,
)

#: The unconstrained case: v0.12.2 as the target, same map.
CURRENT_TARGET = LatestRelease(
    tag=CURRENT_TAG,
    commit_sha=CURRENT_SHA,
    commit_tags=RELEASE_COMMITS,
)

ALLOW = Directive.ALLOW_LIST_PIN_OK

#: Every kind, so the suppression matrix is asserted exhaustively rather
#: than for a convenient subset.
ALL_KINDS: tuple[AllowListFindingKind, ...] = tuple(AllowListFindingKind)


def make_pin(
    *,
    ref: str = STALE_SHA,
    version_comment: str | None = STALE_TAG,
    directives: frozenset[Directive] = frozenset(),
    reason: str | None = None,
    line_number: int = 116,
    file_path: Path | None = None,
    repospec: str = "",
) -> AllowListPin:
    """Build a pin without going through the scanner.

    Args:
        ref: The ref the pin names.
        version_comment: Version token of the trailing comment.
        directives: Suppression directives in force.
        reason: Free text the suppression carried.
        line_number: 1-based source line.
        file_path: File the pin sits in.
        repospec: Repository part of the spec; empty means the shorthand
            form, which takes its host org from the workflow org.

    Returns:
        The pin.
    """
    spec = resolve_spec(f"{repospec}@{ref}", workflow_org=WORKFLOW_ORG)
    return AllowListPin(
        file_path=file_path or Path("/repo/.github/workflows/publish.yaml"),
        line_number=line_number,
        column=10,
        key_path=("jobs", "publish", "steps", "0", "with", "config"),
        raw_line=f"          config: '@{ref}'  # {version_comment}",
        raw_value=f"@{ref}",
        quote_style=QuoteStyle.SINGLE,
        version_comment=version_comment,
        comment_position=CommentPosition.YAML,
        directives=directives,
        suppressed_by=(
            SuppressionSource.INLINE_COMMENT if directives else None
        ),
        suppression_reason=reason,
        spec=spec,
        auto_fixable=True,
    )


def classify_one(
    pin: AllowListPin,
    latest: LatestRelease | None = LATEST,
    *,
    verify: bool = False,
) -> AllowListFinding | None:
    """Classify a single pin and return its finding, if any.

    Args:
        pin: The pin to classify.
        latest: The host repository's latest release.
        verify: Whether enforcement was requested.

    Returns:
        The finding, or ``None`` when the pin produced none.
    """
    findings = classify_pins([pin], {host_key(pin): latest}, verify=verify)
    return findings[0] if findings else None


class TestClassification:
    """The three classification rules of design section 7.2."""

    def test_current_sha_produces_no_finding(self) -> None:
        """A pin at the latest commit, with a truthful comment, is fine."""
        pin = make_pin(ref=CURRENT_SHA, version_comment=CURRENT_TAG)

        assert classify_one(pin) is None

    def test_older_sha_is_stale(self) -> None:
        """A SHA other than the latest release commit is stale."""
        finding = classify_one(make_pin())

        assert finding is not None
        assert finding.kind is AllowListFindingKind.STALE
        assert finding.current_sha == STALE_SHA
        assert finding.target_sha == CURRENT_SHA
        assert finding.target_version == CURRENT_TAG

    def test_tag_object_sha_is_stale_not_current(self) -> None:
        """The annotated tag object is not the release commit.

        ``v0.12.2`` is an annotated tag, so its ref names a tag object
        that GitHub Actions cannot check out. Treating the two SHAs as
        interchangeable would silently bless a broken pin.
        """
        finding = classify_one(
            make_pin(ref=TAG_OBJECT_SHA, version_comment=CURRENT_TAG)
        )

        assert finding is not None
        assert finding.kind is AllowListFindingKind.STALE

    @pytest.mark.parametrize("ref", ["main", "HEAD", "v0.12.2", "develop"])
    def test_non_sha_refs_are_unpinned(self, ref: str) -> None:
        """A branch or tag ref floats, whatever it points at today."""
        finding = classify_one(make_pin(ref=ref, version_comment=None))

        assert finding is not None
        assert finding.kind is AllowListFindingKind.UNPINNED
        assert finding.current_sha is None
        assert finding.target_sha == CURRENT_SHA

    def test_omitted_ref_is_unpinned(self) -> None:
        """An omitted ref resolves to ``HEAD``, which is not a pin."""
        spec = resolve_spec("lfreleng-actions", workflow_org=WORKFLOW_ORG)
        assert spec.ref == "HEAD"

        finding = classify_one(make_pin(ref="HEAD", version_comment=None))

        assert finding is not None
        assert finding.kind is AllowListFindingKind.UNPINNED

    def test_current_sha_with_lying_comment_is_a_mismatch(self) -> None:
        """A truthful SHA with an untruthful comment is still a defect."""
        finding = classify_one(
            make_pin(ref=CURRENT_SHA, version_comment=STALE_TAG)
        )

        assert finding is not None
        assert finding.kind is AllowListFindingKind.COMMENT_MISMATCH
        assert finding.current_sha == CURRENT_SHA
        assert finding.target_sha == CURRENT_SHA
        assert finding.target_version == CURRENT_TAG

    def test_current_sha_without_a_comment_is_not_a_mismatch(self) -> None:
        """A pin carrying no comment cannot lie."""
        assert (
            classify_one(make_pin(ref=CURRENT_SHA, version_comment=None))
            is None
        )

    @pytest.mark.parametrize("comment", ["0.12.2", "V0.12.2", " v0.12.2 "])
    def test_comment_comparison_tolerates_the_v_prefix(
        self, comment: str
    ) -> None:
        """``0.12.2`` and ``v0.12.2`` name the same release."""
        assert (
            classify_one(make_pin(ref=CURRENT_SHA, version_comment=comment))
            is None
        )

    def test_sha_comparison_is_case_insensitive(self) -> None:
        """Hexadecimal case is not a difference in commit identity."""
        assert (
            classify_one(
                make_pin(ref=CURRENT_SHA.upper(), version_comment=CURRENT_TAG)
            )
            is None
        )

    def test_stale_beats_comment_mismatch(self) -> None:
        """A stale pin with a stale comment is reported once, as stale.

        The comment is consistent with what the pin actually names, so
        there is nothing misleading about it; the pin is simply old.
        """
        finding = classify_one(make_pin(version_comment=STALE_TAG))

        assert finding is not None
        assert finding.kind is AllowListFindingKind.STALE

    def test_categories_follow_the_taxonomy(self) -> None:
        """Currency findings are advisory; defects are not."""
        stale = classify_one(make_pin())
        mismatch = classify_one(
            make_pin(ref=CURRENT_SHA, version_comment=STALE_TAG)
        )
        unpinned = classify_one(make_pin(ref="main", version_comment=None))

        assert stale is not None
        assert mismatch is not None
        assert unpinned is not None
        assert stale.category is Category.CURRENCY
        assert unpinned.category is Category.CURRENCY
        assert mismatch.category is Category.DEFECT


class TestCooldownDirection:
    """Staleness has a direction, and a cooldown must respect it.

    A cooldown deliberately selects an *older* release than the newest
    one in existence, so the resolved target is not a ceiling. Comparing
    a pin against it by SHA equality alone reports a repository that is
    correctly pinned to v0.12.2 as stale and tells its owner to move to
    v0.7.0 -- a downgrade, presented as a fix. Direction is therefore
    established from the host repository's own commit-to-tag map, never
    from the version comment, which section 7.2 exists because it lies.
    """

    def test_a_pin_ahead_of_a_cooldown_target_is_not_stale(self) -> None:
        """The exact regression: v0.12.2 against a v0.7.0 target.

        Every pin in the ``java-workflows`` estate sits at v0.12.2 and a
        seven-day cooldown resolves the target to v0.7.0. The user is
        ahead of the target, which is fine, and there is nothing to say.
        """
        finding = classify_one(
            make_pin(ref=CURRENT_SHA, version_comment=CURRENT_TAG),
            latest=COOLDOWN_TARGET,
        )

        assert finding is None

    def test_a_pin_behind_the_target_is_still_stale(self) -> None:
        """Genuine staleness is unaffected by the direction check."""
        finding = classify_one(
            make_pin(ref=STALE_SHA, version_comment=STALE_TAG),
            latest=CURRENT_TARGET,
        )

        assert finding is not None
        assert finding.kind is AllowListFindingKind.STALE
        assert finding.current_sha == STALE_SHA
        assert finding.target_sha == CURRENT_SHA
        assert finding.target_version == CURRENT_TAG

    def test_a_pin_equal_to_the_target_produces_no_finding(self) -> None:
        """Sitting exactly on the cooldown-selected release is correct."""
        finding = classify_one(
            make_pin(ref=COOLDOWN_SHA, version_comment=COOLDOWN_TAG),
            latest=COOLDOWN_TARGET,
        )

        assert finding is None

    def test_a_commit_belonging_to_no_release_is_stale(self) -> None:
        """An unplaceable commit gets the best advice available.

        The annotated tag object of v0.12.2 is not the commit of any
        release, so its position cannot be established and the target
        remains the only thing worth recommending.
        """
        finding = classify_one(
            make_pin(ref=TAG_OBJECT_SHA, version_comment=CURRENT_TAG),
            latest=COOLDOWN_TARGET,
        )

        assert finding is not None
        assert finding.kind is AllowListFindingKind.STALE
        assert finding.target_version == COOLDOWN_TAG

    def test_direction_ignores_the_version_comment(self) -> None:
        """A lying comment can neither create nor conceal staleness."""
        ahead = classify_one(
            make_pin(ref=CURRENT_SHA, version_comment=STALE_TAG),
            latest=COOLDOWN_TARGET,
        )
        behind = classify_one(
            make_pin(ref=STALE_SHA, version_comment="v9.9.9"),
            latest=CURRENT_TARGET,
        )

        assert ahead is None
        assert behind is not None
        assert behind.kind is AllowListFindingKind.STALE

    def test_version_comparison_is_numeric_not_lexicographic(self) -> None:
        """``v0.12.2`` is newer than ``v0.7.0``, whatever ``str`` thinks.

        Sorting these two tags as text puts v0.12.2 *before* v0.7.0,
        which is exactly the shape that hides a direction bug: the
        comparison must go through ``_parse_version``.
        """
        assert CURRENT_TAG < COOLDOWN_TAG
        assert _parse_version(CURRENT_TAG) > _parse_version(COOLDOWN_TAG)

        ahead = classify_one(
            make_pin(ref=CURRENT_SHA, version_comment=CURRENT_TAG),
            latest=COOLDOWN_TARGET,
        )
        behind = classify_one(
            make_pin(ref=COOLDOWN_SHA, version_comment=COOLDOWN_TAG),
            latest=CURRENT_TARGET,
        )

        assert ahead is None
        assert behind is not None
        assert behind.kind is AllowListFindingKind.STALE

    def test_a_target_without_a_commit_map_reports_staleness(self) -> None:
        """A record carrying no map degrades to plain SHA comparison.

        The resolver only omits the map when it restored the record from
        the cache, which it refuses to do while a cooldown is active, so
        the target really is the newest release in that case.
        """
        finding = classify_one(make_pin(ref=STALE_SHA), latest=LATEST)

        assert finding is not None
        assert finding.kind is AllowListFindingKind.STALE


class TestCachedTargetDirection:
    """A warm cache must not reintroduce the downgrade recommendation.

    ``ValidationCache`` persists only ``(tag, sha)``, so a restored
    target carries no commit map and cannot place a pinned commit. The
    resolver therefore bypasses the cache entirely while a cooldown is
    active, which is the only situation in which the target can be older
    than something a pin already names.
    """

    @pytest.mark.asyncio
    async def test_a_cooldown_run_ignores_a_cached_target(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The cached v0.7.0 target is re-resolved, map and all."""
        config = Config(
            cooldown_days=7,
            cache=CacheConfig(enabled=True, cache_dir=tmp_path),
        )
        cache = ValidationCache(config.cache)
        cache.put_latest_version(HOST_REPO, COOLDOWN_TAG, COOLDOWN_SHA)
        resolver = AllowListResolver(config, cache)
        resolved: list[list[str]] = []

        async def fake_uncached(
            repo_keys: list[str],
        ) -> dict[str, LatestRelease | None]:
            """Answer with the same target, but carrying its commit map.

            Args:
                repo_keys: Keys the resolver could not answer locally.

            Returns:
                The cooldown-shifted target for every key.
            """
            resolved.append(repo_keys)
            return dict.fromkeys(repo_keys, COOLDOWN_TARGET)

        monkeypatch.setattr(resolver, "_resolve_uncached", fake_uncached)
        hosts = await resolver.resolve([HOST_REPO])

        pin = make_pin(ref=CURRENT_SHA, version_comment=CURRENT_TAG)
        assert resolved == [[HOST_REPO]]
        assert classify_pins([pin], hosts, verify=False) == []

    @pytest.mark.asyncio
    async def test_a_cache_hit_without_a_cooldown_is_still_free(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Nothing is ahead of an unconstrained target, so the map is
        unnecessary and the cache is used exactly as before.
        """
        config = Config(
            cooldown_days=0,
            cache=CacheConfig(enabled=True, cache_dir=tmp_path),
        )
        cache = ValidationCache(config.cache)
        cache.put_latest_version(HOST_REPO, CURRENT_TAG, CURRENT_SHA)
        resolver = AllowListResolver(config, cache)

        async def explode(repo_keys: list[str]) -> dict[str, object]:
            """Fail if the resolver reaches a backend at all.

            Args:
                repo_keys: Keys the resolver tried to resolve.

            Raises:
                AssertionError: Always.
            """
            raise AssertionError(f"unexpected resolution of {repo_keys}")

        monkeypatch.setattr(resolver, "_resolve_uncached", explode)
        hosts = await resolver.resolve([HOST_REPO])

        pin = make_pin(ref=CURRENT_SHA, version_comment=CURRENT_TAG)
        assert classify_pins([pin], hosts, verify=False) == []


class TestOutOfScopeKinds:
    """``INVALID_SPEC`` and ``UNRESOLVABLE`` are never manufactured."""

    @pytest.mark.parametrize(
        "ref",
        [STALE_SHA, CURRENT_SHA, TAG_OBJECT_SHA, "main", "HEAD"],
    )
    def test_no_defect_kinds_are_invented(self, ref: str) -> None:
        """Neither kind can be substantiated in this phase.

        Proving a SHA absent from the host repository needs a lookup the
        resolver does not perform, and the scanner never hands over a
        scalar that failed the grammar.
        """
        finding = classify_one(make_pin(ref=ref, version_comment=None))

        if finding is not None:
            assert finding.kind not in {
                AllowListFindingKind.UNRESOLVABLE,
                AllowListFindingKind.INVALID_SPEC,
            }


class TestSeverity:
    """Default severities, and promotion under enforcement."""

    @pytest.mark.parametrize(
        ("pin_kwargs", "kind", "severity"),
        [
            ({}, AllowListFindingKind.STALE, Severity.WARNING),
            (
                {"ref": CURRENT_SHA, "version_comment": STALE_TAG},
                AllowListFindingKind.COMMENT_MISMATCH,
                Severity.WARNING,
            ),
            (
                {"ref": "main", "version_comment": None},
                AllowListFindingKind.UNPINNED,
                Severity.NOTICE,
            ),
        ],
    )
    def test_default_severities(
        self,
        pin_kwargs: dict[str, Any],
        kind: AllowListFindingKind,
        severity: Severity,
    ) -> None:
        """Without enforcement, nothing is an error."""
        finding = classify_one(make_pin(**pin_kwargs))

        assert finding is not None
        assert finding.kind is kind
        assert finding.severity is severity

    @pytest.mark.parametrize(
        "pin_kwargs",
        [
            {},
            {"ref": CURRENT_SHA, "version_comment": STALE_TAG},
            {"ref": "main", "version_comment": None},
        ],
    )
    def test_verify_promotes_every_unsuppressed_finding(
        self, pin_kwargs: dict[str, Any]
    ) -> None:
        """Under ``verify`` every unsuppressed finding is an error."""
        finding = classify_one(make_pin(**pin_kwargs), verify=True)

        assert finding is not None
        assert finding.severity is Severity.ERROR

    def test_verify_never_promotes_a_suppressed_finding(self) -> None:
        """Enforcement must not defeat a suppression."""
        finding = classify_one(
            make_pin(directives=frozenset({ALLOW})), verify=True
        )

        assert finding is not None
        assert finding.suppressed is True
        assert finding.severity is Severity.WARNING


class TestSuppressionMatrix:
    """The applicability matrix of design section 7.4."""

    def test_the_suppressible_set_is_exactly_stale_and_unpinned(self) -> None:
        """The directive is a claim about currency, not correctness."""
        suppressible = set(SUPPRESSIBLE_ALLOW_LIST_KINDS)
        assert suppressible == {
            AllowListFindingKind.STALE,
            AllowListFindingKind.UNPINNED,
        }

    @pytest.mark.parametrize("kind", ALL_KINDS)
    def test_suppressibility_matches_the_category(
        self, kind: AllowListFindingKind
    ) -> None:
        """Only currency kinds may be silenced.

        Asserted over every member of the enum, so a kind added later
        cannot quietly become suppressible.
        """
        suppressible = kind in SUPPRESSIBLE_ALLOW_LIST_KINDS
        assert suppressible is (allow_list_category(kind) is Category.CURRENCY)

    def test_stale_is_suppressible(self) -> None:
        """The exact condition the directive asserts."""
        finding = classify_one(make_pin(directives=frozenset({ALLOW})))

        assert finding is not None
        assert finding.kind is AllowListFindingKind.STALE
        assert finding.suppressed is True

    def test_unpinned_is_suppressible(self) -> None:
        """Tracking a branch can be a deliberate development choice."""
        finding = classify_one(
            make_pin(
                ref="main",
                version_comment=None,
                directives=frozenset({ALLOW}),
            )
        )

        assert finding is not None
        assert finding.kind is AllowListFindingKind.UNPINNED
        assert finding.suppressed is True

    def test_comment_mismatch_is_not_suppressible(self) -> None:
        """A comment that lies is a defect regardless of intent."""
        finding = classify_one(
            make_pin(
                ref=CURRENT_SHA,
                version_comment=STALE_TAG,
                directives=frozenset({ALLOW}),
            )
        )

        assert finding is not None
        assert finding.kind is AllowListFindingKind.COMMENT_MISMATCH
        assert finding.suppressed is False

    def test_comment_mismatch_is_promoted_despite_the_directive(self) -> None:
        """Enforcement still reaches a non-suppressible kind."""
        finding = classify_one(
            make_pin(
                ref=CURRENT_SHA,
                version_comment=STALE_TAG,
                directives=frozenset({ALLOW}),
            ),
            verify=True,
        )

        assert finding is not None
        assert finding.severity is Severity.ERROR

    def test_suppressed_findings_are_still_produced(self) -> None:
        """Suppression hides a finding from the exit code, not from view."""
        pins = [
            make_pin(directives=frozenset({ALLOW}), line_number=10),
            make_pin(line_number=20),
        ]
        findings = classify_pins(pins, {HOST_REPO: LATEST}, verify=False)

        assert [finding.suppressed for finding in findings] == [True, False]


class TestResolutionFailure:
    """Fail-soft behaviour of design section 6.4."""

    def test_unresolved_host_produces_no_findings(self) -> None:
        """Guessing under uncertainty is the one forbidden behaviour."""
        assert classify_one(make_pin(), latest=None) is None

    @pytest.mark.asyncio
    async def test_check_records_the_reason(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unresolved host is recorded, not silently dropped."""
        outcome = await run_check(
            tmp_path, monkeypatch, hosts={HOST_REPO: None}
        )

        assert outcome.checked is True
        assert outcome.findings == []
        assert outcome.unresolved == {HOST_REPO: UNRESOLVED_REASON}
        assert outcome.resolved is False

    @pytest.mark.asyncio
    async def test_resolution_failure_is_not_a_verdict(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The outcome states the facts and decides nothing.

        Under ``--verify-allow-list`` the caller maps this to exit code
        ``4``; in default mode it is a notice. Both readings must be
        available from the same outcome.
        """
        outcome = await run_check(
            tmp_path,
            monkeypatch,
            hosts={HOST_REPO: None},
            verify=True,
        )

        assert outcome.unresolved
        assert outcome.unsuppressed == []


class _RecordingResolver:
    """Resolver double that records the keys it was asked for."""

    calls: list[list[str]] = []
    hosts: dict[str, LatestRelease | None] = {}

    def __init__(self, config: Config, cache: ValidationCache) -> None:
        """Accept the real resolver's constructor arguments.

        Args:
            config: Linter configuration.
            cache: Validation cache.
        """
        self.config = config
        self.cache = cache

    async def resolve(
        self, repo_keys: Iterable[str]
    ) -> dict[str, LatestRelease | None]:
        """Record the request and answer from the configured mapping.

        Args:
            repo_keys: Host repository keys the checker asked for.

        Returns:
            The configured latest release of each key.
        """
        keys = list(repo_keys)
        type(self).calls.append(keys)
        return {key: type(self).hosts.get(key) for key in keys}


async def run_check(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    hosts: dict[str, LatestRelease | None] | None = None,
    verify: bool = False,
    files: Iterable[Path] | None = None,
) -> AllowListOutcome:
    """Run a check with the resolver replaced by a recording double.

    Args:
        root: Repository root handed to the checker.
        monkeypatch: Fixture used to install the double.
        hosts: Latest release of each host repository.
        verify: Whether enforcement was requested.
        files: Files to scan; the standard fixture when omitted.

    Returns:
        The check outcome.
    """
    _RecordingResolver.calls = []
    _RecordingResolver.hosts = {HOST_REPO: LATEST} if hosts is None else hosts
    monkeypatch.setattr(
        allow_list_check, "AllowListResolver", _RecordingResolver
    )
    monkeypatch.delenv(ORG_ENV_VAR, raising=False)

    config = Config()
    config.allow_list.org = WORKFLOW_ORG
    config.allow_list.verify = verify
    cache = ValidationCache(CacheConfig(enabled=False, cache_dir=root))
    checker = AllowListChecker(config, cache)

    paths = [FIXTURES / "internal_step_config.yaml"] if files is None else files
    return await checker.check(paths, root)


class TestChecker:
    """End-to-end behaviour of :class:`AllowListChecker`."""

    @pytest.mark.asyncio
    async def test_disabled_check_reports_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A disabled check must not be mistaken for a clean one."""
        _RecordingResolver.calls = []
        monkeypatch.setattr(
            allow_list_check, "AllowListResolver", _RecordingResolver
        )
        config = Config()
        config.allow_list.enabled = False
        cache = ValidationCache(CacheConfig(enabled=False, cache_dir=tmp_path))

        outcome = await AllowListChecker(config, cache).check(
            [FIXTURES / "internal_step_config.yaml"], tmp_path
        )

        assert outcome.checked is False
        assert outcome.findings == []
        assert _RecordingResolver.calls == []

    @pytest.mark.asyncio
    async def test_no_pins_is_not_checked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A file holding no pin resolves nothing at all."""
        outcome = await run_check(
            tmp_path, monkeypatch, files=[FIXTURES / "no_pins.yaml"]
        )

        assert outcome.checked is False
        assert _RecordingResolver.calls == []

    @pytest.mark.asyncio
    async def test_one_lookup_per_distinct_host(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Six pins sharing a host cost exactly one lookup.

        The fixture carries six ``config:`` pins, every one of them
        naming ``lfreleng-actions/.github`` through the shorthand form.
        """
        outcome = await run_check(
            tmp_path, monkeypatch, files=[FIXTURES / "suppression.yaml"]
        )

        assert len(outcome.findings) == 6
        assert _RecordingResolver.calls == [[HOST_REPO]]

    @pytest.mark.asyncio
    async def test_suppression_is_read_from_the_source(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Both authoring forms of the directive reach the finding.

        The fixture's six pins are, in order: preceding-line form,
        inline form, both forms, an in-scalar inline form, a directive
        separated by a blank line (which does not bind), and no
        directive at all.
        """
        outcome = await run_check(
            tmp_path, monkeypatch, files=[FIXTURES / "suppression.yaml"]
        )

        assert [f.suppressed for f in outcome.findings] == [
            True,
            True,
            True,
            True,
            False,
            False,
        ]
        assert outcome.suppressed_count == 4
        assert len(outcome.unsuppressed) == 2

    @pytest.mark.asyncio
    async def test_suppression_reasons_survive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A suppression carries its own justification into the report."""
        outcome = await run_check(
            tmp_path, monkeypatch, files=[FIXTURES / "suppression.yaml"]
        )

        reasons = [f.pin.suppression_reason for f in outcome.findings[:3]]
        assert reasons == [
            "waiting for a release",
            "upstream is broken",
            "inline reason",
        ]

    @pytest.mark.asyncio
    async def test_findings_name_their_host_repository(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The shorthand form takes its host org from the workflow org."""
        outcome = await run_check(tmp_path, monkeypatch)

        assert [f.host_repo for f in outcome.findings] == [HOST_REPO]
        assert HOST_REPO in outcome.hosts

    @pytest.mark.asyncio
    async def test_messages_name_the_host_and_the_target(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Messages are printable verbatim, with no further lookup."""
        outcome = await run_check(tmp_path, monkeypatch)

        message = outcome.findings[0].message
        assert HOST_REPO in message
        assert CURRENT_TAG in message


class TestWorkflowOrgPrecedence:
    """The precedence chain of design section 6.3."""

    @staticmethod
    def _git_repo(root: Path, remotes: dict[str, str]) -> None:
        """Initialise a repository with the given remotes.

        Args:
            root: Directory to initialise.
            remotes: Mapping of remote name to URL.
        """
        subprocess.run(
            ["git", "-c", "init.defaultBranch=main", "init", "-q", str(root)],
            check=True,
            capture_output=True,
        )
        for name, url in remotes.items():
            subprocess.run(
                ["git", "-C", str(root), "remote", "add", name, url],
                check=True,
                capture_output=True,
            )

    def test_configuration_wins(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An explicit setting beats everything below it."""
        monkeypatch.setenv(ORG_ENV_VAR, "env-org")
        self._git_repo(tmp_path, {"upstream": "git@github.com:up-org/r.git"})

        assert (
            resolve_workflow_org(tmp_path, configured="  config-org  ")
            == "config-org"
        )

    def test_environment_beats_the_remotes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``GITHUB_REPOSITORY_OWNER`` is authoritative inside Actions."""
        monkeypatch.setenv(ORG_ENV_VAR, "env-org")
        self._git_repo(tmp_path, {"upstream": "git@github.com:up-org/r.git"})

        assert resolve_workflow_org(tmp_path) == "env-org"

    def test_upstream_beats_origin(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The load-bearing rule: contributors work from forks.

        ``origin`` is the contributor's personal fork, whose owner has no
        ``.github`` repository at all, so resolving to it would make
        every shorthand pin unresolvable.
        """
        monkeypatch.delenv(ORG_ENV_VAR, raising=False)
        self._git_repo(
            tmp_path,
            {
                "origin": (
                    "https://github.com/modeseven-lfreleng-actions/r.git"
                ),
                "upstream": "https://github.com/lfreleng-actions/r.git",
            },
        )

        assert resolve_workflow_org(tmp_path) == "lfreleng-actions"

    def test_origin_is_used_when_upstream_is_absent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A clone with no fork still resolves."""
        monkeypatch.delenv(ORG_ENV_VAR, raising=False)
        self._git_repo(
            tmp_path,
            {"origin": "https://github.com/lfreleng-actions/r.git"},
        )

        assert resolve_workflow_org(tmp_path) == "lfreleng-actions"

    def test_unresolvable_returns_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Not a repository, no environment: no org, and no exception."""
        monkeypatch.delenv(ORG_ENV_VAR, raising=False)

        assert resolve_workflow_org(tmp_path) == ""

    def test_empty_environment_value_is_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An empty variable is absent, not an answer."""
        monkeypatch.setenv(ORG_ENV_VAR, "   ")
        self._git_repo(
            tmp_path,
            {"origin": "https://github.com/lfreleng-actions/r.git"},
        )

        assert resolve_workflow_org(tmp_path) == "lfreleng-actions"

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://github.com/lfreleng-actions/r.git", "lfreleng-actions"),
            ("https://github.com/lfreleng-actions/r", "lfreleng-actions"),
            ("git@github.com:lfreleng-actions/r.git", "lfreleng-actions"),
            (
                "ssh://git@github.com/lfreleng-actions/r.git",
                "lfreleng-actions",
            ),
            ("https://github.com/lfreleng-actions/r/", "lfreleng-actions"),
            (
                "https://token@github.com/lfreleng-actions/r",
                "lfreleng-actions",
            ),
            ("git@github.com:lfreleng-actions/.github.git", "lfreleng-actions"),
            ("not-a-url", ""),
            ("", ""),
            ("https://github.com/repo-only", ""),
        ],
    )
    def test_remote_url_forms(self, url: str, expected: str) -> None:
        """Every remote URL form in everyday use is understood."""
        assert _owner_from_remote_url(url) == expected

    def test_a_remote_url_form_survives_a_real_remote(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The parsing above is reached through a genuine Git remote."""
        monkeypatch.delenv(ORG_ENV_VAR, raising=False)
        self._git_repo(
            tmp_path,
            {"origin": "git@github.com:lfreleng-actions/.github.git"},
        )

        assert resolve_workflow_org(tmp_path) == "lfreleng-actions"

    def test_a_missing_org_skips_shorthand_pins(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unresolvable org is not an error; the pins are skipped.

        The scanner cannot parse ``@<sha>`` without a host org, so it
        drops the coordinate with a debug log, which is exactly the
        documented fail-soft behaviour.
        """
        monkeypatch.delenv(ORG_ENV_VAR, raising=False)
        scanner = AllowListScanner(Config(), "")
        assert scanner.scan_file(FIXTURES / "internal_step_config.yaml") == []

        with pytest.raises(SpecError):
            resolve_spec(f"@{STALE_SHA}", workflow_org="")


class TestUnknownWorkflowOrg:
    """An unknown org must not read as a clean result.

    An empty workflow organisation makes every candidate in-repo path
    unresolvable, so the scanner finds nothing at all. Returning an empty
    outcome would let --verify-allow-list pass without having checked
    anything, which is the failure mode the flag exists to prevent.
    """

    @staticmethod
    def _workflow(tmp_path: Path) -> Path:
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        target = workflows / "ci.yaml"
        target.write_text(
            "---\n"
            "name: T\n"
            "on: [push]\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: lfreleng-actions/harden-runner-block-action@abc\n"
            "        with:\n"
            "          config: "
            "'@18d9c4446bea555d0783e850f6d295f844fe8f67'  # v0.1.1\n"
        )
        return target

    def _check(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> AllowListOutcome:
        # No configured org, no environment, and a directory that is not a
        # git repository, so every resolution route comes up empty.
        monkeypatch.delenv("GITHUB_REPOSITORY_OWNER", raising=False)
        target = self._workflow(tmp_path)
        config = Config()
        return asyncio.run(
            AllowListChecker(config, ValidationCache(config.cache)).check(
                [target], tmp_path
            )
        )

    def test_reports_unresolved_rather_than_clean(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        outcome = self._check(tmp_path, monkeypatch)

        assert outcome.checked is True
        assert outcome.unresolved
        assert not outcome.resolved

    def test_names_the_remedy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        outcome = self._check(tmp_path, monkeypatch)

        assert "--allow-list-org" in "".join(outcome.unresolved.values())

    def test_configured_org_resolves_normally(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With an org supplied, the pin is found and no sentinel appears."""
        monkeypatch.delenv("GITHUB_REPOSITORY_OWNER", raising=False)
        target = self._workflow(tmp_path)
        config = Config()
        config.allow_list.org = "lfreleng-actions"

        with mock.patch.object(
            AllowListResolver, "resolve", new=_no_release_resolver()
        ):
            outcome = asyncio.run(
                AllowListChecker(config, ValidationCache(config.cache)).check(
                    [target], tmp_path
                )
            )

        assert UNKNOWN_ORG_HOST not in outcome.unresolved


def _no_release_resolver() -> Any:
    """Return a resolve() stub reporting no release for every host."""

    async def _resolve(
        _self: AllowListResolver, repo_keys: Any
    ) -> dict[str, Any]:
        return dict.fromkeys(repo_keys)

    return _resolve
