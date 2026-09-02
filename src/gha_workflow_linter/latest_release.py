# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Latest-release records, the GraphQL behind them, and their selection.

A harden-runner allow-list pin names a *commit* of a host repository
(normally ``<org>/.github``), and it is stale when that commit is not the
one behind the host repository's latest release. Answering that question
needs three things, and this module holds all three so both validation
backends share one definition:

* :class:`LatestRelease` -- the answer: a tag plus its **peeled commit**,
  and the commit-to-tag map of every release that was in the running, so
  a caller can ask "which release does *this* commit belong to?".
* :func:`build_latest_releases_query` / :func:`parse_latest_releases_response`
  -- one aliased GraphQL round trip that returns each repository's
  releases *and* its tag refs, so annotated tags peel without a second
  request.
* :func:`select_latest_release` -- the backend-agnostic policy (drafts,
  prereleases, cooldown) applied to whatever candidates a backend found.

The commit-to-tag map exists because a cooldown makes "latest" a moving
target in both directions: when the newest release is still warming, the
selected release is deliberately an *older* one, and a pin sitting on a
newer release is ahead rather than stale. Answering that needs the
position of the pinned commit, which only the resolving backend has seen.

Peeling is the subtle part. ``lfreleng-actions`` releases use annotated
tags, so ``refs/tags/v0.12.2`` names a *tag object*
(``8f363565...``) whose target is the commit (``bf6642f6...``). Pins carry
the commit. Comparing a pin against the tag-object SHA would report every
correctly-pinned reference as stale, which is why the tag-ref selection
here nests ``target { oid ... on Tag { target { oid } } }`` -- the same
shape :meth:`~gha_workflow_linter.action_call_resolver._ReferenceResolutionMixin._extract_sha_from_ref_data`
already relies on.

Note that the GraphQL ``Tag`` type exposes ``name``, not ``tagName``;
``tagName`` exists on ``Release`` only. Selecting it on a ``Tag`` makes
the whole query fail at run time.

This module deliberately depends on nothing inside the package beyond
:mod:`action_call_scanner` and :mod:`version_utils`, so it can sit underneath both
:mod:`github_api` and :mod:`allow_list_resolver` without a cycle.
"""

from __future__ import annotations

import dataclasses
import logging
import re
from typing import TYPE_CHECKING, Any

from .action_call_scanner import ActionCallPatterns
from .version_utils import (
    _get_version_specificity,
    _parse_iso_datetime,
    _parse_version,
    _select_version_with_cooldown,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping, Sequence
    from datetime import datetime

logger = logging.getLogger(__name__)

#: Tag refs requested per repository. Ordered by tag-commit date descending,
#: so the newest releases are covered even for repositories with a long tag
#: history.
_TAG_REFS_PER_REPO = 100

#: Releases requested per repository. Only enough to let a cooldown fall
#: back to an older, already-warm release; the newest few always suffice.
_RELEASES_PER_REPO = 20

#: Owner and repository names GitHub actually permits. Repository keys are
#: interpolated into the query, so anything outside this set is dropped
#: rather than escaped: a key that cannot name a real repository has no
#: business reaching the API.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


@dataclasses.dataclass(frozen=True)
class LatestRelease:
    """The latest release of a repository, resolved to a commit.

    Attributes:
        tag: Release tag name, for example ``v0.12.2``.
        commit_sha: SHA of the commit the tag points at. For an annotated
            tag this is the *peeled* commit, never the tag object.
        published_at: When the release was published, or ``None`` when the
            backend cannot supply a date (the Git backend never can) or
            when the value was restored from the cache, which does not
            persist it.
        commit_tags: Reverse map of lowercased commit SHA to the tag of
            the policy-eligible release behind it, covering every release
            the backend considered and not only the selected one. A
            record restored from the cache carries the map the original
            resolution built, so it can place any commit that resolution
            saw -- but not one published since. Empty when a caller
            constructs a record without one. Excluded from equality and
            ``repr``: it is derived context about the repository, not
            part of the identity of the release. Prefer
            :meth:`tag_for_commit` over indexing it directly.
    """

    tag: str
    commit_sha: str
    published_at: datetime | None = None
    commit_tags: Mapping[str, str] = dataclasses.field(
        default_factory=dict, compare=False, repr=False
    )

    def tag_for_commit(self, commit_sha: str) -> str | None:
        """Return the release tag a commit of this repository belongs to.

        Every tag this can return passed
        :attr:`~gha_workflow_linter.action_call_scanner.ActionCallPatterns.VERSION_TAG_PATTERN`,
        so it is safe to hand to
        :func:`~gha_workflow_linter.version_utils._parse_version`.

        Args:
            commit_sha: A commit SHA, in either case.

        Returns:
            The tag of the release whose peeled commit is ``commit_sha``,
            or ``None`` when the commit belongs to no release this record
            covers -- including one published after a cached record was
            written.
        """
        return self.commit_tags.get(commit_sha.strip().lower())


@dataclasses.dataclass(frozen=True)
class ReleasePolicy:
    """Which releases a caller is willing to accept as "latest".

    Attributes:
        allow_prerelease: Include releases GitHub marks as prereleases.
            Drafts are never eligible regardless of this setting.
        cooldown_days: Minimum age, in days, before a release becomes
            eligible. ``0`` disables the cooldown. A candidate with no
            known publication date is skipped while a cooldown is active,
            because its age cannot be verified.
    """

    allow_prerelease: bool = False
    cooldown_days: int = 0


@dataclasses.dataclass(frozen=True)
class ReleaseCandidate:
    """One release (or bare tag) a backend offered for consideration.

    Attributes:
        tag: Tag name.
        commit_sha: Peeled commit SHA behind the tag.
        published_at: Publication timestamp, or ``None`` when unknown.
        is_draft: Whether GitHub marks the release as a draft.
        is_prerelease: Whether GitHub marks the release as a prerelease.
    """

    tag: str
    commit_sha: str
    published_at: datetime | None = None
    is_draft: bool = False
    is_prerelease: bool = False


def build_latest_releases_query(
    repo_keys: Sequence[str],
) -> tuple[str, dict[str, str]]:
    """Build one aliased GraphQL query covering several repositories.

    Each repository contributes its ``latestRelease``, a page of recent
    releases (for their publication dates and draft/prerelease flags) and
    a page of tag refs (for the peeled commit behind each tag).

    Args:
        repo_keys: Repository keys, ``owner/repo`` or ``owner/repo/path``.
            Any trailing action subpath is ignored; keys that cannot name
            a real repository are skipped.

    Returns:
        Two-tuple of the query document and a mapping of GraphQL alias to
        the originating repository key. ``("", {})`` when no key was
        usable, so callers can skip the request entirely.
    """
    query_parts: list[str] = []
    aliases: dict[str, str] = {}

    for index, repo_key in enumerate(repo_keys):
        owner, _, remainder = repo_key.partition("/")
        name = remainder.split("/")[0]
        if not _SAFE_NAME.match(owner) or not _SAFE_NAME.match(name):
            logger.warning(f"Invalid repository format: {repo_key}")
            continue

        alias = f"repo_{index}"
        aliases[alias] = repo_key
        query_parts.append(
            f'{alias}: repository(owner: "{owner}", name: "{name}") {{ '
            f"latestRelease {{ tagName publishedAt isDraft isPrerelease }} "
            f"releases(first: {_RELEASES_PER_REPO}, "
            f"orderBy: {{field: CREATED_AT, direction: DESC}}) "
            f"{{ nodes {{ tagName publishedAt isDraft isPrerelease }} }} "
            f'refs(refPrefix: "refs/tags/", first: {_TAG_REFS_PER_REPO}, '
            f"orderBy: {{field: TAG_COMMIT_DATE, direction: DESC}}) "
            f"{{ nodes {{ name target {{ oid ... on Tag "
            f"{{ target {{ oid }} }} }} }} }} }}"
        )

    if not query_parts:
        return "", {}

    return f"query {{ {' '.join(query_parts)} }}", aliases


def _peeled_sha(target: Any) -> str | None:
    """Extract the commit SHA from a tag ref's GraphQL ``target``.

    Args:
        target: The ``target`` payload of a ``refs.nodes`` entry.

    Returns:
        The commit SHA: the nested ``target.target.oid`` for an annotated
        tag, or the direct ``target.oid`` for a lightweight tag. ``None``
        when neither is present.
    """
    if not isinstance(target, dict):
        return None

    nested = target.get("target")
    if isinstance(nested, dict) and nested.get("oid"):
        return str(nested["oid"])

    oid = target.get("oid")
    return str(oid) if oid else None


def _tag_commit_shas(repo_data: Mapping[str, Any]) -> dict[str, str]:
    """Map tag name to peeled commit SHA for one repository's tag refs.

    Args:
        repo_data: The per-repository GraphQL response fragment.

    Returns:
        Dictionary mapping tag name to commit SHA. Tags whose target could
        not be peeled are omitted.
    """
    refs = repo_data.get("refs")
    nodes = refs.get("nodes") if isinstance(refs, dict) else None

    shas: dict[str, str] = {}
    for node in nodes or []:
        if not isinstance(node, dict):
            continue
        name = node.get("name")
        sha = _peeled_sha(node.get("target"))
        if name and sha:
            shas[str(name)] = sha

    return shas


def tag_candidates(tag_shas: Mapping[str, str]) -> list[ReleaseCandidate]:
    """Build undated candidates from a tag-to-commit mapping.

    Used by the Git backend, which sees tags but no releases, and as the
    GraphQL fallback for a repository that publishes tags without cutting
    releases. Every candidate is undated, so an active cooldown rejects
    them all rather than guessing at their age.

    Args:
        tag_shas: Mapping of tag name to commit SHA, already peeled.

    Returns:
        One :class:`ReleaseCandidate` per tag carrying a SHA.
    """
    return [
        ReleaseCandidate(tag=tag, commit_sha=sha)
        for tag, sha in tag_shas.items()
        if sha
    ]


def _release_candidates(
    repo_data: Mapping[str, Any],
) -> list[ReleaseCandidate]:
    """Collect the release candidates for one repository's response.

    Releases are matched to a tag ref to obtain the peeled commit SHA; a
    release whose tag has no ref (a draft, typically, since GitHub only
    creates the tag on publication) is dropped. A repository with no
    usable releases falls back to its bare tags, mirroring the preference
    order in ``action_call_versions``.

    Args:
        repo_data: The per-repository GraphQL response fragment.

    Returns:
        Candidates in no particular order; :func:`select_latest_release`
        does the ranking.
    """
    tag_shas = _tag_commit_shas(repo_data)

    payloads: list[Any] = []
    releases = repo_data.get("releases")
    if isinstance(releases, dict):
        payloads.extend(releases.get("nodes") or [])
    payloads.append(repo_data.get("latestRelease"))

    candidates: dict[str, ReleaseCandidate] = {}
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        tag = str(payload.get("tagName") or "")
        sha = tag_shas.get(tag)
        if not tag or not sha or tag in candidates:
            continue
        candidates[tag] = ReleaseCandidate(
            tag=tag,
            commit_sha=sha,
            published_at=_parse_iso_datetime(payload.get("publishedAt")),
            is_draft=bool(payload.get("isDraft")),
            is_prerelease=bool(payload.get("isPrerelease")),
        )

    return list(candidates.values()) or tag_candidates(tag_shas)


def parse_latest_releases_response(
    response_data: Mapping[str, Any], aliases: Mapping[str, str]
) -> dict[str, list[ReleaseCandidate]]:
    """Map a batched release query response back to repository keys.

    Args:
        response_data: The decoded GraphQL response body.
        aliases: Mapping of GraphQL alias to repository key, as returned
            by :func:`build_latest_releases_query`.

    Returns:
        Dictionary mapping repository key to its candidates. A repository
        GitHub could not resolve (its alias is ``null``) maps to an empty
        list rather than being absent, so callers see "no latest release"
        rather than "not asked".
    """
    root = response_data.get("data") or {}

    results: dict[str, list[ReleaseCandidate]] = {}
    for alias, repo_key in aliases.items():
        repo_data = root.get(alias) if isinstance(root, dict) else None
        if not isinstance(repo_data, dict):
            logger.debug(f"No repository data for {repo_key}")
            results[repo_key] = []
            continue
        results[repo_key] = _release_candidates(repo_data)

    return results


def _is_eligible(candidate: ReleaseCandidate, policy: ReleasePolicy) -> bool:
    """Report whether a candidate may be selected under a policy.

    Args:
        candidate: The candidate under consideration.
        policy: The caller's release policy.

    Returns:
        ``True`` when the candidate carries a SHA, is not a draft, is not
        an excluded prerelease, and has a clean version tag. The tag check
        also guarantees :func:`_parse_version` cannot raise later.
    """
    if candidate.is_draft or not candidate.commit_sha:
        return False
    if candidate.is_prerelease and not policy.allow_prerelease:
        return False

    return bool(ActionCallPatterns.VERSION_TAG_PATTERN.match(candidate.tag))


def _commit_tags(
    ordered: Sequence[ReleaseCandidate],
) -> dict[str, str]:
    """Build the commit-to-tag map of a ranked candidate list.

    Several tags can name one commit (``v8`` alongside ``v8.0.0``), so
    the first entry wins and the candidates are expected pre-ranked:
    highest version, then highest specificity.

    Args:
        ordered: Policy-eligible candidates, ranked newest first.

    Returns:
        Dictionary mapping lowercased commit SHA to tag name.
    """
    commit_tags: dict[str, str] = {}
    for candidate in ordered:
        commit_tags.setdefault(candidate.commit_sha.lower(), candidate.tag)
    return commit_tags


def select_latest_release(
    candidates: Sequence[ReleaseCandidate],
    policy: ReleasePolicy,
    now: datetime | None = None,
) -> LatestRelease | None:
    """Pick the newest policy-eligible candidate.

    Ranking reuses the existing version helpers rather than introducing a
    second notion of "newest": candidates are ordered by parsed version
    then tag specificity, both descending, and the cooldown window is
    applied by :func:`~gha_workflow_linter.version_utils._select_version_with_cooldown`.

    The result carries the commit-to-tag map of every eligible candidate,
    not just the selected one, because a cooldown can select a release
    that is *older* than one a caller's pin already names.

    Args:
        candidates: Candidates gathered by a backend, in any order.
        policy: Draft/prerelease and cooldown policy to apply.
        now: Reference time for the cooldown window (defaults to the
            current UTC time); primarily an injection point for tests.

    Returns:
        The selected release, or ``None`` when nothing is eligible --
        including when a cooldown leaves every candidate still warming.
    """
    eligible = [c for c in candidates if _is_eligible(c, policy)]
    if not eligible:
        return None

    ordered = sorted(
        eligible,
        key=lambda c: (
            _parse_version(c.tag),
            _get_version_specificity(c.tag),
        ),
        reverse=True,
    )

    selected = _select_version_with_cooldown(
        [(c.tag, c.commit_sha, c.published_at) for c in ordered],
        policy.cooldown_days,
        now=now,
    )
    if selected is None:
        return None

    tag, commit_sha = selected
    published_at = next((c.published_at for c in ordered if c.tag == tag), None)

    return LatestRelease(
        tag=tag,
        commit_sha=commit_sha,
        published_at=published_at,
        commit_tags=_commit_tags(ordered),
    )


async def resolve_latest_releases_chunk(
    execute: Callable[[str], Awaitable[dict[Any, Any]]],
    repo_keys: Sequence[str],
    policy: ReleasePolicy,
) -> dict[str, LatestRelease | None]:
    """Resolve one query-sized chunk of repositories.

    Args:
        execute: Coroutine function issuing a GraphQL query and returning
            the decoded response body. Supplied by the API client so this
            module needs no dependency on it.
        repo_keys: Repository keys for this chunk.
        policy: Draft/prerelease and cooldown policy to apply.

    Returns:
        Dictionary mapping every supplied repository key to its latest
        release, or ``None`` where none could be resolved.

    Raises:
        Exception: Whatever ``execute`` raises; the caller decides which
            API failures are fatal and which degrade to ``None``.
    """
    query, aliases = build_latest_releases_query(repo_keys)
    if not query:
        return dict.fromkeys(repo_keys, None)

    candidates = parse_latest_releases_response(await execute(query), aliases)

    return {
        repo_key: select_latest_release(candidates.get(repo_key, []), policy)
        for repo_key in repo_keys
    }


__all__ = [
    "LatestRelease",
    "ReleaseCandidate",
    "ReleasePolicy",
    "build_latest_releases_query",
    "parse_latest_releases_response",
    "resolve_latest_releases_chunk",
    "select_latest_release",
    "tag_candidates",
]
