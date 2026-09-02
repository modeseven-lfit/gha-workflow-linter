# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Latest-version discovery for the auto-fixer.

This module hosts :class:`_VersionResolutionMixin`, the portion of the
auto-fixer that discovers the *latest* eligible version for an action
reference: batched GraphQL and REST/Git version lookups, session/disk
caching of results, and cooldown-window enforcement.

It builds on :class:`_ReferenceResolutionMixin` (from :mod:`action_call_resolver`)
for the lower-level reference-to-SHA resolution it depends on, and is combined
into ``AutoFixer`` via inheritance. Splitting version discovery from the
reference-resolution primitives keeps each module focused and reviewable.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import TYPE_CHECKING, Any

from .action_call_git import _get_remote_tags
from .action_call_resolver import _ReferenceResolutionMixin
from .action_call_scanner import ActionCallPatterns
from .exceptions import GitError
from .models import ValidationMethod
from .utils import comment_text
from .utils import version_or_none as _version_or_none
from .version_utils import (
    _find_most_specific_version_tag,
    _get_version_specificity,
    _is_downgrade,
    _parse_iso_datetime,
    _parse_version,
    _select_version_with_cooldown,
)

if TYPE_CHECKING:
    from datetime import datetime

    from .models import ActionCall


class _VersionResolutionMixin(_ReferenceResolutionMixin):
    """Latest-version discovery behaviour for ``AutoFixer``.

    Inherits the reference-resolution primitives (and the shared attribute
    declarations) from :class:`_ReferenceResolutionMixin`, adding the
    higher-level latest-version lookups that build on them.
    """

    @property
    def _persistent_cache_usable(self) -> bool:
        """Whether persisted latest versions may be read or written.

        The persistent cache is keyed on the repository alone, so it
        cannot record which release policy produced an entry. Two
        settings make up that policy.

        A **cooldown** deliberately selects an *older* release, so a
        shared entry would cross policies in both directions: a
        repository with a short cooldown could publish a version that a
        longer-cooled repository is not yet entitled to, and a
        cooldown-shifted entry could later suppress a valid update for a
        repository running no cooldown at all.

        **Prerelease eligibility** changes which releases are candidates
        at all, so a prerelease-enabled run could cache a prerelease that
        a later default run consumes, or consume a stable-only entry and
        miss a newer prerelease.

        This matters most in a multi-repository sweep, where one cache
        serves every repository and each resolves its own policy, but it
        applies equally to successive single-repository runs sharing the
        on-disk cache.

        The session cache is unaffected: it lives on one ``AutoFixer``,
        which serves exactly one repository and therefore one policy.

        Mirrors
        :attr:`gha_workflow_linter.allow_list_resolver.AllowListResolver.cache_usable`,
        which bypasses its own cache under the same conditions.

        Returns:
            ``True`` when the default policy applies, so a stored answer
            means the same thing to every reader.
        """
        return (
            self.config.cooldown_days <= 0 and not self.config.allow_prerelease
        )

    def _moves_backwards(
        self,
        current: str | None,
        target_tag: str,
        repo_key: str,
        *,
        repo_changed: bool,
    ) -> bool:
        """Report whether retargeting a call would move it backwards.

        A resolved "latest" release names the newest at the moment of
        discovery, and a cached one can be older still: nothing stops
        Dependabot, Renovate, a colleague or an earlier run advancing a
        pin inside the cache TTL. The update path treats any differing
        target as a change to apply, so without this a run rewrites the
        pin *backwards* and reports the downgrade as a successful update
        -- reverting a supply-chain fix nobody asked to revert.

        Args:
            current: The version the call pins now, or ``None`` when it
                names none. Callers decide which sources may answer;
                the invalid-reference repair excludes the reference
                itself, having already established that it is broken.
            target_tag: The version the run proposes to move it to.
            repo_key: Repository the call names, for the log line.
            repo_changed: Whether the call is being moved to another
                repository. Two projects' version numbers are not
                comparable -- an action that has moved starts its new
                home's numbering wherever that project happens to be --
                so a redirect answers ``False`` outright. Required
                rather than defaulted, because omitting it is exactly
                the mistake it exists to prevent, and every call site
                must state it.

        Returns:
            ``True`` only when the call provably pins a higher version
            than the target within one repository. A call naming no
            version establishes no direction and is left to the ordinary
            update path.
        """
        if repo_changed or current is None:
            return False
        if not _is_downgrade(current, target_tag):
            return False

        self.logger.debug(
            f"Refusing to move {repo_key} backwards from {current} to "
            f"{target_tag}: the resolved latest release is older than "
            f"the pinned one"
        )
        return True

    async def _repair_invalid_reference(
        self,
        action_call: ActionCall,
        repo_key: str,
        sha_map: dict[tuple[str, str], str],
        latest_versions: dict[str, tuple[str, str]],
        *,
        repo_changed: bool,
    ) -> tuple[str | None, str | None]:
        """Find a valid reference to replace an invalid one.

        Three sources are consulted in order of fidelity to what the file
        already says: the version its comment names, the repository's
        latest release, then a salvaged reference or the default branch.

        The last two are guarded, because both can name a *version*. The
        comment reaches them only when the version it names could not be
        resolved at all, which is as likely to mean a rate limit or an
        outage as a deleted tag -- and the latest release may itself be a
        cached answer older than the comment. Rewriting a call that
        claims v5 down to v4 on that evidence would report a downgrade as
        a repair. The reference is deliberately not consulted for the
        comparison: it is the thing already established as broken.

        Once something has been refused for going backwards, the repair
        will accept **only a version at least as new**, and abandons the
        call otherwise. The branch sources are not a neutral fallback
        here: replacing a pin that claims v5 with a floating ``main``
        loses the pin as well as the version, which is a worse outcome
        than the broken reference it replaces. Leaving it alone is not
        silent, since the call keeps its validation error.

        Args:
            action_call: The call carrying the invalid reference.
            repo_key: Base repository the call names, after any redirect.
            sha_map: References already resolved in this batch.
            latest_versions: Latest ``(tag, sha)`` per repository.
            repo_changed: Whether the call was redirected to another
                repository, which exempts it from the comparison.

        Returns:
            The replacement reference and its commit SHA, either of which
            may be ``None`` when nothing could be established or when
            everything on offer was older than the version claimed.
        """
        # Only a clean version tag is ordering evidence. An arbitrary
        # comment is not: '# 2026-08-19' would parse as version 2026 and
        # veto every repair the call could possibly need.
        claimed = _version_or_none(comment_text(action_call))
        if claimed:
            sha = await self._resolve_ref(repo_key, claimed, sha_map)
            if sha:
                return claimed, sha

        refused = False
        latest = latest_versions.get(repo_key)
        if latest:
            if not self._moves_backwards(
                claimed, latest[0], repo_key, repo_changed=repo_changed
            ):
                tag, cached_sha = latest
                return tag, cached_sha or await self._resolve_ref(
                    repo_key, tag, sha_map
                )
            refused = True

        salvaged = await self._find_valid_reference(
            repo_key, action_call.reference
        )
        if salvaged and self._moves_backwards(
            claimed, salvaged, repo_key, repo_changed=repo_changed
        ):
            return None, None
        if refused and not _version_or_none(salvaged):
            return None, None

        salvaged = salvaged or await self._get_fallback_reference(
            repo_key, action_call.reference
        )
        if not salvaged:
            # Last resort: use default branch
            repo_info = await self._get_repository_info(repo_key)
            salvaged = (
                repo_info.get("default_branch", "main") if repo_info else "main"
            )

        return salvaged, await self._resolve_ref(repo_key, salvaged, sha_map)

    async def _resolve_ref(
        self,
        repo_key: str,
        ref: str,
        sha_map: dict[tuple[str, str], str],
    ) -> str | None:
        """Resolve one reference to a commit, preferring the batch.

        Args:
            repo_key: Repository the reference belongs to.
            ref: The reference to resolve.
            sha_map: References already resolved in this batch.

        Returns:
            The commit SHA, or ``None`` when it could not be resolved.
        """
        if (repo_key, ref) in sha_map:
            return sha_map[(repo_key, ref)]
        sha_info = await self._get_commit_sha_for_reference(repo_key, ref)
        return sha_info["sha"] if sha_info else None

    async def _get_latest_versions_batch(
        self, repo_keys: list[str]
    ) -> dict[str, tuple[str, str]]:
        """
        Batch-fetch latest versions for multiple repositories.

        Returns dict mapping repo_key to (tag, sha) tuple.
        Uses both persistent disk cache and session cache for optimal performance.
        """
        results: dict[str, tuple[str, str]] = {}
        repos_to_fetch: list[str] = []
        session_cache_hits = 0
        disk_cache_hits = 0

        # Check session cache first (fastest)
        current_time = time.time()
        for repo_key in repo_keys:
            if repo_key in self._latest_versions_cache:
                tag, sha, timestamp = self._latest_versions_cache[repo_key]
                if current_time - timestamp < self._cache_ttl:
                    results[repo_key] = (tag, sha)
                    session_cache_hits += 1
                    continue

            cached_version = (
                self._cache.get_latest_version(repo_key)
                if self._persistent_cache_usable
                else None
            )
            if cached_version:
                tag, sha = cached_version
                results[repo_key] = (tag, sha)
                # Also populate session cache for faster subsequent access
                self._latest_versions_cache[repo_key] = (tag, sha, current_time)
                disk_cache_hits += 1
                continue

            repos_to_fetch.append(repo_key)

        if session_cache_hits > 0 or disk_cache_hits > 0:
            self.logger.debug(
                f"Latest version cache hits: {session_cache_hits} session, {disk_cache_hits} disk, "
                f"{len(repos_to_fetch)} to fetch"
            )

        if not repos_to_fetch:
            return results

        # Use GraphQL batch query if available
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._graphql_client
        ):
            try:
                graphql_results = await self._get_latest_versions_graphql_batch(
                    repos_to_fetch
                )

                for repo_key, (tag, sha) in graphql_results.items():
                    results[repo_key] = (tag, sha)
                    # Cache in both session and persistent storage
                    self._latest_versions_cache[repo_key] = (
                        tag,
                        sha,
                        current_time,
                    )
                    if self._persistent_cache_usable:
                        self._cache.put_latest_version(repo_key, tag, sha)

                repos_to_fetch = [
                    repo
                    for repo in repos_to_fetch
                    if repo not in graphql_results
                ]
                if not repos_to_fetch:
                    return results

                self.logger.debug(
                    f"GraphQL returned results for {len(graphql_results)} repos, falling back to REST API for {len(repos_to_fetch)} repos"
                )
            except Exception as e:
                self.logger.debug(
                    f"GraphQL batch fetch failed, falling back to individual queries: {e}"
                )

        # Fallback to parallel REST API or Git operations
        if repos_to_fetch:
            tasks = [
                self._get_latest_version_single(repo_key)
                for repo_key in repos_to_fetch
            ]
            fetch_results = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            fetch_results = []

        for repo_key, result in zip(repos_to_fetch, fetch_results, strict=True):
            if isinstance(result, Exception):
                self.logger.debug(
                    f"Failed to fetch latest version for {repo_key}: {result}"
                )
                continue
            if result and isinstance(result, tuple):
                tag, sha = result
                results[repo_key] = (tag, sha)
                # Cache in both session and persistent storage
                self._latest_versions_cache[repo_key] = (tag, sha, current_time)
                if self._persistent_cache_usable:
                    self._cache.put_latest_version(repo_key, tag, sha)

        # Saved unconditionally: the cache holds validation results
        # written elsewhere in the run, and those are unaffected by the
        # cooldown that suppressed the latest-version writes above.
        self._cache.save()

        return results

    async def _get_latest_versions_graphql_batch(
        self, repo_keys: list[str]
    ) -> dict[str, tuple[str, str]]:
        """
        Fetch latest releases for multiple repos using a single GraphQL query.

        Returns dict mapping repo_key to (tag, sha) tuple.
        """
        query, aliases = self._build_graphql_batch_query(repo_keys)
        if not query:
            return {}

        try:
            if not self._graphql_client:
                return {}
            response_data = await self._graphql_client._execute_graphql_query(
                query
            )

            results: dict[str, tuple[str, str]] = {}
            response_root = response_data.get("data") or {}
            for alias, repo_key in aliases.items():
                repo_data = response_root.get(alias)
                if not repo_data:
                    continue
                choice = self._resolve_repo_version_from_graphql(
                    repo_key, repo_data
                )
                if choice:
                    results[repo_key] = choice

            return results
        except Exception as e:
            self.logger.debug(f"GraphQL batch query failed: {e}")
            return {}

    def _build_graphql_batch_query(
        self, repo_keys: list[str]
    ) -> tuple[str, dict[str, str]]:
        """Build the batched GraphQL query and its alias-to-repo mapping.

        Returns ``("", {})`` when no valid repository keys are supplied so
        callers can short-circuit without issuing a network request.
        """
        query_parts = []
        aliases: dict[str, str] = {}

        for i, repo_key in enumerate(repo_keys):
            try:
                owner, name = repo_key.split("/", 1)
            except ValueError:
                self.logger.warning(f"Invalid repository format: {repo_key}")
                continue
            base_name = name.split("/")[0]
            alias = f"repo_{i}"
            aliases[alias] = repo_key

            query_parts.append(f"""
                {alias}: repository(owner: "{owner}", name: "{base_name}") {{
                    latestRelease {{
                        tagName
                        createdAt
                        publishedAt
                        tagCommit {{
                            oid
                        }}
                    }}
                    refs(refPrefix: "refs/tags/", first: 100, orderBy: {{field: TAG_COMMIT_DATE, direction: DESC}}) {{
                        nodes {{
                            name
                            target {{
                                ... on Commit {{
                                    oid
                                }}
                                ... on Tag {{
                                    tagger {{
                                        date
                                    }}
                                    target {{
                                        ... on Commit {{
                                            oid
                                        }}
                                    }}
                                }}
                            }}
                        }}
                    }}
                }}
            """)

        if not query_parts:
            return "", {}

        return f"query {{ {' '.join(query_parts)} }}", aliases

    def _collect_graphql_tags(
        self, refs: list[dict[str, Any]]
    ) -> tuple[list[tuple[str, str]], dict[str, datetime | None]]:
        """Extract version tags and their publication dates from GraphQL refs.

        ``tag_dates`` records a verifiable *publication* timestamp per tag so
        the cooldown can reason about release age: the tagger date for
        annotated tags. Lightweight tags carry no creation timestamp of their
        own (only the commit they point at, which may be far older than the
        tag), so they are recorded as undated and skipped while a cooldown
        applies. The latest release's publication date is layered on
        separately by ``_select_cooldown_version_graphql``.
        """
        all_tags: list[tuple[str, str]] = []
        tag_dates: dict[str, datetime | None] = {}
        for ref in refs:
            if not ActionCallPatterns.VERSION_TAG_PATTERN.match(ref["name"]):
                continue
            target = ref.get("target", {})
            if "oid" in target:
                # Lightweight tag: target is the commit itself and has no
                # verifiable tag-creation time.
                all_tags.append((ref["name"], target["oid"]))
                tag_dates[ref["name"]] = None
            elif "target" in target and "oid" in target["target"]:
                # Annotated tag: use the tagger date as the publication time.
                all_tags.append((ref["name"], target["target"]["oid"]))
                tagger = target.get("tagger") or {}
                tag_dates[ref["name"]] = _parse_iso_datetime(tagger.get("date"))
        return all_tags, tag_dates

    def _select_fallback_tag(
        self, refs: list[dict[str, Any]]
    ) -> tuple[str, str] | None:
        """Pick the newest version-like tag (e.g. ``v1.2``) as a last resort.

        Used when no tag matches the strict version pattern. ``refs`` arrive
        already sorted by TAG_COMMIT_DATE DESC, so the first match is the
        newest candidate.
        """
        fallback_pattern = re.compile(r"^v?\d+\.\d+")
        for ref in refs:
            if not fallback_pattern.match(ref["name"]):
                continue
            target = ref.get("target", {})
            if "oid" in target:
                # Direct commit
                return (ref["name"], target["oid"])
            if "target" in target and "oid" in target["target"]:
                # Annotated tag pointing to commit
                return (ref["name"], target["target"]["oid"])
        return None

    def _resolve_repo_version_from_graphql(
        self, repo_key: str, repo_data: dict[str, Any]
    ) -> tuple[str, str] | None:
        """Resolve the ``(tag, sha)`` to adopt for one repo's GraphQL data.

        Applies, in order: cooldown selection (when active), the excluded-
        prerelease ``latestRelease``, the newest version tag by specificity,
        and finally a version-like fallback tag. Returns ``None`` when no
        eligible version is found (for example when a cooldown leaves every
        release still "warming").
        """
        refs_field = repo_data.get("refs") or {}
        refs = refs_field.get("nodes") or []
        all_tags, tag_dates = self._collect_graphql_tags(refs)

        # When a cooldown is active, select the newest version that has been
        # available long enough, falling back to older eligible versions when
        # the very latest is still "warming".
        if self.config.cooldown_days > 0:
            cooldown_choice = self._select_cooldown_version_graphql(
                repo_data, all_tags, tag_dates
            )
            if not cooldown_choice:
                self.logger.debug(
                    "No release for %s satisfies the %d-day "
                    "cooldown; leaving reference unchanged",
                    repo_key,
                    self.config.cooldown_days,
                )
            return cooldown_choice

        # Try latestRelease first, but only if prereleases are NOT allowed
        # (latestRelease excludes prereleases by GitHub's API design). If
        # allow_prerelease is True, skip latestRelease and check all tags.
        if not self.config.allow_prerelease and repo_data.get("latestRelease"):
            tag = repo_data["latestRelease"]["tagName"]
            sha = repo_data["latestRelease"]["tagCommit"]["oid"]
            # Only use latestRelease if it matches our version patterns
            if ActionCallPatterns.VERSION_TAG_PATTERN.match(tag):
                # Find most specific version tag for this SHA (e.g. v8 -> v8.0.0)
                specific_tag = _find_most_specific_version_tag(
                    tag, sha, all_tags
                )
                return (specific_tag, sha)

        # Fall back to tags with version pattern filtering
        if all_tags:
            # Sort by specificity first, then version
            sorted_tags = sorted(
                all_tags,
                key=lambda x: (
                    _get_version_specificity(x[0]),
                    _parse_version(x[0]),
                ),
                reverse=True,
            )
            return sorted_tags[0]

        # No clean version tags found, try version-like tags (v1.2, v0.9, etc.)
        return self._select_fallback_tag(refs)

    def _select_cooldown_version_graphql(
        self,
        repo_data: dict[str, Any],
        all_tags: list[tuple[str, str]],
        tag_dates: dict[str, datetime | None],
        now: datetime | None = None,
    ) -> tuple[str, str] | None:
        """Choose a cooldown-eligible ``(tag, sha)`` from GraphQL repo data.

        Builds a newest-first list of version-tag candidates (each
        annotated with a verifiable publication timestamp) and delegates
        to :func:`_select_version_with_cooldown`. The latest release's
        publish date is layered on for its tag because it best reflects
        when the version became consumable.

        Args:
            repo_data: The per-repository GraphQL response fragment.
            all_tags: ``(tag, sha)`` pairs for every matching version tag.
            tag_dates: Mapping of tag name to its publication ``datetime``
                (``None`` when no verifiable publication time exists, e.g.
                lightweight tags).
            now: Reference time for the cooldown window (defaults to the
                current UTC time); primarily an injection point for tests.

        Returns:
            The newest eligible ``(tag, sha)`` tuple, or ``None`` when no
            version satisfies the configured cooldown.
        """
        # Prefer the published date of the latest release, which better
        # reflects when the version became available to consumers.
        latest_release = repo_data.get("latestRelease")
        if latest_release:
            release_tag = latest_release.get("tagName")
            release_date = _parse_iso_datetime(
                latest_release.get("publishedAt")
                or latest_release.get("createdAt")
            )
            if release_tag and release_date is not None:
                tag_dates[release_tag] = release_date

        candidates = sorted(
            ((name, sha, tag_dates.get(name)) for name, sha in all_tags),
            key=lambda item: (
                _parse_version(item[0]),
                _get_version_specificity(item[0]),
            ),
            reverse=True,
        )

        selected = _select_version_with_cooldown(
            candidates, self.config.cooldown_days, now=now
        )
        if not selected:
            return None

        tag, sha = selected
        # Resolve to the most specific equivalent tag for the chosen SHA
        # (e.g. prefer v8.0.0 over v8 when both point at the same commit).
        specific_tag = _find_most_specific_version_tag(tag, sha, all_tags)
        return (specific_tag, sha)

    def _select_release_tag_with_cooldown(
        self,
        repo_key: str,
        sorted_releases: list[dict[str, Any]],
    ) -> str | None:
        """Pick a REST release tag honouring the configured cooldown.

        Args:
            repo_key: Repository identifier (used for debug logging).
            sorted_releases: REST API release objects ordered newest
                version first.

        Returns:
            The chosen tag name, or ``None`` when no release satisfies the
            cooldown window. When the cooldown is disabled the newest tag
            is returned unchanged.
        """
        if self.config.cooldown_days <= 0:
            return sorted_releases[0].get("tag_name")

        candidates = [
            (
                release.get("tag_name", ""),
                "",  # SHA is resolved separately by the caller
                _parse_iso_datetime(
                    release.get("published_at") or release.get("created_at")
                ),
            )
            for release in sorted_releases
        ]
        selected = _select_version_with_cooldown(
            candidates, self.config.cooldown_days
        )
        if selected is None:
            self.logger.debug(
                "No release for %s satisfies the %d-day cooldown",
                repo_key,
                self.config.cooldown_days,
            )
            return None
        return selected[0]

    async def _get_latest_version_single(
        self, repo_key: str
    ) -> tuple[str, str] | None:
        """
        Fetch latest version for a single repository.

        Returns (tag, sha) tuple or None.
        Supports both REST API and Git operations.
        """
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._http_client
        ):
            return await self._get_latest_version_via_api(repo_key)
        if (
            self.config.validation_method == ValidationMethod.GIT
            and self._git_client
        ):
            return await self._get_latest_version_via_git(repo_key)
        return None

    async def _get_latest_version_via_api(  # noqa: PLR0911
        self, repo_key: str
    ) -> tuple[str, str] | None:
        """Fetch the latest eligible version via the GitHub REST API.

        Prefers the releases endpoint (which carries prerelease/draft and
        publication metadata for cooldown enforcement), falling back to the
        tags endpoint. Returns ``None`` when no eligible version is found or
        a cooldown leaves every candidate ineligible.
        """
        if not self._http_client:
            return None
        try:
            # Try latest release
            response = await self._http_client.get(
                f"https://api.github.com/repos/{repo_key}/releases?per_page=100"
            )
            if response.status_code == 200:
                release_choice = await self._select_release_version(
                    repo_key, response.json()
                )
                if release_choice is not None:
                    return release_choice

            # Fall back to tags
            response = await self._http_client.get(
                f"https://api.github.com/repos/{repo_key}/tags?per_page=100"
            )
            if response.status_code == 200:
                return self._select_tag_version(repo_key, response.json())
        except Exception as e:
            self.logger.debug(f"REST API fetch failed for {repo_key}: {e}")

        return None

    async def _select_release_version(
        self, repo_key: str, releases: list[dict[str, Any]]
    ) -> tuple[str, str] | None:
        """Choose a ``(tag, sha)`` from the releases endpoint payload.

        Filters out drafts (and prereleases unless allowed), applies the
        cooldown window, then resolves the chosen tag to a commit SHA.
        Returns ``None`` when no release qualifies.
        """
        clean_releases = [
            r
            for r in releases
            if ActionCallPatterns.VERSION_TAG_PATTERN.match(
                r.get("tag_name", "")
            )
            and not r.get("draft", False)
            and (self.config.allow_prerelease or not r.get("prerelease", False))
        ]
        if not clean_releases:
            return None
        sorted_releases = sorted(
            clean_releases,
            key=lambda r: _parse_version(r.get("tag_name", "")),
            reverse=True,
        )
        tag = self._select_release_tag_with_cooldown(repo_key, sorted_releases)
        if tag is None:
            # No release satisfies the cooldown window.
            return None
        sha_info = await self._get_commit_sha_for_reference(repo_key, tag)
        sha = sha_info["sha"] if sha_info else ""
        return (tag, sha)

    def _select_tag_version(
        self, repo_key: str, tags: list[dict[str, Any]]
    ) -> tuple[str, str] | None:
        """Choose a ``(tag, sha)`` from the tags endpoint payload.

        The tags endpoint carries no release dates, so a cooldown cannot be
        verified here; when one is active the reference is left unchanged.
        Returns ``None`` when no version tag qualifies.
        """
        # Note: GitHub tags API doesn't include prerelease info; only the
        # releases API has that metadata, so prereleases cannot be filtered.
        clean_tags = [
            tag
            for tag in tags
            if ActionCallPatterns.VERSION_TAG_PATTERN.match(tag.get("name", ""))
        ]
        if not clean_tags:
            return None
        if self.config.cooldown_days > 0:
            # The tags endpoint carries no release dates, so we cannot verify
            # the cooldown window here.
            self.logger.debug(
                "Cooldown active but %s exposes no release dates via the "
                "tags API; leaving reference unchanged",
                repo_key,
            )
            return None
        sorted_tags = sorted(
            clean_tags,
            key=lambda t: _parse_version(t.get("name", "")),
            reverse=True,
        )
        return (sorted_tags[0]["name"], sorted_tags[0]["commit"]["sha"])

    async def _get_latest_version_via_git(
        self, repo_key: str
    ) -> tuple[str, str] | None:
        """Fetch the latest eligible version with ``git ls-remote`` tags.

        ``git ls-remote`` does not expose tag dates, so a cooldown cannot be
        enforced for the Git validation method; when one is active the
        reference is left unchanged. Returns ``None`` when no version tag
        qualifies.
        """
        if not self._git_client:
            return None
        try:
            url = f"https://github.com/{repo_key}.git"
            git_tags = _get_remote_tags(url, self.config.git)
            if not git_tags:
                return None
            clean_tags = [
                tag
                for tag in sorted(git_tags, reverse=True)
                if ActionCallPatterns.VERSION_TAG_PATTERN.match(tag)
            ]
            if not clean_tags:
                return None
            if self.config.cooldown_days > 0:
                # ``git ls-remote`` does not expose tag dates, so the
                # cooldown cannot be enforced for the Git validation method.
                self.logger.debug(
                    "Cooldown active but release dates are unavailable via "
                    "Git for %s; leaving reference unchanged",
                    repo_key,
                )
                return None
            tag = sorted(clean_tags, key=_parse_version, reverse=True)[0]
            sha_info = await self._get_commit_sha_for_reference(repo_key, tag)
            sha = sha_info["sha"] if sha_info else ""
            return (tag, sha)
        except GitError as e:
            self.logger.debug(f"Git fetch failed for {repo_key}: {e}")

        return None
