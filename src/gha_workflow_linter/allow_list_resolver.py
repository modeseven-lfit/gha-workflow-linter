# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Latest-release resolution for harden-runner allow-list host repos.

A harden-runner allow-list pin names a commit of a host repository
(normally ``<org>/.github``) and is stale when that commit is not the one
behind the host repository's latest release. This module answers the
second half of that question: given host repositories, what is the latest
release and which *commit* does its tag peel to?

:class:`AllowListResolver` is deliberately backend-agnostic. It drives the
GitHub GraphQL client when ``validation_method`` is
:attr:`~gha_workflow_linter.models.ValidationMethod.GITHUB_API` and
``git ls-remote`` otherwise, but the ranking, draft/prerelease filtering
and cooldown enforcement are the shared, pure helpers in
:mod:`gha_workflow_linter.latest_release`, so both backends give the same
answer for the same repository.

Two behaviours are worth stating up front, because they are contracts the
caller depends on rather than incidental implementation details:

* **Resolution is fail-soft.** No token, no network, a rate limit, a
  missing repository, a repository with no releases, or a cooldown that
  excludes everything all produce ``None`` for that repository. Deciding
  whether "could not check" is fatal belongs to the caller, which knows
  whether enforcement was requested.
* **Each distinct host repository costs one lookup.** Twenty pins naming
  ``lfreleng-actions/.github`` resolve it once, and a repeated run within
  the cache TTL resolves it zero times -- except while a cooldown or
  prerelease eligibility applies, when the cache is bypassed entirely
  (see :attr:`cache_usable`), and except when a pin sits on a release the
  cached entry never saw, when that one repository is resolved afresh
  rather than risk recommending a downgrade (see
  :meth:`AllowListResolver._cache_can_place`).
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from .git_refs import get_remote_tag_shas
from .github_api import GitHubGraphQLClient
from .github_auth import get_github_token_with_fallback
from .latest_release import (
    LatestRelease,
    ReleasePolicy,
    select_latest_release,
    tag_candidates,
)
from .models import ValidationMethod
from .paths import base_repository

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from .cache import ValidationCache
    from .models import Config


class AllowListResolver:
    """Resolve the latest release of each allow-list host repository.

    Attributes:
        config: The linter configuration, supplying the validation method,
            prerelease and cooldown policy, and backend settings.
        cache: Validation cache reused for latest-version storage.
    """

    def __init__(self, config: Config, cache: ValidationCache) -> None:
        """
        Initialise the resolver.

        Args:
            config: Linter configuration.
            cache: Validation cache used to avoid repeat lookups across
                runs. The existing ``get_latest_version`` /
                ``put_latest_version`` pair is reused unchanged; no new
                cache store is introduced.
        """
        self.config = config
        self.cache = cache
        self.logger = logging.getLogger(__name__)

    @property
    def policy(self) -> ReleasePolicy:
        """The release policy implied by the configuration.

        Returns:
            A :class:`~gha_workflow_linter.latest_release.ReleasePolicy`
            carrying ``allow_prerelease`` and ``cooldown_days``.
        """
        return ReleasePolicy(
            allow_prerelease=self.config.allow_prerelease,
            cooldown_days=self.config.cooldown_days,
        )

    @property
    def cache_usable(self) -> bool:
        """Whether persisted results may be used and written this run.

        The cache stores a target and the commit-to-tag map behind it,
        but no record of the release policy that produced either. Two
        settings make up that policy.

        A **cooldown** deliberately selects an *older* release than the
        newest in existence, so a cooldown-shifted entry read back by a
        run with no cooldown would suppress a valid update, and a
        default-policy entry read under a cooldown would offer a release
        the caller is not yet entitled to.

        **Prerelease eligibility** changes which releases are candidates
        at all, so a prerelease-enabled run could cache a prerelease that
        a later default run consumes, or consume a stable-only entry and
        miss a newer prerelease.

        Bypassing the cache under either also keeps the stored entries
        honest: only default-policy answers are ever written, so a later
        run cannot read back a policy-shifted target.

        Returns:
            ``True`` when the default policy applies, so a stored answer
            means the same thing to every reader.
        """
        return self.config.cooldown_days <= 0 and not (
            self.config.allow_prerelease
        )

    async def resolve(
        self,
        repo_keys: Iterable[str],
        pinned: Mapping[str, Iterable[str]] | None = None,
    ) -> dict[str, LatestRelease | None]:
        """
        Resolve the latest release of each distinct host repository.

        Repository keys are de-duplicated first, so a host shared by many
        pins costs exactly one lookup. Cached repositories are answered
        without touching a backend at all, unless :attr:`cache_usable` is
        ``False`` or the cached answer cannot place one of the commits
        ``pinned`` names.

        Args:
            repo_keys: Host repository keys, ``owner/repo``. Duplicates
                and empty entries are ignored.
            pinned: Commits already pinned against each host repository.
                Supplying them lets a cached answer be checked for
                sufficiency before it is trusted; omitting them keeps the
                cache unconditional, which is only safe for a caller that
                will not rewrite anything.

        Returns:
            Dictionary mapping each distinct repository key to its latest
            release, or ``None`` where resolution failed or no release
            qualified. Never raises for a resolution failure.
        """
        unique = list(dict.fromkeys(key for key in repo_keys if key))
        if not unique:
            return {}

        cache_usable = self.cache_usable
        results: dict[str, LatestRelease | None] = {}
        pending: list[str] = []
        for repo_key in unique:
            cached = self._cached(repo_key) if cache_usable else None
            if cached is not None and self._cache_can_place(
                repo_key, cached, (pinned or {}).get(repo_key, ())
            ):
                results[repo_key] = cached
            else:
                pending.append(repo_key)

        if not pending:
            self.logger.debug(
                f"Latest-release cache hits: {len(results)}, 0 to resolve"
            )
            return results

        if not cache_usable:
            self.logger.debug(
                "Non-default release policy (cooldown or prerelease "
                "eligibility); bypassing the latest-release cache so the "
                "release each pinned commit belongs to stays known"
            )

        self.logger.debug(
            f"Latest-release cache hits: {len(results)}, "
            f"{len(pending)} to resolve"
        )
        results.update(await self._resolve_uncached(pending))
        if cache_usable:
            self._store(results, pending)

        return results

    def _cache_can_place(
        self,
        repo_key: str,
        cached: LatestRelease,
        pinned: Iterable[str],
    ) -> bool:
        """
        Report whether a cached answer can place every pinned commit.

        A cached entry is the newest release *as of the moment it was
        written*, and it stays usable for the whole TTL. If anything else
        advances a pin inside that window -- Dependabot, Renovate, a
        human, or an earlier repository in the same sweep -- the pin ends
        up on a release the cached entry never saw. The classifier then
        finds a commit it cannot place, calls the pin stale, and
        ``--update-allow-list`` rewrites it *backwards*.

        A commit the entry can place is safe either way: it belongs to a
        release the resolution ranked, so the classifier can compare
        versions and decide direction for itself. Only an unplaceable
        commit forces a live lookup, which makes this cheap in the case
        that matters -- nothing to do -- and precise in the case that
        does not.

        Args:
            repo_key: Host repository key, for the log line.
            cached: The release restored from the cache.
            pinned: Commit SHAs pinned against this host repository.

        Returns:
            ``True`` when every pinned commit is the cached target or
            belongs to a release the cached entry recorded.
        """
        for commit_sha in pinned:
            if commit_sha.strip().lower() == cached.commit_sha.strip().lower():
                continue
            if cached.tag_for_commit(commit_sha) is not None:
                continue
            self.logger.debug(
                f"Cached latest release {cached.tag} of {repo_key} cannot "
                f"place pinned commit {commit_sha[:8]}; resolving afresh "
                f"rather than risk recommending a downgrade"
            )
            return False
        return True

    def _cached(self, repo_key: str) -> LatestRelease | None:
        """
        Read a repository's latest release from the persistent cache.

        Args:
            repo_key: Host repository key.

        Returns:
            The cached release, or ``None`` on a miss, an expired entry,
            or an unreadable cache. ``published_at`` is always ``None``:
            the cache does not persist it, and it is not needed once a
            release has been selected without a cooldown.
            ``commit_tags`` is restored, so the record can still place a
            commit among the releases the original resolution ranked --
            though not one published after it, which
            :meth:`_cache_can_place` is there to catch.
        """
        try:
            entry = self.cache.get_latest_version_entry(repo_key)
        except Exception as e:
            self.logger.debug(f"Latest-version cache read failed: {e}")
            return None

        if not entry:
            return None

        if not entry.latest_tag or not entry.latest_sha:
            return None

        return LatestRelease(
            tag=entry.latest_tag,
            commit_sha=entry.latest_sha,
            commit_tags=dict(entry.commit_tags),
        )

    def _store(
        self,
        results: dict[str, LatestRelease | None],
        repo_keys: list[str],
    ) -> None:
        """
        Persist freshly resolved releases so the next run costs nothing.

        The commit-to-tag map is stored alongside the target, so a later
        run can still place a pinned commit among the releases this one
        ranked instead of assuming the stored target is the newer of the
        two.

        Unresolved repositories are deliberately not cached: a transient
        outage must not be remembered as "this repository has no release"
        for the duration of the cache TTL.

        Args:
            results: The resolution results.
            repo_keys: Keys that were resolved in this run (as opposed to
                served from the cache).
        """
        try:
            stored = False
            for repo_key in repo_keys:
                release = results.get(repo_key)
                if release is None:
                    continue
                self.cache.put_latest_version(
                    repo_key,
                    release.tag,
                    release.commit_sha,
                    release.commit_tags,
                )
                stored = True
            if stored:
                self.cache.save()
        except Exception as e:
            self.logger.debug(f"Latest-version cache write failed: {e}")

    async def _resolve_uncached(
        self, repo_keys: list[str]
    ) -> dict[str, LatestRelease | None]:
        """
        Resolve repositories that the cache could not answer.

        Args:
            repo_keys: Distinct host repository keys.

        Returns:
            Dictionary mapping every supplied key to its latest release or
            ``None``. This is the fail-soft boundary: no failure escapes.
        """
        try:
            if self.config.validation_method == ValidationMethod.GITHUB_API:
                return await self._resolve_via_api(repo_keys)
            return await self._resolve_via_git(repo_keys)
        except Exception as e:
            self.logger.warning(
                f"Could not resolve the latest release of "
                f"{len(repo_keys)} repositories: {e}"
            )
            return dict.fromkeys(repo_keys, None)

    def _make_github_client(self) -> GitHubGraphQLClient:
        """
        Build the GraphQL client, reusing the shared token discovery.

        Returns:
            A client configured with the best available token. Tests
            override this method to supply a double.
        """
        api_config = self.config.github_api
        token = get_github_token_with_fallback(api_config.token, quiet=True)
        if token and token != api_config.token:
            api_config = api_config.model_copy(update={"token": token})

        return GitHubGraphQLClient(api_config)

    async def _resolve_via_api(
        self, repo_keys: list[str]
    ) -> dict[str, LatestRelease | None]:
        """
        Resolve latest releases through the batched GraphQL query.

        Args:
            repo_keys: Distinct host repository keys.

        Returns:
            Dictionary mapping every supplied key to its latest release or
            ``None``.
        """
        client = self._make_github_client()
        async with client:
            resolved = await client.resolve_latest_releases_batch(
                repo_keys, self.policy
            )

        return {repo_key: resolved.get(repo_key) for repo_key in repo_keys}

    async def _resolve_via_git(
        self, repo_keys: list[str]
    ) -> dict[str, LatestRelease | None]:
        """
        Resolve latest releases through ``git ls-remote``, in parallel.

        Args:
            repo_keys: Distinct host repository keys.

        Returns:
            Dictionary mapping every supplied key to its latest release or
            ``None``.
        """
        semaphore = asyncio.Semaphore(max(1, self.config.parallel_workers))

        async def resolve_one(
            repo_key: str,
        ) -> tuple[str, LatestRelease | None]:
            """Resolve one repository off the event loop."""
            async with semaphore:
                release = await asyncio.to_thread(
                    self._resolve_one_via_git, repo_key
                )
                return repo_key, release

        results: dict[str, LatestRelease | None] = {}
        for repo_key, release in await asyncio.gather(
            *[resolve_one(repo_key) for repo_key in repo_keys]
        ):
            results[repo_key] = release

        return results

    def _resolve_one_via_git(self, repo_key: str) -> LatestRelease | None:
        """
        Resolve one repository's latest release from its remote tags.

        ``git ls-remote`` advertises tags but no release metadata, so this
        path can supply no publication dates. Rather than guess at a
        release's age it declines to answer while a cooldown is active,
        matching ``auto_fix_versions._get_latest_version_via_git``.

        Args:
            repo_key: Host repository key.

        Returns:
            The latest release, or ``None`` when the remote could not be
            read, no clean version tag exists, or a cooldown is active.
        """
        if self.config.cooldown_days > 0:
            self.logger.debug(
                "Cooldown active but release dates are unavailable via "
                "Git for %s; reporting no latest release",
                repo_key,
            )
            return None

        url = f"https://github.com/{base_repository(repo_key)}.git"
        try:
            tag_shas = get_remote_tag_shas(url, self.config.git)
        except Exception as e:
            self.logger.debug(f"Git tag listing failed for {repo_key}: {e}")
            return None

        return select_latest_release(tag_candidates(tag_shas), self.policy)


__all__ = [
    "AllowListResolver",
    "LatestRelease",
    "ReleasePolicy",
]
