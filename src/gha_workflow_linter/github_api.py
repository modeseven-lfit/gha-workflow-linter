# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""GitHub GraphQL API client for efficient repository validation."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, NoReturn

import httpx

from .exceptions import (
    AuthenticationError,
    GitHubAPIError,
    NetworkError,
    RateLimitError,
    TemporaryAPIError,
)
from .git_refs import AnnotatedTagPeel
from .models import (
    APICallStats,
    GitHubAPIConfig,
    GitHubRateLimitInfo,
)
from .paths import (
    action_subpath,
    action_subpath_candidates,
    base_repository,
)
from .system_utils import get_default_workers

if TYPE_CHECKING:
    from collections.abc import Mapping


class GitHubGraphQLClient:
    """GitHub GraphQL API client for batch validation of repositories and references."""

    def __init__(self, config: GitHubAPIConfig) -> None:
        """
        Initialize the GitHub GraphQL client.

        Args:
            config: GitHub API configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._http_client: httpx.AsyncClient | None = None
        # pydantic BaseModel subclasses with all-defaulted fields require
        # no constructor args (keyword args are still accepted), but
        # basedpyright reports the no-arg call as missing parameters.
        # Suppress that one diagnostic on the calls below.
        self._rate_limit_info = GitHubRateLimitInfo()
        self.api_stats = APICallStats()

        # Get GitHub token from config (which handles environment fallback)
        self._token = config.token or os.getenv("GITHUB_TOKEN")
        if not self._token:
            # Warning will be handled by CLI layer for consistent formatting
            pass

        # Cache for validation results
        self._repository_cache: dict[str, bool] = {}
        self._reference_cache: dict[str, dict[str, bool]] = {}
        # Cache for subdirectory-action subpath existence, keyed by
        # (full action identifier including subpath, ref).
        self._subpath_cache: dict[tuple[str, str], bool] = {}
        # Peels behind any reference resolved to an annotated tag object,
        # keyed by (repo_key, reference); see annotated_tag_peels.
        self._annotated_tag_peels: dict[tuple[str, str], AnnotatedTagPeel] = {}

        # Parallel workers for concurrent operations (set by validator)
        self.parallel_workers: int = (
            get_default_workers()
        )  # Default, will be overridden

    @property
    def annotated_tag_peels(
        self,
    ) -> Mapping[tuple[str, str], AnnotatedTagPeel]:
        """Annotated tag peels discovered while validating references.

        A pinned SHA that resolves to a ``Tag`` object rather than a
        ``Commit`` is not checkout-able by GitHub Actions. The commit-SHA
        query peels such objects in the same request, so the remediation is
        recorded here as a side effect instead of costing a second query.
        Mirrors :attr:`GitValidationClient.annotated_tag_peels` so both
        backends report the same verdict with the same context. Entries
        accumulate over the client's lifetime.

        Returns:
            Read-only mapping of ``(repo_key, reference)`` to the peel
            behind that reference. Only references naming a tag object are
            present.
        """
        return MappingProxyType(self._annotated_tag_peels)

    async def __aenter__(self) -> GitHubGraphQLClient:
        """Async context manager entry."""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "gha-workflow-linter/1.0",
        }

        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        self._http_client = httpx.AsyncClient(
            headers=headers,
            timeout=30.0,
            limits=httpx.Limits(
                max_connections=10, max_keepalive_connections=5
            ),
        )

        await self._update_rate_limit_info()

        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        if self._http_client:
            await self._http_client.aclose()

    async def validate_repositories_batch(
        self, repo_keys: list[str]
    ) -> dict[str, bool]:
        """
        Validate multiple repositories in batch using GraphQL.

        Args:
            repo_keys: List of repository keys in format "owner/repo"

        Returns:
            Dictionary mapping repo keys to validation results
        """
        results = {}

        uncached_repos = []
        for repo_key in repo_keys:
            if repo_key in self._repository_cache:
                self.api_stats.increment_cache_hit()
                results[repo_key] = self._repository_cache[repo_key]
                self.logger.debug(f"Repository cache hit: {repo_key}")
            else:
                uncached_repos.append(repo_key)

        if not uncached_repos:
            return results

        self.logger.debug(
            f"Validating {len(uncached_repos)} repositories via GraphQL "
            f"(cache hits: {len(results)})"
        )

        batch_size = self.config.max_repositories_per_query
        batches = []
        for i in range(0, len(uncached_repos), batch_size):
            batch = uncached_repos[i : i + batch_size]
            batches.append(batch)

        # Use semaphore to limit concurrent batches (respects parallel_workers config)
        semaphore = asyncio.Semaphore(self.parallel_workers)

        async def process_batch_with_limit(batch: list[str]) -> dict[str, bool]:
            """Process a single batch with rate limiting."""
            async with semaphore:
                await self._check_rate_limit()
                try:
                    batch_results = (
                        await self._validate_repositories_graphql_batch(batch)
                    )
                    # Cache results
                    for repo_key, is_valid in batch_results.items():
                        self._repository_cache[repo_key] = is_valid
                    return batch_results
                except (
                    NetworkError,
                    GitHubAPIError,
                    AuthenticationError,
                    RateLimitError,
                ) as e:
                    # Re-raise known API/network errors - don't treat as validation failure
                    self.logger.error(f"Error validating repository batch: {e}")
                    raise
                except Exception as e:
                    self.logger.error(
                        f"Unexpected error validating repository batch: {e}"
                    )
                    self.api_stats.increment_failed_call()
                    # Mark all as invalid on error
                    batch_results = {}
                    for repo_key in batch:
                        batch_results[repo_key] = False
                        self._repository_cache[repo_key] = False
                    return batch_results

        batch_results_list = await asyncio.gather(
            *[process_batch_with_limit(batch) for batch in batches]
        )

        # Merge all results
        for batch_result in batch_results_list:
            results.update(batch_result)

        return results

    async def validate_references_batch(
        self, repo_refs: list[tuple[str, str]]
    ) -> dict[tuple[str, str], bool]:
        """
        Validate multiple repository references in batch using GraphQL.

        Args:
            repo_refs: List of (repo_key, reference) tuples

        Returns:
            Dictionary mapping (repo_key, reference) to validation results
        """
        results = {}

        uncached_refs = []
        for repo_key, ref in repo_refs:
            if (
                repo_key in self._reference_cache
                and ref in self._reference_cache[repo_key]
            ):
                self.api_stats.increment_cache_hit()
                results[(repo_key, ref)] = self._reference_cache[repo_key][ref]
                self.logger.debug(f"Reference cache hit: {repo_key}@{ref}")
            else:
                uncached_refs.append((repo_key, ref))

        if not uncached_refs:
            return results

        self.logger.debug(
            f"Validating {len(uncached_refs)} references via GraphQL "
            f"(cache hits: {len(results)})"
        )

        # Group by repository for efficient querying
        refs_by_repo: dict[str, list[str]] = {}
        for repo_key, ref in uncached_refs:
            if repo_key not in refs_by_repo:
                refs_by_repo[repo_key] = []
            refs_by_repo[repo_key].append(ref)

        # Process each repository's references - create all tasks for parallel execution
        all_tasks: list[tuple[str, list[str]]] = []

        for repo_key, refs in refs_by_repo.items():
            batch_size = self.config.max_references_per_query
            for i in range(0, len(refs), batch_size):
                ref_batch = refs[i : i + batch_size]
                all_tasks.append((repo_key, ref_batch))

        # Use semaphore to limit concurrent batches (respects parallel_workers config)
        semaphore = asyncio.Semaphore(self.parallel_workers)

        async def process_ref_batch_with_limit(
            repo_key: str, ref_batch: list[str]
        ) -> tuple[str, dict[str, bool]]:
            """Process a single reference batch with rate limiting."""
            async with semaphore:
                await self._check_rate_limit()
                try:
                    batch_results = (
                        await self._validate_references_graphql_batch(
                            repo_key, ref_batch
                        )
                    )

                    # Cache results
                    if repo_key not in self._reference_cache:
                        self._reference_cache[repo_key] = {}
                    for ref, is_valid in batch_results.items():
                        self._reference_cache[repo_key][ref] = is_valid

                    return repo_key, batch_results
                except (
                    NetworkError,
                    GitHubAPIError,
                    AuthenticationError,
                    RateLimitError,
                ) as e:
                    # Re-raise known API/network errors - don't treat as validation failure
                    self.logger.error(
                        f"Error validating references for {repo_key}: {e}"
                    )
                    raise
                except Exception as e:
                    self.logger.error(
                        f"Unexpected error validating references for {repo_key}: {e}"
                    )
                    self.api_stats.increment_failed_call()

                    # Mark all as invalid on error
                    batch_results = {}
                    if repo_key not in self._reference_cache:
                        self._reference_cache[repo_key] = {}
                    for ref in ref_batch:
                        batch_results[ref] = False
                        self._reference_cache[repo_key][ref] = False

                    return repo_key, batch_results

        batch_results_list = await asyncio.gather(
            *[process_ref_batch_with_limit(rk, rb) for rk, rb in all_tasks]
        )

        # Merge all results
        for repo_key, batch_result in batch_results_list:
            for ref, is_valid in batch_result.items():
                results[(repo_key, ref)] = is_valid

        return results

    async def validate_subpaths_batch(
        self, subpath_refs: list[tuple[str, str]]
    ) -> dict[tuple[str, str], bool]:
        """
        Validate subdirectory-action subpaths exist at their referenced ref.

        Each entry is a ``(repo_key, ref)`` tuple where ``repo_key`` is a full
        action identifier that includes a subdirectory subpath
        (``owner/repo/path``). The base repository and ref are assumed to have
        already been validated; this method only confirms that ``path`` exists
        in the repository tree at ``ref`` (preferring an ``action.yml`` /
        ``action.yaml`` within it). A cheap GraphQL ``object(expression: ...)``
        tree lookup is used, batched alongside other subpath checks, so this
        adds ~O(1) extra work per subdirectory action.

        Args:
            subpath_refs: List of ``(repo_key, ref)`` tuples, where each
                ``repo_key`` includes a subdirectory subpath.

        Returns:
            Dictionary mapping ``(repo_key, ref)`` to subpath-existence result.
        """
        results: dict[tuple[str, str], bool] = {}

        uncached: list[tuple[str, str]] = []
        for repo_key, ref in subpath_refs:
            cache_key = (repo_key, ref)
            if cache_key in self._subpath_cache:
                self.api_stats.increment_cache_hit()
                results[cache_key] = self._subpath_cache[cache_key]
                self.logger.debug(f"Subpath cache hit: {repo_key}@{ref}")
            else:
                uncached.append((repo_key, ref))

        if not uncached:
            return results

        self.logger.debug(
            f"Validating {len(uncached)} subdirectory action subpaths via "
            f"GraphQL (cache hits: {len(results)})"
        )

        # Process in batches - create all tasks for parallel execution.
        batch_size = self.config.max_repositories_per_query
        batches = [
            uncached[i : i + batch_size]
            for i in range(0, len(uncached), batch_size)
        ]

        semaphore = asyncio.Semaphore(self.parallel_workers)

        async def process_subpath_batch_with_limit(
            batch: list[tuple[str, str]],
        ) -> dict[tuple[str, str], bool]:
            """Process a single subpath batch with rate limiting."""
            async with semaphore:
                await self._check_rate_limit()
                try:
                    batch_results = await self._validate_subpaths_graphql_batch(
                        batch
                    )
                    for cache_key, is_valid in batch_results.items():
                        self._subpath_cache[cache_key] = is_valid
                    return batch_results
                except (
                    NetworkError,
                    GitHubAPIError,
                    AuthenticationError,
                    RateLimitError,
                    TemporaryAPIError,
                ):
                    # Re-raise known API/network errors so the caller can
                    # surface them rather than treating them as bogus paths.
                    # (TemporaryAPIError subclasses GitHubAPIError, so it is
                    # already covered; it is named explicitly for clarity and
                    # to mirror the validator's abort handler.)
                    self.logger.error(
                        "Error validating subdirectory action subpaths"
                    )
                    raise
                except Exception as e:
                    # Propagate unexpected (non-API/network) errors instead of
                    # caching a bogus ``False`` (INVALID_PATH) for every entry.
                    # Returning False here would poison ``_subpath_cache`` for
                    # the rest of the run and misclassify an internal bug as a
                    # real bogus subpath. The validator turns any raised error
                    # into a ValidationAbortedError, mirroring how the Git path
                    # keeps inconclusive checks out of the cache.
                    self.logger.error(
                        f"Unexpected error validating subpath batch: {e}"
                    )
                    self.api_stats.increment_failed_call()
                    raise

        batch_results_list = await asyncio.gather(
            *[process_subpath_batch_with_limit(batch) for batch in batches]
        )

        for batch_result in batch_results_list:
            results.update(batch_result)

        return results

    async def _validate_repositories_graphql_batch(
        self, repo_keys: list[str]
    ) -> dict[str, bool]:
        """
        Validate repositories using GraphQL batch query.

        Args:
            repo_keys: List of repository keys in format "owner/repo"

        Returns:
            Dictionary mapping repo keys to validation results
        """
        query_parts = []
        aliases = {}

        for i, repo_key in enumerate(repo_keys):
            try:
                owner, name = repo_key.split("/", 1)
                base_name = name.split("/")[0]

                alias = f"repo_{i}"
                aliases[alias] = repo_key

                query_parts.append(f"""
                    {alias}: repository(owner: "{owner}", name: "{base_name}") {{
                        id
                        name
                        owner {{
                            login
                        }}
                    }}
                """)
            except ValueError:
                self.logger.warning(f"Invalid repository format: {repo_key}")
                continue

        if not query_parts:
            return {}

        query = f"""
        query {{
            {" ".join(query_parts)}
        }}
        """

        response_data = await self._execute_graphql_query(query)

        results = {}
        response_root = response_data.get("data") or {}
        for alias, repo_key in aliases.items():
            repo_data = response_root.get(alias)
            results[repo_key] = repo_data is not None

            if repo_data:
                self.logger.debug(f"Repository exists: {repo_key}")
            else:
                self.logger.debug(f"Repository not found: {repo_key}")

        return results

    async def _validate_references_graphql_batch(
        self, repo_key: str, references: list[str]
    ) -> dict[str, bool]:
        """
        Validate references for a single repository using GraphQL.

        Args:
            repo_key: Repository key in format "owner/repo"
            references: List of Git references to validate

        Returns:
            Dictionary mapping references to validation results

        Side effects:
            Records any reference that resolves to an annotated tag object;
            see :attr:`annotated_tag_peels`.
        """
        try:
            owner, name = repo_key.split("/", 1)
            base_name = name.split("/")[0]
        except ValueError:
            self.logger.warning(f"Invalid repository format: {repo_key}")
            return dict.fromkeys(references, False)

        # Separate commit SHAs from branch/tag names
        commit_shas = []
        branch_tag_names = []

        for ref in references:
            if len(ref) == 40 and all(
                c in "0123456789abcdef" for c in ref.lower()
            ):
                commit_shas.append(ref)
            else:
                branch_tag_names.append(ref)

        results = {}

        if commit_shas:
            sha_results, peels = await self._resolve_commit_shas_graphql(
                owner, base_name, commit_shas
            )
            results.update(sha_results)
            # Key peels by the caller's repo_key, which may carry an action
            # subpath that base_name has stripped.
            for sha, peel in peels.items():
                self._annotated_tag_peels[(repo_key, sha)] = peel

        if branch_tag_names:
            ref_results = await self._validate_branch_tag_names_graphql(
                owner, base_name, branch_tag_names
            )
            results.update(ref_results)

        return results

    async def _validate_commit_shas_graphql(
        self, owner: str, name: str, shas: list[str]
    ) -> dict[str, bool]:
        """
        Validate commit SHAs using GraphQL.

        Args:
            owner: Repository owner
            name: Repository name
            shas: List of commit SHAs

        Returns:
            Dictionary mapping SHAs to validation results
        """
        results, _peels = await self._resolve_commit_shas_graphql(
            owner, name, shas
        )
        return results

    async def _resolve_commit_shas_graphql(
        self, owner: str, name: str, shas: list[str]
    ) -> tuple[dict[str, bool], dict[str, AnnotatedTagPeel]]:
        """
        Resolve commit SHAs, distinguishing commits from tag objects.

        ``object(oid: ...)`` resolves any Git object, so a SHA naming an
        annotated tag object resolves successfully but is not checkout-able
        by GitHub Actions. Narrowing on ``Tag`` as well as ``Commit`` peels
        it in the same request, which lets this backend agree with the Git
        backend on both the verdict (invalid) and the remediation (use the
        peeled commit).

        Args:
            owner: Repository owner
            name: Repository name
            shas: List of commit SHAs

        Returns:
            Tuple of (results, peels): results maps each SHA to whether it
            names a real commit, and peels maps each SHA naming an
            annotated tag object to the tag and commit behind it.
        """
        query_parts = []
        aliases = {}

        for i, sha in enumerate(shas):
            alias = f"commit_{i}"
            aliases[alias] = sha

            query_parts.append(f"""
                {alias}: object(oid: "{sha}") {{
                    __typename
                    ... on Commit {{
                        oid
                    }}
                    ... on Tag {{
                        name
                        target {{
                            oid
                        }}
                    }}
                }}
            """)

        query = f"""
        query {{
            repository(owner: "{owner}", name: "{name}") {{
                {" ".join(query_parts)}
            }}
        }}
        """

        response_data = await self._execute_graphql_query(query)

        results: dict[str, bool] = {}
        peels: dict[str, AnnotatedTagPeel] = {}
        response_root = response_data.get("data") or {}
        repo_data = response_root.get("repository") or {}

        for alias, sha in aliases.items():
            commit_data = repo_data.get(alias)
            peel = self._annotated_tag_peel(commit_data)

            if peel is not None:
                results[sha] = False
                peels[sha] = peel
                self.logger.debug(
                    f"SHA names an annotated tag object: "
                    f"{owner}/{name}@{sha} -> {peel.tag} ({peel.commit_sha})"
                )
            elif commit_data:
                results[sha] = True
                self.logger.debug(f"Commit SHA exists: {owner}/{name}@{sha}")
            else:
                results[sha] = False
                self.logger.debug(f"Commit SHA not found: {owner}/{name}@{sha}")

        return results, peels

    @staticmethod
    def _annotated_tag_peel(object_data: Any) -> AnnotatedTagPeel | None:
        """Extract the peel from a GraphQL ``Tag`` object payload.

        Args:
            object_data: The ``object(oid: ...)`` payload, or None when the
                SHA resolved to nothing.

        Returns:
            The tag and commit behind an annotated tag object, or None when
            the payload is absent, is not a tag, or lacks a peeled target.
        """
        if not isinstance(object_data, dict):
            return None
        if object_data.get("__typename") != "Tag":
            return None

        target = object_data.get("target") or {}
        commit_sha = target.get("oid") if isinstance(target, dict) else None
        if not commit_sha:
            return None

        return AnnotatedTagPeel(
            tag=str(object_data.get("name") or ""),
            commit_sha=str(commit_sha),
        )

    async def _validate_branch_tag_names_graphql(
        self, owner: str, name: str, refs: list[str]
    ) -> dict[str, bool]:
        """
        Validate branch and tag names using GraphQL aliases.

        Resolves each requested reference directly by qualified name in a
        single GraphQL request, regardless of how many branches or tags the
        repository has. This avoids paginating through every ref in the
        repository (some repos have hundreds or thousands of refs) and
        eliminates the previous "first 100 + fallback" pattern.

        Args:
            owner: Repository owner
            name: Repository name
            refs: List of branch/tag names

        Returns:
            Dictionary mapping references to validation results
        """
        if not refs:
            return {}

        results = await self._validate_refs_batch_graphql(owner, name, refs)

        for ref, valid in results.items():
            if valid:
                self.logger.debug(f"Reference exists: {owner}/{name}@{ref}")
            else:
                self.logger.debug(f"Reference not found: {owner}/{name}@{ref}")

        return results

    async def _validate_refs_batch_graphql(
        self, owner: str, name: str, refs: list[str]
    ) -> dict[str, bool]:
        """
        Batch validate references using GraphQL aliases.

        Resolves each ref directly by qualified name in a single GraphQL
        request, checking both refs/heads/<ref> and refs/tags/<ref>. This is
        O(1) per ref regardless of how many refs the repository contains.

        Args:
            owner: Repository owner
            name: Repository name
            refs: List of reference names to validate

        Returns:
            Dictionary mapping references to validation results
        """
        results = {}

        # Build query with aliases for all refs (both as branches and tags)
        branch_queries = []
        tag_queries = []

        for idx, ref in enumerate(refs):
            # Use the loop index to generate a stable GraphQL-safe alias.
            # The ref itself appears only inside the qualifiedName string,
            # never in the alias, so no ref sanitization is needed here.
            alias = f"ref_{idx}"
            branch_queries.append(
                f'{alias}: ref(qualifiedName: "refs/heads/{ref}") {{ name }}'
            )
            tag_queries.append(
                f'{alias}_tag: ref(qualifiedName: "refs/tags/{ref}") {{ name }}'
            )

        query = f"""
        query {{
            repository(owner: "{owner}", name: "{name}") {{
                {" ".join(branch_queries)}
                {" ".join(tag_queries)}
            }}
        }}
        """

        try:
            response_data = await self._execute_graphql_query(query)
        except (
            AuthenticationError,
            RateLimitError,
            NetworkError,
            TemporaryAPIError,
            GitHubAPIError,
        ):
            # Propagate real API/network failures so higher-level code can
            # surface them properly instead of silently marking all refs as
            # invalid.
            raise
        except Exception as e:
            # Truly unexpected error (e.g. malformed response handling): log
            # at debug and conservatively mark refs as invalid for this repo.
            self.logger.debug(
                f"Unexpected batch ref validation error for {owner}/{name}: {e}"
            )
            results.update(dict.fromkeys(refs, False))
            return results

        response_root = response_data.get("data") or {}
        repo_data = response_root.get("repository") or {}

        for idx, ref in enumerate(refs):
            alias = f"ref_{idx}"
            tag_alias = f"{alias}_tag"

            # Found if exists as either branch or tag
            is_valid = bool(repo_data.get(alias) or repo_data.get(tag_alias))
            results[ref] = is_valid

        return results

    @staticmethod
    def _graphql_string_literal(value: str) -> str:
        """Escape a value for safe inclusion in a GraphQL string literal.

        Refs and paths are interpolated into GraphQL ``expression`` strings;
        escape the characters that would otherwise terminate or corrupt the
        string literal. Refs/paths almost never contain these, but escaping
        keeps the generated query well-formed regardless of input.

        Args:
            value: Raw string to embed inside a GraphQL double-quoted string.

        Returns:
            The escaped string (without surrounding quotes).
        """
        return (
            value.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        )

    async def _validate_subpaths_graphql_batch(
        self, subpath_refs: list[tuple[str, str]]
    ) -> dict[tuple[str, str], bool]:
        """
        Validate a batch of subdirectory subpaths using a single GraphQL query.

        For each ``(repo_key, ref)`` entry, the subpath is probed at the ref
        via ``object(expression: "<ref>:<candidate>")`` for each candidate path
        returned by :func:`action_subpath_candidates` (the action metadata
        files first, then the directory itself). The subpath is considered to
        exist if any candidate object resolves to a non-null tree/blob.

        Args:
            subpath_refs: List of ``(repo_key, ref)`` tuples to validate.

        Returns:
            Dictionary mapping ``(repo_key, ref)`` to subpath-existence result.
        """
        query_parts: list[str] = []
        # (repo_key, ref) -> list of candidate GraphQL field aliases
        entry_aliases: dict[tuple[str, str], list[str]] = {}

        for i, (repo_key, ref) in enumerate(subpath_refs):
            base = base_repository(repo_key)
            subpath = action_subpath(repo_key)
            if subpath is None:
                # No subpath: nothing to verify, treat as present.
                entry_aliases[(repo_key, ref)] = []
                continue

            try:
                owner, name = base.split("/", 1)
            except ValueError:
                self.logger.warning(
                    f"Invalid repository format for subpath check: {repo_key}"
                )
                entry_aliases[(repo_key, ref)] = []
                continue

            repo_alias = f"sp_{i}"
            object_parts: list[str] = []
            candidate_aliases: list[str] = []
            for j, candidate in enumerate(action_subpath_candidates(subpath)):
                obj_alias = f"{repo_alias}_c{j}"
                candidate_aliases.append(f"{repo_alias}.{obj_alias}")
                expression = self._graphql_string_literal(f"{ref}:{candidate}")
                object_parts.append(
                    f'{obj_alias}: object(expression: "{expression}") '
                    f"{{ __typename }}"
                )

            owner_lit = self._graphql_string_literal(owner)
            name_lit = self._graphql_string_literal(name)
            query_parts.append(
                f'{repo_alias}: repository(owner: "{owner_lit}", '
                f'name: "{name_lit}") {{ {" ".join(object_parts)} }}'
            )
            entry_aliases[(repo_key, ref)] = candidate_aliases

        results: dict[tuple[str, str], bool] = {}

        # If no entry produced a queryable subpath (all entries lacked a
        # subpath or had an invalid format), there is nothing to disprove, so
        # treat them all as present.
        if not query_parts:
            return dict.fromkeys(entry_aliases, True)

        query = f"query {{ {' '.join(query_parts)} }}"

        try:
            response_data = await self._execute_graphql_query(query)
        except (
            AuthenticationError,
            RateLimitError,
            NetworkError,
            TemporaryAPIError,
            GitHubAPIError,
        ):
            raise
        except Exception as e:
            # Propagate unexpected errors rather than reporting every entry as
            # a bogus subpath. Returning False here would let the caller cache
            # a potentially-wrong INVALID_PATH for a non-data failure (e.g. a
            # response-parsing bug); re-raising lets the validator abort the
            # run, consistent with the Git path's inconclusive handling.
            self.logger.debug(f"Unexpected subpath batch validation error: {e}")
            raise

        data = response_data.get("data", {}) or {}

        for cache_key, candidate_aliases in entry_aliases.items():
            if not candidate_aliases:
                # No subpath to verify (defensive: should not normally reach
                # here since such entries are filtered out upstream).
                results[cache_key] = True
                continue

            found = False
            for combined in candidate_aliases:
                repo_alias, obj_alias = combined.split(".", 1)
                repo_obj = data.get(repo_alias) or {}
                if repo_obj.get(obj_alias) is not None:
                    found = True
                    break
            results[cache_key] = found

        return results

    async def _execute_graphql_query(self, query: str) -> dict[Any, Any]:
        """
        Execute a GraphQL query and return the response.

        Args:
            query: GraphQL query string

        Returns:
            GraphQL response data

        Raises:
            Exception: If the query fails
        """
        if not self._http_client:
            raise RuntimeError("HTTP client not initialized")

        self.api_stats.increment_graphql()

        payload = {"query": query}

        try:
            response = await self._http_client.post(
                self.config.graphql_url, json=payload
            )

            self._update_rate_limit_from_headers(response.headers)
            self._raise_for_graphql_status(response)

            data = response.json()
            self._check_graphql_errors(data)

            self.logger.debug(
                f"GraphQL query successful (API calls made: {self.api_stats.total_calls})"
            )

            return data  # type: ignore[no-any-return]

        except httpx.RequestError as e:
            self._raise_network_error(e)

    def _raise_for_graphql_status(self, response: httpx.Response) -> None:
        """Raise the appropriate API error for a non-200 GraphQL response."""
        if response.status_code == 200:
            return

        self.logger.error(
            f"GraphQL query failed: {response.status_code} - {response.text}"
        )
        self.api_stats.increment_failed_call()

        status = response.status_code
        if status == 401:
            raise AuthenticationError(
                "GitHub API authentication failed. Please check your token."
            )
        if status == 403:
            # Could be rate limit or permissions
            if "rate limit" in response.text.lower():
                raise RateLimitError(
                    "GitHub API rate limit exceeded. Please wait and try again."
                )
            raise AuthenticationError(
                "GitHub API access forbidden. Please check your token permissions."
            )
        if status == 429:
            raise RateLimitError(
                "GitHub API rate limit exceeded. Please wait and try again."
            )
        if status >= 500:
            raise TemporaryAPIError(
                f"GitHub API server error ({status}). This may be temporary.",
                status_code=status,
            )
        raise GitHubAPIError(
            f"GitHub API request failed: {status} - {response.text}",
            status_code=status,
        )

    def _check_graphql_errors(self, data: dict[Any, Any]) -> None:
        """Inspect a GraphQL response body and raise on fatal errors.

        "Not found" / "could not resolve" errors are expected for invalid
        repositories and are left in the response for the caller to handle.
        """
        if "errors" not in data:
            return

        self.logger.error(f"GraphQL errors: {data['errors']}")
        self.api_stats.increment_failed_call()

        error_messages = [
            str(error.get("message", "")) for error in data["errors"]
        ]
        combined_errors = "; ".join(error_messages)

        if any("rate limit" in msg.lower() for msg in error_messages):
            raise RateLimitError(
                f"GitHub API rate limit exceeded: {combined_errors}"
            )
        if any(
            "not found" in msg.lower() or "could not resolve" in msg.lower()
            for msg in error_messages
        ):
            # Expected for invalid repositories - don't raise an exception.
            # Let the caller handle the GraphQL errors in the response.
            return
        raise GitHubAPIError(f"GitHub API GraphQL errors: {combined_errors}")

    def _raise_network_error(self, e: httpx.RequestError) -> NoReturn:
        """Classify an httpx request error and raise a NetworkError."""
        self.logger.error(f"HTTP request failed: {e}")
        self.api_stats.increment_failed_call()

        # Classify different types of network errors
        error_str = str(e).lower()
        if "name resolution" in error_str or "dns" in error_str:
            raise NetworkError(
                "DNS resolution failed. Please check your internet connection and try again.",
                original_error=e,
            ) from e
        if "connection" in error_str:
            raise NetworkError(
                "Network connection failed. Please check your internet connection and try again.",
                original_error=e,
            ) from e
        if "timeout" in error_str:
            raise NetworkError(
                "Network request timed out. Please check your internet connection and try again.",
                original_error=e,
            ) from e
        raise NetworkError(
            f"Network request failed: {e}", original_error=e
        ) from e

    async def _update_rate_limit_info(self) -> None:
        """Update rate limit information from GitHub API."""
        if not self._http_client:
            return

        try:
            self.api_stats.increment_rest()

            response = await self._http_client.get(
                f"{self.config.base_url}/rate_limit"
            )

            if response.status_code == 200:
                data = response.json()
                resources = data.get("resources") or {}
                graphql_limits = resources.get("graphql") or {}

                self._rate_limit_info = GitHubRateLimitInfo(
                    limit=graphql_limits.get("limit", 5000),
                    remaining=graphql_limits.get("remaining", 5000),
                    reset_at=graphql_limits.get("reset", 0),
                    used=graphql_limits.get("used", 0),
                )

                self.logger.debug(
                    f"Rate limit updated: {self._rate_limit_info.remaining}/"
                    f"{self._rate_limit_info.limit} remaining"
                )
            else:
                self.logger.warning(
                    f"Failed to get rate limit info: {response.status_code}"
                )

        except Exception as e:
            self.logger.warning(f"Error updating rate limit info: {e}")

    def _update_rate_limit_from_headers(
        self, headers: httpx.Headers | Mapping[str, str]
    ) -> None:
        """Update rate limit info from response headers."""
        try:
            if "x-ratelimit-remaining" in headers:
                self._rate_limit_info.remaining = int(
                    headers["x-ratelimit-remaining"]
                )
            if "x-ratelimit-limit" in headers:
                self._rate_limit_info.limit = int(headers["x-ratelimit-limit"])
            if "x-ratelimit-reset" in headers:
                self._rate_limit_info.reset_at = int(
                    headers["x-ratelimit-reset"]
                )
            if "x-ratelimit-used" in headers:
                self._rate_limit_info.used = int(headers["x-ratelimit-used"])

        except (ValueError, KeyError):
            pass  # Ignore header parsing errors

    async def _check_rate_limit(self) -> None:
        """Check rate limit and delay if necessary."""
        if self._rate_limit_info.remaining <= self.config.rate_limit_threshold:
            current_time = time.time()
            reset_time = self._rate_limit_info.reset_at

            if reset_time > current_time:
                delay = (
                    reset_time
                    - current_time
                    + self.config.rate_limit_reset_buffer
                )

                self.logger.warning(
                    f"Rate limit threshold reached. Waiting {delay:.1f} seconds "
                    f"(remaining: {self._rate_limit_info.remaining}/"
                    f"{self._rate_limit_info.limit})"
                )

                self.api_stats.increment_rate_limit_delay()
                await asyncio.sleep(delay)

                await self._update_rate_limit_info()

    def get_api_stats(self) -> APICallStats:
        """Get current API call statistics."""
        return self.api_stats.model_copy()

    def get_rate_limit_info(self) -> GitHubRateLimitInfo:
        """Get current rate limit information."""
        return self._rate_limit_info.model_copy()

    def _is_rate_limited(self) -> bool:
        """Check if we are currently rate-limited."""
        # Consider rate-limited if we have 0 remaining requests
        if self._rate_limit_info.remaining == 0:
            return True

        # Also check if we're very close to being rate-limited (1 request
        # or less remaining) and the reset time is in the future.
        current_time = time.time()
        return (
            self._rate_limit_info.remaining <= 1
            and self._rate_limit_info.reset_at > current_time
        )

    def check_rate_limit_and_exit_if_needed(self) -> None:
        """
        Synchronously check rate limits and exit if rate limited.

        This method performs a synchronous HTTP request to check rate limits
        and exits the program if rate limited. Should be called early in the
        application flow before showing progress bars.
        """
        # We can check rate limits even without a token for unauthenticated requests

        import httpx

        try:
            # Create a temporary synchronous client for the rate limit check
            with httpx.Client(
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "gha-workflow-linter/1.0",
                    **(
                        {"Authorization": f"Bearer {self._token}"}
                        if self._token
                        else {}
                    ),
                },
                timeout=30.0,
            ) as client:
                response = client.get(f"{self.config.base_url}/rate_limit")

                if response.status_code == 200:
                    data = response.json()
                    resources = data.get("resources") or {}
                    graphql_limits = resources.get("graphql") or {}

                    remaining = graphql_limits.get("remaining", 5000)
                    limit = graphql_limits.get("limit", 5000)
                    reset_at = graphql_limits.get("reset", 0)

                    self._rate_limit_info = GitHubRateLimitInfo(
                        limit=limit,
                        remaining=remaining,
                        reset_at=reset_at,
                        used=graphql_limits.get("used", 0),
                    )

                    # Check if we're rate limited and exit if so
                    if self._is_rate_limited():
                        self.logger.warning(
                            "GitHub API Rate-limited; Skipping Checks ⚠️"
                        )
                        sys.exit(0)

        except Exception as e:
            # If we can't check rate limits, log it but don't exit
            # The async flow will handle errors later
            self.logger.debug(f"Could not check rate limits synchronously: {e}")
