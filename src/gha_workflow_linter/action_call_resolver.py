# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Reference and version resolution for the auto-fixer.

This module hosts :class:`_ReferenceResolutionMixin`, the portion of the
auto-fixer responsible for querying GitHub (via the GraphQL API or Git) to
resolve action references: discovering tags and branches, mapping
references to commit SHAs, and detecting repository redirects. Latest-
version selection and cooldown enforcement live in
:class:`action_call_versions._VersionResolutionMixin`, which builds on this
mixin.

It is split out of :mod:`action_call_fix` so the network-facing resolution logic is
isolated from the orchestration and file-rewriting concerns of
``AutoFixer``. The mixin is combined into ``AutoFixer`` via inheritance, so
the concrete instance supplies the attributes declared below in its
``__init__``.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
import re
from typing import TYPE_CHECKING, Any

from .action_call_git import (
    _get_remote_branches,
    _get_remote_tags,
)
from .action_call_scanner import ActionCallPatterns
from .exceptions import GitError
from .models import (
    Config,
    ValidationMethod,
    ValidationResult,
)
from .paths import base_repository

if TYPE_CHECKING:
    import logging

    import httpx

    from .action_call_git import GitValidationClient
    from .cache import ValidationCache
    from .github_api import GitHubGraphQLClient


class _ReferenceResolutionMixin:
    """GitHub reference/version resolution behaviour for ``AutoFixer``.

    The attributes below are provided by the concrete ``AutoFixer``
    instance; they are declared here only so the resolution methods type
    check in isolation.
    """

    config: Config
    logger: logging.Logger
    _http_client: httpx.AsyncClient | None
    _graphql_client: GitHubGraphQLClient | None
    _cache: ValidationCache
    _git_client: GitValidationClient | None
    _latest_versions_cache: dict[str, tuple[str, str, float]]
    _cache_ttl: int

    async def _get_repository_info(
        self, repo_key: str
    ) -> dict[str, Any] | None:
        """Get repository information using the configured validation method."""
        # Use API if we're in GitHub API validation mode
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._http_client
        ):
            try:
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}"
                )
                response.raise_for_status()
                return response.json()  # type: ignore[no-any-return]
            except Exception as e:
                self.logger.debug(
                    f"Failed to get repository info via API for {repo_key}: {e}"
                )

        # Use Git operations if we're in Git validation mode
        if (
            self.config.validation_method == ValidationMethod.GIT
            and self._git_client
        ):
            try:
                url = f"https://github.com/{repo_key}.git"
                branches = _get_remote_branches(url, self.config.git)

                # Determine default branch from available branches
                default_branch = "main"
                if "main" in branches:
                    default_branch = "main"
                elif "master" in branches:
                    default_branch = "master"
                elif branches:
                    # Use the first branch if neither main nor master exists
                    default_branch = sorted(branches)[0]

                return {"default_branch": default_branch}
            except GitError as e:
                self.logger.debug(
                    f"Failed to get repository info via Git for {repo_key}: {e}"
                )

        return None

    async def _get_fallback_reference(  # noqa: PLR0911
        self, repo_key: str, invalid_ref: str
    ) -> str | None:
        """Get fallback reference using Git operations or cached data."""
        # First check cache for known valid references for this repository
        cached_entry = self._cache.get(repo_key, "main")
        if cached_entry and cached_entry.result == ValidationResult.VALID:
            return "main"

        cached_entry = self._cache.get(repo_key, "master")
        if cached_entry and cached_entry.result == ValidationResult.VALID:
            return "master"

        # Try Git operations if we have the client
        if self._git_client:
            try:
                url = f"https://github.com/{repo_key}.git"
                branches = _get_remote_branches(url, self.config.git)

                # Common fallbacks for invalid references
                if invalid_ref == "master" and "main" in branches:
                    return "main"
                elif invalid_ref == "main" and "master" in branches:
                    return "master"
                elif invalid_ref.startswith("invalid"):
                    for default_branch in ["main", "master"]:
                        if default_branch in branches:
                            return default_branch

                # Try to find similar branch names
                for branch in branches:
                    if branch.endswith(invalid_ref) or invalid_ref in branch:
                        return branch

            except GitError as e:
                self.logger.debug(f"Git fallback failed for {repo_key}: {e}")

        # Final fallbacks without Git access
        if invalid_ref == "master":
            return "main"
        elif invalid_ref == "main":
            return "master"
        elif invalid_ref.startswith("invalid"):
            return "main"
        return None

    async def _get_latest_release_or_tag(self, repo_key: str) -> str | None:
        """Get the latest release or tag for a repository."""
        # Use API if we're in GitHub API validation mode
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._http_client
        ):
            # Try to get latest release first
            try:
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}/releases/latest"
                )
                if response.status_code == 200:
                    release_data = response.json()
                    return release_data.get("tag_name")  # type: ignore[no-any-return]
            except Exception as e:
                # A request failure or malformed-JSON error: fall back to the
                # tags API below. (A non-200 status such as 404 -- normal for
                # repos that only tag -- is not an error here: it simply skips
                # the block above and falls through, since the response is not
                # raised for status.)
                self.logger.debug(
                    f"Failed to get latest release via API for {repo_key}: {e}"
                )

            # Fall back to getting latest tag via API
            try:
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}/tags?per_page=1"
                )
                response.raise_for_status()
                tags = response.json()
                if tags:
                    return tags[0]["name"]  # type: ignore[no-any-return]
            except Exception as e:
                self.logger.debug(
                    f"Failed to get latest tag via API for {repo_key}: {e}"
                )

        # Use Git operations if we're in Git validation mode
        if (
            self.config.validation_method == ValidationMethod.GIT
            and self._git_client
        ):
            try:
                url = f"https://github.com/{repo_key}.git"
                git_tags = _get_remote_tags(url, self.config.git)

                if git_tags:
                    # Convert to sorted list (Git ls-remote doesn't guarantee order)
                    tag_list = sorted(git_tags, reverse=True)

                    # Try to find semantic version tags first
                    version_tags = [
                        tag
                        for tag in tag_list
                        if ActionCallPatterns.VERSION_TAG_PATTERN.match(tag)
                    ]
                    if version_tags:
                        return version_tags[0]

                    # Otherwise return the first tag
                    return tag_list[0]

            except GitError as e:
                self.logger.debug(
                    f"Git tag enumeration failed for {repo_key}: {e}"
                )

        return None

    async def _find_valid_reference(  # noqa: PLR0911
        self, repo_key: str, invalid_ref: str
    ) -> str | None:
        """Try to find a valid reference similar to the invalid one."""
        for potential_ref in [invalid_ref, "main", "master"]:
            cached_entry = self._cache.get(repo_key, potential_ref)
            if (
                cached_entry
                and cached_entry.result == ValidationResult.VALID
                and potential_ref != invalid_ref
            ):
                return potential_ref

        # Use API if we're in GitHub API validation mode
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._http_client
        ):
            # For common patterns like "main" vs "master"
            if invalid_ref in ["main", "master"]:
                alternative = "master" if invalid_ref == "main" else "main"
                if await self._check_reference_exists(repo_key, alternative):
                    return alternative

            # Try to find similar tags/branches
            try:
                # Check if it's a partial version match
                if re.match(r"^v?\d+", invalid_ref):
                    api_tags = await self._get_tags(repo_key, limit=50)
                    for api_tag in api_tags:
                        if api_tag["name"].startswith(invalid_ref):
                            return api_tag["name"]  # type: ignore[no-any-return]

                api_branches = await self._get_branches(repo_key, limit=20)
                for api_branch in api_branches:
                    if api_branch["name"] == invalid_ref or api_branch[
                        "name"
                    ].endswith(invalid_ref):
                        return api_branch["name"]  # type: ignore[no-any-return]

            except Exception as e:
                self.logger.debug(
                    f"Failed to find valid reference via API for {repo_key}@{invalid_ref}: {e}"
                )

        # Use Git operations if we're in Git validation mode
        if (
            self.config.validation_method == ValidationMethod.GIT
            and self._git_client
        ):
            try:
                url = f"https://github.com/{repo_key}.git"

                git_branches = _get_remote_branches(url, self.config.git)
                git_tags = _get_remote_tags(url, self.config.git)

                # For common patterns like "main" vs "master"
                if invalid_ref == "main" and "master" in git_branches:
                    return "master"
                elif invalid_ref == "master" and "main" in git_branches:
                    return "main"

                # Check if it's a partial version match in tags
                if re.match(r"^v?\d+", invalid_ref):
                    for git_tag in sorted(git_tags, reverse=True):
                        if git_tag.startswith(invalid_ref):
                            return git_tag

                for git_branch in git_branches:
                    if git_branch == invalid_ref or git_branch.endswith(
                        invalid_ref
                    ):
                        return git_branch

            except GitError as e:
                self.logger.debug(
                    f"Git reference search failed for {repo_key}@{invalid_ref}: {e}"
                )

        return None

    async def _check_reference_exists(self, repo_key: str, ref: str) -> bool:
        """Check if a specific reference exists."""
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._http_client
        ):
            try:
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}/git/refs/heads/{ref}"
                )
                if response.status_code == 200:
                    return True

                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}/git/refs/tags/{ref}"
                )
                return bool(response.status_code == 200)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.logger.debug(
                    f"GitHub API reference check failed for {repo_key}@{ref}: {exc}",
                    exc_info=True,
                )

        # Use Git operations if we're in Git validation mode
        if (
            self.config.validation_method == ValidationMethod.GIT
            and self._git_client
        ):
            try:
                url = f"https://github.com/{repo_key}.git"
                git_branches = _get_remote_branches(url, self.config.git)
                git_tags = _get_remote_tags(url, self.config.git)
                return ref in git_branches or ref in git_tags
            except GitError as exc:
                self.logger.debug(
                    f"Git reference check failed for {repo_key}@{ref}: {exc}",
                    exc_info=True,
                )

        return False

    async def _get_tags(
        self, repo_key: str, limit: int = 30
    ) -> list[dict[str, Any]]:
        """Get repository tags."""
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._http_client
        ):
            try:
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}/tags?per_page={limit}"
                )
                response.raise_for_status()
                return response.json()  # type: ignore[no-any-return]
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.logger.debug(
                    f"GitHub API tag lookup failed for {repo_key}: {exc}",
                    exc_info=True,
                )

        # Use Git operations if we're in Git validation mode - convert to API-like format
        if (
            self.config.validation_method == ValidationMethod.GIT
            and self._git_client
        ):
            try:
                url = f"https://github.com/{repo_key}.git"
                git_tags = _get_remote_tags(url, self.config.git)
                # Convert to API-like format for compatibility
                return [
                    {"name": tag}
                    for tag in sorted(git_tags, reverse=True)[:limit]
                ]
            except GitError as exc:
                self.logger.debug(
                    f"Git tag lookup failed for {repo_key}: {exc}",
                    exc_info=True,
                )

        return []

    async def _get_branches(
        self, repo_key: str, limit: int = 20
    ) -> list[dict[str, Any]]:
        """Get repository branches."""
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._http_client
        ):
            try:
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{repo_key}/branches?per_page={limit}"
                )
                response.raise_for_status()
                return response.json()  # type: ignore[no-any-return]
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.logger.debug(
                    f"GitHub API branch lookup failed for {repo_key}: {exc}",
                    exc_info=True,
                )

        # Use Git operations if we're in Git validation mode - convert to API-like format
        if (
            self.config.validation_method == ValidationMethod.GIT
            and self._git_client
        ):
            try:
                url = f"https://github.com/{repo_key}.git"
                git_branches = _get_remote_branches(url, self.config.git)
                # Convert to API-like format for compatibility
                return [
                    {"name": branch} for branch in sorted(git_branches)[:limit]
                ]
            except GitError as exc:
                self.logger.debug(
                    f"Git branch lookup failed for {repo_key}: {exc}",
                    exc_info=True,
                )

        return []

    async def _get_commit_sha_for_reference(
        self, repo_key: str, ref: str
    ) -> dict[str, Any] | None:
        """Get commit SHA for a specific reference."""
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._http_client
        ):
            return await self._resolve_sha_via_api(repo_key, ref)
        if (
            self.config.validation_method == ValidationMethod.GIT
            and self._git_client
        ):
            return await self._resolve_sha_via_git(repo_key, ref)
        return None

    async def _resolve_sha_via_api(
        self, repo_key: str, ref: str
    ) -> dict[str, Any] | None:
        """Resolve a ref to a commit SHA via the GitHub REST API.

        Tries the ref as a branch, then a tag (dereferencing annotated tags),
        then a raw commit SHA. Returns ``None`` when the ref cannot be
        resolved or the API errors.
        """
        if not self._http_client:
            return None
        try:
            # Try as branch first
            response = await self._http_client.get(
                f"https://api.github.com/repos/{repo_key}/git/refs/heads/{ref}"
            )
            if response.status_code == 200:
                ref_data = response.json()
                return {"sha": ref_data["object"]["sha"], "type": "branch"}

            # Try as tag
            response = await self._http_client.get(
                f"https://api.github.com/repos/{repo_key}/git/refs/tags/{ref}"
            )
            if response.status_code == 200:
                ref_data = response.json()
                sha = ref_data["object"]["sha"]

                # If it's an annotated tag, get the commit SHA
                if ref_data["object"]["type"] == "tag":
                    tag_response = await self._http_client.get(
                        f"https://api.github.com/repos/{repo_key}/git/tags/{sha}"
                    )
                    if tag_response.status_code == 200:
                        tag_data = tag_response.json()
                        sha = tag_data["object"]["sha"]

                return {"sha": sha, "type": "tag"}

            # Try as commit SHA
            response = await self._http_client.get(
                f"https://api.github.com/repos/{repo_key}/commits/{ref}"
            )
            if response.status_code == 200:
                commit_data = response.json()
                return {"sha": commit_data["sha"], "type": "commit"}
        except Exception as e:
            self.logger.debug(
                f"Failed to get commit SHA via API for {repo_key}@{ref}: {e}"
            )

        return None

    async def _resolve_sha_via_git(
        self, repo_key: str, ref: str
    ) -> dict[str, Any] | None:
        """Resolve a ref to a commit SHA with ``git ls-remote``.

        Tries the ref as a branch, then as a tag (preferring the
        dereferenced commit of an annotated tag). Returns ``None`` when the
        ref cannot be resolved.
        """
        import subprocess

        if not self._git_client:
            return None
        try:
            url = f"https://github.com/{repo_key}.git"

            # Try as branch. The ``--`` end-of-options marker stops git
            # from misreading a ref beginning with "-" (REF_PATTERN allows
            # it) as an option (argument injection).
            cmd = ["git", "ls-remote", "--heads", "--", url, ref]
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.config.git.timeout_seconds,
                    check=True,
                )
                if result.stdout.strip():
                    sha = result.stdout.strip().split("\t")[0]
                    return {"sha": sha, "type": "branch"}
            except subprocess.CalledProcessError:
                # ref is not a branch; fall through to try it as a tag.
                pass

            # Try as tag - need to dereference annotated tags
            # Query both the tag and the dereferenced commit
            cmd = [
                "git",
                "ls-remote",
                "--tags",
                "--",
                url,
                f"refs/tags/{ref}",
                f"refs/tags/{ref}^{{}}",
            ]
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.config.git.timeout_seconds,
                    check=True,
                )
                if result.stdout.strip():
                    lines = result.stdout.strip().split("\n")
                    # Look for dereferenced tag first (ends with ^{})
                    for line in lines:
                        if line.endswith(f"refs/tags/{ref}^{{}}"):
                            sha = line.split("\t")[0]
                            return {"sha": sha, "type": "tag"}
                    # Fall back to tag object if no dereferenced version
                    if lines:
                        sha = lines[0].split("\t")[0]
                        return {"sha": sha, "type": "tag"}
            except subprocess.CalledProcessError:
                # ref is not a tag either; leave it unresolved (returns
                # None below) so the caller can handle the miss.
                pass
        except Exception as e:
            self.logger.debug(
                f"Git SHA resolution failed for {repo_key}@{ref}: {e}"
            )

        return None

    async def _get_shas_batch(
        self, refs: list[tuple[str, str]]
    ) -> dict[tuple[str, str], str]:
        """
        Batch-fetch SHAs for multiple (repo, ref) pairs.

        Returns dict mapping (repo_key, ref) to SHA.
        Supports both GraphQL and parallel Git operations.
        """
        if not refs:
            return {}

        # Use GraphQL batch query if available, falling back to parallel Git
        # fetches when it is unavailable or errors.
        if (
            self.config.validation_method == ValidationMethod.GITHUB_API
            and self._graphql_client
        ):
            graphql_results = await self._get_shas_via_graphql(refs)
            if graphql_results is not None:
                return graphql_results

        return await self._get_shas_via_git(refs)

    def _build_shas_batch_query(
        self, refs: list[tuple[str, str]]
    ) -> tuple[str, dict[str, tuple[str, str]]]:
        """Build a batched GraphQL query resolving many tags to commit SHAs.

        Refs are grouped by repository for efficient querying. Returns the
        query text and an alias map from ``repo_<i>_ref_<j>`` to the original
        ``(repo_key, ref)`` pair.
        """
        refs_by_repo: dict[str, list[str]] = defaultdict(list)
        for repo_key, ref in refs:
            refs_by_repo[repo_key].append(ref)

        query_parts = []
        aliases: dict[str, tuple[str, str]] = {}

        for repo_idx, (repo_key, repo_refs) in enumerate(refs_by_repo.items()):
            owner, name = repo_key.split("/", 1)
            base_name = name.split("/")[0]

            ref_queries = []
            for ref_idx, ref in enumerate(repo_refs):
                ref_alias = f"ref_{ref_idx}"
                aliases[f"repo_{repo_idx}_{ref_alias}"] = (repo_key, ref)
                ref_queries.append(f"""
                    {ref_alias}: ref(qualifiedName: "refs/tags/{ref}") {{
                        target {{
                            oid
                            ... on Tag {{
                                target {{
                                    oid
                                }}
                            }}
                        }}
                    }}
                """)

            repo_alias = f"repo_{repo_idx}"
            query_parts.append(f"""
                {repo_alias}: repository(owner: "{owner}", name: "{base_name}") {{
                    {" ".join(ref_queries)}
                }}
            """)

        return f"query {{ {' '.join(query_parts)} }}", aliases

    def _extract_sha_from_ref_data(
        self, ref_data: dict[str, Any]
    ) -> str | None:
        """Extract a commit SHA from a single ref's GraphQL target.

        Annotated tags nest the commit SHA under ``target.target.oid``;
        lightweight tags expose it directly at ``target.oid``. Returns
        ``None`` when neither form is present.
        """
        target = ref_data.get("target")
        if not isinstance(target, dict):
            return None
        nested_target = target.get("target")
        if isinstance(nested_target, dict) and "oid" in nested_target:
            return str(nested_target["oid"])
        if "oid" in target:
            return str(target["oid"])
        return None

    def _parse_shas_batch_response(
        self,
        response_root: dict[str, Any],
        aliases: dict[str, tuple[str, str]],
    ) -> dict[tuple[str, str], str]:
        """Map a batched SHA query response back to ``(repo, ref)`` pairs."""
        results: dict[tuple[str, str], str] = {}
        for full_alias, (repo_key, ref) in aliases.items():
            # Alias format: "repo_{repo_idx}_ref_{ref_idx}"
            match = re.match(r"repo_(\d+)_ref_(\d+)", full_alias)
            if not match:
                self.logger.warning(
                    f"Failed to parse alias format: {full_alias}"
                )
                continue
            repo_alias = f"repo_{match.group(1)}"
            ref_alias = f"ref_{match.group(2)}"
            repo_data = response_root.get(repo_alias) or {}
            ref_data = repo_data.get(ref_alias)
            if not ref_data:
                continue
            sha = self._extract_sha_from_ref_data(ref_data)
            if sha is not None:
                results[(repo_key, ref)] = sha
        return results

    async def _get_shas_via_graphql(
        self, refs: list[tuple[str, str]]
    ) -> dict[tuple[str, str], str] | None:
        """Resolve SHAs via a single batched GraphQL query.

        Returns the resolved mapping on success, or ``None`` when the query
        errors so the caller can fall back to per-ref Git fetches.
        """
        if not self._graphql_client:
            return None
        try:
            query, aliases = self._build_shas_batch_query(refs)
            response_data = await self._graphql_client._execute_graphql_query(
                query
            )
            response_root = response_data.get("data") or {}
            return self._parse_shas_batch_response(response_root, aliases)
        except Exception as e:
            self.logger.debug(
                f"GraphQL batch SHA fetch failed, falling back: {e}"
            )
            return None

    async def _get_shas_via_git(
        self, refs: list[tuple[str, str]]
    ) -> dict[tuple[str, str], str]:
        """Resolve SHAs with parallel per-ref Git fetches (fallback path)."""
        tasks = [
            self._get_commit_sha_for_reference(repo_key, ref)
            for repo_key, ref in refs
        ]
        fetch_results = await asyncio.gather(*tasks, return_exceptions=True)

        results: dict[tuple[str, str], str] = {}
        for (repo_key, ref), result in zip(refs, fetch_results, strict=True):
            if isinstance(result, Exception):
                self.logger.debug(
                    f"Failed to fetch SHA for {repo_key}@{ref}: {result}"
                )
                continue
            if result and isinstance(result, dict) and "sha" in result:
                results[(repo_key, ref)] = result["sha"]
        return results

    async def _detect_repository_redirect(self, repo_key: str) -> str | None:
        """
        Detect if a repository has been moved/redirected.

        Uses HTTP HEAD requests to the GitHub web URL (not API) to detect
        repository moves via HTTP 301 redirects. This avoids API rate limits
        and works for both validation methods.

        Args:
            repo_key: Repository in format "owner/repo"

        Returns:
            New repository location if redirected, None otherwise
        """
        cached = self._cache.get_redirect(repo_key)
        if cached:
            return cached

        # Use HTTP HEAD request to detect redirect via web URL (not API)
        if self._http_client:
            try:
                # Use web URL instead of API URL to avoid rate limits
                response = await self._http_client.head(
                    f"https://github.com/{repo_key}"
                )

                # Check for redirect (301 Moved Permanently)
                if (
                    response.status_code == 301
                    and "location" in response.headers
                ):
                    location = response.headers["location"]

                    match = re.search(r"github\.com/([^/]+/[^/]+)", location)
                    if match:
                        new_repo = match.group(1)
                        if new_repo.lower() != repo_key.lower():
                            self.logger.debug(
                                f"Detected redirect: {repo_key} -> {new_repo}"
                            )
                            # Cache the redirect
                            self._cache.put_redirect(repo_key, new_repo)
                            return new_repo
            except Exception as e:
                self.logger.debug(
                    f"Redirect detection failed for {repo_key}: {e}"
                )

        return None

    def _get_base_repository(self, repo_key: str) -> str:
        """
        Extract base repository from a repo key that might include a path.

        For example:
        - "github/codeql-action/init" -> "github/codeql-action"
        - "actions/checkout" -> "actions/checkout"

        Args:
            repo_key: Repository key, possibly with path

        Returns:
            Base repository (owner/repo)
        """
        return base_repository(repo_key)
