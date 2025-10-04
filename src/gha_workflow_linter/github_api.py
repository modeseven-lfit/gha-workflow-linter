# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""GitHub GraphQL API client for efficient repository validation."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from typing import Any

import httpx

from .exceptions import (
    AuthenticationError,
    GitHubAPIError,
    NetworkError,
    RateLimitError,
    TemporaryAPIError,
)
from .models import (
    APICallStats,
    GitHubAPIConfig,
    GitHubRateLimitInfo,
)


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

        # Get initial rate limit info
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

        # Check cache first
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

        # Process in batches
        batch_size = self.config.max_repositories_per_query
        for i in range(0, len(uncached_repos), batch_size):
            batch = uncached_repos[i : i + batch_size]

            await self._check_rate_limit()

            try:
                batch_results = await self._validate_repositories_graphql_batch(
                    batch
                )
                results.update(batch_results)

                # Cache results
                for repo_key, is_valid in batch_results.items():
                    self._repository_cache[repo_key] = is_valid

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
                for repo_key in batch:
                    results[repo_key] = False
                    self._repository_cache[repo_key] = False

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

        # Check cache first
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

        # Process each repository's references
        for repo_key, refs in refs_by_repo.items():
            # Process references in batches
            batch_size = self.config.max_references_per_query
            for i in range(0, len(refs), batch_size):
                ref_batch = refs[i : i + batch_size]

                await self._check_rate_limit()

                try:
                    batch_results = (
                        await self._validate_references_graphql_batch(
                            repo_key, ref_batch
                        )
                    )

                    # Update results
                    for ref, is_valid in batch_results.items():
                        results[(repo_key, ref)] = is_valid

                        # Cache results
                        if repo_key not in self._reference_cache:
                            self._reference_cache[repo_key] = {}
                        self._reference_cache[repo_key][ref] = is_valid

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
                    for ref in ref_batch:
                        results[(repo_key, ref)] = False
                        if repo_key not in self._reference_cache:
                            self._reference_cache[repo_key] = {}
                        self._reference_cache[repo_key][ref] = False

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
        # Build GraphQL query for multiple repositories
        query_parts = []
        aliases = {}

        for i, repo_key in enumerate(repo_keys):
            try:
                owner, name = repo_key.split("/", 1)
                # Remove workflow paths for base repository
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
        for alias, repo_key in aliases.items():
            repo_data = response_data.get("data", {}).get(alias)
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
        """
        try:
            owner, name = repo_key.split("/", 1)
            # Remove workflow paths for base repository
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

        # Validate commit SHAs
        if commit_shas:
            sha_results = await self._validate_commit_shas_graphql(
                owner, base_name, commit_shas
            )
            results.update(sha_results)

        # Validate branches and tags
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
        query_parts = []
        aliases = {}

        for i, sha in enumerate(shas):
            alias = f"commit_{i}"
            aliases[alias] = sha

            query_parts.append(f"""
                {alias}: object(oid: "{sha}") {{
                    ... on Commit {{
                        oid
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

        results = {}
        repo_data = response_data.get("data", {}).get("repository", {})

        for alias, sha in aliases.items():
            commit_data = repo_data.get(alias)
            results[sha] = commit_data is not None

            if commit_data:
                self.logger.debug(f"Commit SHA exists: {owner}/{name}@{sha}")
            else:
                self.logger.debug(f"Commit SHA not found: {owner}/{name}@{sha}")

        return results

    async def _validate_branch_tag_names_graphql(
        self, owner: str, name: str, refs: list[str]
    ) -> dict[str, bool]:
        """
        Validate branch and tag names using GraphQL.

        Args:
            owner: Repository owner
            name: Repository name
            refs: List of branch/tag names

        Returns:
            Dictionary mapping references to validation results
        """
        # Query both branches and tags
        query = f"""
        query {{
            repository(owner: "{owner}", name: "{name}") {{
                refs(refPrefix: "refs/heads/", first: 100) {{
                    nodes {{
                        name
                    }}
                }}
                tags: refs(refPrefix: "refs/tags/", first: 100) {{
                    nodes {{
                        name
                    }}
                }}
            }}
        }}
        """

        response_data = await self._execute_graphql_query(query)

        # Extract available branches and tags
        repo_data = response_data.get("data", {}).get("repository", {})

        branches = set()
        if repo_data.get("refs", {}).get("nodes"):
            branches = {node["name"] for node in repo_data["refs"]["nodes"]}

        tags = set()
        if repo_data.get("tags", {}).get("nodes"):
            tags = {node["name"] for node in repo_data["tags"]["nodes"]}

        # Validate each reference
        results = {}
        for ref in refs:
            is_valid = ref in branches or ref in tags
            results[ref] = is_valid

            if is_valid:
                ref_type = "branch" if ref in branches else "tag"
                self.logger.debug(
                    f"{ref_type.title()} exists: {owner}/{name}@{ref}"
                )
            else:
                self.logger.debug(f"Reference not found: {owner}/{name}@{ref}")

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

            # Update rate limit info from headers
            self._update_rate_limit_from_headers(response.headers)

            if response.status_code != 200:
                self.logger.error(
                    f"GraphQL query failed: {response.status_code} - {response.text}"
                )
                self.api_stats.increment_failed_call()

                # Handle specific HTTP status codes
                if response.status_code == 401:
                    raise AuthenticationError(
                        "GitHub API authentication failed. Please check your token."
                    )
                elif response.status_code == 403:
                    # Could be rate limit or permissions
                    if "rate limit" in response.text.lower():
                        raise RateLimitError(
                            "GitHub API rate limit exceeded. Please wait and try again."
                        )
                    else:
                        raise AuthenticationError(
                            "GitHub API access forbidden. Please check your token permissions."
                        )
                elif response.status_code == 429:
                    raise RateLimitError(
                        "GitHub API rate limit exceeded. Please wait and try again."
                    )
                elif response.status_code >= 500:
                    raise TemporaryAPIError(
                        f"GitHub API server error ({response.status_code}). This may be temporary.",
                        status_code=response.status_code,
                    )
                else:
                    raise GitHubAPIError(
                        f"GitHub API request failed: {response.status_code} - {response.text}",
                        status_code=response.status_code,
                    )

            data = response.json()

            if "errors" in data:
                self.logger.error(f"GraphQL errors: {data['errors']}")
                self.api_stats.increment_failed_call()

                # Check for specific GraphQL error types
                error_messages = [
                    str(error.get("message", "")) for error in data["errors"]
                ]
                combined_errors = "; ".join(error_messages)

                if any("rate limit" in msg.lower() for msg in error_messages):
                    raise RateLimitError(
                        f"GitHub API rate limit exceeded: {combined_errors}"
                    )
                elif any(
                    "not found" in msg.lower()
                    or "could not resolve" in msg.lower()
                    for msg in error_messages
                ):
                    # This is expected for invalid repositories - don't raise an exception
                    # Let the caller handle the GraphQL errors in the response
                    pass
                else:
                    raise GitHubAPIError(
                        f"GitHub API GraphQL errors: {combined_errors}"
                    )

            self.logger.debug(
                f"GraphQL query successful (API calls made: {self.api_stats.total_calls})"
            )

            return data  # type: ignore[no-any-return]

        except httpx.RequestError as e:
            self.logger.error(f"HTTP request failed: {e}")
            self.api_stats.increment_failed_call()

            # Classify different types of network errors
            error_str = str(e).lower()
            if "name resolution" in error_str or "dns" in error_str:
                raise NetworkError(
                    "DNS resolution failed. Please check your internet connection and try again.",
                    original_error=e,
                ) from e
            elif "connection" in error_str:
                raise NetworkError(
                    "Network connection failed. Please check your internet connection and try again.",
                    original_error=e,
                ) from e
            elif "timeout" in error_str:
                raise NetworkError(
                    "Network request timed out. Please check your internet connection and try again.",
                    original_error=e,
                ) from e
            else:
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
                graphql_limits = data.get("resources", {}).get("graphql", {})

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

    def _update_rate_limit_from_headers(self, headers: httpx.Headers) -> None:
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

                # Update rate limit info after waiting
                await self._update_rate_limit_info()

    def get_api_stats(self) -> APICallStats:
        """Get current API call statistics."""
        return self.api_stats.model_copy()  # type: ignore[no-any-return]

    def get_rate_limit_info(self) -> GitHubRateLimitInfo:
        """Get current rate limit information."""
        return self._rate_limit_info.model_copy()  # type: ignore[no-any-return]

    def _is_rate_limited(self) -> bool:
        """Check if we are currently rate-limited."""
        # Consider rate-limited if we have 0 remaining requests
        if self._rate_limit_info.remaining == 0:
            return True

        # Also check if we're very close to being rate-limited (1 request or less remaining)
        # and the reset time is in the future
        current_time = time.time()
        if (self._rate_limit_info.remaining <= 1 and
            self._rate_limit_info.reset_at > current_time):
            return True

        return False

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
                    **({"Authorization": f"Bearer {self._token}"} if self._token else {}),
                },
                timeout=30.0,
            ) as client:

                response = client.get(f"{self.config.base_url}/rate_limit")

                if response.status_code == 200:
                    data = response.json()
                    graphql_limits = data.get("resources", {}).get("graphql", {})

                    remaining = graphql_limits.get("remaining", 5000)
                    limit = graphql_limits.get("limit", 5000)
                    reset_at = graphql_limits.get("reset", 0)

                    # Update our rate limit info
                    self._rate_limit_info = GitHubRateLimitInfo(
                        limit=limit,
                        remaining=remaining,
                        reset_at=reset_at,
                        used=graphql_limits.get("used", 0),
                    )

                    # Check if we're rate limited and exit if so
                    if self._is_rate_limited():
                        self.logger.warning("⚠️ GitHub API Rate-limited; Skipping Checks")
                        sys.exit(0)

        except Exception as e:
            # If we can't check rate limits, log it but don't exit
            # The async flow will handle errors later
            self.logger.debug(f"Could not check rate limits synchronously: {e}")
