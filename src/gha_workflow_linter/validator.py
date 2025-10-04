# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Validator for GitHub Actions calls using GraphQL API with comprehensive tracking."""

from __future__ import annotations

import asyncio
from collections import defaultdict
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    from rich.progress import Progress, TaskID

    pass


from .cache import ValidationCache
from .exceptions import (
    AuthenticationError,
    GitHubAPIError,
    NetworkError,
    RateLimitError,
    TemporaryAPIError,
    ValidationAbortedError,
)
from .github_api import GitHubGraphQLClient
from .models import (
    ActionCall,
    APICallStats,
    Config,
    ReferenceType,
    ValidationError,
    ValidationResult,
)


class ActionCallValidator:
    """Validator for GitHub Actions and workflow calls using GraphQL API."""

    def __init__(self, config: Config) -> None:
        """
        Initialize the validator.

        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._github_client: GitHubGraphQLClient | None = None
        self.api_stats = APICallStats()
        self._cache = ValidationCache(config.cache)

    async def __aenter__(self) -> ActionCallValidator:
        """Async context manager entry."""
        self._github_client = GitHubGraphQLClient(self.config.github_api)
        await self._github_client.__aenter__()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        if self._github_client:
            await self._github_client.__aexit__(exc_type, exc_val, exc_tb)
        # Merge cache stats into API stats
        self.api_stats.cache_hits += self._cache.stats.hits
        # Save cache before exiting
        self._cache.save()

    async def validate_action_calls_async(
        self,
        action_calls: dict[Path, dict[int, ActionCall]],
        progress: Progress | None = None,
        task_id: TaskID | None = None,
    ) -> list[ValidationError]:
        """
        Validate all action calls against remote repositories using GraphQL.

        Args:
            action_calls: Dictionary mapping file paths to action calls
            progress: Optional progress bar
            task_id: Optional task ID for progress updates

        Returns:
            List of validation errors
        """
        if not self._github_client:
            raise RuntimeError("GitHub client not initialized")

        self.logger.info(
            "Starting action call validation using GitHub GraphQL API"
        )

        errors: list[ValidationError] = []

        # Flatten and deduplicate action calls
        all_calls: list[tuple[Path, ActionCall]] = []
        unique_calls: dict[str, ActionCall] = {}
        call_locations: dict[str, list[tuple[Path, ActionCall]]] = defaultdict(
            list
        )

        for file_path, calls in action_calls.items():
            for action_call in calls.values():
                all_calls.append((file_path, action_call))

                # Create unique key for deduplication
                call_key = f"{action_call.organization}/{action_call.repository}@{action_call.reference}"
                unique_calls[call_key] = action_call
                call_locations[call_key].append((file_path, action_call))

        total_calls = len(all_calls)
        unique_count = len(unique_calls)

        if total_calls == 0:
            self.logger.info("No action calls to validate")
            return errors

        self.logger.info(
            f"Validating {total_calls} action calls "
            f"({unique_count} unique calls) using GraphQL API"
        )

        # Deduplication savings
        saved_validations = total_calls - unique_count
        if saved_validations > 0:
            self.logger.info(
                f"Deduplication saved {saved_validations} validations "
                f"({saved_validations / total_calls * 100:.1f}% reduction)"
            )

        # Extract unique repositories and references
        unique_repos = set()
        repo_refs: list[tuple[str, str]] = []

        for _call_key, action_call in unique_calls.items():
            repo_key = f"{action_call.organization}/{action_call.repository}"
            unique_repos.add(repo_key)
            repo_refs.append((repo_key, action_call.reference))

        # Check cache for existing validation results
        cached_results, cache_misses = self._cache.get_batch(repo_refs)

        if cached_results:
            self.logger.debug(
                f"Found {len(cached_results)} cached validation results"
            )

        # Filter out cached results from what needs to be validated
        repos_to_validate = set()
        refs_to_validate = []

        for repo, ref in cache_misses:
            repos_to_validate.add(repo)
            refs_to_validate.append((repo, ref))

        # Update progress
        if progress and task_id:
            progress.update(
                task_id,
                total=len(repos_to_validate) + len(refs_to_validate),
                description="Validating repositories...",
            )

        # Step 1: Validate repositories in batch (only for cache misses)
        self.logger.debug(
            f"Validating {len(repos_to_validate)} unique repositories (after cache)"
        )

        repo_results = {}

        if repos_to_validate:
            try:
                repo_results = (
                    await self._github_client.validate_repositories_batch(
                        list(repos_to_validate)
                    )
                )

                # Merge API stats
                self._merge_api_stats(self._github_client.get_api_stats())

                self.logger.debug(
                    f"Repository validation complete. API calls so far: "
                    f"{self.api_stats.total_calls} (GraphQL: {self.api_stats.graphql_calls}, "
                    f"Cache hits: {self.api_stats.cache_hits})"
                )

            except (
                NetworkError,
                GitHubAPIError,
                AuthenticationError,
                RateLimitError,
                TemporaryAPIError,
            ) as e:
                self.logger.error(
                    f"GitHub API/Network error during repository validation: {e}"
                )
                raise ValidationAbortedError(
                    "Unable to validate GitHub Actions due to API/network issues",
                    reason=str(e),
                    original_error=e,
                ) from e
            except Exception as e:
                self.logger.error(
                    f"Unexpected error during repository validation: {e}"
                )
                raise ValidationAbortedError(
                    "Validation failed due to unexpected error",
                    reason=str(e),
                    original_error=e,
                ) from e

        # Merge cached repository results
        for repo, ref in cached_results:
            if repo not in repo_results:
                # Assume cached results are for valid repositories if they were cached
                repo_results[repo] = cached_results[(repo, ref)].result not in [
                    ValidationResult.INVALID_REPOSITORY
                ]

        # Update progress
        if progress and task_id:
            progress.update(
                task_id,
                completed=len(unique_repos),
                description="Validating references...",
            )

        # Step 2: Validate references for valid repositories only (excluding cached results)
        valid_repo_refs_to_validate = [
            (repo_key, ref)
            for repo_key, ref in refs_to_validate
            if repo_results.get(repo_key, False)
        ]

        self.logger.debug(
            f"Validating {len(valid_repo_refs_to_validate)} references for valid repositories (after cache)"
        )

        ref_results = {}

        if valid_repo_refs_to_validate:
            try:
                ref_results = (
                    await self._github_client.validate_references_batch(
                        valid_repo_refs_to_validate
                    )
                )

                # Merge API stats again
                self._merge_api_stats(self._github_client.get_api_stats())

                self.logger.debug(
                    f"Reference validation complete. Total API calls: "
                    f"{self.api_stats.total_calls} (GraphQL: {self.api_stats.graphql_calls}, "
                    f"REST: {self.api_stats.rest_calls}, "
                    f"Cache hits: {self.api_stats.cache_hits})"
                )

            except (
                NetworkError,
                GitHubAPIError,
                AuthenticationError,
                RateLimitError,
                TemporaryAPIError,
            ) as e:
                self.logger.error(
                    f"GitHub API/Network error during reference validation: {e}"
                )
                raise ValidationAbortedError(
                    "Unable to validate GitHub Actions due to API/network issues",
                    reason=str(e),
                    original_error=e,
                ) from e
            except Exception as e:
                self.logger.error(
                    f"Unexpected error during reference validation: {e}"
                )
                raise ValidationAbortedError(
                    "Validation failed due to unexpected error",
                    reason=str(e),
                    original_error=e,
                ) from e

        # Merge cached reference results
        for (repo, ref), cached_entry in cached_results.items():
            ref_results[(repo, ref)] = (
                cached_entry.result == ValidationResult.VALID
            )

        # Update progress
        if progress and task_id:
            progress.update(
                task_id,
                completed=len(repos_to_validate)
                + len(valid_repo_refs_to_validate),
                description="Processing validation results...",
            )

        # Cache new validation results
        cache_entries_to_store = []
        for repo, ref in refs_to_validate:
            repo_valid = repo_results.get(repo, False)
            ref_valid = ref_results.get((repo, ref), False)

            if repo_valid and ref_valid:
                result = ValidationResult.VALID
                api_call_type = "graphql"
                error_message = None
            elif not repo_valid:
                result = ValidationResult.INVALID_REPOSITORY
                api_call_type = "graphql"
                error_message = f"Repository {repo} not found or not accessible"
            else:
                result = ValidationResult.INVALID_REFERENCE
                api_call_type = "graphql"
                error_message = (
                    f"Reference {ref} not found in repository {repo}"
                )

            cache_entries_to_store.append(
                (repo, ref, result, api_call_type, error_message)
            )

        if cache_entries_to_store:
            self._cache.put_batch(cache_entries_to_store)

        # Step 3: Map results back to all occurrences (including cached results)
        # Reconstruct full repo_refs list for _combine_validation_results
        # all_repo_refs = repo_refs  # Not needed since we use repo_refs directly
        all_repo_results = repo_results.copy()
        all_ref_results = ref_results.copy()

        # Add cached results to the full results dictionaries
        for (repo, ref), cached_entry in cached_results.items():
            all_repo_results[repo] = cached_entry.result not in [
                ValidationResult.INVALID_REPOSITORY
            ]
            all_ref_results[(repo, ref)] = (
                cached_entry.result == ValidationResult.VALID
            )

        validation_results = self._combine_validation_results(
            unique_calls, all_repo_results, all_ref_results
        )

        for call_key, result in validation_results.items():
            if result != ValidationResult.VALID:
                for file_path, action_call in call_locations[call_key]:
                    error = ValidationError(
                        file_path=file_path,
                        action_call=action_call,
                        result=result,
                        error_message=self._get_error_message(result),
                    )
                    errors.append(error)

        # Step 4: Check SHA pinning requirements if enabled
        if self.config.require_pinned_sha:
            for call_key, action_call in unique_calls.items():
                # Only check if the call passed other validations
                if (
                    validation_results.get(call_key) == ValidationResult.VALID
                    and action_call.reference_type != ReferenceType.COMMIT_SHA
                ):
                    # Add error for each occurrence of this unpinned call
                    for file_path, _ in call_locations[call_key]:
                        error = ValidationError(
                            file_path=file_path,
                            action_call=action_call,
                            result=ValidationResult.NOT_PINNED_TO_SHA,
                            error_message=self._get_error_message(
                                ValidationResult.NOT_PINNED_TO_SHA
                            ),
                        )
                        errors.append(error)

        # Log final statistics
        rate_limit_info = self._github_client.get_rate_limit_info()
        self.logger.info(
            f"Validation complete: {len(errors)} errors out of "
            f"{total_calls} calls ({unique_count} unique calls validated)"
        )
        self.logger.info(
            f"API Statistics: {self.api_stats.total_calls} total calls "
            f"(GraphQL: {self.api_stats.graphql_calls}, "
            f"REST: {self.api_stats.rest_calls}, "
            f"Cache hits: {self.api_stats.cache_hits})"
        )
        self.logger.info(
            f"GitHub Rate Limit: {rate_limit_info.remaining}/"
            f"{rate_limit_info.limit} remaining"
        )

        if self.api_stats.rate_limit_delays > 0:
            self.logger.warning(
                f"Rate limit delays encountered: {self.api_stats.rate_limit_delays}"
            )

        return errors

    def validate_action_calls(
        self,
        action_calls: dict[Path, dict[int, ActionCall]],
        progress: Progress | None = None,
        task_id: TaskID | None = None,
    ) -> list[ValidationError]:
        """
        Synchronous wrapper for async validation.

        Args:
            action_calls: Dictionary mapping file paths to action calls
            progress: Optional progress bar
            task_id: Optional task ID for progress updates

        Returns:
            List of validation errors
        """

        async def _run_validation() -> list[ValidationError]:
            async with self:
                return await self.validate_action_calls_async(
                    action_calls, progress, task_id
                )

        return asyncio.run(_run_validation())

    def _combine_validation_results(
        self,
        unique_calls: dict[str, ActionCall],
        repo_results: dict[str, bool],
        ref_results: dict[tuple[str, str], bool],
    ) -> dict[str, ValidationResult]:
        """
        Combine repository and reference validation results.

        Args:
            unique_calls: Dictionary of unique action calls
            repo_results: Repository validation results
            ref_results: Reference validation results

        Returns:
            Dictionary mapping call keys to validation results
        """
        validation_results = {}

        for call_key, action_call in unique_calls.items():
            repo_key = f"{action_call.organization}/{action_call.repository}"

            # Check repository validity
            if not repo_results.get(repo_key, False):
                validation_results[call_key] = (
                    ValidationResult.INVALID_REPOSITORY
                )
                continue

            # Check reference validity
            ref_key = (repo_key, action_call.reference)
            if not ref_results.get(ref_key, False):
                validation_results[call_key] = (
                    ValidationResult.INVALID_REFERENCE
                )
                continue

            # Both repository and reference are valid
            validation_results[call_key] = ValidationResult.VALID

        return validation_results

    def _merge_api_stats(self, client_stats: APICallStats) -> None:
        """
        Merge API statistics from GitHub client.

        Args:
            client_stats: API statistics from GitHub client
        """
        self.api_stats.total_calls = client_stats.total_calls
        self.api_stats.graphql_calls = client_stats.graphql_calls
        self.api_stats.rest_calls = client_stats.rest_calls
        self.api_stats.git_calls = client_stats.git_calls
        self.api_stats.cache_hits = client_stats.cache_hits
        self.api_stats.rate_limit_delays = client_stats.rate_limit_delays
        self.api_stats.failed_calls = client_stats.failed_calls

    def _get_error_message(self, result: ValidationResult) -> str:
        """
        Get human-readable error message for validation result.

        Args:
            result: ValidationResult enum value

        Returns:
            Error message string
        """
        messages = {
            ValidationResult.INVALID_REPOSITORY: "Repository not found",
            ValidationResult.INVALID_REFERENCE: "Invalid branch, tag, or commit SHA",
            ValidationResult.INVALID_SYNTAX: "Invalid action call syntax",
            ValidationResult.NETWORK_ERROR: "Network error during validation",
            ValidationResult.TIMEOUT: "Timeout during validation",
            ValidationResult.NOT_PINNED_TO_SHA: "Action not pinned to commit SHA",
        }

        return messages.get(result, "Unknown validation error")

    def get_validation_summary(
        self,
        errors: list[ValidationError],
        total_calls: int = 0,
        unique_calls: int = 0,
    ) -> dict[str, int]:
        """
        Generate summary statistics for validation errors.

        Args:
            errors: List of validation errors
            total_calls: Total number of action calls processed
            unique_calls: Number of unique calls validated

        Returns:
            Dictionary with error statistics and API metrics
        """
        summary = {
            "total_errors": len(errors),
            "total_calls": total_calls,
            "unique_calls_validated": unique_calls,
            "duplicate_calls_avoided": max(0, total_calls - unique_calls),
            "invalid_repositories": 0,
            "invalid_references": 0,
            "syntax_errors": 0,
            "network_errors": 0,
            "timeouts": 0,
            "not_pinned_to_sha": 0,
            # API call statistics
            "api_calls_total": self.api_stats.total_calls,
            "api_calls_graphql": self.api_stats.graphql_calls,
            "api_calls_rest": self.api_stats.rest_calls,
            "api_calls_git": self.api_stats.git_calls,
            "cache_hits": self.api_stats.cache_hits,
            "rate_limit_delays": self.api_stats.rate_limit_delays,
            "failed_api_calls": self.api_stats.failed_calls,
        }

        # Count error types
        for error in errors:
            if error.result == ValidationResult.INVALID_REPOSITORY:
                summary["invalid_repositories"] += 1
            elif error.result == ValidationResult.INVALID_REFERENCE:
                summary["invalid_references"] += 1
            elif error.result == ValidationResult.INVALID_SYNTAX:
                summary["syntax_errors"] += 1
            elif error.result == ValidationResult.NETWORK_ERROR:
                summary["network_errors"] += 1
            elif error.result == ValidationResult.TIMEOUT:
                summary["timeouts"] += 1
            elif error.result == ValidationResult.NOT_PINNED_TO_SHA:
                summary["not_pinned_to_sha"] += 1

        return summary

    def get_api_stats(self) -> APICallStats:
        """Get current API call statistics."""
        return self.api_stats.model_copy()  # type: ignore[no-any-return]
