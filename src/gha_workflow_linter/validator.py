# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Validator for GitHub Actions calls using GraphQL API or Git operations with comprehensive tracking."""

from __future__ import annotations

import asyncio
from collections import defaultdict
import logging
from typing import TYPE_CHECKING, Any, NoReturn

if TYPE_CHECKING:
    from pathlib import Path

    from rich.progress import Progress, TaskID

from .cache import ValidationCache
from .exceptions import (
    AuthenticationError,
    GitHubAPIError,
    NetworkError,
    RateLimitError,
    TemporaryAPIError,
    ValidationAbortedError,
)
from .git_validator import GitValidationClient
from .github_api import GitHubGraphQLClient
from .github_auth import get_github_token_with_fallback
from .models import (
    ActionCall,
    APICallStats,
    Config,
    ReferenceType,
    ValidationError,
    ValidationMethod,
    ValidationResult,
)
from .paths import (
    action_subpath,
    base_repository,
    has_action_subpath,
)
from .utils import has_test_comment


class ActionCallValidator:
    """Validator for GitHub Actions and workflow calls using GraphQL API or Git operations."""

    def __init__(
        self,
        config: Config,
        cache: ValidationCache | None = None,
    ) -> None:
        """
        Initialize the validator.

        Args:
            config: Configuration object.
            cache: Optional pre-built ``ValidationCache``. The CLI layer
                builds and primes a single shared cache and threads it
                through both the validator and the auto-fixer to avoid
                duplicate disk reads / writes. When ``None`` the validator
                builds its own cache (useful for ad-hoc / library use).
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._github_client: GitHubGraphQLClient | None = None
        self._git_client: GitValidationClient | None = None
        self.api_stats = APICallStats()
        self._cache = (
            cache if cache is not None else ValidationCache(config.cache)
        )
        self._validation_method: ValidationMethod | None = None

    async def __aenter__(self) -> ActionCallValidator:
        """Async context manager entry."""
        # Determine validation method
        self._validation_method = self._determine_validation_method()

        if self._validation_method == ValidationMethod.GITHUB_API:
            self._github_client = GitHubGraphQLClient(self.config.github_api)
            # Store parallel_workers from parent config for concurrent operations
            self._github_client.parallel_workers = self.config.parallel_workers
            await self._github_client.__aenter__()
        else:
            self._git_client = GitValidationClient(self.config.git)

        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        if self._github_client:
            await self._github_client.__aexit__(exc_type, exc_val, exc_tb)
        elif self._git_client:
            # Merge Git client stats
            git_stats = self._git_client.get_api_stats()
            self.api_stats.total_calls += git_stats.total_calls
            self.api_stats.git_calls += git_stats.git_calls
            self.api_stats.git_clone_operations += (
                git_stats.git_clone_operations
            )
            self.api_stats.git_ls_remote_operations += (
                git_stats.git_ls_remote_operations
            )
            self.api_stats.failed_calls += git_stats.failed_calls
            self.api_stats.repositories_validated += (
                git_stats.repositories_validated
            )

        # Merge cache stats into API stats
        self.api_stats.cache_hits += self._cache.stats.hits
        self._cache.save()

    async def validate_action_calls_async(
        self,
        action_calls: dict[Path, dict[int, ActionCall]],
        progress: Progress | None = None,
        task_id: TaskID | None = None,
    ) -> list[ValidationError]:
        """
        Validate all action calls against remote repositories.

        Args:
            action_calls: Dictionary mapping file paths to action calls
            progress: Optional progress bar
            task_id: Optional task ID for progress updates

        Returns:
            List of validation errors
        """
        # Eagerly run startup-time cache checks (version mismatch /
        # suspicious-patterns purge) on the first call. prime() is
        # idempotent: if the CLI passed a pre-primed shared cache via
        # ``cache=``, this is a no-op. If the validator built its own
        # cache (ad-hoc / library use), this is the only place that
        # would otherwise prime it.
        self._cache.prime()
        if self._validation_method == ValidationMethod.GITHUB_API:
            if not self._github_client:
                raise RuntimeError("GitHub client not initialized")
            return await self._validate_with_github_api(
                action_calls, progress, task_id
            )
        else:
            if not self._git_client:
                raise RuntimeError("Git client not initialized")
            return await self._validate_with_git(
                action_calls, progress, task_id
            )

    def _determine_validation_method(self) -> ValidationMethod:
        """
        Determine which validation method to use.

        Returns:
            ValidationMethod to use
        """
        # If explicitly specified in config, use that
        if self.config.validation_method:
            self.logger.debug(
                f"Using explicitly specified validation method: {self.config.validation_method}"
            )
            return self.config.validation_method

        # Try to get a GitHub token
        token = get_github_token_with_fallback(
            explicit_token=self.config.github_api.token, quiet=True
        )

        if token:
            self.logger.info(
                "GitHub token available, using GitHub API validation"
            )
            return ValidationMethod.GITHUB_API
        else:
            self.logger.info(
                "No GitHub token available, falling back to Git validation"
            )
            return ValidationMethod.GIT

    async def _validate_with_github_api(
        self,
        action_calls: dict[Path, dict[int, ActionCall]],
        progress: Progress | None = None,
        task_id: TaskID | None = None,
    ) -> list[ValidationError]:
        """
        Validate action calls using GitHub GraphQL API.

        Args:
            action_calls: Dictionary mapping file paths to action calls
            progress: Optional progress bar
            task_id: Optional task ID for progress updates

        Returns:
            List of validation errors
        """
        self.logger.debug(
            "Starting action call validation using GitHub GraphQL API"
        )

        return await self._perform_validation(
            action_calls, progress, task_id, use_github_api=True
        )

    async def _validate_with_git(
        self,
        action_calls: dict[Path, dict[int, ActionCall]],
        progress: Progress | None = None,
        task_id: TaskID | None = None,
    ) -> list[ValidationError]:
        """
        Validate action calls using Git operations.

        Args:
            action_calls: Dictionary mapping file paths to action calls
            progress: Optional progress bar
            task_id: Optional task ID for progress updates

        Returns:
            List of validation errors
        """
        self.logger.debug(
            "Starting action call validation using Git operations"
        )
        return await self._perform_validation(
            action_calls, progress, task_id, use_github_api=False
        )

    async def _perform_validation(
        self,
        action_calls: dict[Path, dict[int, ActionCall]],
        progress: Progress | None = None,
        task_id: TaskID | None = None,
        use_github_api: bool = True,
    ) -> list[ValidationError]:
        """
        Perform the actual validation using the specified method.

        Args:
            action_calls: Dictionary mapping file paths to action calls
            progress: Optional progress bar
            task_id: Optional task ID for progress updates
            use_github_api: Whether to use GitHub API or Git operations

        Returns:
            List of validation errors
        """
        errors: list[ValidationError] = []

        all_calls, unique_calls, call_locations = self._flatten_action_calls(
            action_calls
        )
        total_calls = len(all_calls)
        unique_count = len(unique_calls)

        if total_calls == 0:
            self.logger.info("No action calls to validate")
            return errors

        self._log_validation_plan(total_calls, unique_count, use_github_api)

        _unique_repos, repo_refs = self._collect_repo_refs(unique_calls)
        cached_results, cache_misses = self._cache.get_batch(repo_refs)
        if cached_results:
            self.logger.debug(
                f"Found {len(cached_results)} cached validation results"
            )

        repos_to_validate, refs_to_validate = self._prepare_validation_targets(
            cache_misses, progress, task_id
        )

        repo_results = await self._validate_repositories_stage(
            repos_to_validate, use_github_api
        )
        self._merge_cached_repo_results(repo_results, cached_results)
        # Progress is scaled to cache misses (see _prepare_validation_targets),
        # so advance by the number of repositories actually validated here,
        # not len(unique_repos), which would include cached repos and could
        # push completed beyond total.
        self._advance_progress(
            progress,
            task_id,
            len(repos_to_validate),
            "Validating references...",
        )

        valid_repo_refs_to_validate = self._select_valid_repo_refs(
            refs_to_validate, repo_results
        )
        ref_results = await self._validate_references_stage(
            valid_repo_refs_to_validate, use_github_api
        )

        subpath_refs_to_validate = self._select_subpath_refs(
            valid_repo_refs_to_validate, ref_results
        )
        (
            subpath_results,
            inconclusive_subpaths,
        ) = await self._validate_subpaths_stage(
            subpath_refs_to_validate, use_github_api
        )

        self._merge_cached_ref_results(ref_results, cached_results)
        self._advance_progress(
            progress,
            task_id,
            len(repos_to_validate) + len(valid_repo_refs_to_validate),
            "Processing validation results...",
        )

        cache_entries_to_store = self._build_cache_entries(
            refs_to_validate,
            inconclusive_subpaths,
            repo_results,
            ref_results,
            subpath_results,
            use_github_api,
        )
        if cache_entries_to_store:
            self._cache.put_batch(cache_entries_to_store)

        all_repo_results, all_ref_results, all_subpath_results = (
            self._merge_all_results(
                repo_results, ref_results, subpath_results, cached_results
            )
        )

        validation_results = self._combine_validation_results(
            unique_calls,
            all_repo_results,
            all_ref_results,
            all_subpath_results,
        )

        errors = self._build_validation_errors(
            validation_results, call_locations, unique_calls
        )

        self.logger.debug(
            f"Validation complete: {len(errors)} errors out of "
            f"{total_calls} calls ({unique_count} unique calls validated)"
        )

        self._log_final_statistics(use_github_api)
        self._finalize_progress(progress, task_id)

        return errors

    def _log_validation_plan(
        self, total_calls: int, unique_count: int, use_github_api: bool
    ) -> None:
        """Log the validation method and deduplication savings."""
        validation_method_str = (
            "GitHub GraphQL API" if use_github_api else "Git operations"
        )
        self.logger.debug(
            f"Validating {total_calls} action calls "
            f"({unique_count} unique calls) using {validation_method_str}"
        )
        saved_validations = total_calls - unique_count
        if saved_validations > 0:
            self.logger.debug(
                f"Deduplication saved {saved_validations} validations "
                f"({saved_validations / total_calls * 100:.1f}% reduction)"
            )

    def _prepare_validation_targets(
        self,
        cache_misses: list[tuple[str, str]],
        progress: Progress | None,
        task_id: TaskID | None,
    ) -> tuple[set[str], list[tuple[str, str]]]:
        """Split cache misses into repos/refs to validate and size progress."""
        repos_to_validate: set[str] = set()
        refs_to_validate: list[tuple[str, str]] = []
        for repo, ref in cache_misses:
            repos_to_validate.add(repo)
            refs_to_validate.append((repo, ref))

        # Update progress - don't set total to 0 if everything is cached
        if progress and task_id:
            new_total = len(repos_to_validate) + len(refs_to_validate)
            if new_total > 0:
                progress.update(
                    task_id,
                    total=new_total,
                    description="Validating repositories...",
                )
            else:
                # Everything is cached, mark as complete immediately
                task = progress.tasks[task_id]
                progress.update(
                    task_id,
                    completed=task.total,
                    description="Validation complete (all cached)",
                )

        self.logger.debug(
            f"Validating {len(repos_to_validate)} unique repositories (after cache)"
        )
        return repos_to_validate, refs_to_validate

    def _merge_cached_repo_results(
        self,
        repo_results: dict[str, bool],
        cached_results: dict[tuple[str, str], Any],
    ) -> None:
        """Fold cached repository verdicts into the fresh repo results."""
        for repo, ref in cached_results:
            if repo not in repo_results:
                # Cached entries imply the repository was reachable.
                repo_results[repo] = cached_results[(repo, ref)].result not in [
                    ValidationResult.INVALID_REPOSITORY
                ]

    def _merge_cached_ref_results(
        self,
        ref_results: dict[tuple[str, str], bool],
        cached_results: dict[tuple[str, str], Any],
    ) -> None:
        """Fold cached reference verdicts into the fresh reference results."""
        for (repo, ref), cached_entry in cached_results.items():
            ref_results[(repo, ref)] = (
                cached_entry.result == ValidationResult.VALID
            )

    def _advance_progress(
        self,
        progress: Progress | None,
        task_id: TaskID | None,
        completed: int,
        description: str,
    ) -> None:
        """Advance the progress task when progress reporting is enabled."""
        if progress and task_id:
            progress.update(
                task_id, completed=completed, description=description
            )

    def _select_valid_repo_refs(
        self,
        refs_to_validate: list[tuple[str, str]],
        repo_results: dict[str, bool],
    ) -> list[tuple[str, str]]:
        """Keep only the refs whose repository validated successfully."""
        valid = [
            (repo_key, ref)
            for repo_key, ref in refs_to_validate
            if repo_results.get(repo_key, False)
        ]
        self.logger.debug(
            f"Validating {len(valid)} references for valid repositories "
            f"(after cache)"
        )
        return valid

    def _select_subpath_refs(
        self,
        valid_repo_refs_to_validate: list[tuple[str, str]],
        ref_results: dict[tuple[str, str], bool],
    ) -> list[tuple[str, str]]:
        """Keep only valid refs that carry an action subpath to check."""
        return [
            (repo_key, ref)
            for (repo_key, ref) in valid_repo_refs_to_validate
            if has_action_subpath(repo_key)
            and ref_results.get((repo_key, ref), False)
        ]

    def _flatten_action_calls(
        self, action_calls: dict[Path, dict[int, ActionCall]]
    ) -> tuple[
        list[tuple[Path, ActionCall]],
        dict[str, ActionCall],
        dict[str, list[tuple[Path, ActionCall]]],
    ]:
        """Flatten per-file action calls and deduplicate by repo@ref."""
        all_calls: list[tuple[Path, ActionCall]] = []
        unique_calls: dict[str, ActionCall] = {}
        call_locations: dict[str, list[tuple[Path, ActionCall]]] = defaultdict(
            list
        )
        for file_path, calls in action_calls.items():
            for action_call in calls.values():
                all_calls.append((file_path, action_call))
                repo_for_validation = self._extract_repository_for_validation(
                    action_call
                )
                call_key = f"{action_call.organization}/{repo_for_validation}@{action_call.reference}"
                unique_calls[call_key] = action_call
                call_locations[call_key].append((file_path, action_call))
        return all_calls, unique_calls, call_locations

    def _collect_repo_refs(
        self, unique_calls: dict[str, ActionCall]
    ) -> tuple[set[str], list[tuple[str, str]]]:
        """Collect the unique repositories and (repo, ref) pairs to validate."""
        unique_repos: set[str] = set()
        repo_refs: list[tuple[str, str]] = []
        for action_call in unique_calls.values():
            repo_for_validation = self._extract_repository_for_validation(
                action_call
            )
            repo_key = f"{action_call.organization}/{repo_for_validation}"
            unique_repos.add(repo_key)
            repo_refs.append((repo_key, action_call.reference))
        return unique_repos, repo_refs

    def _build_cache_entries(
        self,
        refs_to_validate: list[tuple[str, str]],
        inconclusive_subpaths: set[tuple[str, str]],
        repo_results: dict[str, bool],
        ref_results: dict[tuple[str, str], bool],
        subpath_results: dict[tuple[str, str], bool],
        use_github_api: bool,
    ) -> list[
        tuple[str, str, ValidationResult, str, ValidationMethod, str | None]
    ]:
        """Build the cache entries to persist for freshly validated refs."""
        api_call_type = "graphql" if use_github_api else "git"
        cache_entries: list[
            tuple[str, str, ValidationResult, str, ValidationMethod, str | None]
        ] = []
        for repo, ref in refs_to_validate:
            # Skip caching entries whose subpath check was inconclusive so a
            # transient failure is retried next run rather than persisted as a
            # (benefit-of-the-doubt) VALID.
            if (repo, ref) in inconclusive_subpaths:
                continue

            repo_valid = repo_results.get(repo, False)
            ref_valid = ref_results.get((repo, ref), False)
            # Subpath is considered valid unless we explicitly determined it is
            # bogus. Entries without a subpath never populate subpath_results.
            subpath_valid = subpath_results.get((repo, ref), True)

            if repo_valid and ref_valid and subpath_valid:
                result = ValidationResult.VALID
                error_message = None
            elif not repo_valid:
                result = ValidationResult.INVALID_REPOSITORY
                error_message = f"Repository {repo} not found or not accessible"
            elif not ref_valid:
                result = ValidationResult.INVALID_REFERENCE
                error_message = (
                    f"Reference {ref} not found in repository {repo}"
                )
            else:
                result = ValidationResult.INVALID_PATH
                error_message = (
                    f"Subdirectory path '{action_subpath(repo)}' not found in "
                    f"{base_repository(repo)} at {ref}"
                )

            cache_entries.append(
                (
                    repo,
                    ref,
                    result,
                    api_call_type,
                    self._validation_method or ValidationMethod.GITHUB_API,
                    error_message,
                )
            )
        return cache_entries

    def _merge_all_results(
        self,
        repo_results: dict[str, bool],
        ref_results: dict[tuple[str, str], bool],
        subpath_results: dict[tuple[str, str], bool],
        cached_results: dict[tuple[str, str], Any],
    ) -> tuple[
        dict[str, bool],
        dict[tuple[str, str], bool],
        dict[tuple[str, str], bool],
    ]:
        """Combine freshly validated results with cached results.

        A cached INVALID_PATH means the base repo and ref are valid but the
        subdirectory subpath is bogus, so it must be reflected as repo-valid
        + ref-valid + subpath-invalid (not as an invalid ref).
        """
        all_repo_results = repo_results.copy()
        all_ref_results = ref_results.copy()
        all_subpath_results = dict(subpath_results)
        for (repo, ref), cached_entry in cached_results.items():
            all_repo_results[repo] = cached_entry.result not in [
                ValidationResult.INVALID_REPOSITORY
            ]
            all_ref_results[(repo, ref)] = cached_entry.result in (
                ValidationResult.VALID,
                ValidationResult.INVALID_PATH,
            )
            all_subpath_results[(repo, ref)] = (
                cached_entry.result != ValidationResult.INVALID_PATH
            )
        return all_repo_results, all_ref_results, all_subpath_results

    def _build_validation_errors(
        self,
        validation_results: dict[str, ValidationResult],
        call_locations: dict[str, list[tuple[Path, ActionCall]]],
        unique_calls: dict[str, ActionCall],
    ) -> list[ValidationError]:
        """Turn per-call validation results into ``ValidationError`` records."""
        errors: list[ValidationError] = []
        for call_key, result in validation_results.items():
            if result != ValidationResult.VALID:
                for file_path, action_call in call_locations[call_key]:
                    errors.append(
                        ValidationError(
                            file_path=file_path,
                            action_call=action_call,
                            result=result,
                            error_message=self._get_error_message(result),
                        )
                    )

        if self.config.require_pinned_sha:
            for call_key, action_call in unique_calls.items():
                if (
                    validation_results.get(call_key) == ValidationResult.VALID
                    and action_call.reference_type != ReferenceType.COMMIT_SHA
                ):
                    for file_path, actual_action_call in call_locations[
                        call_key
                    ]:
                        errors.append(
                            ValidationError(
                                file_path=file_path,
                                action_call=actual_action_call,
                                result=ValidationResult.NOT_PINNED_TO_SHA,
                                error_message=self._get_error_message(
                                    ValidationResult.NOT_PINNED_TO_SHA
                                ),
                            )
                        )
        return errors

    def _log_final_statistics(self, use_github_api: bool) -> None:
        """Emit end-of-run API/Git statistics at debug level."""
        if use_github_api and self._github_client:
            rate_limit_info = self._github_client.get_rate_limit_info()
            self.logger.debug(
                f"API Statistics: {self.api_stats.total_calls} total calls "
                f"(GraphQL: {self.api_stats.graphql_calls}, "
                f"REST: {self.api_stats.rest_calls}, "
                f"Cache hits: {self.api_stats.cache_hits})"
            )
            self.logger.debug(
                f"GitHub Rate Limit: {rate_limit_info.remaining}/{rate_limit_info.limit} remaining"
            )
        else:
            # Merge cache statistics before printing
            self.api_stats.cache_hits += self._cache.stats.hits
            self.logger.debug(
                f"Git Statistics: {self.api_stats.total_calls} total calls "
                f"(Git: {self.api_stats.git_calls}, "
                f"Clone ops: {self.api_stats.git_clone_operations}, "
                f"ls-remote ops: {self.api_stats.git_ls_remote_operations}, "
                f"Cache hits: {self.api_stats.cache_hits})"
            )

        if self.api_stats.rate_limit_delays > 0:
            self.logger.warning(
                f"Rate limit delays encountered: {self.api_stats.rate_limit_delays}"
            )

    def _finalize_progress(
        self, progress: Progress | None, task_id: TaskID | None
    ) -> None:
        """Mark the progress task complete if it is not already."""
        if progress and task_id:
            task = progress.tasks[task_id]
            if task.total is not None and task.completed < task.total:
                progress.update(
                    task_id,
                    completed=task.total,
                    description="Validation complete",
                )

    _ABORT_ERRORS: tuple[type[Exception], ...] = (
        NetworkError,
        GitHubAPIError,
        AuthenticationError,
        RateLimitError,
        TemporaryAPIError,
    )

    def _abort_validation(
        self, stage: str, use_github_api: bool, error: Exception
    ) -> NoReturn:
        """Wrap a stage failure in ``ValidationAbortedError`` and raise."""
        if isinstance(error, self._ABORT_ERRORS):
            context = "GitHub API/Network" if use_github_api else "Git/Network"
            self.logger.error(
                f"{context} error during {stage} validation: {error}"
            )
            raise ValidationAbortedError(
                "Unable to validate GitHub Actions due to API/network issues",
                reason=str(error),
                original_error=error,
            ) from error
        self.logger.error(
            f"Unexpected error during {stage} validation: {error}"
        )
        raise ValidationAbortedError(
            "Validation failed due to unexpected error",
            reason=str(error),
            original_error=error,
        ) from error

    async def _validate_repositories_stage(
        self, repos_to_validate: set[str], use_github_api: bool
    ) -> dict[str, bool]:
        """Validate a batch of repositories via the API or Git backend."""
        repo_results: dict[str, bool] = {}
        if not repos_to_validate:
            return repo_results
        try:
            if use_github_api:
                assert self._github_client is not None
                repo_results = (
                    await self._github_client.validate_repositories_batch(
                        list(repos_to_validate)
                    )
                )
                self._merge_api_stats(self._github_client.get_api_stats())
            else:
                assert self._git_client is not None
                git_repo_results = (
                    await self._git_client.validate_repositories_batch(
                        list(repos_to_validate)
                    )
                )
                repo_results = {
                    repo: result == ValidationResult.VALID
                    for repo, result in git_repo_results.items()
                }
            self._log_stage_stats("Repository", use_github_api)
        except Exception as e:
            self._abort_validation("repository", use_github_api, e)
        return repo_results

    async def _validate_references_stage(
        self,
        valid_repo_refs_to_validate: list[tuple[str, str]],
        use_github_api: bool,
    ) -> dict[tuple[str, str], bool]:
        """Validate a batch of references for already-valid repositories."""
        ref_results: dict[tuple[str, str], bool] = {}
        if not valid_repo_refs_to_validate:
            return ref_results
        try:
            if use_github_api:
                assert self._github_client is not None
                ref_results = (
                    await self._github_client.validate_references_batch(
                        valid_repo_refs_to_validate
                    )
                )
                self._merge_api_stats(self._github_client.get_api_stats())
            else:
                assert self._git_client is not None
                git_ref_results = (
                    await self._git_client.validate_references_batch(
                        valid_repo_refs_to_validate
                    )
                )
                ref_results = {
                    repo_ref: result == ValidationResult.VALID
                    for repo_ref, result in git_ref_results.items()
                }
            self._log_stage_stats("Reference", use_github_api)
        except Exception as e:
            self._abort_validation("reference", use_github_api, e)
        return ref_results

    async def _validate_subpaths_stage(
        self,
        subpath_refs_to_validate: list[tuple[str, str]],
        use_github_api: bool,
    ) -> tuple[dict[tuple[str, str], bool], set[tuple[str, str]]]:
        """Validate action subpaths, returning results and inconclusive keys.

        Inconclusive subpaths (e.g. a transient Git fetch failure on an
        already-valid ref) are given the benefit of the doubt for the
        current run's surfaced result but must NOT be cached, so a
        transient failure cannot persist as a false VALID that masks a
        bogus subpath; the next run re-checks them instead.
        """
        subpath_results: dict[tuple[str, str], bool] = {}
        inconclusive_subpaths: set[tuple[str, str]] = set()
        if not subpath_refs_to_validate:
            return subpath_results, inconclusive_subpaths
        self.logger.debug(
            f"Validating {len(subpath_refs_to_validate)} subdirectory "
            f"action subpaths (after cache)"
        )
        try:
            if use_github_api:
                assert self._github_client is not None
                subpath_results = (
                    await self._github_client.validate_subpaths_batch(
                        subpath_refs_to_validate
                    )
                )
                self._merge_api_stats(self._github_client.get_api_stats())
            else:
                assert self._git_client is not None
                git_subpath_results = (
                    await self._git_client.validate_subpaths_batch(
                        subpath_refs_to_validate
                    )
                )
                # Classify into three states. A definitive INVALID_PATH
                # marks the subpath bogus; VALID marks it present; any
                # other (e.g. NETWORK_ERROR/TIMEOUT) is inconclusive --
                # given the benefit of the doubt for this run but recorded
                # so it is excluded from caching.
                for key, result in git_subpath_results.items():
                    if result == ValidationResult.INVALID_PATH:
                        subpath_results[key] = False
                    elif result == ValidationResult.VALID:
                        subpath_results[key] = True
                    else:
                        subpath_results[key] = True
                        inconclusive_subpaths.add(key)
        except Exception as e:
            self._abort_validation("subpath", use_github_api, e)
        return subpath_results, inconclusive_subpaths

    def _log_stage_stats(self, stage: str, use_github_api: bool) -> None:
        """Emit a debug line summarising API-call counts after a stage."""
        method_stats = "GraphQL" if use_github_api else "Git"
        backend_calls = (
            self.api_stats.graphql_calls
            if use_github_api
            else self.api_stats.git_calls
        )
        self.logger.debug(
            f"{stage} validation complete. API calls so far: "
            f"{self.api_stats.total_calls} ({method_stats}: {backend_calls}, "
            f"Cache hits: {self.api_stats.cache_hits})"
        )

    def _extract_repository_for_validation(
        self, action_call: ActionCall
    ) -> str:
        """
        Extract the repository name for validation purposes.

        For reusable workflows, the repository field contains the full path like:
        'releng-reusable-workflows/.github/workflows/workflow.yaml'

        For validation, we need just the repository part:
        'releng-reusable-workflows'

        Args:
            action_call: The action call to extract repository from

        Returns:
            Repository name suitable for validation
        """
        from .models import ActionCallType

        if action_call.call_type == ActionCallType.WORKFLOW:
            # For workflows, extract just the repository part before /.github/workflows/
            repo_path = action_call.repository
            if "/.github/workflows/" in repo_path:
                return repo_path.split("/.github/workflows/")[0]
            else:
                # Fallback: use the full path as repository name
                return repo_path
        else:
            # For regular actions, use the repository as-is
            return action_call.repository

    def _extract_workflow_path(self, action_call: ActionCall) -> str | None:
        """
        Extract the workflow file path for validation.

        Args:
            action_call: The action call to extract workflow path from

        Returns:
            Workflow file path if this is a workflow call, None otherwise
        """
        from .models import ActionCallType

        if action_call.call_type == ActionCallType.WORKFLOW:
            repo_path = action_call.repository
            if "/.github/workflows/" in repo_path:
                return repo_path.split("/.github/workflows/", 1)[1]
        return None

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
        subpath_results: dict[tuple[str, str], bool] | None = None,
    ) -> dict[str, ValidationResult]:
        """
        Combine repository, reference and subpath validation results.

        Args:
            unique_calls: Dictionary of unique action calls
            repo_results: Repository validation results
            ref_results: Reference validation results
            subpath_results: Subdirectory-action subpath validation results,
                keyed by ``(repo_key, ref)``. Entries are present only for
                subdirectory actions; a missing entry is treated as valid.

        Returns:
            Dictionary mapping call keys to validation results
        """
        subpath_results = subpath_results or {}
        validation_results = {}

        for call_key, action_call in unique_calls.items():
            repo_for_validation = self._extract_repository_for_validation(
                action_call
            )
            repo_key = f"{action_call.organization}/{repo_for_validation}"

            if not repo_results.get(repo_key, False):
                validation_results[call_key] = (
                    ValidationResult.INVALID_REPOSITORY
                )
                continue

            ref_key = (repo_key, action_call.reference)
            if not ref_results.get(ref_key, False):
                validation_results[call_key] = (
                    ValidationResult.INVALID_REFERENCE
                )
                continue

            # Check subdirectory subpath validity (subdir actions only)
            if has_action_subpath(repo_key) and not subpath_results.get(
                ref_key, True
            ):
                validation_results[call_key] = ValidationResult.INVALID_PATH
                continue

            # Repository, reference and subpath are all valid
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
            ValidationResult.INVALID_PATH: "Subdirectory action path not found at reference",
            ValidationResult.INVALID_SYNTAX: "Invalid action call syntax",
            ValidationResult.NETWORK_ERROR: "Network error during validation",
            ValidationResult.TIMEOUT: "Timeout during validation",
            ValidationResult.NOT_PINNED_TO_SHA: "Action not pinned to commit SHA",
            ValidationResult.TEST_REFERENCE: "Test action reference",
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
            "invalid_paths": 0,
            "syntax_errors": 0,
            "network_errors": 0,
            "timeouts": 0,
            "test_references": 0,
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
            # Check if this is a test reference for any error type
            if has_test_comment(error.action_call):
                summary["test_references"] += 1
            elif error.result == ValidationResult.INVALID_REPOSITORY:
                summary["invalid_repositories"] += 1
            elif error.result == ValidationResult.INVALID_REFERENCE:
                summary["invalid_references"] += 1
            elif error.result == ValidationResult.INVALID_PATH:
                summary["invalid_paths"] += 1
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
        return self.api_stats.model_copy()
