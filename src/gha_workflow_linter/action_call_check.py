# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Validator for GitHub Actions calls using GraphQL API or Git operations with comprehensive tracking."""

from __future__ import annotations

import asyncio
from collections import defaultdict
import dataclasses
import logging
from typing import TYPE_CHECKING, Any, NoReturn

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from rich.progress import Progress, TaskID

from .action_call_git import GitValidationClient
from .action_call_report import (
    ReferenceFinding,
    build_validation_errors,
    cache_verdict,
    client_peels,
    get_error_message,
    merge_cached_findings,
    peel_findings,
    specific_ref_result,
)
from .cache import ValidationCache
from .exceptions import (
    AuthenticationError,
    GitHubAPIError,
    GitInconclusiveError,
    GitUnreachableError,
    NetworkError,
    RateLimitError,
    TemporaryAPIError,
    ValidationAbortedError,
)
from .github_api import GitHubGraphQLClient
from .github_auth import get_github_token_with_fallback
from .models import (
    ActionCall,
    APICallStats,
    Category,
    Config,
    ValidationError,
    ValidationMethod,
    ValidationResult,
    result_category,
)
from .paths import has_action_subpath
from .utils import has_test_comment


@dataclasses.dataclass(frozen=True)
class _StageResults:
    """Combined output of the repository, reference and subpath stages.

    Attributes:
        repo_results: Whether each repository exists.
        ref_results: Whether each ``(repo, ref)`` pair resolves.
        ref_findings: Specific verdicts and remediation context for refs
            that did not resolve cleanly.
        subpath_results: Whether each subdirectory action path exists.
        inconclusive_subpaths: Subpath checks that failed transiently and
            so must not be cached as a verdict.
    """

    repo_results: dict[str, bool]
    ref_results: dict[tuple[str, str], bool]
    ref_findings: dict[tuple[str, str], ReferenceFinding]
    subpath_results: dict[tuple[str, str], bool]
    inconclusive_subpaths: set[tuple[str, str]]


def _abort_if_unreachable(
    results: Mapping[Any, ValidationResult],
    cause: GitInconclusiveError | None = None,
) -> None:
    """Stop the run when the Git backend established nothing.

    The caller reduces each result to ``result == VALID``, which is the
    right shape for a verdict but destroys the difference between "the
    remote said no" and "no answer was obtained". Flattened, a lost
    connection became ``INVALID_REPOSITORY`` -- the linter telling the
    user their workflow was wrong because the network was.

    Raising here matches what the API backend already does, and yields
    the same observable: the run fails, and reports no findings, because
    it established none.

    The kind of ``cause`` is carried into the error raised, since a
    ``NETWORK_ERROR`` result has no room for a reason and the advice
    given to the user turns on it.

    Args:
        results: What the Git backend reported.
        cause: The failure behind those results, where the backend
            kept one.

    Raises:
        GitInconclusiveError: If any result reports a failure to
            establish anything.
    """
    unreachable = [
        str(key)
        for key, result in results.items()
        if result is ValidationResult.NETWORK_ERROR
    ]
    if not unreachable:
        return
    summary = (
        f"Could not complete {len(unreachable)} of "
        f"{len(results)} lookups: {', '.join(sorted(unreachable)[:3])}"
    )
    if cause is None:
        raise GitUnreachableError(summary)
    raise type(cause)(summary, cause)


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
        # Refreshed on context entry; see ``_own_cache_hits``.
        self._cache_hits_at_start = self._cache.stats.hits
        self._validation_method: ValidationMethod | None = None

    async def __aenter__(self) -> ActionCallValidator:
        """Async context manager entry."""
        # The cache's hit counter is cumulative, and a multi-repository
        # sweep shares one cache across every repository. Taking the
        # baseline here rather than at construction means each context
        # reports the hits *it* caused: a validator entered twice does
        # not count the first pass again, and hits made through the
        # shared cache before this one began are not claimed.
        self._cache_hits_at_start = self._cache.stats.hits

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

        # Merge cache stats into API stats. Counted as a delta, since a
        # shared cache carries the hits of every repository visited
        # before this one. This is the only place the tally is merged.
        self.api_stats.cache_hits += self._own_cache_hits
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

        stages = await self._run_validation_stages(
            repos_to_validate,
            refs_to_validate,
            cached_results,
            progress,
            task_id,
            use_github_api,
        )

        cache_entries_to_store = self._build_cache_entries(
            refs_to_validate,
            stages.inconclusive_subpaths,
            stages.repo_results,
            stages.ref_results,
            stages.subpath_results,
            use_github_api,
            stages.ref_findings,
        )
        if cache_entries_to_store:
            self._cache.put_batch(cache_entries_to_store)

        all_repo_results, all_ref_results, all_subpath_results = (
            self._merge_all_results(
                stages.repo_results,
                stages.ref_results,
                stages.subpath_results,
                cached_results,
            )
        )

        validation_results = self._combine_validation_results(
            unique_calls,
            all_repo_results,
            all_ref_results,
            all_subpath_results,
            stages.ref_findings,
        )

        errors = build_validation_errors(
            validation_results,
            call_locations,
            unique_calls,
            self._ref_key,
            self.config.require_pinned_sha,
            stages.ref_findings,
        )

        self.logger.debug(
            f"Validation complete: {len(errors)} errors out of "
            f"{total_calls} calls ({unique_count} unique calls validated)"
        )

        self._log_final_statistics(use_github_api)
        self._finalize_progress(progress, task_id)

        return errors

    async def _run_validation_stages(
        self,
        repos_to_validate: set[str],
        refs_to_validate: list[tuple[str, str]],
        cached_results: dict[tuple[str, str], Any],
        progress: Progress | None,
        task_id: TaskID | None,
        use_github_api: bool,
    ) -> _StageResults:
        """Run the repository, reference and subpath validation stages.

        Each stage narrows the work for the next: only references whose
        repository resolved are looked up, and only subdirectory actions
        whose reference resolved have their path checked.

        Args:
            repos_to_validate: Repositories not satisfied from cache
            refs_to_validate: ``(repo, ref)`` pairs not satisfied from cache
            cached_results: Previously cached entries, merged back in
            progress: Optional progress bar
            task_id: Optional task ID for progress updates
            use_github_api: Whether to use the GitHub API or Git operations

        Returns:
            The combined results of all three stages.
        """
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
        ref_results, ref_findings = await self._validate_references_stage(
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
        merge_cached_findings(ref_findings, cached_results)
        self._advance_progress(
            progress,
            task_id,
            len(repos_to_validate) + len(valid_repo_refs_to_validate),
            "Processing validation results...",
        )

        return _StageResults(
            repo_results=repo_results,
            ref_results=ref_results,
            ref_findings=ref_findings,
            subpath_results=subpath_results,
            inconclusive_subpaths=inconclusive_subpaths,
        )

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
        ref_findings: dict[tuple[str, str], ReferenceFinding] | None = None,
    ) -> list[
        tuple[str, str, ValidationResult, str, ValidationMethod, str | None]
    ]:
        """Build the cache entries to persist for freshly validated refs.

        Args:
            refs_to_validate: The ``(repo, ref)`` pairs validated this run.
            inconclusive_subpaths: Pairs whose subpath check was
                inconclusive and so must not be cached.
            repo_results: Repository verdicts.
            ref_results: Reference verdicts.
            subpath_results: Subpath verdicts.
            use_github_api: Whether the API backend produced the results.
            ref_findings: Specific reference failures. A definite verdict
                such as ``ANNOTATED_TAG_SHA`` is cached with its rendered
                remediation message; an infrastructure failure (network,
                timeout) is skipped so the next run retries it instead of
                inheriting a false ``INVALID_REFERENCE``.

        Returns:
            List of cache-entry tuples to hand to ``ValidationCache``.
        """
        api_call_type = "graphql" if use_github_api else "git"
        findings = ref_findings or {}
        cache_entries: list[
            tuple[str, str, ValidationResult, str, ValidationMethod, str | None]
        ] = []
        for repo, ref in refs_to_validate:
            # Skip caching entries whose subpath check was inconclusive so a
            # transient failure is retried next run rather than persisted as a
            # (benefit-of-the-doubt) VALID.
            if (repo, ref) in inconclusive_subpaths:
                continue

            finding = findings.get((repo, ref))
            # Never persist a verdict the check could not actually reach.
            if (
                finding is not None
                and result_category(finding.result) is Category.INFRASTRUCTURE
            ):
                continue

            repo_valid = repo_results.get(repo, False)
            ref_valid = ref_results.get((repo, ref), False)
            # Subpath is considered valid unless we explicitly determined it is
            # bogus. Entries without a subpath never populate subpath_results.
            subpath_valid = subpath_results.get((repo, ref), True)

            result, error_message = cache_verdict(
                repo,
                ref,
                finding,
                repo_valid=repo_valid,
                ref_valid=ref_valid,
                subpath_valid=subpath_valid,
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

    @property
    def _own_cache_hits(self) -> int:
        """Cache hits this validator is responsible for.

        The cache's counter is cumulative and a multi-repository sweep
        shares one cache, so the raw value credits this validator with
        every hit since the sweep began. The baseline is taken on
        context entry, so each pass reports only its own.

        Returns:
            Hits recorded since this validator's context was entered.
        """
        return self._cache.stats.hits - self._cache_hits_at_start

    def _log_final_statistics(self, use_github_api: bool) -> None:
        """Emit end-of-run API/Git statistics at debug level.

        Reads the cache tally rather than merging it. The merge belongs
        to ``__aexit__``, and performing it here as well counted every
        hit twice on the Git path.

        Args:
            use_github_api: Whether the GitHub API backend was used.
        """
        # What __aexit__ will add, shown here so the debug line agrees
        # with the final statistics without altering them.
        cache_hits = self.api_stats.cache_hits + self._own_cache_hits

        if use_github_api and self._github_client:
            rate_limit_info = self._github_client.get_rate_limit_info()
            self.logger.debug(
                f"API Statistics: {self.api_stats.total_calls} total calls "
                f"(GraphQL: {self.api_stats.graphql_calls}, "
                f"REST: {self.api_stats.rest_calls}, "
                f"Cache hits: {cache_hits})"
            )
            self.logger.debug(
                f"GitHub Rate Limit: {rate_limit_info.remaining}/{rate_limit_info.limit} remaining"
            )
        else:
            self.logger.debug(
                f"Git Statistics: {self.api_stats.total_calls} total calls "
                f"(Git: {self.api_stats.git_calls}, "
                f"Clone ops: {self.api_stats.git_clone_operations}, "
                f"ls-remote ops: {self.api_stats.git_ls_remote_operations}, "
                f"Cache hits: {cache_hits})"
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
        GitInconclusiveError,
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
                _abort_if_unreachable(
                    git_repo_results, self._git_client.inconclusive_cause
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
    ) -> tuple[
        dict[tuple[str, str], bool],
        dict[tuple[str, str], ReferenceFinding],
    ]:
        """Validate a batch of references for already-valid repositories.

        Args:
            valid_repo_refs_to_validate: ``(repo_key, ref)`` pairs whose
                repository already validated.
            use_github_api: Whether to use the API or the Git backend.

        Returns:
            Tuple of (results, findings): results is the pass/fail verdict
            per pair, and findings carries the specific reason for each
            failure (plus any remediation context) so a caller can report
            something better than a generic invalid reference.
        """
        ref_results: dict[tuple[str, str], bool] = {}
        ref_findings: dict[tuple[str, str], ReferenceFinding] = {}
        if not valid_repo_refs_to_validate:
            return ref_results, ref_findings
        try:
            if use_github_api:
                assert self._github_client is not None
                ref_results = (
                    await self._github_client.validate_references_batch(
                        valid_repo_refs_to_validate
                    )
                )
                # The API backend reports a bare boolean; a recorded peel
                # is what distinguishes a tag-object SHA from a reference
                # that simply does not exist.
                ref_findings = peel_findings(
                    ref_results, client_peels(self._github_client)
                )
                self._merge_api_stats(self._github_client.get_api_stats())
            else:
                assert self._git_client is not None
                git_ref_results = (
                    await self._git_client.validate_references_batch(
                        valid_repo_refs_to_validate
                    )
                )
                _abort_if_unreachable(
                    git_ref_results, self._git_client.inconclusive_cause
                )
                ref_results = {
                    repo_ref: result == ValidationResult.VALID
                    for repo_ref, result in git_ref_results.items()
                }
                peels = client_peels(self._git_client)
                ref_findings = {
                    repo_ref: ReferenceFinding(
                        result=result, peel=peels.get(repo_ref)
                    )
                    for repo_ref, result in git_ref_results.items()
                    if result != ValidationResult.VALID
                }
            self._log_stage_stats("Reference", use_github_api)
        except Exception as e:
            self._abort_validation("reference", use_github_api, e)
        return ref_results, ref_findings

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

    def _ref_key(self, action_call: ActionCall) -> tuple[str, str]:
        """Return the ``(repo_key, reference)`` a call is validated under.

        Args:
            action_call: The call whose reference key is wanted.

        Returns:
            The key used throughout the validation stages for this call.
        """
        repo_for_validation = self._extract_repository_for_validation(
            action_call
        )
        return (
            f"{action_call.organization}/{repo_for_validation}",
            action_call.reference,
        )

    def _combine_validation_results(
        self,
        unique_calls: dict[str, ActionCall],
        repo_results: dict[str, bool],
        ref_results: dict[tuple[str, str], bool],
        subpath_results: dict[tuple[str, str], bool] | None = None,
        ref_findings: dict[tuple[str, str], ReferenceFinding] | None = None,
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
            ref_findings: Specific reference failures keyed by
                ``(repo_key, ref)``. Consulted when a reference failed, so
                a tag-object SHA is reported as ``ANNOTATED_TAG_SHA``
                rather than as a generic ``INVALID_REFERENCE``.

        Returns:
            Dictionary mapping call keys to validation results
        """
        subpath_results = subpath_results or {}
        findings = ref_findings or {}
        validation_results = {}

        for call_key, action_call in unique_calls.items():
            ref_key = self._ref_key(action_call)
            repo_key = ref_key[0]

            if not repo_results.get(repo_key, False):
                validation_results[call_key] = (
                    ValidationResult.INVALID_REPOSITORY
                )
                continue

            if not ref_results.get(ref_key, False):
                validation_results[call_key] = specific_ref_result(
                    findings.get(ref_key)
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

    def _get_error_message(
        self,
        result: ValidationResult,
        finding: ReferenceFinding | None = None,
    ) -> str:
        """Get human-readable error message for validation result.

        Thin delegation to
        :func:`gha_workflow_linter.action_call_report.get_error_message`,
        kept as a method because callers already reach for it here.

        Args:
            result: ValidationResult enum value.
            finding: Optional context for a reference-level failure.

        Returns:
            Error message string.
        """
        return get_error_message(result, finding)

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
            "annotated_tag_shas": 0,
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
            elif error.result == ValidationResult.ANNOTATED_TAG_SHA:
                summary["annotated_tag_shas"] += 1

        return summary

    def get_api_stats(self) -> APICallStats:
        """Get current API call statistics."""
        return self.api_stats.model_copy()
