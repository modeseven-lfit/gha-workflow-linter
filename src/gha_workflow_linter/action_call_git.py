# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Git-based validation for GitHub Actions without requiring API tokens."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import logging
import os
import re
from types import MappingProxyType
from typing import TYPE_CHECKING

from .exceptions import (
    GitError,
    GitInconclusiveError,
    GitUnreachableError,
    GitUnusableError,
)
from .git_refs import (
    AnnotatedTagPeel,
    get_remote_ref_shas,
    git_environment,
    git_invocation_failure,
    is_transport_failure,
    ls_remote_failure,
    was_killed_by_signal,
)
from .git_subpath import _validate_repository_subpaths
from .models import APICallStats, GitConfig, ReferenceType, ValidationResult
from .paths import base_repository as _shared_base_repository

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

logger = logging.getLogger(__name__)


def _base_repository(repository: str) -> str:
    """Return the ``owner/repo`` base, stripping any action subpath.

    Thin wrapper around :func:`gha_workflow_linter.paths.base_repository` so
    the Git validation path shares a single definition of how subdirectory
    action identifiers are split. Kept as an explicit module-level function so
    it remains an importable symbol for callers and tests.

    Args:
        repository: Repository identifier, possibly including a subpath.

    Returns:
        The ``owner/repo`` portion when a subpath is present, otherwise the
        input unchanged.
    """
    return _shared_base_repository(repository)


class GitValidationClient:
    """Client for validating GitHub Actions using Git operations."""

    def __init__(self, config: GitConfig) -> None:
        """
        Initialize the Git validation client.

        Args:
            config: Git configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.api_stats = APICallStats()
        self._annotated_tag_peels: dict[tuple[str, str], AnnotatedTagPeel] = {}
        self._inconclusive: GitInconclusiveError | None = None

        # Determine optimal worker count
        if config.max_parallel_operations:
            self._max_workers = config.max_parallel_operations
        else:
            # Use CPU count, but cap at reasonable limits
            cpu_count = os.cpu_count() or 4
            self._max_workers = min(max(cpu_count, 4), 16)

        self.logger.debug(
            f"Git client initialized with {self._max_workers} max workers"
        )

    @property
    def inconclusive_cause(self) -> GitInconclusiveError | None:
        """Why a lookup produced no answer, if one did not.

        Batch results are ``ValidationResult`` values, which carry no
        room for a reason, so the failure behind a ``NETWORK_ERROR`` is
        otherwise lost by the time anything can act on it. Keeping it
        here lets the run be reported for what it was: advising someone
        with no ``git`` to check their DNS would send them looking in
        the wrong place.

        Returns:
            The most recent inconclusive failure, or ``None`` if every
            lookup was answered.
        """
        return self._inconclusive

    def _record_inconclusive(self, error: Exception) -> None:
        """Remember a failure that produced no answer.

        Args:
            error: What a worker raised.
        """
        if isinstance(error, GitInconclusiveError):
            self._inconclusive = error

    @property
    def annotated_tag_peels(
        self,
    ) -> Mapping[tuple[str, str], AnnotatedTagPeel]:
        """Annotated tag peels discovered while validating references.

        ``validate_references_batch`` already runs ``git ls-remote``, which
        advertises both the tag object and the commit it peels to, so the
        remediation for an ``ANNOTATED_TAG_SHA`` verdict is recorded as a
        side effect of that batch rather than costing a second network
        round trip. Entries accumulate over the client's lifetime.

        Returns:
            Read-only mapping of ``(repository, reference)`` to the peel
            behind that reference. Only references reported as
            ``ANNOTATED_TAG_SHA`` are present.
        """
        return MappingProxyType(self._annotated_tag_peels)

    async def validate_repositories_batch(
        self, repositories: list[str]
    ) -> dict[str, ValidationResult]:
        """
        Validate that repositories exist and are accessible.

        Args:
            repositories: List of repository names (org/repo format)

        Returns:
            Dictionary mapping repository names to validation results
        """
        if not repositories:
            return {}

        self.logger.debug(
            f"Validating {len(repositories)} repositories using Git"
        )

        # Run the blocking Git operations in a thread pool. The work is
        # I/O-bound (it shells out to ``git``), so threads avoid the per-call
        # process-pool startup cost and the multiprocessing start-method
        # differences across platforms / Python versions (e.g. Python 3.14
        # defaulting to ``forkserver`` on Linux).
        loop = asyncio.get_running_loop()

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            # Submit all validation tasks
            futures = [
                loop.run_in_executor(
                    executor, _validate_repository_exists, repo, self.config
                )
                for repo in repositories
            ]

            # Wait for all results
            try:
                validation_results = await asyncio.gather(
                    *futures, return_exceptions=True
                )
            except Exception as e:
                self.logger.error(
                    f"Unexpected error in repository validation: {e}"
                )
                validation_results = [ValidationResult.NETWORK_ERROR] * len(
                    repositories
                )

            results = {}
            for repo, result in zip(
                repositories, validation_results, strict=True
            ):
                if isinstance(result, Exception):
                    self.logger.warning(
                        f"Failed to validate repository {repo}: {result}"
                    )
                    self._record_inconclusive(result)
                    results[repo] = ValidationResult.NETWORK_ERROR
                    self.api_stats.increment_failed_call()
                elif isinstance(result, ValidationResult):
                    results[repo] = result
                    self.api_stats.repositories_validated += 1
                    self.api_stats.git_ls_remote_operations += 1
                    self.api_stats.increment_git()
                else:
                    # This shouldn't happen, but handle it gracefully
                    self.logger.warning(
                        f"Unexpected result type for repository {repo}: {type(result)}"
                    )
                    results[repo] = ValidationResult.NETWORK_ERROR
                    self.api_stats.increment_failed_call()

        self.logger.debug(
            f"Repository validation complete: {len(results)} results"
        )
        return results

    async def validate_references_batch(
        self, repo_refs: list[tuple[str, str]]
    ) -> dict[tuple[str, str], ValidationResult]:
        """
        Validate Git references (branches, tags, commit SHAs) for repositories.

        Args:
            repo_refs: List of (repository, reference) tuples

        Returns:
            Dictionary mapping (repository, reference) tuples to validation results

        Side effects:
            Records any annotated tag peels discovered by the underlying
            ``ls-remote`` calls; see :attr:`annotated_tag_peels`.
        """
        if not repo_refs:
            return {}

        self.logger.debug(f"Validating {len(repo_refs)} references using Git")

        # Group references by repository to optimize Git operations
        repo_to_refs: dict[str, list[str]] = {}
        for repo, ref in repo_refs:
            if repo not in repo_to_refs:
                repo_to_refs[repo] = []
            repo_to_refs[repo].append(ref)

        loop = asyncio.get_running_loop()
        results = {}

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            # Submit validation tasks grouped by repository
            futures = []
            repo_ref_list = []

            for repo, refs in repo_to_refs.items():
                future = loop.run_in_executor(
                    executor,
                    _validate_repository_references,
                    repo,
                    refs,
                    self.config,
                )
                futures.append(future)
                repo_ref_list.append((repo, refs))

            # Wait for all results
            try:
                validation_results = await asyncio.gather(
                    *futures, return_exceptions=True
                )
            except Exception as e:
                self.logger.error(
                    f"Unexpected error in reference validation: {e}"
                )
                validation_results = [({}, {})] * len(futures)

            for (repo, refs), repo_results in zip(
                repo_ref_list, validation_results, strict=True
            ):
                if isinstance(repo_results, Exception):
                    self.logger.warning(
                        f"Failed to validate references for {repo}: {repo_results}"
                    )
                    self._record_inconclusive(repo_results)
                    # Mark all references for this repo as having network errors
                    for ref in refs:
                        results[(repo, ref)] = ValidationResult.NETWORK_ERROR
                        self.api_stats.increment_failed_call()
                elif isinstance(repo_results, tuple):
                    # Map results back to the expected format
                    ref_results, peels = repo_results
                    for ref in refs:
                        results[(repo, ref)] = ref_results.get(
                            ref, ValidationResult.INVALID_REFERENCE
                        )
                        peel = peels.get(ref)
                        if peel is not None:
                            self._annotated_tag_peels[(repo, ref)] = peel
                        self.api_stats.increment_git()

                    self.api_stats.git_clone_operations += 1
                else:
                    # This shouldn't happen, but handle it gracefully
                    self.logger.warning(
                        f"Unexpected result type for repository {repo}: {type(repo_results)}"
                    )
                    for ref in refs:
                        results[(repo, ref)] = ValidationResult.NETWORK_ERROR
                        self.api_stats.increment_failed_call()

        self.logger.debug(
            f"Reference validation complete: {len(results)} results"
        )
        return results

    async def validate_subpaths_batch(
        self, subpath_refs: list[tuple[str, str]]
    ) -> dict[tuple[str, str], ValidationResult]:
        """
        Validate subdirectory-action subpaths exist at their referenced ref.

        Each entry is a ``(repo_key, ref)`` tuple where ``repo_key`` is a full
        action identifier that includes a subdirectory subpath
        (``owner/repo/path``). The base repository and ref are assumed to have
        already been validated; this method only confirms that ``path`` exists
        in the repository tree at ``ref``.

        ``ls-remote`` cannot inspect trees, so a blobless partial fetch of
        the ref is performed (``--filter=blob:none``) followed by
        ``git ls-tree`` of the candidate paths. This heavier path runs *only*
        for subdirectory actions; plain ``owner/repo`` calls never reach here
        and keep their lightweight ``ls-remote`` flow.

        Args:
            subpath_refs: List of ``(repo_key, ref)`` tuples, where each
                ``repo_key`` includes a subdirectory subpath.

        Returns:
            Dictionary mapping ``(repo_key, ref)`` to a ``ValidationResult``:

            * ``VALID`` -- the subpath exists at the ref.
            * ``INVALID_PATH`` -- the ref was inspected cleanly and the
              subpath is absent (a definitively bogus path).
            * ``NETWORK_ERROR`` -- the check was inconclusive (e.g. a
              transient partial-fetch / ``ls-tree`` failure, or a
              gather-level error). Callers treat this as benefit-of-the-doubt
              for the current run but must not cache it.
        """
        if not subpath_refs:
            return {}

        self.logger.debug(
            f"Validating {len(subpath_refs)} subdirectory action subpaths "
            f"using Git"
        )

        # Group entries by base repository so each repo is fetched once.
        repo_to_entries: dict[str, list[tuple[str, str]]] = {}
        for repo_key, ref in subpath_refs:
            base = _base_repository(repo_key)
            repo_to_entries.setdefault(base, []).append((repo_key, ref))

        loop = asyncio.get_running_loop()
        results: dict[tuple[str, str], ValidationResult] = {}

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = []
            entry_groups: list[list[tuple[str, str]]] = []
            for base, entries in repo_to_entries.items():
                futures.append(
                    loop.run_in_executor(
                        executor,
                        _validate_repository_subpaths,
                        base,
                        entries,
                        self.config,
                    )
                )
                entry_groups.append(entries)

            try:
                group_results = await asyncio.gather(
                    *futures, return_exceptions=True
                )
            except Exception as e:
                self.logger.error(
                    f"Unexpected error in subpath validation: {e}"
                )
                # Propagate the exception per group so the isinstance branch
                # below maps it to NETWORK_ERROR (inconclusive). Substituting
                # empty dicts here would instead be read as INVALID_PATH and
                # misclassify an internal failure as a bogus subpath.
                group_results = [e] * len(futures)

            for entries, group_result in zip(
                entry_groups, group_results, strict=True
            ):
                if isinstance(group_result, Exception):
                    self.logger.warning(
                        f"Failed to validate subpaths: {group_result}"
                    )
                    for entry in entries:
                        results[entry] = ValidationResult.NETWORK_ERROR
                        self.api_stats.increment_failed_call()
                elif isinstance(group_result, dict):
                    for entry in entries:
                        if entry in group_result:
                            results[entry] = group_result[entry]
                            self.api_stats.increment_git()
                        else:
                            # A missing per-entry result means the worker
                            # returned a partial dict (an internal/edge-case
                            # failure), not a definitive absence. Treat it as
                            # inconclusive so it is not cached or reported as a
                            # bogus INVALID_PATH.
                            results[entry] = ValidationResult.NETWORK_ERROR
                            self.api_stats.increment_failed_call()
                    self.api_stats.git_clone_operations += 1
                else:
                    for entry in entries:
                        results[entry] = ValidationResult.NETWORK_ERROR
                        self.api_stats.increment_failed_call()

        self.logger.debug(
            f"Subpath validation complete: {len(results)} results"
        )
        return results

    def get_api_stats(self) -> APICallStats:
        """Get API call statistics."""
        return self.api_stats


def _validate_repository_exists(
    repository: str, config: GitConfig
) -> ValidationResult:
    """
    Validate that a repository exists and is accessible via Git.

    This function runs in a worker thread.

    Args:
        repository: Repository name (org/repo format)
        config: Git configuration

    Returns:
        ValidationResult indicating if repository exists

    Raises:
        GitError: If no attempt reached the remote. The caller maps that
            to ``NETWORK_ERROR``; returning ``INVALID_REPOSITORY``
            instead would report a network problem as a finding about
            the repository.
    """
    # Try both HTTPS and SSH URLs
    # Strip any action subpath (e.g. anchore/scan-action/download-grype)
    # so the URL targets the real owner/repo remote.
    base_repo = _base_repository(repository)
    https_url = f"https://github.com/{base_repo}.git"
    ssh_url = f"git@github.com:{base_repo}.git"

    answered = False
    unreachable: GitInconclusiveError | None = None

    # Try HTTPS first (more likely to work without auth for public repos)
    for url in [https_url, ssh_url]:
        try:
            if _run_git_ls_remote(url, config):
                return ValidationResult.VALID
            # The remote answered, and its answer was no.
            answered = True
        except GitInconclusiveError as error:
            unreachable = error
        except Exception:  # noqa: BLE001 - try the next URL format
            continue

    if not answered and unreachable is not None:
        # Nothing reached the remote, so nothing was learned about the
        # repository. One definitive "not found" from either URL is
        # enough to outrank this.
        raise unreachable

    return ValidationResult.INVALID_REPOSITORY


def _validate_repository_references(
    repository: str, references: list[str], config: GitConfig
) -> tuple[dict[str, ValidationResult], dict[str, AnnotatedTagPeel]]:
    """
    Validate multiple references for a single repository.

    This function runs in a worker thread.

    Args:
        repository: Repository name (org/repo format)
        references: List of Git references to validate
        config: Git configuration

    Returns:
        Tuple of (results, peels): results maps each reference to its
        validation result, and peels maps each reference reported as
        ``ANNOTATED_TAG_SHA`` to the tag and commit behind it.

    Raises:
        GitError: If no attempt reached the remote. The caller maps that
            to ``NETWORK_ERROR`` for every reference; filling them in as
            ``INVALID_REFERENCE`` instead would report a network problem
            as findings about the workflow.
    """
    results: dict[str, ValidationResult] = {}
    peels: dict[str, AnnotatedTagPeel] = {}

    # Try both HTTPS and SSH URLs
    # Strip any action subpath (e.g. anchore/scan-action/download-grype)
    # so the URL targets the real owner/repo remote.
    base_repo = _base_repository(repository)
    https_url = f"https://github.com/{base_repo}.git"
    ssh_url = f"git@github.com:{base_repo}.git"

    # Group references by type for optimization
    commit_shas = []
    branches = []
    tags = []
    unknown_refs = []

    for ref in references:
        ref_type = _determine_reference_type(ref)
        if ref_type == ReferenceType.COMMIT_SHA:
            commit_shas.append(ref)
        elif ref_type == ReferenceType.BRANCH:
            branches.append(ref)
        elif ref_type == ReferenceType.TAG:
            tags.append(ref)
        else:
            unknown_refs.append(ref)

    # Try HTTPS first, then SSH
    reached = False
    unreachable: GitInconclusiveError | None = None
    for url in [https_url, ssh_url]:
        try:
            if commit_shas:
                sha_results, sha_peels = _validate_commit_shas_with_peels(
                    url, commit_shas, config
                )
                _keep_the_better_answer(results, peels, sha_results, sha_peels)

            if branches:
                branch_results = _validate_branches_git(url, branches, config)
                _keep_the_better_answer(results, peels, branch_results)

            if tags:
                tag_results = _validate_tags_git(url, tags, config)
                _keep_the_better_answer(results, peels, tag_results)

            if unknown_refs:
                unknown_results = _validate_unknown_refs_git(
                    url, unknown_refs, config
                )
                _keep_the_better_answer(results, peels, unknown_results)

            # If we got here without errors, we're done
            reached = True
            break

        except GitInconclusiveError as e:
            logger.debug(f"Could not reach {url} for {repository}: {e}")
            unreachable = e
            continue  # Try next URL format
        except Exception as e:  # noqa: BLE001 - try the next URL format
            logger.debug(
                f"Failed to validate references for {repository} with {url}: {e}"
            )
            reached = True
            continue

    if not reached and unreachable is not None:
        # Nothing reached the remote, so nothing was learned about these
        # references. Reporting them as invalid would blame the workflow
        # for a network problem.
        raise unreachable

    # Fill in any missing results as invalid
    for ref in references:
        if ref not in results:
            results[ref] = ValidationResult.INVALID_REFERENCE

    return results, peels


def _upgrades(known: ValidationResult, found: ValidationResult) -> bool:
    """Whether a later answer improves on one already established.

    Only one direction counts: a reference an earlier attempt could not
    find, that a later one did. Two positive classifications are not
    interchangeable -- ``VALID`` and ``ANNOTATED_TAG_SHA`` disagree
    about whether the workflow is correct -- so a retry may not swap one
    for the other in either direction. Allowing it would let an SSH
    fallback erase an annotated-tag finding that HTTPS had established,
    which passes a workflow that is wrong.

    Args:
        known: What an earlier attempt established.
        found: What this attempt says.

    Returns:
        ``True`` when the later answer should replace the earlier one.
    """
    return (
        known is ValidationResult.INVALID_REFERENCE
        and found is not ValidationResult.INVALID_REFERENCE
    )


def _keep_the_better_answer(
    results: dict[str, ValidationResult],
    peels: dict[str, AnnotatedTagPeel],
    found: dict[str, ValidationResult],
    found_peels: dict[str, AnnotatedTagPeel] | None = None,
) -> None:
    """Fold one attempt's answers into what earlier attempts established.

    The retry exists to fill gaps left by an attempt that could not
    finish, not to revise the answers it did get. Overwriting them turns
    a working HTTPS lookup into a finding whenever the SSH fallback has
    no key: the SHA lookup succeeds, a later branch lookup fails, and
    the retry then reports every reference the first attempt had proved
    as ``INVALID_REFERENCE``.

    Existence is not symmetric, though, so a later answer that *finds* a
    reference does outrank an earlier one that did not. A remote which
    finds it has settled the question; one which does not may simply be
    seeing less. That is the only revision allowed -- see
    :func:`_upgrades`.

    Args:
        results: What is known so far, updated in place.
        peels: Tag peels known so far, kept in step with ``results``.
        found: What this attempt established.
        found_peels: Tag peels from this attempt, where it produced any.
    """
    for ref, result in found.items():
        known = results.get(ref)
        if known is not None and not _upgrades(known, result):
            continue
        results[ref] = result
        peel = (found_peels or {}).get(ref)
        if peel is None:
            peels.pop(ref, None)
        else:
            peels[ref] = peel


def _run_git_ls_remote(url: str, config: GitConfig) -> bool:
    """
    Run git ls-remote to check if repository is accessible.

    Args:
        url: Git repository URL
        config: Git configuration

    Returns:
        True if repository exists and is accessible

    Raises:
        GitError: If git could not reach the remote, so its answer says
            nothing about whether the repository exists.
    """
    import subprocess

    cmd = ["git", "ls-remote", "--heads", "--tags", url]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout_seconds,
            env=git_environment(),
            check=False,
        )

        if result.returncode == 0:
            return True

        if was_killed_by_signal(result.returncode):
            raise GitUnusableError(
                f"Git ls-remote was killed before it could ask {url}"
            )

        if is_transport_failure(result.stderr):
            raise GitUnreachableError(
                f"Git ls-remote could not reach {url}: {result.stderr.strip()}"
            )

        # The remote answered and said no.
        return False

    except subprocess.TimeoutExpired:
        raise GitUnreachableError(
            f"Git ls-remote timed out for {url}"
        ) from None
    except GitError:
        raise
    except Exception as e:
        raise git_invocation_failure(
            f"Git ls-remote failed for {url}", e
        ) from e


def _validate_commit_shas_git(
    url: str, commit_shas: list[str], config: GitConfig
) -> dict[str, ValidationResult]:
    """
    Validate commit SHAs by checking if they exist in remote refs.

    A SHA that names an annotated *tag object* rather than a commit is
    reported as ``ANNOTATED_TAG_SHA``: ``git ls-remote`` advertises it, but
    GitHub Actions cannot check it out, so treating it as valid is a false
    pass. Use :func:`_validate_commit_shas_with_peels` when the commit SHA
    to recommend in its place is needed too.

    Args:
        url: Git repository URL
        commit_shas: List of commit SHAs to validate
        config: Git configuration

    Returns:
        Dictionary mapping commit SHAs to validation results
    """
    return _validate_commit_shas_with_peels(url, commit_shas, config)[0]


def _validate_commit_shas_with_peels(
    url: str, commit_shas: list[str], config: GitConfig
) -> tuple[dict[str, ValidationResult], dict[str, AnnotatedTagPeel]]:
    """
    Validate commit SHAs, keeping the peel behind any tag-object SHA.

    The single ``ls-remote`` this performs already carries the peeled
    commit for every annotated tag, so the remediation for an
    ``ANNOTATED_TAG_SHA`` verdict is returned alongside the verdict rather
    than re-fetched later.

    Args:
        url: Git repository URL
        commit_shas: List of commit SHAs to validate
        config: Git configuration

    Returns:
        Tuple of (results, peels): results maps each SHA to its validation
        result, and peels maps each tag-object SHA to the tag name and
        commit SHA behind it.
    """
    results = {}
    peels: dict[str, AnnotatedTagPeel] = {}

    try:
        # Get all remote refs (heads and tags), keeping annotated tag
        # objects distinguishable from the commits they peel to.
        remote_refs = get_remote_ref_shas(url, config)

        for sha in commit_shas:
            peel = remote_refs.tag_objects.get(sha)
            if peel is not None:
                results[sha] = ValidationResult.ANNOTATED_TAG_SHA
                peels[sha] = peel
            elif sha in remote_refs.commit_shas:
                results[sha] = ValidationResult.VALID
            else:
                results[sha] = ValidationResult.INVALID_REFERENCE

    except GitInconclusiveError:
        # Nothing was learned about these references, so reporting them
        # as invalid would blame the workflow for a broken network.
        raise
    except Exception as e:
        logger.debug(f"Failed to validate commit SHAs for {url}: {e}")
        # Mark all SHAs as invalid
        for sha in commit_shas:
            results[sha] = ValidationResult.INVALID_REFERENCE
        peels.clear()

    return results, peels


def _validate_branches_git(
    url: str, branches: list[str], config: GitConfig
) -> dict[str, ValidationResult]:
    """
    Validate branches using git ls-remote.

    Args:
        url: Git repository URL
        branches: List of branch names to validate
        config: Git configuration

    Returns:
        Dictionary mapping branch names to validation results
    """
    results = {}

    try:
        remote_branches = _get_remote_branches(url, config)

        for branch in branches:
            if branch in remote_branches:
                results[branch] = ValidationResult.VALID
            else:
                results[branch] = ValidationResult.INVALID_REFERENCE

    except GitInconclusiveError:
        # Nothing was learned about these references, so reporting them
        # as invalid would blame the workflow for a broken network.
        raise
    except Exception as e:
        logger.debug(f"Failed to validate branches for {url}: {e}")
        # Mark all branches as invalid
        for branch in branches:
            results[branch] = ValidationResult.INVALID_REFERENCE

    return results


def _validate_tags_git(
    url: str, tags: list[str], config: GitConfig
) -> dict[str, ValidationResult]:
    """
    Validate tags using git ls-remote.

    Args:
        url: Git repository URL
        tags: List of tag names to validate
        config: Git configuration

    Returns:
        Dictionary mapping tag names to validation results
    """
    results = {}

    try:
        remote_tags = _get_remote_tags(url, config)

        for tag in tags:
            if tag in remote_tags:
                results[tag] = ValidationResult.VALID
            else:
                results[tag] = ValidationResult.INVALID_REFERENCE

    except GitInconclusiveError:
        # Nothing was learned about these references, so reporting them
        # as invalid would blame the workflow for a broken network.
        raise
    except Exception as e:
        logger.debug(f"Failed to validate tags for {url}: {e}")
        # Mark all tags as invalid
        for tag in tags:
            results[tag] = ValidationResult.INVALID_REFERENCE

    return results


def _validate_unknown_refs_git(
    url: str, refs: list[str], config: GitConfig
) -> dict[str, ValidationResult]:
    """
    Validate references of unknown type using comprehensive approach.

    Args:
        url: Git repository URL
        refs: List of references to validate
        config: Git configuration

    Returns:
        Dictionary mapping references to validation results
    """
    results = {}

    try:
        # Get all remote references (branches and tags)
        remote_branches = _get_remote_branches(url, config)
        remote_tags = _get_remote_tags(url, config)

        for ref in refs:
            if ref in remote_branches or ref in remote_tags:
                results[ref] = ValidationResult.VALID
            else:
                # For unknown refs, try to validate as commit SHA
                try:
                    sha_results = _validate_commit_shas_git(url, [ref], config)
                    results[ref] = sha_results.get(
                        ref, ValidationResult.INVALID_REFERENCE
                    )
                except GitInconclusiveError:
                    # The enumeration above reached the remote, but this
                    # lookup did not, so the ref is unresolved rather
                    # than absent. Left to the fallback below, it would
                    # be reported as a finding on the strength of a
                    # question that was never answered.
                    raise
                except Exception:
                    results[ref] = ValidationResult.INVALID_REFERENCE

    except GitInconclusiveError:
        # Nothing was learned about these references, so reporting them
        # as invalid would blame the workflow for a broken network.
        raise
    except Exception as e:
        logger.debug(f"Failed to validate unknown refs for {url}: {e}")
        # Mark all refs as invalid
        for ref in refs:
            results[ref] = ValidationResult.INVALID_REFERENCE

    return results


def _run_git_clone(
    url: str, target_path: Path, config: GitConfig, depth: int = 1
) -> None:
    """
    Clone a Git repository.

    Args:
        url: Git repository URL
        target_path: Path to clone repository to
        config: Git configuration
        depth: Clone depth for shallow clones

    Raises:
        GitError: If clone operation fails
    """
    import subprocess

    cmd = [
        "git",
        "clone",
        "--depth",
        str(depth),
        "--no-checkout",  # Don't checkout working files
        "--quiet",
        url,
        str(target_path),
    ]

    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout_seconds,
            env=git_environment(),
            check=True,
        )

    except subprocess.TimeoutExpired:
        raise GitUnreachableError(f"Git clone timed out for {url}") from None
    except subprocess.CalledProcessError as e:
        raise ls_remote_failure(
            f"Git clone failed for {url}", e.stderr, e
        ) from e
    except Exception as e:
        raise git_invocation_failure(f"Git clone failed for {url}", e) from e


def _commit_exists_in_repo(
    repo_path: Path, commit_sha: str, config: GitConfig
) -> bool:
    """
    Check if a commit SHA exists in the cloned repository.

    Args:
        repo_path: Path to cloned repository
        commit_sha: Commit SHA to check
        config: Git configuration

    Returns:
        True if commit exists, False otherwise
    """
    import subprocess

    cmd = ["git", "-C", str(repo_path), "cat-file", "-e", commit_sha]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout_seconds,
            env=git_environment(),
            check=False,
        )

        return result.returncode == 0

    except Exception:
        return False


def _get_remote_branches(url: str, config: GitConfig) -> set[str]:
    """
    Get all remote branch names.

    Args:
        url: Git repository URL
        config: Git configuration

    Returns:
        Set of branch names

    Raises:
        GitError: If operation fails
    """
    import subprocess

    cmd = ["git", "ls-remote", "--heads", url]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout_seconds,
            env=git_environment(),
            check=True,
        )

        branches = set()
        for line in result.stdout.strip().split("\n"):
            if line:
                # Format: "commit_sha\trefs/heads/branch_name"
                parts = line.split("\t")
                if len(parts) == 2 and parts[1].startswith("refs/heads/"):
                    branch_name = parts[1].replace("refs/heads/", "")
                    branches.add(branch_name)

        return branches

    except subprocess.TimeoutExpired:
        raise GitUnreachableError(
            f"Git ls-remote timed out for {url}"
        ) from None
    except subprocess.CalledProcessError as e:
        raise ls_remote_failure(
            f"Git ls-remote failed for {url}", e.stderr, e
        ) from e
    except Exception as e:
        raise git_invocation_failure(
            f"Git ls-remote failed for {url}", e
        ) from e


def _get_remote_tags(url: str, config: GitConfig) -> set[str]:
    """
    Get all remote tag names.

    Args:
        url: Git repository URL
        config: Git configuration

    Returns:
        Set of tag names

    Raises:
        GitError: If operation fails
    """
    import subprocess

    cmd = ["git", "ls-remote", "--tags", url]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout_seconds,
            env=git_environment(),
            check=True,
        )

        tags = set()
        for line in result.stdout.strip().split("\n"):
            if line:
                # Line format: "commit_sha\trefs/tags/tag_name" or "commit_sha\trefs/tags/tag_name^{}"
                parts = line.split("\t")
                if len(parts) == 2 and parts[1].startswith("refs/tags/"):
                    tag_ref = parts[1][len("refs/tags/") :]
                    # Remove ^{} suffix for annotated tags
                    if tag_ref.endswith("^{}"):
                        tag_ref = tag_ref[:-3]
                    tags.add(tag_ref)

        return tags

    except subprocess.TimeoutExpired:
        raise GitUnreachableError(
            f"Git ls-remote (tags) timed out for {url}"
        ) from None
    except subprocess.CalledProcessError as e:
        raise ls_remote_failure(
            f"Git ls-remote (tags) failed for {url}", e.stderr, e
        ) from e
    except Exception as e:
        raise git_invocation_failure(
            f"Git ls-remote (tags) failed for {url}", e
        ) from e


def _determine_reference_type(reference: str) -> ReferenceType:
    """
    Determine the type of a Git reference.

    Args:
        reference: Git reference string

    Returns:
        ReferenceType enum value
    """
    # Check if it looks like a commit SHA (40 hex characters or shorter for partial SHAs)
    if re.match(r"^[a-fA-F0-9]{7,40}$", reference):
        return ReferenceType.COMMIT_SHA

    # Check for common tag patterns (starting with 'v' followed by version)
    if re.match(r"^v\d+(\.\d+)*", reference):
        return ReferenceType.TAG

    if any(
        pattern in reference.lower()
        for pattern in ["release", "stable", "alpha", "beta", "rc"]
    ):
        return ReferenceType.TAG

    # Default to branch for everything else
    return ReferenceType.BRANCH
