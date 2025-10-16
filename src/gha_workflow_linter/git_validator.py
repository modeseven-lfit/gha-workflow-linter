# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Git-based validation for GitHub Actions without requiring API tokens."""

from __future__ import annotations

import asyncio
import logging
import multiprocessing
import os
import re
import shutil
import tempfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .exceptions import (
    GitError,
    NetworkError,
    RepositoryNotFoundError,
    ReferenceNotFoundError,
)
from .models import APICallStats, GitConfig, ReferenceType, ValidationResult


logger = logging.getLogger(__name__)


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

        # Determine optimal worker count
        if config.max_parallel_operations:
            self._max_workers = config.max_parallel_operations
        else:
            # Use CPU count, but cap at reasonable limits
            cpu_count = multiprocessing.cpu_count()
            self._max_workers = min(max(cpu_count, 4), 16)

        self.logger.debug(
            f"Git client initialized with {self._max_workers} max workers"
        )

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

        # Use asyncio to run the multiprocessing validation
        loop = asyncio.get_event_loop()

        with ProcessPoolExecutor(max_workers=self._max_workers) as executor:
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

            # Process results
            results = {}
            for repo, result in zip(repositories, validation_results):
                if isinstance(result, Exception):
                    self.logger.warning(
                        f"Failed to validate repository {repo}: {result}"
                    )
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

        loop = asyncio.get_event_loop()
        results = {}

        with ProcessPoolExecutor(max_workers=self._max_workers) as executor:
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
                validation_results = [{}] * len(futures)

            # Process results
            for (repo, refs), repo_results in zip(
                repo_ref_list, validation_results
            ):
                if isinstance(repo_results, Exception):
                    self.logger.warning(
                        f"Failed to validate references for {repo}: {repo_results}"
                    )
                    # Mark all references for this repo as having network errors
                    for ref in refs:
                        results[(repo, ref)] = ValidationResult.NETWORK_ERROR
                        self.api_stats.increment_failed_call()
                elif isinstance(repo_results, dict):
                    # Map results back to the expected format
                    for ref in refs:
                        results[(repo, ref)] = repo_results.get(
                            ref, ValidationResult.INVALID_REFERENCE
                        )
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

    def get_api_stats(self) -> APICallStats:
        """Get API call statistics."""
        return self.api_stats


def _validate_repository_exists(
    repository: str, config: GitConfig
) -> ValidationResult:
    """
    Validate that a repository exists and is accessible via Git.

    This function runs in a separate process.

    Args:
        repository: Repository name (org/repo format)
        config: Git configuration

    Returns:
        ValidationResult indicating if repository exists
    """
    # Try both HTTPS and SSH URLs
    https_url = f"https://github.com/{repository}.git"
    ssh_url = f"git@github.com:{repository}.git"

    # Try HTTPS first (more likely to work without auth for public repos)
    for url in [https_url, ssh_url]:
        try:
            result = _run_git_ls_remote(url, config)
            if result:
                return ValidationResult.VALID
        except Exception:
            continue  # Try next URL format

    return ValidationResult.INVALID_REPOSITORY


def _validate_repository_references(
    repository: str, references: list[str], config: GitConfig
) -> dict[str, ValidationResult]:
    """
    Validate multiple references for a single repository.

    This function runs in a separate process.

    Args:
        repository: Repository name (org/repo format)
        references: List of Git references to validate
        config: Git configuration

    Returns:
        Dictionary mapping references to validation results
    """
    results = {}

    # Try both HTTPS and SSH URLs
    https_url = f"https://github.com/{repository}.git"
    ssh_url = f"git@github.com:{repository}.git"

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
    for url in [https_url, ssh_url]:
        try:
            # Validate different reference types with optimized approaches
            if commit_shas:
                sha_results = _validate_commit_shas_git(
                    url, commit_shas, config
                )
                results.update(sha_results)

            if branches:
                branch_results = _validate_branches_git(url, branches, config)
                results.update(branch_results)

            if tags:
                tag_results = _validate_tags_git(url, tags, config)
                results.update(tag_results)

            if unknown_refs:
                unknown_results = _validate_unknown_refs_git(
                    url, unknown_refs, config
                )
                results.update(unknown_results)

            # If we got here without errors, we're done
            break

        except Exception as e:
            logger.debug(
                f"Failed to validate references for {repository} with {url}: {e}"
            )
            continue  # Try next URL format

    # Fill in any missing results as invalid
    for ref in references:
        if ref not in results:
            results[ref] = ValidationResult.INVALID_REFERENCE

    return results


def _run_git_ls_remote(url: str, config: GitConfig) -> bool:
    """
    Run git ls-remote to check if repository is accessible.

    Args:
        url: Git repository URL
        config: Git configuration

    Returns:
        True if repository is accessible, False otherwise

    Raises:
        GitError: If git command fails
    """
    import subprocess

    cmd = ["git", "ls-remote", "--heads", "--tags", url]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout_seconds,
            check=False,
        )

        # Return True if command succeeded (exit code 0)
        return result.returncode == 0

    except subprocess.TimeoutExpired:
        raise GitError(f"Git ls-remote timed out for {url}")
    except Exception as e:
        raise GitError(f"Git ls-remote failed for {url}: {e}")


def _validate_commit_shas_git(
    url: str, commit_shas: list[str], config: GitConfig
) -> dict[str, ValidationResult]:
    """
    Validate commit SHAs by checking if they exist in remote refs.

    Args:
        url: Git repository URL
        commit_shas: List of commit SHAs to validate
        config: Git configuration

    Returns:
        Dictionary mapping commit SHAs to validation results
    """
    results = {}

    try:
        # Get all remote refs (heads and tags) to find commit SHAs
        remote_refs = _get_all_remote_refs(url, config)

        for sha in commit_shas:
            if sha in remote_refs:
                results[sha] = ValidationResult.VALID
            else:
                results[sha] = ValidationResult.INVALID_REFERENCE

    except Exception as e:
        logger.debug(f"Failed to validate commit SHAs for {url}: {e}")
        # Mark all SHAs as invalid
        for sha in commit_shas:
            results[sha] = ValidationResult.INVALID_REFERENCE

    return results


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
        # Get all remote branches
        remote_branches = _get_remote_branches(url, config)

        for branch in branches:
            if branch in remote_branches:
                results[branch] = ValidationResult.VALID
            else:
                results[branch] = ValidationResult.INVALID_REFERENCE

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
        # Get all remote tags
        remote_tags = _get_remote_tags(url, config)

        for tag in tags:
            if tag in remote_tags:
                results[tag] = ValidationResult.VALID
            else:
                results[tag] = ValidationResult.INVALID_REFERENCE

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
                except Exception:
                    results[ref] = ValidationResult.INVALID_REFERENCE

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
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout_seconds,
            check=True,
        )

    except subprocess.TimeoutExpired:
        raise GitError(f"Git clone timed out for {url}")
    except subprocess.CalledProcessError as e:
        raise GitError(f"Git clone failed for {url}: {e.stderr}")
    except Exception as e:
        raise GitError(f"Git clone failed for {url}: {e}")


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
            check=False,
        )

        return result.returncode == 0

    except Exception:
        return False


def _get_all_remote_refs(url: str, config: GitConfig) -> set[str]:
    """
    Get all commit SHAs from remote refs (heads and tags).

    Args:
        url: Git repository URL
        config: Git configuration

    Returns:
        Set of commit SHAs

    Raises:
        GitError: If operation fails
    """
    import subprocess

    cmd = ["git", "ls-remote", "--heads", "--tags", url]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout_seconds,
            check=True,
        )

        shas = set()
        for line in result.stdout.strip().split("\n"):
            if line:
                # Format: "commit_sha\tref_name"
                parts = line.split("\t")
                if len(parts) == 2:
                    commit_sha = parts[0]
                    shas.add(commit_sha)

        return shas

    except subprocess.TimeoutExpired:
        raise GitError(f"Git ls-remote timed out for {url}")
    except subprocess.CalledProcessError as e:
        raise GitError(f"Git ls-remote failed for {url}: {e.stderr}")
    except Exception as e:
        raise GitError(f"Git ls-remote failed for {url}: {e}")


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
        raise GitError(f"Git ls-remote timed out for {url}")
    except subprocess.CalledProcessError as e:
        raise GitError(f"Git ls-remote failed for {url}: {e.stderr}")
    except Exception as e:
        raise GitError(f"Git ls-remote failed for {url}: {e}")


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
        raise GitError(f"Git ls-remote (tags) timed out for {url}")
    except subprocess.CalledProcessError as e:
        raise GitError(f"Git ls-remote (tags) failed for {url}: {e.stderr}")
    except Exception as e:
        raise GitError(f"Git ls-remote (tags) failed for {url}: {e}")


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

    # Check for other tag patterns
    if any(
        pattern in reference.lower()
        for pattern in ["release", "stable", "alpha", "beta", "rc"]
    ):
        return ReferenceType.TAG

    # Default to branch for everything else
    return ReferenceType.BRANCH
