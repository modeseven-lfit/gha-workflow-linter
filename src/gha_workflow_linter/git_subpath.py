# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Checking that an action's subdirectory exists at the ref it names.

Every other check here is answerable by asking the remote what it has:
``git ls-remote`` names repositories and references without fetching
anything. A subpath is not, because it is a property of the *tree* at a
ref rather than of the ref itself, so this is the one concern that needs
objects on disk -- a throwaway repository, a partial fetch, and
``ls-tree``. It lives apart for that reason.
"""

from __future__ import annotations

import logging
import tempfile
from typing import TYPE_CHECKING

from .exceptions import GitError
from .git_refs import git_environment
from .models import GitConfig, ValidationResult
from .paths import action_subpath, action_subpath_candidates

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


def _validate_repository_subpaths(
    base_repository_key: str,
    entries: list[tuple[str, str]],
    config: GitConfig,
) -> dict[tuple[str, str], ValidationResult]:
    """
    Validate that subdirectory subpaths exist at their referenced ref.

    Runs in a worker thread. Performs one partial (``--filter=blob:none``)
    shallow fetch per unique ref into a throwaway repository, then checks the
    candidate paths with ``git ls-tree``. ``blob:none`` keeps file *contents*
    off the wire while still downloading the tree objects ``ls-tree`` needs, so
    the path-existence check works entirely offline after the fetch.

    Args:
        base_repository_key: ``owner/repo`` base (no subpath).
        entries: List of ``(repo_key, ref)`` tuples sharing this base repo,
            where each ``repo_key`` includes a subdirectory subpath.
        config: Git configuration.

    Returns:
        Dictionary mapping ``(repo_key, ref)`` to a ``ValidationResult``
        (``VALID``, ``INVALID_PATH`` or ``NETWORK_ERROR``).
    """
    import pathlib

    results: dict[tuple[str, str], ValidationResult] = {}

    https_url = f"https://github.com/{base_repository_key}.git"
    ssh_url = f"git@github.com:{base_repository_key}.git"

    # Group entries by ref so each ref is fetched only once.
    ref_to_repo_keys: dict[str, list[str]] = {}
    for repo_key, ref in entries:
        ref_to_repo_keys.setdefault(ref, []).append(repo_key)

    with tempfile.TemporaryDirectory(prefix="gha-subpath-") as tmpdir:
        repo_dir = pathlib.Path(tmpdir)
        if not _run_git_init(repo_dir, config):
            for repo_key, ref in entries:
                results[(repo_key, ref)] = ValidationResult.NETWORK_ERROR
            return results

        for ref, repo_keys in ref_to_repo_keys.items():
            fetched = False
            for url in (https_url, ssh_url):
                if _run_git_fetch_partial(repo_dir, url, ref, config):
                    fetched = True
                    break

            for repo_key in repo_keys:
                entry = (repo_key, ref)
                if not fetched:
                    # The ref was already validated to exist, so a fetch
                    # failure here is treated as a transient/network problem
                    # rather than a bogus subpath.
                    results[entry] = ValidationResult.NETWORK_ERROR
                    continue

                subpath = action_subpath(repo_key)
                if subpath is None:
                    results[entry] = ValidationResult.VALID
                    continue

                try:
                    exists = _run_git_subpath_exists(
                        repo_dir, "FETCH_HEAD", subpath, config
                    )
                except GitError as e:
                    # The ls-tree check could not be completed (a local or
                    # transient Git failure, distinct from the subpath being
                    # absent). Treat as inconclusive so the caller does not
                    # report or cache it as a bogus path.
                    logger.debug(
                        f"Inconclusive subpath check for {repo_key}@{ref}: {e}"
                    )
                    results[entry] = ValidationResult.NETWORK_ERROR
                    continue

                results[entry] = (
                    ValidationResult.VALID
                    if exists
                    else ValidationResult.INVALID_PATH
                )

    return results


def _run_git_init(repo_dir: Path, config: GitConfig) -> bool:
    """Initialise an empty Git repository for partial fetches.

    Args:
        repo_dir: Directory in which to initialise the repository.
        config: Git configuration.

    Returns:
        True if initialisation succeeded, False otherwise.
    """
    import subprocess

    cmd = ["git", "init", "--quiet", str(repo_dir)]
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


def _run_git_fetch_partial(
    repo_dir: Path, url: str, ref: str, config: GitConfig
) -> bool:
    """Shallow, blobless fetch of a single ref into ``repo_dir``.

    ``--filter=blob:none`` omits file contents while still fetching the tree
    objects required to enumerate paths. ``--depth=1`` keeps history minimal.
    Fetching by branch, tag, or (server permitting) commit SHA all resolve to
    ``FETCH_HEAD``.

    Args:
        repo_dir: Initialised repository directory.
        url: Git remote URL for the base ``owner/repo``.
        ref: The branch, tag, or commit SHA to fetch.
        config: Git configuration.

    Returns:
        True if the fetch succeeded, False otherwise.
    """
    import subprocess

    cmd = [
        "git",
        "-C",
        str(repo_dir),
        "-c",
        "protocol.version=2",
        "fetch",
        "--depth=1",
        "--filter=blob:none",
        "--no-tags",
        "--quiet",
        # End option parsing so a ref beginning with "-" (REF_PATTERN allows
        # it) cannot be misread by git as an option (argument injection).
        "--",
        url,
        ref,
    ]
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
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False


def _run_git_subpath_exists(
    repo_dir: Path, treeish: str, subpath: str, config: GitConfig
) -> bool:
    """Check whether a subdirectory action path exists at ``treeish``.

    Probes the candidate paths from :func:`action_subpath_candidates` (the
    action metadata files first, then the directory itself) in a single
    ``git ls-tree`` call. Non-empty output means at least one candidate exists.

    A definitive absence (``ls-tree`` succeeds with no matching entry) is
    distinguished from a failure to run the check at all (non-zero exit,
    timeout, or other error). The former returns ``False``; the latter raises
    ``GitError`` so callers can treat it as inconclusive rather than a bogus
    path.

    Args:
        repo_dir: Repository directory containing the fetched objects.
        treeish: Tree-ish to inspect (typically ``FETCH_HEAD``).
        subpath: The subdirectory path to verify.
        config: Git configuration.

    Returns:
        True if the subpath exists at the ref, False if it is definitively
        absent.

    Raises:
        GitError: If the ``ls-tree`` check could not be completed.
    """
    import subprocess

    candidates = action_subpath_candidates(subpath)
    cmd = [
        "git",
        "-C",
        str(repo_dir),
        "ls-tree",
        treeish,
        "--",
        *candidates,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout_seconds,
            env=git_environment(),
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise GitError(
            f"Git ls-tree timed out for {treeish} in {repo_dir}"
        ) from None
    except Exception as e:
        raise GitError(
            f"Git ls-tree failed for {treeish} in {repo_dir}: {e}"
        ) from e

    if result.returncode != 0:
        # A non-zero exit means the command itself failed (e.g. a missing
        # object or a local Git problem), which is distinct from the subpath
        # being absent. Surface it as inconclusive rather than bogus.
        raise GitError(
            f"Git ls-tree failed (exit {result.returncode}) for {treeish} "
            f"in {repo_dir}: {result.stderr.strip()}"
        )

    # Exit 0: the subpath exists iff ls-tree listed a matching entry.
    return bool(result.stdout.strip())
