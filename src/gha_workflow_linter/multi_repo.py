# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Discovery of the repositories a multi-repository run should visit.

Scanning stops at repository boundaries (see
:meth:`gha_workflow_linter.scanner.WorkflowScanner._crosses_repository_boundary`),
so pointing the linter at a directory that merely *contains* repositories
finds nothing: every child is a boundary. That is the correct behaviour
for a single run, and this module is the sanctioned way to cover many --
each repository is visited as its own root, so its workflow organisation,
its Dependabot cooldown and its findings all belong to it.

Discovery is deliberately separate from the run itself, so a caller that
already knows which repositories it wants -- a scheduled workflow using a
matrix of one-repository checkouts, for instance -- can skip it without
duplicating anything.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

logger = logging.getLogger(__name__)

#: How far below the given root to look when none is specified. One level
#: matches the usual layout of a directory of checkouts.
DEFAULT_DEPTH = 1

#: Directory names never worth descending into. Discovery stops at
#: repository boundaries anyway, so this only saves walking large trees
#: that cannot contain a sibling checkout. These names suppress descent
#: alone: a checkout genuinely called ``venv`` is still recognised,
#: because the repository test runs first.
_SKIP_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "node_modules",
        "venv",
    }
)

__all__ = [
    "DEFAULT_DEPTH",
    "find_repositories",
    "is_repository",
]


def is_repository(path: Path) -> bool:
    """Report whether a directory is the root of a Git repository.

    A plain clone carries a ``.git`` directory; a worktree or submodule
    carries a ``.git`` file pointing elsewhere. Both count, so a
    directory of worktrees is as valid a target as a directory of
    clones.

    Args:
        path: Directory to test.

    Returns:
        True when the directory contains a ``.git`` entry.
    """
    try:
        return (path / ".git").exists()
    except OSError:
        # An unreadable directory is not a repository we can visit.
        return False


def find_repositories(root: Path, *, depth: int = DEFAULT_DEPTH) -> list[Path]:
    """Find the repositories to visit beneath a container directory.

    The search stops descending as soon as it finds a repository, so a
    checkout keeping worktrees under ``.worktrees/`` yields the checkout
    itself rather than the checkout and each of its worktrees. Results
    are sorted, so a run's output order does not depend on the
    filesystem.

    Args:
        root: Directory holding the repositories.
        depth: How many levels below ``root`` to search. ``0`` considers
            only ``root`` itself.

    Returns:
        Repository roots, sorted by path. Empty when none is found.

    Raises:
        ValueError: If ``depth`` is negative.
        OSError: If ``root`` itself cannot be listed. A descendant that
            cannot be read is skipped with a warning, since the rest of
            the sweep is still worth doing -- but an unreadable *root*
            means nothing was examined at all, and returning an empty
            list would make that indistinguishable from a container
            holding no repositories.
    """
    if depth < 0:
        raise ValueError(f"depth must not be negative, got {depth}")

    # The root being a repository is unambiguous: visit it and nothing
    # else, so `--multi-repo` inside a checkout does something sensible
    # rather than nothing.
    if is_repository(root):
        logger.debug(f"{root} is itself a repository")
        return [root]

    # Listed strictly, and the result reused: a root that cannot be read
    # raises rather than yielding the same empty list as a root with
    # nothing in it. Listing it a second time through the tolerant
    # ``_children`` would reopen exactly that ambiguity if the root
    # became unreadable in between.
    found: list[Path] = []
    _visit(_list_subdirectories(root), depth, found, {}, set())
    found.sort()

    logger.debug(f"Found {len(found)} repositories under {root}")
    return found


def _descend(
    directory: Path,
    remaining: int,
    found: list[Path],
    explored: dict[Path, int],
    reported: set[Path],
) -> None:
    """Collect repositories below a directory, depth-first.

    Args:
        directory: Directory to search.
        remaining: Levels still permitted below this one.
        found: Accumulator, appended to in place.
        explored: Largest budget each identity has been searched with,
            updated in place.
        reported: Identities already recorded in ``found``, updated in
            place.
    """
    if remaining <= 0:
        return
    _visit(_children(directory), remaining, found, explored, reported)


def _visit(
    children: Iterable[Path],
    remaining: int,
    found: list[Path],
    explored: dict[Path, int],
    reported: set[Path],
) -> None:
    """Examine one directory's children.

    Split from :func:`_descend` so the root can be traversed from a
    listing obtained strictly, rather than being listed a second time by
    the tolerant path.

    Directory identity is tracked by resolved path, because both the
    directory test and the ``.git`` probe follow symbolic links. Without
    it, a container holding a checkout *and* a link to it yields the same
    repository twice -- and a sweep would scan, and under remediation
    rewrite, one working tree once per name it goes by -- while a link
    pointing back into the tree being searched recurses until the depth
    runs out.

    Identity alone is not enough, though. A directory first reached
    through a deep symbolic link arrives with little budget left, and
    marking it visited would then hide it from a later, shallower route
    that could still afford to explore it. So the *budget* each identity
    was explored with is recorded, and a larger one supersedes it.
    Budgets strictly decrease and an identity is re-entered only with a
    strictly larger one, so this terminates.

    Repositories are reported once per identity, by the first path that
    reaches them, so the output still names what the caller asked about.

    Args:
        children: Subdirectories to examine, in order.
        remaining: Levels still permitted at this depth.
        found: Accumulator, appended to in place.
        explored: Largest budget each identity has been searched with,
            updated in place.
        reported: Identities already recorded in ``found``, updated in
            place.
    """
    if remaining <= 0:
        return

    for child in children:
        identity = _identity(child)

        # Test for a repository before consulting the skip list, so a
        # checkout whose name happens to collide with a build directory
        # is still visited. The skip list exists to avoid walking large
        # trees, not to disqualify a repository.
        if is_repository(child):
            if identity in reported:
                logger.debug(f"Skipping {child}: already found as {identity}")
                continue
            reported.add(identity)
            found.append(child)
            # Do not descend into a repository: its worktrees and
            # submodules belong to it, and visiting them separately
            # would report the same findings several times over.
            continue
        if child.name in _SKIP_DIRECTORIES:
            continue

        budget = remaining - 1
        if explored.get(identity, -1) >= budget:
            continue
        explored[identity] = budget
        _descend(child, budget, found, explored, reported)


def _identity(path: Path) -> Path:
    """Reduce a path to something two names for one directory share.

    Args:
        path: Path to identify.

    Returns:
        The resolved path, or the original when it cannot be resolved.
    """
    try:
        return path.resolve()
    except OSError:
        # A path that cannot be resolved is its own identity; it will
        # fail the repository test anyway.
        return path


def _children(directory: Path) -> Iterable[Path]:
    """List a directory's subdirectories, tolerating an unreadable one.

    Sorted, so traversal order does not depend on the filesystem. That
    matters beyond tidiness: which of several names for one directory is
    reported depends on which is reached first.

    Args:
        directory: Directory to list.

    Returns:
        Its subdirectories in name order, or nothing when it cannot be
        read.
    """
    try:
        return _list_subdirectories(directory)
    except OSError as error:
        logger.warning(f"Cannot read {directory}: {error}")
        return []


def _list_subdirectories(directory: Path) -> list[Path]:
    """List a directory's subdirectories, or raise.

    The strict counterpart of :func:`_children`, used where an
    unreadable directory must not pass for an empty one.

    Args:
        directory: Directory to list.

    Returns:
        Its subdirectories in name order.

    Raises:
        OSError: If the directory cannot be read.
    """
    return sorted(child for child in directory.iterdir() if child.is_dir())
