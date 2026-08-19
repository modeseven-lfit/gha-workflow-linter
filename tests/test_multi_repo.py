# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for repository discovery in multi-repository mode.

Discovery decides which trees a sweep visits, so every one of its rules
is a behaviour a user can observe: a directory of checkouts is expanded,
a checkout is not expanded into its own worktrees, and the visit order
is the same on every machine. Those rules are cheap to state and easy to
break silently -- a stray descent into ``.worktrees/`` reports the same
findings several times over, and an unsorted result makes a sweep's
output differ run to run -- so they are pinned here rather than left to
the integration tests.

Repositories are built by creating a ``.git`` entry directly rather than
by shelling out to ``git``. Discovery only ever asks whether that entry
exists, so a real clone would buy nothing and cost the suite a
subprocess and a dependency on the host's git.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING
from unittest import mock

import pytest

from gha_workflow_linter import multi_repo
from gha_workflow_linter.multi_repo import (
    DEFAULT_DEPTH,
    find_repositories,
    is_repository,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


def make_clone(path: Path) -> Path:
    """Create a directory that looks like a plain clone.

    Args:
        path: Directory to create; parents are created as needed.

    Returns:
        The same path, now carrying a ``.git`` directory.
    """
    (path / ".git").mkdir(parents=True)
    return path


def make_worktree(
    path: Path, *, points_at: str = "../.git/worktrees/x"
) -> Path:
    """Create a directory that looks like a worktree or submodule.

    Git marks these with a ``.git`` *file* holding a ``gitdir:`` pointer
    rather than a directory, which is exactly the case a naive
    ``is_dir()`` check would miss.

    Args:
        path: Directory to create; parents are created as needed.
        points_at: Value written after the ``gitdir:`` prefix.

    Returns:
        The same path, now carrying a ``.git`` file.
    """
    path.mkdir(parents=True, exist_ok=True)
    (path / ".git").write_text(f"gitdir: {points_at}\n", encoding="utf-8")
    return path


class TestIsRepository:
    """What counts as a repository root."""

    def test_clone_is_a_repository(self, tmp_path: Path) -> None:
        """A ``.git`` directory marks a plain clone."""
        assert is_repository(make_clone(tmp_path / "clone")) is True

    def test_worktree_file_is_a_repository(self, tmp_path: Path) -> None:
        """A ``.git`` file marks a worktree or submodule."""
        assert is_repository(make_worktree(tmp_path / "worktree")) is True

    def test_plain_directory_is_not_a_repository(self, tmp_path: Path) -> None:
        """A directory with no ``.git`` entry is not a repository."""
        plain = tmp_path / "plain"
        plain.mkdir()

        assert is_repository(plain) is False

    def test_missing_directory_is_not_a_repository(
        self, tmp_path: Path
    ) -> None:
        """A path that does not exist is not a repository."""
        assert is_repository(tmp_path / "absent") is False

    def test_unreadable_directory_is_not_a_repository(
        self, tmp_path: Path
    ) -> None:
        """A directory we cannot stat is reported as 'not a repository'.

        Raising here would abort a sweep because one checkout in twenty
        had awkward permissions, so the error is swallowed instead.
        """
        with mock.patch.object(
            Path, "exists", side_effect=PermissionError("denied")
        ):
            assert is_repository(tmp_path) is False


class TestFindRepositoriesRoot:
    """How the root directory itself is treated."""

    def test_root_that_is_a_repository_yields_only_itself(
        self, tmp_path: Path
    ) -> None:
        """``--multi-repo`` inside a checkout visits that checkout.

        The child repository is deliberately *not* visited: the root
        being a repository is unambiguous, and expanding it as a
        container as well would scan the same tree twice.
        """
        root = make_clone(tmp_path / "checkout")
        make_clone(root / "vendored")

        assert find_repositories(root) == [root]

    def test_root_that_is_a_repository_ignores_depth(
        self, tmp_path: Path
    ) -> None:
        """The root shortcut applies whatever depth was requested."""
        root = make_clone(tmp_path / "checkout")
        make_clone(root / "nested")

        assert find_repositories(root, depth=0) == [root]
        assert find_repositories(root, depth=5) == [root]

    def test_empty_container_finds_nothing(self, tmp_path: Path) -> None:
        """A container with no repositories yields an empty list."""
        assert find_repositories(tmp_path) == []


class TestFindRepositoriesDepth:
    """How far below the root the search reaches."""

    def test_default_depth_is_one_level(self, tmp_path: Path) -> None:
        """The default matches a flat directory of checkouts."""
        assert DEFAULT_DEPTH == 1

        repository = make_clone(tmp_path / "one")

        assert find_repositories(tmp_path) == [repository]

    @pytest.mark.parametrize(
        ("depth", "expected_count"),
        [(0, 0), (1, 0), (2, 3), (3, 3)],
    )
    def test_grouped_repositories_need_two_levels(
        self, tmp_path: Path, depth: int, expected_count: int
    ) -> None:
        """Repositories nested one group deep appear only at depth 2.

        A layout of ``group-a/one``, ``group-a/two`` and ``group-b/three``
        is invisible at the default depth, which is the observable
        consequence of ``--repo-depth`` existing at all.

        Args:
            tmp_path: Container directory.
            depth: Depth passed to discovery.
            expected_count: Repositories that depth should reach.
        """
        make_clone(tmp_path / "group-a" / "one")
        make_clone(tmp_path / "group-a" / "two")
        make_clone(tmp_path / "group-b" / "three")

        found = find_repositories(tmp_path, depth=depth)

        assert len(found) == expected_count

    def test_depth_zero_considers_only_the_root(self, tmp_path: Path) -> None:
        """Depth 0 never looks at children."""
        make_clone(tmp_path / "one")

        assert find_repositories(tmp_path, depth=0) == []

    def test_negative_depth_is_rejected(self, tmp_path: Path) -> None:
        """A negative depth is a caller error, not an empty result."""
        with pytest.raises(ValueError, match="must not be negative"):
            find_repositories(tmp_path, depth=-1)


class TestFindRepositoriesTraversal:
    """Which directories the search walks into, and which it skips."""

    def test_does_not_descend_into_a_repository(self, tmp_path: Path) -> None:
        """A checkout's worktrees belong to it, not to the sweep.

        Keeping worktrees under ``.worktrees/`` is a common layout. If
        discovery descended into the checkout it would report the same
        findings once per worktree.
        """
        checkout = make_clone(tmp_path / "checkout")
        make_worktree(checkout / ".worktrees" / "feature")

        assert find_repositories(tmp_path, depth=4) == [checkout]

    def test_worktree_container_is_expanded(self, tmp_path: Path) -> None:
        """A directory of worktrees is as valid a target as clones."""
        first = make_worktree(tmp_path / "feature-a")
        second = make_worktree(tmp_path / "feature-b")

        assert find_repositories(tmp_path) == [first, second]

    def test_mixed_clones_and_worktrees(self, tmp_path: Path) -> None:
        """Clones and worktrees are discovered side by side."""
        clone = make_clone(tmp_path / "clone")
        worktree = make_worktree(tmp_path / "worktree")

        assert find_repositories(tmp_path) == [clone, worktree]

    @pytest.mark.parametrize(
        "skipped",
        ["node_modules", ".venv", "venv", "__pycache__", ".tox"],
    )
    def test_skipped_directories_are_not_searched(
        self, tmp_path: Path, skipped: str
    ) -> None:
        """Vendored trees cannot hide a repository worth visiting.

        Args:
            tmp_path: Container directory.
            skipped: Directory name discovery must not walk into.
        """
        make_clone(tmp_path / skipped / "buried")
        wanted = make_clone(tmp_path / "wanted")

        assert find_repositories(tmp_path, depth=3) == [wanted]

    @pytest.mark.parametrize(
        "name",
        ["node_modules", ".venv", "venv", "__pycache__", ".tox"],
    )
    def test_a_checkout_named_like_a_skipped_directory_is_found(
        self, tmp_path: Path, name: str
    ) -> None:
        """The skip list suppresses descent, not recognition.

        A repository whose name collides with a vendored-tree name is
        still a repository, and omitting it would silently drop it from
        a sweep. The names exist to avoid walking large trees, so they
        are consulted only once the child has been ruled out as a
        checkout in its own right.

        Args:
            tmp_path: Container directory.
            name: Repository name colliding with the skip list.
        """
        repository = make_clone(tmp_path / name)

        assert find_repositories(tmp_path) == [repository]

    def test_a_checkout_named_like_a_skipped_directory_is_not_entered(
        self, tmp_path: Path
    ) -> None:
        """Recognising such a checkout must not also mean descending it.

        Args:
            tmp_path: Container directory.
        """
        repository = make_clone(tmp_path / "venv")
        make_clone(tmp_path / "venv" / "nested")

        assert find_repositories(tmp_path, depth=3) == [repository]

    def test_files_are_not_mistaken_for_repositories(
        self, tmp_path: Path
    ) -> None:
        """A regular file beside the repositories is ignored."""
        (tmp_path / "README.md").write_text("notes\n", encoding="utf-8")
        repository = make_clone(tmp_path / "one")

        assert find_repositories(tmp_path) == [repository]

    def test_results_are_sorted(self, tmp_path: Path) -> None:
        """Visit order is the same whatever order the filesystem lists.

        Creation order here is deliberately not alphabetical, so a
        result that merely echoed ``iterdir()`` would fail on at least
        some filesystems.
        """
        make_clone(tmp_path / "zeta")
        make_clone(tmp_path / "alpha")
        make_clone(tmp_path / "middle")

        found = find_repositories(tmp_path)

        assert [path.name for path in found] == ["alpha", "middle", "zeta"]
        assert found == sorted(found)

    def test_a_symlink_to_a_checkout_is_not_a_second_repository(
        self, tmp_path: Path
    ) -> None:
        """One working tree is visited once, whatever it is called.

        Both the directory test and the ``.git`` probe follow symbolic
        links, so a container holding a checkout and a link to it would
        otherwise report the same repository twice -- and a sweep under
        ``--update-allow-list`` would rewrite one working tree once per
        name it goes by.

        Which name is reported is not asserted: it is whichever the
        traversal reaches first, and both denote the same tree.

        Args:
            tmp_path: Container directory.
        """
        repository = make_clone(tmp_path / "real")
        (tmp_path / "link").symlink_to(repository, target_is_directory=True)

        found = find_repositories(tmp_path)

        assert len(found) == 1
        assert found[0].resolve() == repository.resolve()

    def test_a_symlink_back_into_the_tree_does_not_duplicate(
        self, tmp_path: Path
    ) -> None:
        """A link pointing at an ancestor cannot re-report its contents.

        Args:
            tmp_path: Container directory.
        """
        repository = make_clone(tmp_path / "group" / "real")
        (tmp_path / "loop").symlink_to(tmp_path, target_is_directory=True)

        assert find_repositories(tmp_path, depth=4) == [repository]

    def test_a_shallow_symlink_does_not_hide_a_deeper_route(
        self, tmp_path: Path
    ) -> None:
        """Identity alone would lose repositories within the depth.

        ``deep/link`` reaches ``group`` with only one level of budget
        left, too little to see the repository two levels below it.
        Recording the identity as merely "visited" would then hide
        ``group`` from the direct route, which still has the budget to
        find it. The budget explored with is recorded instead, so a
        larger one supersedes a smaller.

        Traversal is in name order, so ``deep`` is reached before
        ``group`` and the shallow route genuinely comes first.

        Args:
            tmp_path: Container directory.
        """
        repository = make_clone(tmp_path / "group" / "nested" / "real")
        (tmp_path / "deep").mkdir()
        (tmp_path / "deep" / "link").symlink_to(
            tmp_path / "group", target_is_directory=True
        )

        assert find_repositories(tmp_path, depth=3) == [repository]

    def test_distinct_repositories_are_all_reported(
        self, tmp_path: Path
    ) -> None:
        """Deduplication must not collapse genuinely separate checkouts.

        This is the guard against identifying repositories too coarsely.

        Args:
            tmp_path: Container directory.
        """
        first = make_clone(tmp_path / "one")
        second = make_clone(tmp_path / "two")

        assert find_repositories(tmp_path) == [first, second]

    def test_unreadable_directory_is_logged_and_skipped(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """One unreadable directory must not cost the others their scan.

        Args:
            tmp_path: Container directory.
            monkeypatch: Used to make one directory raise on listing.
            caplog: Captures the warning discovery emits.
        """
        blocked = tmp_path / "blocked"
        blocked.mkdir()
        wanted = make_clone(tmp_path / "wanted")

        real_iterdir = Path.iterdir

        def guarded_iterdir(self: Path) -> Iterator[Path]:
            if self == blocked:
                raise PermissionError("Permission denied")
            return real_iterdir(self)

        monkeypatch.setattr(Path, "iterdir", guarded_iterdir)

        with caplog.at_level(logging.WARNING, logger=multi_repo.__name__):
            found = find_repositories(tmp_path, depth=2)

        assert found == [wanted]
        assert "Cannot read" in caplog.text
        assert "blocked" in caplog.text

    def test_an_unreadable_root_is_raised_rather_than_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Nothing examined must not read as nothing found.

        Skipping an unreadable *descendant* is right: the rest of the
        sweep is still worth doing. Skipping an unreadable *root* would
        return the same empty list as a container holding no
        repositories, and the sweep would report success having looked
        at nothing at all.

        Args:
            tmp_path: The root, made unreadable.
            monkeypatch: Used to make the root raise on listing.
        """
        real_iterdir = Path.iterdir

        def guarded_iterdir(self: Path) -> Iterator[Path]:
            """Refuse to list the root.

            Args:
                self: Directory being listed.

            Returns:
                Its entries, for any directory but the root.

            Raises:
                PermissionError: When the root is listed.
            """
            if self == tmp_path:
                raise PermissionError("Permission denied")
            return real_iterdir(self)

        monkeypatch.setattr(Path, "iterdir", guarded_iterdir)

        with pytest.raises(PermissionError):
            find_repositories(tmp_path)

    def test_an_empty_root_is_still_simply_empty(self, tmp_path: Path) -> None:
        """The guard against turning every empty container into an error.

        Args:
            tmp_path: An empty, readable container.
        """
        assert find_repositories(tmp_path) == []

    def test_the_root_is_listed_exactly_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The strict listing is reused, not thrown away.

        Listing the root strictly and then again through the tolerant
        path would reopen the ambiguity the strict listing exists to
        close: were the root to become unreadable between the two, the
        second listing would swallow the failure and discovery would
        return an empty list after all.

        Args:
            tmp_path: Container directory.
            monkeypatch: Counts listings of the root.
        """
        make_clone(tmp_path / "one")
        listings = 0
        real_iterdir = Path.iterdir

        def counting_iterdir(self: Path) -> Iterator[Path]:
            """Count listings of the root, then defer to the real one.

            Args:
                self: Directory being listed.

            Returns:
                Its entries.
            """
            nonlocal listings
            if self == tmp_path:
                listings += 1
            return real_iterdir(self)

        monkeypatch.setattr(Path, "iterdir", counting_iterdir)

        find_repositories(tmp_path)

        assert listings == 1
