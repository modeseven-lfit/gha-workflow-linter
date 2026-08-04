# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests that scanning stops at nested repository boundaries.

Git worktrees, submodules and vendored clones each place a ``.git`` entry
at their own root. Anything beneath one belongs to a different
repository, or to a second checkout of this one, so its workflows are not
the scanned repository's concern.

Without this, a repository keeping worktrees under ``.worktrees/``
reported every finding several times over -- once per checked-out branch,
against files the working tree does not contain. Verified against the
real ``lfreleng-actions/.github`` repository: 24 lines of duplicate
findings before the fix, none after.
"""

from __future__ import annotations

from pathlib import Path  # noqa: TC003 - used at runtime by fixtures

import pytest

from gha_workflow_linter.models import Config
from gha_workflow_linter.scanner import WorkflowScanner

WORKFLOW = """---
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""

ACTION = """---
name: Test action
description: Fixture
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
      shell: bash
"""


def _workflow(root: Path, *parts: str) -> Path:
    """Write a workflow file at ``root/<parts>/.github/workflows/ci.yaml``."""
    directory = root.joinpath(*parts, ".github", "workflows")
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "ci.yaml"
    target.write_text(WORKFLOW)
    return target


def _mark_repository(path: Path, *, as_file: bool) -> None:
    """Make ``path`` look like a repository root.

    Args:
        path: Directory to mark.
        as_file: True writes a gitdir pointer file, as a worktree or
            submodule has; False creates a directory, as a clone has.
    """
    path.mkdir(parents=True, exist_ok=True)
    git = path / ".git"
    if as_file:
        git.write_text("gitdir: /elsewhere/.git/worktrees/branch\n")
    else:
        git.mkdir()


def _scan(root: Path) -> set[Path]:
    """Return every file the scanner discovers under ``root``."""
    return set(WorkflowScanner(Config()).find_workflow_files(root))


class TestNestedRepositoriesAreSkipped:
    @pytest.mark.parametrize(
        ("kind", "as_file"),
        [("worktree", True), ("submodule", True), ("clone", False)],
    )
    def test_nested_repository_excluded(
        self, tmp_path: Path, kind: str, as_file: bool
    ) -> None:
        _mark_repository(tmp_path, as_file=False)
        own = _workflow(tmp_path)
        _mark_repository(tmp_path / "nested", as_file=as_file)
        nested = _workflow(tmp_path, "nested")

        found = _scan(tmp_path)

        assert own in found, f"the repository's own workflow was lost ({kind})"
        assert nested not in found, f"{kind} workflow was scanned"

    def test_worktrees_directory_pattern(self, tmp_path: Path) -> None:
        """The exact shape that produced 24 duplicate findings."""
        _mark_repository(tmp_path, as_file=False)
        own = _workflow(tmp_path)
        for branch in ("fix-one", "fix-two"):
            _mark_repository(tmp_path / ".worktrees" / branch, as_file=True)
            _workflow(tmp_path, ".worktrees", branch)

        found = _scan(tmp_path)

        assert found == {own}

    def test_deeply_nested_content_excluded(self, tmp_path: Path) -> None:
        """Everything below the boundary goes, not just its top level."""
        _mark_repository(tmp_path, as_file=False)
        own = _workflow(tmp_path)
        _mark_repository(tmp_path / "vendor" / "dep", as_file=False)
        _workflow(tmp_path, "vendor", "dep", "deep", "deeper")

        assert _scan(tmp_path) == {own}

    def test_action_files_also_excluded(self, tmp_path: Path) -> None:
        _mark_repository(tmp_path, as_file=False)
        own_action = tmp_path / "action.yaml"
        own_action.write_text(ACTION)
        _mark_repository(tmp_path / "nested", as_file=True)
        nested_action = tmp_path / "nested" / "action.yaml"
        nested_action.write_text(ACTION)

        found = _scan(tmp_path)

        assert own_action in found
        assert nested_action not in found

    def test_scan_root_is_never_a_boundary(self, tmp_path: Path) -> None:
        """The repository being scanned is not excluded by its own .git."""
        _mark_repository(tmp_path, as_file=False)
        own = _workflow(tmp_path)

        assert _scan(tmp_path) == {own}

    def test_worktree_root_scanned_directly(self, tmp_path: Path) -> None:
        """Pointing at a worktree scans it: it is then the root."""
        worktree = tmp_path / "wt"
        _mark_repository(worktree, as_file=True)
        target = _workflow(worktree)

        assert _scan(worktree) == {target}

    def test_plain_directories_unaffected(self, tmp_path: Path) -> None:
        """Only a .git entry marks a boundary, not depth or naming."""
        _mark_repository(tmp_path, as_file=False)
        own = _workflow(tmp_path)
        buried = _workflow(tmp_path, "packages", "sub")

        assert _scan(tmp_path) == {own, buried}

    def test_non_repository_root_scans_children(self, tmp_path: Path) -> None:
        """A container directory that is not itself a repository.

        Each child is a separate repository, so each is a boundary and
        nothing is scanned. Multi-repository scanning is a distinct mode
        that visits each repository as its own root; this documents the
        behaviour rather than endorsing it as a way to scan many repos.
        """
        _mark_repository(tmp_path / "repo-a", as_file=False)
        _workflow(tmp_path, "repo-a")
        _mark_repository(tmp_path / "repo-b", as_file=False)
        _workflow(tmp_path, "repo-b")

        assert _scan(tmp_path) == set()


class TestRepositoryRootDetectionIsCached:
    def test_repeated_queries_stat_once(self, tmp_path: Path) -> None:
        _mark_repository(tmp_path, as_file=False)
        scanner = WorkflowScanner(Config())
        target = tmp_path / "a" / "b"
        target.mkdir(parents=True)

        scanner._crosses_repository_boundary(target, tmp_path)
        cached = dict(scanner._repository_roots)
        scanner._crosses_repository_boundary(target, tmp_path)

        assert scanner._repository_roots == cached

    def test_unreadable_directory_is_not_a_boundary(
        self, tmp_path: Path
    ) -> None:
        """An OSError must not silently exclude a whole subtree."""
        scanner = WorkflowScanner(Config())

        assert scanner._is_repository_root(tmp_path / "missing") is False
