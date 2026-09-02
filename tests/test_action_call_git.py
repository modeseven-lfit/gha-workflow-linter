# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for Git-based validation of subdirectory (monorepo) action calls."""

from __future__ import annotations

import asyncio

import pytest

from gha_workflow_linter import action_call_git, git_subpath
from gha_workflow_linter.action_call_git import (
    GitValidationClient,
    _base_repository,
    _validate_repository_exists,
)
from gha_workflow_linter.exceptions import GitError
from gha_workflow_linter.git_subpath import (
    _run_git_subpath_exists,
    _validate_repository_subpaths,
)
from gha_workflow_linter.models import GitConfig, ValidationResult


@pytest.mark.parametrize(
    ("repository", "expected"),
    [
        ("actions/checkout", "actions/checkout"),
        ("anchore/scan-action/download-grype", "anchore/scan-action"),
        ("github/codeql-action/init", "github/codeql-action"),
        ("owner/repo/nested/path", "owner/repo"),
        ("owner/repo", "owner/repo"),
        ("single", "single"),
    ],
)
def test_base_repository_strips_subpath(repository: str, expected: str) -> None:
    """The owner/repo base is returned, dropping any trailing action subpath."""
    assert _base_repository(repository) == expected


def test_validate_repository_exists_uses_base_repo_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Subdirectory actions validate against the owner/repo remote URL.

    Regression test: ``anchore/scan-action/download-grype`` previously built
    ``https://github.com/anchore/scan-action/download-grype.git`` and failed
    with INVALID_REPOSITORY under the token-less Git validation path, because
    a Git remote only exists for the ``owner/repo`` portion.
    """
    seen_urls: list[str] = []

    def fake_ls_remote(url: str, _config: GitConfig) -> bool:
        seen_urls.append(url)
        return True

    monkeypatch.setattr(action_call_git, "_run_git_ls_remote", fake_ls_remote)

    result = _validate_repository_exists(
        "anchore/scan-action/download-grype", GitConfig()
    )

    assert result == ValidationResult.VALID
    assert seen_urls == ["https://github.com/anchore/scan-action.git"]
    assert "download-grype" not in seen_urls[0]


def test_validate_repository_subpaths_valid_and_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Existing subpaths validate; bogus subpaths report INVALID_PATH.

    The base repo + ref are assumed already validated, so this exercises only
    the tree-existence check: ``init`` exists at the ref while ``not-real``
    does not.
    """
    monkeypatch.setattr(
        git_subpath, "_run_git_init", lambda _dir, _config: True
    )

    fetched_refs: list[str] = []

    def fake_fetch(
        _repo_dir: object, _url: str, ref: str, _config: GitConfig
    ) -> bool:
        fetched_refs.append(ref)
        return True

    monkeypatch.setattr(git_subpath, "_run_git_fetch_partial", fake_fetch)

    def fake_subpath_exists(
        _repo_dir: object, _treeish: str, subpath: str, _config: GitConfig
    ) -> bool:
        return subpath == "init"

    monkeypatch.setattr(
        git_subpath, "_run_git_subpath_exists", fake_subpath_exists
    )

    entries = [
        ("github/codeql-action/init", "v3"),
        ("github/codeql-action/not-real", "v3"),
    ]
    results = _validate_repository_subpaths(
        "github/codeql-action", entries, GitConfig()
    )

    assert results[("github/codeql-action/init", "v3")] == (
        ValidationResult.VALID
    )
    assert results[("github/codeql-action/not-real", "v3")] == (
        ValidationResult.INVALID_PATH
    )
    # The shared ref is fetched exactly once for both subpath entries.
    assert fetched_refs == ["v3"]


def test_validate_repository_subpaths_fetch_failure_is_not_bogus(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fetch failure on an already-valid ref is a network error, not bogus.

    Reporting INVALID_PATH here would be a false negative, so the worker
    returns NETWORK_ERROR and never consults the tree.
    """
    monkeypatch.setattr(
        git_subpath, "_run_git_init", lambda _dir, _config: True
    )
    monkeypatch.setattr(
        git_subpath,
        "_run_git_fetch_partial",
        lambda _repo_dir, _url, _ref, _config: False,
    )

    def unexpected_subpath_check(*_args: object, **_kwargs: object) -> bool:
        raise AssertionError("subpath check must not run when fetch fails")

    monkeypatch.setattr(
        git_subpath, "_run_git_subpath_exists", unexpected_subpath_check
    )

    entries = [("github/codeql-action/init", "v3")]
    results = _validate_repository_subpaths(
        "github/codeql-action", entries, GitConfig()
    )

    assert results[("github/codeql-action/init", "v3")] == (
        ValidationResult.NETWORK_ERROR
    )


def test_run_git_subpath_exists_command_and_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ls-tree probes all candidates and treats non-empty output as present."""
    import pathlib
    import subprocess

    captured: dict[str, list[str]] = {}

    class FakeCompleted:
        def __init__(self, returncode: int, stdout: str) -> None:
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = ""

    def fake_run(cmd: list[str], **_kwargs: object) -> FakeCompleted:
        captured["cmd"] = cmd
        # Simulate a found directory entry.
        return FakeCompleted(0, "040000 tree abc123\tinit\n")

    monkeypatch.setattr(subprocess, "run", fake_run)

    exists = _run_git_subpath_exists(
        pathlib.Path("/tmp/repo"), "FETCH_HEAD", "init", GitConfig()
    )

    assert exists is True
    # All candidate paths are passed to a single ls-tree invocation.
    assert "ls-tree" in captured["cmd"]
    assert "init/action.yml" in captured["cmd"]
    assert "init/action.yaml" in captured["cmd"]
    assert "init" in captured["cmd"]


def test_run_git_subpath_exists_empty_output_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty ls-tree output (exit 0) means the path does not exist."""
    import pathlib
    import subprocess

    class FakeCompleted:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda _cmd, **_kwargs: FakeCompleted(),
    )

    exists = _run_git_subpath_exists(
        pathlib.Path("/tmp/repo"), "FETCH_HEAD", "not-real", GitConfig()
    )

    assert exists is False


def test_run_git_subpath_exists_nonzero_exit_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-zero ls-tree exit is inconclusive and raises GitError.

    A command failure (e.g. a missing object) must be distinguished from a
    subpath being genuinely absent, so callers can treat it as inconclusive
    rather than a bogus path.
    """
    import pathlib
    import subprocess

    class FakeCompleted:
        returncode = 128
        stdout = ""
        stderr = "fatal: not a tree object"

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda _cmd, **_kwargs: FakeCompleted(),
    )

    with pytest.raises(GitError):
        _run_git_subpath_exists(
            pathlib.Path("/tmp/repo"), "FETCH_HEAD", "init", GitConfig()
        )


def test_run_git_subpath_exists_timeout_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A timeout while running ls-tree is inconclusive and raises GitError."""
    import pathlib
    import subprocess

    def fake_run(_cmd: list[str], **_kwargs: object) -> object:
        raise subprocess.TimeoutExpired(cmd="git ls-tree", timeout=1)

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(GitError):
        _run_git_subpath_exists(
            pathlib.Path("/tmp/repo"), "FETCH_HEAD", "init", GitConfig()
        )


def test_validate_repository_subpaths_ls_tree_failure_is_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A GitError from the ls-tree check maps to NETWORK_ERROR, not bogus.

    The repo + ref are already validated and the fetch succeeds, so a failure
    to run the tree check itself must be reported as inconclusive rather than
    a definitive INVALID_PATH.
    """
    monkeypatch.setattr(
        git_subpath, "_run_git_init", lambda _dir, _config: True
    )
    monkeypatch.setattr(
        git_subpath,
        "_run_git_fetch_partial",
        lambda _repo_dir, _url, _ref, _config: True,
    )

    def boom(*_args: object, **_kwargs: object) -> bool:
        raise GitError("ls-tree exploded")

    monkeypatch.setattr(git_subpath, "_run_git_subpath_exists", boom)

    entries = [("github/codeql-action/init", "v3")]
    results = _validate_repository_subpaths(
        "github/codeql-action", entries, GitConfig()
    )

    assert results[("github/codeql-action/init", "v3")] == (
        ValidationResult.NETWORK_ERROR
    )


@pytest.mark.asyncio
async def test_validate_subpaths_batch_gather_failure_is_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A gather-level failure maps every entry to NETWORK_ERROR, not bogus.

    If ``asyncio.gather`` itself raises (e.g. cancellation), the fallback must
    route entries through the ``isinstance(..., Exception)`` branch so they are
    reported as inconclusive ``NETWORK_ERROR`` rather than misclassified as
    ``INVALID_PATH``. Uses a fake executor so no real subprocess/network runs.
    """
    import concurrent.futures

    class _FakeExecutor:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> _FakeExecutor:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def submit(
            self, _fn: object, *_args: object, **_kwargs: object
        ) -> concurrent.futures.Future[object]:
            future: concurrent.futures.Future[object] = (
                concurrent.futures.Future()
            )
            # Never consumed: gather is patched to raise before awaiting.
            future.set_result({})
            return future

    monkeypatch.setattr(action_call_git, "ThreadPoolExecutor", _FakeExecutor)

    async def boom(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("gather exploded")

    # Patch the shared asyncio module object (action_call_git references the same
    # singleton via ``import asyncio``); nothing between here and the awaited
    # call uses gather, so this only affects validate_subpaths_batch.
    monkeypatch.setattr(asyncio, "gather", boom)

    client = GitValidationClient(GitConfig())
    results = await client.validate_subpaths_batch(
        [
            ("github/codeql-action/init", "v3"),
            ("github/codeql-action/analyze", "v3"),
        ]
    )

    assert results[("github/codeql-action/init", "v3")] == (
        ValidationResult.NETWORK_ERROR
    )
    assert results[("github/codeql-action/analyze", "v3")] == (
        ValidationResult.NETWORK_ERROR
    )


@pytest.mark.asyncio
async def test_validate_subpaths_batch_partial_result_is_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A worker dict missing an entry maps that entry to NETWORK_ERROR.

    If ``_validate_repository_subpaths`` ever returns a partial dict (an
    internal/edge-case failure), the absent entry must be treated as
    inconclusive rather than a definitive ``INVALID_PATH``, so it is neither
    cached nor reported as a bogus subpath. The present entry is unaffected.
    Uses a fake executor so no real subprocess/network runs.
    """
    import concurrent.futures

    # Both share base ``github/codeql-action`` so they land in one group whose
    # single worker future returns a dict containing only ``present``.
    present = ("github/codeql-action/init", "v3")
    missing = ("github/codeql-action/analyze", "v3")

    class _FakeExecutor:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> _FakeExecutor:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def submit(
            self, _fn: object, *_args: object, **_kwargs: object
        ) -> concurrent.futures.Future[object]:
            future: concurrent.futures.Future[object] = (
                concurrent.futures.Future()
            )
            future.set_result({present: ValidationResult.VALID})
            return future

    monkeypatch.setattr(action_call_git, "ThreadPoolExecutor", _FakeExecutor)

    client = GitValidationClient(GitConfig())
    results = await client.validate_subpaths_batch([present, missing])

    assert results[present] == ValidationResult.VALID
    assert results[missing] == ValidationResult.NETWORK_ERROR
