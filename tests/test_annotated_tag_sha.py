# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for annotated tag handling in the token-less Git validation path.

``git ls-remote --tags`` advertises two lines for an annotated tag: the SHA
of the tag object, and the SHA of the commit it peels to. Conflating the two
makes the Git backend report a tag-object SHA as VALID even though GitHub
Actions cannot check out a tag object.
"""

from __future__ import annotations

import subprocess

import pytest

from gha_workflow_linter.exceptions import GitError, GitUnreachableError
from gha_workflow_linter.git_refs import (
    AnnotatedTagPeel,
    get_all_remote_refs,
    get_annotated_tag_peels,
    get_remote_ref_shas,
    get_remote_tag_object_shas,
    get_remote_tag_shas,
)
from gha_workflow_linter.git_validator import _validate_commit_shas_git
from gha_workflow_linter.models import GitConfig, ValidationResult

URL = "https://github.com/lfreleng-actions/.github.git"

# Real output from ``git ls-remote --tags`` against
# git@github.com:lfreleng-actions/.github.git. Both tags are annotated:
# each has an unpeeled tag-object line and a ``^{}`` commit line.
V0_12_2_TAG_OBJECT = "8f363565e79650362c3359ee23b6d6fd295866ee"
V0_12_2_COMMIT = "bf6642f68d58c1b81bbe993e676d6cc339ac3654"
V0_1_1_TAG_OBJECT = "a5c2d7a4620ab83fcaeabac868d07ee27335053e"
V0_1_1_COMMIT = "18d9c4446bea555d0783e850f6d295f844fe8f67"

ANNOTATED_TAGS_OUTPUT = (
    f"{V0_12_2_TAG_OBJECT}\trefs/tags/v0.12.2\n"
    f"{V0_12_2_COMMIT}\trefs/tags/v0.12.2^{{}}\n"
    f"{V0_1_1_TAG_OBJECT}\trefs/tags/v0.1.1\n"
    f"{V0_1_1_COMMIT}\trefs/tags/v0.1.1^{{}}\n"
)

# A lightweight tag has a single line and no ``^{}`` peel.
LIGHTWEIGHT_COMMIT = "3b7bd5b9e1cd3e0d4ed4a6b3d0e1f2a3b4c5d6e7"
LIGHTWEIGHT_TAGS_OUTPUT = f"{LIGHTWEIGHT_COMMIT}\trefs/tags/v1.0.0\n"

MIXED_TAGS_OUTPUT = ANNOTATED_TAGS_OUTPUT + LIGHTWEIGHT_TAGS_OUTPUT

BRANCH_COMMIT = "0000111122223333444455556666777788889999"
HEADS_AND_TAGS_OUTPUT = (
    f"{BRANCH_COMMIT}\trefs/heads/main\n" + MIXED_TAGS_OUTPUT
)


class FakeCompleted:
    """Minimal stand-in for ``subprocess.CompletedProcess``."""

    def __init__(self, stdout: str, returncode: int = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = ""


def _patch_ls_remote(
    monkeypatch: pytest.MonkeyPatch, stdout: str
) -> list[list[str]]:
    """Stub ``subprocess.run`` with fixed ls-remote output.

    Args:
        monkeypatch: pytest monkeypatch fixture
        stdout: Canned standard output for every invocation

    Returns:
        List that accumulates each command the code under test ran
    """
    commands: list[list[str]] = []

    def fake_run(cmd: list[str], **_kwargs: object) -> FakeCompleted:
        commands.append(cmd)
        return FakeCompleted(stdout)

    monkeypatch.setattr(subprocess, "run", fake_run)
    return commands


# --------------------------------------------------------------------------
# _get_remote_tag_shas
# --------------------------------------------------------------------------


def test_get_remote_tag_shas_prefers_peeled_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An annotated tag resolves to its commit, not to its tag object.

    Core requirement: ``uses: org/repo@<tag-object-sha>`` is unusable, so the
    tag -> SHA map must expose the peeled ``^{}`` commit.
    """
    commands = _patch_ls_remote(monkeypatch, ANNOTATED_TAGS_OUTPUT)

    tag_shas = get_remote_tag_shas(URL, GitConfig())

    assert tag_shas == {
        "v0.12.2": V0_12_2_COMMIT,
        "v0.1.1": V0_1_1_COMMIT,
    }
    assert V0_12_2_TAG_OBJECT not in tag_shas.values()
    assert commands == [["git", "ls-remote", "--tags", URL]]


def test_get_remote_tag_shas_lightweight_tag_uses_single_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lightweight tag has no peel line and keeps its only SHA."""
    _patch_ls_remote(monkeypatch, LIGHTWEIGHT_TAGS_OUTPUT)

    tag_shas = get_remote_tag_shas(URL, GitConfig())

    assert tag_shas == {"v1.0.0": LIGHTWEIGHT_COMMIT}


def test_get_remote_tag_shas_mixed_annotated_and_lightweight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Annotated and lightweight tags coexist in one ls-remote output."""
    _patch_ls_remote(monkeypatch, MIXED_TAGS_OUTPUT)

    tag_shas = get_remote_tag_shas(URL, GitConfig())

    assert tag_shas == {
        "v0.12.2": V0_12_2_COMMIT,
        "v0.1.1": V0_1_1_COMMIT,
        "v1.0.0": LIGHTWEIGHT_COMMIT,
    }


def test_get_remote_tag_shas_ignores_non_tag_refs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Branch refs never leak into the tag map."""
    _patch_ls_remote(monkeypatch, HEADS_AND_TAGS_OUTPUT)

    tag_shas = get_remote_tag_shas(URL, GitConfig())

    assert "main" not in tag_shas
    assert BRANCH_COMMIT not in tag_shas.values()


# --------------------------------------------------------------------------
# _get_remote_tag_object_shas / _get_annotated_tag_peels
# --------------------------------------------------------------------------


def test_get_remote_tag_object_shas_annotated_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only annotated tags contribute a tag-object SHA."""
    _patch_ls_remote(monkeypatch, MIXED_TAGS_OUTPUT)

    tag_objects = get_remote_tag_object_shas(URL, GitConfig())

    assert tag_objects == {
        V0_12_2_TAG_OBJECT: "v0.12.2",
        V0_1_1_TAG_OBJECT: "v0.1.1",
    }
    assert LIGHTWEIGHT_COMMIT not in tag_objects


def test_get_annotated_tag_peels_carries_tag_and_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The peel record supplies everything a remediation message needs."""
    _patch_ls_remote(monkeypatch, ANNOTATED_TAGS_OUTPUT)

    peels = get_annotated_tag_peels(URL, GitConfig())

    assert peels[V0_12_2_TAG_OBJECT] == AnnotatedTagPeel(
        tag="v0.12.2", commit_sha=V0_12_2_COMMIT
    )
    assert peels[V0_1_1_TAG_OBJECT].commit_sha == V0_1_1_COMMIT


def test_annotated_tag_peel_is_frozen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The peel record is immutable, so callers cannot corrupt the map."""
    _patch_ls_remote(monkeypatch, ANNOTATED_TAGS_OUTPUT)

    peel = get_annotated_tag_peels(URL, GitConfig())[V0_12_2_TAG_OBJECT]

    with pytest.raises(Exception):  # noqa: B017 - FrozenInstanceError
        peel.commit_sha = "deadbeef"  # type: ignore[misc]


# --------------------------------------------------------------------------
# _get_remote_ref_shas
# --------------------------------------------------------------------------


def test_get_remote_ref_shas_splits_commits_from_tag_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Commit SHAs and tag-object SHAs are disjoint and correctly assigned."""
    commands = _patch_ls_remote(monkeypatch, HEADS_AND_TAGS_OUTPUT)

    remote_refs = get_remote_ref_shas(URL, GitConfig())

    assert remote_refs.commit_shas == frozenset(
        {
            BRANCH_COMMIT,
            V0_12_2_COMMIT,
            V0_1_1_COMMIT,
            LIGHTWEIGHT_COMMIT,
        }
    )
    assert set(remote_refs.tag_objects) == {
        V0_12_2_TAG_OBJECT,
        V0_1_1_TAG_OBJECT,
    }
    assert not remote_refs.commit_shas & set(remote_refs.tag_objects)
    assert commands == [["git", "ls-remote", "--heads", "--tags", URL]]


def test_get_all_remote_refs_still_returns_every_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The legacy helper keeps its contract: every advertised SHA.

    Existing callers rely on the union, so the split is additive rather than
    a change to this function's meaning.
    """
    _patch_ls_remote(monkeypatch, HEADS_AND_TAGS_OUTPUT)

    assert get_all_remote_refs(URL, GitConfig()) == {
        BRANCH_COMMIT,
        V0_12_2_TAG_OBJECT,
        V0_12_2_COMMIT,
        V0_1_1_TAG_OBJECT,
        V0_1_1_COMMIT,
        LIGHTWEIGHT_COMMIT,
    }


# --------------------------------------------------------------------------
# _validate_commit_shas_git — the regression under test
# --------------------------------------------------------------------------


def test_tag_object_sha_is_annotated_tag_sha_not_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tag-object SHA is ANNOTATED_TAG_SHA, never VALID.

    Regression test for the confirmed defect: ``ls-remote`` advertises the
    tag object, so a plain set-membership test passed it, while GitHub
    Actions cannot check it out and the API backend rejects it.
    """
    _patch_ls_remote(monkeypatch, HEADS_AND_TAGS_OUTPUT)

    results = _validate_commit_shas_git(URL, [V0_12_2_TAG_OBJECT], GitConfig())

    assert results[V0_12_2_TAG_OBJECT] == ValidationResult.ANNOTATED_TAG_SHA
    assert results[V0_12_2_TAG_OBJECT] != ValidationResult.VALID
    assert results[V0_12_2_TAG_OBJECT] != ValidationResult.INVALID_REFERENCE


def test_peeled_commit_sha_is_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The commit an annotated tag peels to remains VALID."""
    _patch_ls_remote(monkeypatch, HEADS_AND_TAGS_OUTPUT)

    results = _validate_commit_shas_git(URL, [V0_12_2_COMMIT], GitConfig())

    assert results[V0_12_2_COMMIT] == ValidationResult.VALID


def test_branch_head_and_lightweight_tag_shas_are_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ordinary commit SHAs are unaffected by the tag-object split."""
    _patch_ls_remote(monkeypatch, HEADS_AND_TAGS_OUTPUT)

    results = _validate_commit_shas_git(
        URL, [BRANCH_COMMIT, LIGHTWEIGHT_COMMIT], GitConfig()
    )

    assert results == {
        BRANCH_COMMIT: ValidationResult.VALID,
        LIGHTWEIGHT_COMMIT: ValidationResult.VALID,
    }


def test_unknown_sha_is_invalid_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A SHA the remote never advertises stays INVALID_REFERENCE."""
    _patch_ls_remote(monkeypatch, HEADS_AND_TAGS_OUTPUT)
    unknown = "1234567890abcdef1234567890abcdef12345678"

    results = _validate_commit_shas_git(URL, [unknown], GitConfig())

    assert results[unknown] == ValidationResult.INVALID_REFERENCE


def test_mixed_shas_classified_independently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each SHA in a batch gets its own verdict."""
    _patch_ls_remote(monkeypatch, HEADS_AND_TAGS_OUTPUT)
    unknown = "1234567890abcdef1234567890abcdef12345678"

    results = _validate_commit_shas_git(
        URL,
        [V0_12_2_TAG_OBJECT, V0_1_1_COMMIT, unknown],
        GitConfig(),
    )

    assert results == {
        V0_12_2_TAG_OBJECT: ValidationResult.ANNOTATED_TAG_SHA,
        V0_1_1_COMMIT: ValidationResult.VALID,
        unknown: ValidationResult.INVALID_REFERENCE,
    }


# --------------------------------------------------------------------------
# Degraded inputs
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "stdout",
    [
        "",
        "\n\n",
        "not-tab-separated output\n",
        "sha\trefs/tags/a\textra-column\n",
        "\trefs/tags/v1.0.0\n",
        f"{V0_12_2_COMMIT}\t\n",
        f"{V0_12_2_COMMIT}\trefs/tags/^{{}}\n",
    ],
)
def test_malformed_ls_remote_output_degrades_safely(
    monkeypatch: pytest.MonkeyPatch, stdout: str
) -> None:
    """Unparsable lines are skipped rather than raising or half-parsed."""
    _patch_ls_remote(monkeypatch, stdout)

    assert get_remote_tag_shas(URL, GitConfig()) == {}
    assert get_remote_tag_object_shas(URL, GitConfig()) == {}
    assert get_remote_ref_shas(URL, GitConfig()).tag_objects == {}


def test_peel_line_matching_unpeeled_sha_is_not_annotated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Identical unpeeled and peeled SHAs mean no tag object exists."""
    stdout = (
        f"{LIGHTWEIGHT_COMMIT}\trefs/tags/v1.0.0\n"
        f"{LIGHTWEIGHT_COMMIT}\trefs/tags/v1.0.0^{{}}\n"
    )
    _patch_ls_remote(monkeypatch, stdout)

    assert get_remote_tag_object_shas(URL, GitConfig()) == {}
    results = _validate_commit_shas_git(URL, [LIGHTWEIGHT_COMMIT], GitConfig())
    assert results[LIGHTWEIGHT_COMMIT] == ValidationResult.VALID


def test_ls_remote_failure_raises_git_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-zero exit surfaces as GitError, matching existing behaviour."""

    def fake_run(cmd: list[str], **_kwargs: object) -> FakeCompleted:
        raise subprocess.CalledProcessError(
            returncode=128, cmd=cmd, stderr="fatal: repository not found"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(GitError):
        get_remote_tag_shas(URL, GitConfig())
    with pytest.raises(GitError):
        get_remote_ref_shas(URL, GitConfig())


def test_ls_remote_timeout_raises_unreachable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A timeout surfaces as the unreachable-remote GitError.

    Nothing was heard back, so nothing is known about the refs. The
    narrower type is asserted because the plain :class:`GitError` the
    branch used to raise reads, one layer up, as a definitive answer.
    """

    def fake_run(cmd: list[str], **_kwargs: object) -> FakeCompleted:
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=1)

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(GitUnreachableError):
        get_remote_tag_object_shas(URL, GitConfig())
    with pytest.raises(GitUnreachableError):
        get_remote_ref_shas(URL, GitConfig())


def test_validate_commit_shas_git_falls_back_to_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An answered failure marks every SHA invalid, as it did before.

    The tag-object split must not change how a refusal is handled: the
    caller retries with the SSH URL, and an unresolved SHA ends up
    INVALID_REFERENCE rather than a misleading ANNOTATED_TAG_SHA.
    """

    def fake_run(_cmd: list[str], **_kwargs: object) -> FakeCompleted:
        raise subprocess.CalledProcessError(
            returncode=128, cmd=["git"], stderr="boom"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    results = _validate_commit_shas_git(
        URL, [V0_12_2_TAG_OBJECT, V0_12_2_COMMIT], GitConfig()
    )

    assert results == {
        V0_12_2_TAG_OBJECT: ValidationResult.INVALID_REFERENCE,
        V0_12_2_COMMIT: ValidationResult.INVALID_REFERENCE,
    }


def test_validate_commit_shas_git_propagates_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A timed-out lookup is not an answer about the SHAs.

    Falling back to INVALID_REFERENCE here blamed every SHA-pinned
    workflow for a slow network -- and SHA pinning is the shape this
    linter exists to encourage, so the blame landed on its own advice.
    """

    def fake_run(cmd: list[str], **_kwargs: object) -> FakeCompleted:
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=1)

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(GitUnreachableError):
        _validate_commit_shas_git(
            URL, [V0_12_2_TAG_OBJECT, V0_12_2_COMMIT], GitConfig()
        )
