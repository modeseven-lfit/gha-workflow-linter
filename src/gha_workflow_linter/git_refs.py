# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Parsing of ``git ls-remote`` output, including annotated tag peeling.

``git ls-remote --tags`` advertises two lines for an annotated tag: an
unpeeled line carrying the SHA of the *tag object*, and a ``^{}`` peeled
line carrying the SHA of the *commit* that tag points at. For example::

    8f363565...  refs/tags/v0.12.2      # the tag object
    bf6642f6...  refs/tags/v0.12.2^{}   # the commit

GitHub Actions cannot check out a tag object, so a workflow pinned to the
unpeeled SHA fails at run time. Treating both SHAs as interchangeable
therefore produces a false pass on a broken reference, which is why this
module keeps them apart.

The helpers here are pure parsing plus thin ``git`` invocations, kept
separate from :mod:`gha_workflow_linter.git_validator` so both the
validation path and the version-resolution path share one definition of
how refs are read.
"""

from __future__ import annotations

import dataclasses
import logging
import subprocess
from typing import TYPE_CHECKING

from .exceptions import GitError

if TYPE_CHECKING:
    from .models import GitConfig

logger = logging.getLogger(__name__)

#: Prefix every tag reference carries in ``git ls-remote`` output.
_TAG_REF_PREFIX = "refs/tags/"

#: Suffix Git appends to the *peeled* line it emits for an annotated tag.
_PEELED_TAG_SUFFIX = "^{}"


@dataclasses.dataclass(frozen=True)
class AnnotatedTagPeel:
    """The tag and commit behind an annotated tag object.

    ``git ls-remote --tags`` emits two lines for an annotated tag: an
    unpeeled line carrying the SHA of the *tag object*, and a ``^{}``
    peeled line carrying the SHA of the *commit* the tag points at.
    GitHub Actions cannot check out a tag object, so a workflow pinned to
    the tag-object SHA fails at run time. This record carries the
    information needed to tell a user what to use instead.

    Attributes:
        tag: Tag name, without the ``refs/tags/`` prefix or ``^{}`` suffix.
        commit_sha: SHA of the commit the annotated tag peels to.
    """

    tag: str
    commit_sha: str


@dataclasses.dataclass(frozen=True)
class RemoteRefShas:
    """Remote ref SHAs split by the kind of object they name.

    Attributes:
        commit_shas: SHAs naming real commits; these are checkout-able.
        tag_objects: Mapping of annotated tag-object SHA to the tag name
            and peeled commit SHA behind it. Keys are disjoint from
            ``commit_shas``.
    """

    commit_shas: frozenset[str]
    tag_objects: dict[str, AnnotatedTagPeel]


def _parse_ls_remote_lines(stdout: str) -> list[tuple[str, str]]:
    """
    Parse ``git ls-remote`` output into ``(sha, ref)`` pairs.

    Malformed lines (blank, or not exactly two tab-separated columns) are
    skipped rather than raising, so partial or unexpected output degrades
    to fewer refs instead of an error.

    Args:
        stdout: Raw standard output of a ``git ls-remote`` invocation

    Returns:
        List of ``(sha, ref)`` pairs, in output order. The ``ref`` retains
        any ``^{}`` peel suffix.
    """
    pairs: list[tuple[str, str]] = []

    for line in stdout.strip().split("\n"):
        if not line:
            continue
        # Format: "sha\tref_name"
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        sha = parts[0].strip()
        ref = parts[1].strip()
        if not sha or not ref:
            continue
        pairs.append((sha, ref))

    return pairs


def _split_tag_ref_shas(
    pairs: list[tuple[str, str]],
) -> tuple[dict[str, str], dict[str, str]]:
    """
    Split ``ls-remote`` pairs into unpeeled and peeled tag SHA maps.

    Non-tag refs (e.g. ``refs/heads/...``) are ignored.

    Args:
        pairs: ``(sha, ref)`` pairs as returned by
            :func:`_parse_ls_remote_lines`

    Returns:
        Two-tuple of ``(unpeeled, peeled)`` dictionaries, each mapping a
        tag name to the SHA on the corresponding line. For an annotated
        tag the unpeeled SHA names the tag object and the peeled SHA names
        the commit; a lightweight tag has an unpeeled entry only.
    """
    unpeeled: dict[str, str] = {}
    peeled: dict[str, str] = {}

    for sha, ref in pairs:
        if not ref.startswith(_TAG_REF_PREFIX):
            continue
        tag = ref[len(_TAG_REF_PREFIX) :]
        if tag.endswith(_PEELED_TAG_SUFFIX):
            tag = tag[: -len(_PEELED_TAG_SUFFIX)]
            if tag:
                peeled[tag] = sha
        elif tag:
            unpeeled[tag] = sha

    return unpeeled, peeled


def _annotated_tag_peels(
    unpeeled: dict[str, str], peeled: dict[str, str]
) -> dict[str, AnnotatedTagPeel]:
    """
    Identify annotated tags from the unpeeled/peeled SHA maps.

    A tag is annotated when ``ls-remote`` advertises both an unpeeled line
    and a ``^{}`` peeled line whose SHAs differ; the unpeeled SHA is then
    the tag object. A lightweight tag has no peeled line at all.

    Args:
        unpeeled: Mapping of tag name to unpeeled SHA
        peeled: Mapping of tag name to peeled (``^{}``) SHA

    Returns:
        Dictionary mapping tag-object SHA to its :class:`AnnotatedTagPeel`
    """
    peels: dict[str, AnnotatedTagPeel] = {}

    for tag, commit_sha in peeled.items():
        tag_object_sha = unpeeled.get(tag)
        if tag_object_sha is not None and tag_object_sha != commit_sha:
            peels[tag_object_sha] = AnnotatedTagPeel(
                tag=tag, commit_sha=commit_sha
            )

    return peels


def _run_ls_remote_tags(url: str, config: GitConfig) -> list[tuple[str, str]]:
    """
    Run ``git ls-remote --tags`` and return its parsed lines.

    Args:
        url: Git repository URL
        config: Git configuration

    Returns:
        List of ``(sha, ref)`` pairs; ``ref`` retains any ``^{}`` suffix

    Raises:
        GitError: If operation fails
    """
    cmd = ["git", "ls-remote", "--tags", url]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout_seconds,
            check=True,
        )

        return _parse_ls_remote_lines(result.stdout)

    except subprocess.TimeoutExpired:
        raise GitError(f"Git ls-remote (tags) timed out for {url}") from None
    except subprocess.CalledProcessError as e:
        raise GitError(
            f"Git ls-remote (tags) failed for {url}: {e.stderr}"
        ) from e
    except Exception as e:
        raise GitError(f"Git ls-remote (tags) failed for {url}: {e}") from e


def get_remote_tag_shas(url: str, config: GitConfig) -> dict[str, str]:
    """
    Map tag name to the commit SHA it ultimately points at.

    The peeled ``^{}`` line is preferred over the unpeeled one, so an
    annotated tag resolves to its commit rather than to the tag object. A
    lightweight tag has only one line and resolves to that SHA.

    Args:
        url: Git repository URL
        config: Git configuration

    Returns:
        Dictionary mapping tag name to commit SHA

    Raises:
        GitError: If operation fails
    """
    unpeeled, peeled = _split_tag_ref_shas(_run_ls_remote_tags(url, config))

    # Peeled entries win: for an annotated tag they name the commit.
    return {**unpeeled, **peeled}


def get_annotated_tag_peels(
    url: str, config: GitConfig
) -> dict[str, AnnotatedTagPeel]:
    """
    Map tag-object SHA to its tag name and peeled commit SHA.

    This is the lookup behind the ``ANNOTATED_TAG_SHA`` remediation
    message: given the SHA a workflow is pinned to, it yields both the tag
    that SHA belongs to and the commit SHA to use instead.

    Args:
        url: Git repository URL
        config: Git configuration

    Returns:
        Dictionary mapping tag-object SHA to :class:`AnnotatedTagPeel`.
        Lightweight tags never appear, since they have no tag object.

    Raises:
        GitError: If operation fails
    """
    unpeeled, peeled = _split_tag_ref_shas(_run_ls_remote_tags(url, config))

    return _annotated_tag_peels(unpeeled, peeled)


def get_remote_tag_object_shas(url: str, config: GitConfig) -> dict[str, str]:
    """
    Map tag-object SHA to tag name, for annotated tags only.

    A tag is annotated when ls-remote emits both an unpeeled line and a
    ``^{}`` peeled line whose SHAs differ.

    Args:
        url: Git repository URL
        config: Git configuration

    Returns:
        Dictionary mapping tag-object SHA to tag name

    Raises:
        GitError: If operation fails
    """
    return {
        tag_object_sha: peel.tag
        for tag_object_sha, peel in get_annotated_tag_peels(url, config).items()
    }


def get_remote_ref_shas(url: str, config: GitConfig) -> RemoteRefShas:
    """
    Get remote ref SHAs, split into commits and annotated tag objects.

    ``git ls-remote --heads --tags`` advertises a tag object *and* the
    commit it peels to for every annotated tag. Collecting both into one
    set makes a tag-object SHA look like a valid commit, so they are kept
    apart here.

    Args:
        url: Git repository URL
        config: Git configuration

    Returns:
        :class:`RemoteRefShas` with disjoint commit and tag-object SHAs

    Raises:
        GitError: If operation fails
    """
    cmd = ["git", "ls-remote", "--heads", "--tags", url]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout_seconds,
            check=True,
        )

        pairs = _parse_ls_remote_lines(result.stdout)
        unpeeled, peeled = _split_tag_ref_shas(pairs)
        tag_objects = _annotated_tag_peels(unpeeled, peeled)
        commit_shas = frozenset(sha for sha, _ in pairs) - set(tag_objects)

        return RemoteRefShas(commit_shas=commit_shas, tag_objects=tag_objects)

    except subprocess.TimeoutExpired:
        raise GitError(f"Git ls-remote timed out for {url}") from None
    except subprocess.CalledProcessError as e:
        raise GitError(f"Git ls-remote failed for {url}: {e.stderr}") from e
    except Exception as e:
        raise GitError(f"Git ls-remote failed for {url}: {e}") from e


def get_all_remote_refs(url: str, config: GitConfig) -> set[str]:
    """
    Get all SHAs from remote refs (heads and tags).

    Note the returned set includes annotated tag-object SHAs alongside
    commit SHAs, which is why it is unsafe for deciding whether a pinned
    SHA is checkout-able; use :func:`get_remote_ref_shas` for that.

    Args:
        url: Git repository URL
        config: Git configuration

    Returns:
        Set of SHAs

    Raises:
        GitError: If operation fails
    """
    remote_refs = get_remote_ref_shas(url, config)

    return set(remote_refs.commit_shas) | set(remote_refs.tag_objects)


__all__ = [
    "AnnotatedTagPeel",
    "RemoteRefShas",
    "get_all_remote_refs",
    "get_annotated_tag_peels",
    "get_remote_ref_shas",
    "get_remote_tag_object_shas",
    "get_remote_tag_shas",
]
