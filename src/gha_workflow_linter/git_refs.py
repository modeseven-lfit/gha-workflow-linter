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
separate from :mod:`gha_workflow_linter.action_call_git` so both the
validation path and the version-resolution path share one definition of
how refs are read.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import re
import subprocess
from typing import TYPE_CHECKING, Final

from .exceptions import GitError, GitUnreachableError, GitUnusableError

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


#: Fragments git writes to standard error when it could not reach the
#: remote, as opposed to reaching it and being told no. The exit status
#: does not distinguish them -- ``128`` covers both -- so the message is
#: the only evidence available.
#:
#: These cover the failures git reports in its own or SSH's words. The
#: HTTP transport is handled by rule instead, below, because the ways a
#: connection can fail have no end and enumerating them was losing.
#:
#: SSH is not closed the same way, and the asymmetry is deliberate. Over
#: HTTP the shape of an answer is fixed by the protocol and written by
#: git, so excluding it is safe. Over SSH the answer comes from whatever
#: the server chooses to print, and inverting the test there would mean
#: that wording we had not anticipated silently suppressed a finding --
#: the failure worth avoiding most, since it passes a workflow that is
#: wrong.
_TRANSPORT_FAILURE_MARKERS: Final = (
    "could not resolve host",
    "could not resolve proxy",
    "temporary failure in name resolution",
    "failed to connect",
    "couldn't connect to server",
    "connection refused",
    "connection timed out",
    "operation timed out",
    "network is unreachable",
    "no route to host",
    "connection reset by peer",
    "unable to look up",
    # SSH speaks for itself, outside git's HTTP wording. A dropped
    # handshake arrives before the git protocol has begun -- earlier
    # than any answer about a repository could be given.
    "ssh: connect to host",
    "kex_exchange_identification:",
    "connection closed by",
    "unexpected disconnect while reading sideband packet",
    # The SSH counterpart of a rejected certificate: the session is
    # refused over how the host identified itself, so nothing was ever
    # asked about the repository.
    "host key verification failed",
    "remote host identification has changed",
    # git started, but could not start what it needs to reach the
    # remote: no ssh on PATH, no memory to fork, or a missing transport
    # helper. The lookup ends before the URL is ever opened.
    "cannot run",
    "unable to fork",
    "unable to find remote helper",
    "is not a git command",
)

#: git introduces every HTTP failure with ``unable to access '<url>':``
#: and appends curl's reason for it.
_HTTP_ATTEMPT_MARKER: Final = "unable to access"

#: The one reason under that prefix that carries a reply from the
#: server, since HTTP states a verdict in the status code and nowhere
#: else.
_HTTP_STATUS_PATTERN: Final = re.compile(
    r"the requested url returned error:\s*(\d{3})"
)


#: 4xx statuses that carry no verdict about the repository. Everything
#: from 500 up is the server failing and is caught by range; these are
#: the client errors that mean something other than "no" -- 408 when the
#: server gave up receiving the request, 429 when it will not take
#: another yet, and 407 when a proxy in between refused to pass it on,
#: so GitHub never saw it at all.
_CLIENT_ERRORS_WITHOUT_AN_ANSWER: Final = frozenset({407, 408, 429})


def git_environment() -> dict[str, str]:
    """The environment every git command here runs in.

    git translates its messages, and this module reads them: the
    transport classifier looks for English. Under a translated locale it
    would recognise nothing, so every failure would look like the remote
    answering -- turning a broken network back into findings about the
    workflow, for exactly the developers whose environment is not
    English. The bug this change removes would have survived there.

    ``LC_ALL=C`` settles it. ``LANGUAGE`` is cleared as well because
    gettext consults it ahead of the locale; it is ignored once the
    locale is ``C``, but not relying on that costs nothing.

    Returns:
        A copy of the current environment with the locale pinned, so
        that credentials, ``PATH`` and the SSH agent still reach git.
    """
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env.pop("LANGUAGE", None)
    return env


def _status_withholds_an_answer(status: int) -> bool:
    """Whether an HTTP status declined to answer about the repository.

    A 5xx is the server failing; 408 or 429 is it declining to be asked
    just now; 407 is a proxy in between refusing to pass the request on,
    so GitHub never saw it. None says anything about whether the
    repository exists, so reporting one as a finding would blame a
    workflow for an outage elsewhere. Other 4xx codes do answer: 404 for
    absent, 403 for present but not ours to see.

    The API backend treats the same transient codes that way, raising
    ``TemporaryAPIError`` and ``RateLimitError``. It does not report the
    remaining 4xx as findings either -- 403 becomes an
    ``AuthenticationError`` and the rest a ``GitHubAPIError``, both of
    which abort -- so the two backends agree on what is transient
    without agreeing on what to do with an answer.

    Args:
        status: The HTTP status git reported.

    Returns:
        ``True`` when the status is no verdict about the repository.
    """
    return status >= 500 or status in _CLIENT_ERRORS_WITHOUT_AN_ANSWER


def is_transport_failure(stderr: str | None) -> bool:
    """Whether git failed because it could not reach the remote.

    Over HTTP the question is settled by rule rather than by a list, and
    that rule is applied first. Reading git's generic ``unable to
    access`` prefix as a transport fault is wrong on its own -- it
    introduces a 404 as readily as a lost connection, and calling that
    unreachable would discard a real finding. But the remote's answer
    can only arrive as a status code, so *any other* reason under that
    prefix is curl reporting that it never got one. Naming those reasons
    individually meant a fragment per way a connection can fail, which
    has no end; excluding the shapes an answer takes closes the set
    instead.

    A status is present but not always an answer: see
    :func:`_status_withholds_an_answer`.

    The fragments are consulted only when that prefix is absent, because
    they are matched against the whole message -- which includes the URL
    git was asked for, and therefore the repository's own name. A
    repository called ``kex_exchange_identification`` would otherwise
    answer 404 and have its finding discarded on the strength of its
    name.

    Args:
        stderr: Standard error from the failed invocation, if captured.

    Returns:
        ``True`` when the failure was in reaching the remote rather than
        in what the remote said.
    """
    if not stderr:
        return False
    lowered = stderr.lower()
    if _HTTP_ATTEMPT_MARKER in lowered:
        reported = _HTTP_STATUS_PATTERN.search(lowered)
        if reported is None:
            # curl gave a reason other than a status, so it never got one.
            return True
        return _status_withholds_an_answer(int(reported.group(1)))
    return any(marker in lowered for marker in _TRANSPORT_FAILURE_MARKERS)


def was_killed_by_signal(returncode: int | None) -> bool:
    """Whether the process was terminated rather than allowed to exit.

    POSIX reports this as a negative return code. A git killed part way
    through -- by the out-of-memory killer, or by a CI job being
    cancelled -- never reached the point of having anything to say, so
    its silence carries no verdict. Without this the empty output of a
    killed process reads as the remote answering no.

    Args:
        returncode: Status the process finished with, if known.

    Returns:
        ``True`` when a signal ended the process.
    """
    return returncode is not None and returncode < 0


def ls_remote_failure(
    summary: str, stderr: str | None, original: Exception
) -> GitError:
    """Build the right error for a failed ``ls-remote``.

    Args:
        summary: What was being attempted.
        stderr: Standard error from the invocation.
        original: The underlying exception.

    Returns:
        A :class:`GitUnusableError` when a signal ended the process, a
        :class:`GitUnreachableError` when the remote was never reached,
        otherwise a plain :class:`GitError`.
    """
    detail = f"{summary}: {stderr}"
    if isinstance(
        original, subprocess.CalledProcessError
    ) and was_killed_by_signal(original.returncode):
        return GitUnusableError(detail, original)
    if is_transport_failure(stderr):
        return GitUnreachableError(detail, original)
    return GitError(detail, original)


def git_invocation_failure(summary: str, original: Exception) -> GitError:
    """Build the right error for a git command that would not run.

    This is the last resort of each remote helper, reached when the
    failure was neither a non-zero exit nor a timeout. An
    :class:`OSError` here means the command never started -- ``git`` is
    absent, or not executable -- so the remote was never asked, and its
    silence says nothing about the repository. Anything else is a fault
    in handling the reply, which is a defect in this code rather than a
    verdict about the network, and keeps the plain type.

    Args:
        summary: What was being attempted.
        original: The underlying exception.

    Returns:
        A :class:`GitUnusableError` when the command never ran,
        otherwise a plain :class:`GitError`.
    """
    detail = f"{summary}: {original}"
    if isinstance(original, OSError):
        return GitUnusableError(detail, original)
    return GitError(detail, original)


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
            env=git_environment(),
            check=True,
        )

        return _parse_ls_remote_lines(result.stdout)

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
            env=git_environment(),
            check=True,
        )

        pairs = _parse_ls_remote_lines(result.stdout)
        unpeeled, peeled = _split_tag_ref_shas(pairs)
        tag_objects = _annotated_tag_peels(unpeeled, peeled)
        commit_shas = frozenset(sha for sha, _ in pairs) - set(tag_objects)

        return RemoteRefShas(commit_shas=commit_shas, tag_objects=tag_objects)

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
