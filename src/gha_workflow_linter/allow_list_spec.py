# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Parsing of the allow-list ``config`` coordinate grammar.

``step-security/harden-runner`` egress allow-lists reach a workflow
through the ``config`` input of
``lfreleng-actions/harden-runner-block-action``, written as a
GitHub-Actions ``uses:``-style coordinate::

    <config> ::= <source> [ "@" <ref> ] [ <ws>+ "#" <comment> ]
    <source> ::= [ <host-org> [ "/" <repo> ] ] [ "//" <subpath> ]

Dependabot cannot see those coordinates, so the SHAs they pin drift.
Detecting that drift requires the linter to read the grammar exactly as
the action reads it: any divergence produces findings against pins that
are in fact valid.

This module is a **port of the parsing half** of
``src/resolve_config_source.py``, a file mirrored byte-for-byte between
two repositories:

* ``lfreleng-actions/harden-runner-block-action``
* ``lfreleng-actions/python-audit-action``

A CI check in each of those repositories diffs the file against the
other's copy, so the grammar has exactly one definition. **Any change
made to it upstream must be reflected here.** Only parsing and
resolution are ported -- this module is pure, and performs no network,
filesystem or subprocess work whatsoever. ``tests/test_allow_list_spec``
carries a port of the upstream conformance tests so that divergence
shows up as a test failure rather than as a false finding.

The port makes two deliberate, behaviour-preserving changes: results are
frozen dataclasses rather than ``dict`` objects, and the error type
derives from :class:`ValueError` rather than :class:`Exception`. Neither
changes which inputs are accepted or rejected.

:func:`render_spec` has no upstream counterpart. Remediation needs to
rebuild a coordinate around a new ref while disturbing nothing else the
author wrote, which is why :class:`ResolvedSpec` retains the raw source
components in :attr:`ResolvedSpec.source` alongside the resolved ones.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

__all__ = [
    "DEFAULT_FAMILY",
    "DEFAULT_FILENAME",
    "DEFAULT_REPO",
    "MAX_REF_LENGTH",
    "ORG_RE",
    "REF_RE",
    "REPO_RE",
    "SEGMENT_RE",
    "ResolvedSpec",
    "SpecError",
    "SpecParts",
    "parse_spec",
    "render_spec",
    "resolve_spec",
    "split_comment",
]

#: GitHub org/user names: 1-39 chars, alphanumerics and single hyphens,
#: no leading/trailing hyphen, no consecutive hyphens.
ORG_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")

#: Repository names: alphanumerics plus ``.``, ``_``, ``-``. The
#: canonical host repo is the special ``.github`` repo, so a leading dot
#: must be allowed.
REPO_RE = re.compile(r"^[A-Za-z0-9._-]+$")

#: A single in-repo path segment. No empty segments, no slashes (the
#: path is split on ``/`` before validation), no shell metacharacters.
#: ``..`` matches this pattern and is rejected separately.
SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")

#: Git ref: branch name, tag name, or commit SHA. A conservative subset
#: of the characters git permits.
REF_RE = re.compile(r"^[A-Za-z0-9._/-]+$")

#: Trailing comment separator: a ``#`` preceded by at least one space or
#: tab, running to end of line. Newlines are excluded deliberately (see
#: :func:`split_comment`).
_COMMENT_RE = re.compile(r"[ \t]+#[^\r\n]*$")

#: Longest ref the upstream parser accepts.
MAX_REF_LENGTH = 255

#: Config family for ``harden-runner-block-action``. The sibling
#: ``python-audit-action`` passes ``"python-audit"``; the parser itself
#: holds no per-action constants, so the family is always a caller
#: concern.
DEFAULT_FAMILY = "harden-runner"

#: Repository assumed when the coordinate names only an org.
DEFAULT_REPO = ".github"

#: Filename assumed when the coordinate names no file.
DEFAULT_FILENAME = "allow_list.txt"

#: The ref standing for "the host repository's default branch".
HEAD_REF = "HEAD"


class SpecError(ValueError):
    """A config spec that does not satisfy the grammar.

    Upstream raises a bare ``ResolveError(Exception)`` because it fails
    the action; here the condition is "this string is not a valid
    coordinate", for which :class:`ValueError` is the natural base.
    """


@dataclass(frozen=True)
class SpecParts:
    """The raw components of a config spec, before defaults apply.

    Attributes:
        repospec: Text before ``//`` (or the whole source when no ``//``
            is present); ``""`` when the coordinate omits it.
        subpath: Text after ``//``; ``""`` when absent or empty.
        has_subpath: Whether a ``//`` separator was present at all. A
            bare ``//`` is not the same as no ``//`` for round-tripping,
            though both resolve identically.
        ref: Text after ``@``; ``""`` when the coordinate omits the ref.
    """

    repospec: str
    subpath: str
    has_subpath: bool
    ref: str


@dataclass(frozen=True)
class ResolvedSpec:
    """A config spec resolved into concrete lookup coordinates.

    Attributes:
        host_org: Org owning the repository that holds the file.
        repo: Repository within ``host_org``.
        ref: Git ref to read at; ``"HEAD"`` when the spec omitted one.
        candidates: Ordered in-repo paths to try. One entry when the
            author gave an explicit path, otherwise the two-entry
            search chain.
        path_explicit: Whether the author gave an explicit in-repo path,
            disabling the search chain.
        comment: In-scalar trailing comment, ``""`` when there is none.
            Informational only; it never affects resolution.
        source: The raw components the spec was written with, retained
            so that :func:`render_spec` can rebuild the source form
            without normalising away the author's choices.
    """

    host_org: str
    repo: str
    ref: str
    candidates: tuple[str, ...]
    path_explicit: bool
    comment: str
    source: SpecParts


def split_comment(value: str) -> tuple[str, str]:
    """Split a trailing ``' #...'`` comment off a config spec.

    The separator is one or more spaces or tabs before the ``#``, so
    ``foo#bar`` is a single token rather than a token plus a comment.

    A newline is deliberately *not* accepted as the separator. Were it
    accepted, ``"lfit@main\\n# hidden"`` would split into a clean spec
    plus a comment and slip past the newline rejection in
    :func:`parse_spec`.

    Args:
        value: The raw scalar value.

    Returns:
        A ``(spec, comment)`` tuple. ``comment`` has its leading
        whitespace and ``#`` removed and is stripped; it is ``""`` when
        the value carries no trailing comment.
    """
    match = _COMMENT_RE.search(value)
    if match is None:
        return value, ""
    comment = value[match.start() :].lstrip(" \t")[1:].strip()
    return value[: match.start()], comment


def parse_spec(spec: str) -> SpecParts:
    """Parse a config spec into its raw components.

    The grammar handled here is::

        <spec>     ::= <source> [ "@" <ref> ]
        <source>   ::= <repospec> [ "//" <subpath> ]
        <repospec> ::= [ <host-org> [ "/" <repo> ] ]
        <subpath>  ::= [ <dir> "/" ]... [ <filename> ]

    Any trailing comment must already have been removed with
    :func:`split_comment`.

    Args:
        spec: The comment-free spec text.

    Returns:
        The raw components, with no defaults applied and no validation
        of their contents beyond the separator rules.

    Raises:
        SpecError: The spec contains a newline, more than one ``@``,
            an empty ref after ``@``, or more than one ``//``.
    """
    if "\n" in spec or "\r" in spec:
        raise SpecError("config must not contain newline characters")

    ref = ""
    if "@" in spec:
        source, _, ref = spec.partition("@")
        if "@" in ref:
            raise SpecError("config contains more than one '@' separator")
        if ref == "":
            raise SpecError("config has an empty ref after '@'")
    else:
        source = spec

    subpath = ""
    has_subpath = False
    if "//" in source:
        repospec, _, subpath = source.partition("//")
        has_subpath = True
        if "//" in subpath:
            raise SpecError("config contains more than one '//' separator")
    else:
        repospec = source

    return SpecParts(
        repospec=repospec,
        subpath=subpath,
        has_subpath=has_subpath,
        ref=ref,
    )


def _resolve_repository(
    repospec: str, *, workflow_org: str, default_repo: str
) -> tuple[str, str]:
    """Apply defaults to the repository part and validate it.

    Args:
        repospec: Raw text before any ``//`` separator.
        workflow_org: Org of the workflow being linted, used when the
            coordinate omits the host org.
        default_repo: Repository assumed when the coordinate names only
            an org.

    Returns:
        A ``(host_org, repo)`` tuple.

    Raises:
        SpecError: The repository part has more than two segments, or
            either segment fails validation.
    """
    trimmed = repospec.strip("/")
    if trimmed == "":
        host_org, repo = workflow_org, default_repo
    else:
        segments = trimmed.split("/")
        if len(segments) == 1:
            host_org, repo = segments[0], default_repo
        elif len(segments) == 2:
            host_org, repo = segments[0], segments[1]
        else:
            raise SpecError(
                "config repository part accepts at most '<org>/<repo>'; "
                "put any in-repo path after '//'"
            )

    if host_org == "":
        host_org = workflow_org
    if not ORG_RE.match(host_org):
        raise SpecError(f"invalid host org in config: '{host_org}'")
    if repo == "":
        repo = default_repo
    if repo in ("..", ".") or not REPO_RE.match(repo):
        raise SpecError(f"invalid repository in config: '{repo}'")
    return host_org, repo


def _validate_ref(ref: str) -> str:
    """Validate a git ref and return it unchanged.

    ``HEAD`` stands for the host repository's default branch and is
    accepted without further checks.

    Args:
        ref: The ref to validate.

    Returns:
        The ref, unchanged.

    Raises:
        SpecError: The ref is empty, over-long, starts with ``-`` or
            ``/``, contains ``..`` or ``@{``, or holds a character
            outside :data:`REF_RE`.
    """
    if ref == HEAD_REF:
        return ref
    if (
        ref == ""
        or ref.startswith("-")
        or ref.startswith("/")
        or ".." in ref
        or "@{" in ref
        or len(ref) > MAX_REF_LENGTH
        or not REF_RE.match(ref)
    ):
        raise SpecError(f"invalid git ref in config: '{ref}'")
    return ref


def _resolve_candidates(
    parts: SpecParts,
    *,
    workflow_org: str,
    family: str,
    default_filename: str,
) -> tuple[tuple[str, ...], bool]:
    """Turn the subpath into the ordered list of paths to try.

    Args:
        parts: The raw parsed components.
        workflow_org: Org of the workflow being linted; it names the
            org-specific directory in the search chain.
        family: Config family, for example ``harden-runner``. The
            parser is family-agnostic: callers supply it.
        default_filename: Filename assumed when the spec names none.

    Returns:
        A ``(candidates, path_explicit)`` tuple. ``candidates`` holds
        the two-entry search chain unless the author gave an explicit
        path, in which case it holds that path alone.
    """
    org_specific_dir = f".github/{family}/{workflow_org}"
    family_dir = f".github/{family}"

    if not parts.has_subpath or parts.subpath == "":
        filename = default_filename
    elif "/" not in parts.subpath:
        filename = parts.subpath
    else:
        return (parts.subpath,), True

    return (
        f"{org_specific_dir}/{filename}",
        f"{family_dir}/{filename}",
    ), False


def _validate_candidates(candidates: tuple[str, ...]) -> None:
    """Validate every segment of every candidate in-repo path.

    Args:
        candidates: The resolved candidate paths.

    Raises:
        SpecError: A path is absolute, holds a backslash or a ``..``
            segment, has an empty segment, or has a segment outside
            :data:`SEGMENT_RE`.
    """
    for candidate in candidates:
        segments = candidate.split("/")
        if (
            candidate.startswith("/")
            or "\\" in candidate
            or ".." in segments
            or any(segment == "" for segment in segments)
        ):
            raise SpecError(f"invalid in-repo path in config: '{candidate}'")
        for segment in segments:
            if not SEGMENT_RE.match(segment):
                raise SpecError(
                    f"invalid path segment '{segment}' in config path "
                    f"'{candidate}'"
                )


def resolve_spec(
    spec: str,
    *,
    workflow_org: str,
    family: str = DEFAULT_FAMILY,
    default_repo: str = DEFAULT_REPO,
    default_filename: str = DEFAULT_FILENAME,
) -> ResolvedSpec:
    """Resolve a config spec into concrete lookup coordinates.

    Args:
        spec: The raw scalar value, with or without a trailing comment
            and with or without surrounding whitespace.
        workflow_org: Org owning the workflow being linted. It supplies
            the host org when the spec omits it, and names the
            org-specific directory of the search chain.
        family: Config family; ``harden-runner`` for the allow-list
            action, ``python-audit`` for its sibling.
        default_repo: Repository assumed when the spec names only an
            org.
        default_filename: Filename assumed when the spec names none.

    Returns:
        The resolved spec.

    Raises:
        SpecError: The spec is empty or violates the grammar in any of
            the ways described by the helpers it delegates to.
    """
    text, comment = split_comment(spec.strip())
    if text == "":
        raise SpecError("config is empty")

    parts = parse_spec(text)
    host_org, repo = _resolve_repository(
        parts.repospec,
        workflow_org=workflow_org,
        default_repo=default_repo,
    )
    ref = _validate_ref(parts.ref or HEAD_REF)
    candidates, path_explicit = _resolve_candidates(
        parts,
        workflow_org=workflow_org,
        family=family,
        default_filename=default_filename,
    )
    _validate_candidates(candidates)

    if workflow_org != "" and not ORG_RE.match(workflow_org):
        raise SpecError(f"invalid workflow org: '{workflow_org}'")

    return ResolvedSpec(
        host_org=host_org,
        repo=repo,
        ref=ref,
        candidates=candidates,
        path_explicit=path_explicit,
        comment=comment,
        source=parts,
    )


def render_spec(spec: ResolvedSpec, *, ref: str) -> str:
    """Rebuild the source form of a spec around a (possibly new) ref.

    Remediation rewrites the ref and nothing else, so the repository and
    subpath parts are re-emitted exactly as the author wrote them --
    including a bare ``//``, an omitted org, or a redundant separator
    that resolution would otherwise normalise away. Round-tripping a
    valid spec with its own :attr:`ResolvedSpec.ref` therefore
    reproduces its source form character for character.

    Three properties of the source form are, by definition, outside what
    this returns, and callers must handle them:

    1. Any trailing comment. :func:`split_comment` removed it, and
       comment rewriting belongs to the caller.
    2. Whitespace around the spec, which
       :func:`resolve_spec` strips before parsing.
    3. A ref that the author omitted. Rendering with a real ref adds
       ``@<ref>``; that is the point of the function. The ref is only
       omitted when it is ``HEAD`` *and* the author wrote no ``@`` --
       so a spec that named ``@HEAD`` explicitly keeps it.

    Args:
        spec: A previously resolved spec.
        ref: The ref to emit. ``HEAD`` requests the default branch.

    Returns:
        The source form, without any trailing comment. It is never
        empty: an empty source implies the author wrote a ref, so at
        minimum ``@<ref>`` is emitted.

    Raises:
        SpecError: ``ref`` is not a valid git ref.
    """
    _validate_ref(ref)
    source = spec.source.repospec
    if spec.source.has_subpath:
        source = f"{source}//{spec.source.subpath}"
    if ref == HEAD_REF and spec.source.ref == "":
        return source
    return f"{source}@{ref}"
