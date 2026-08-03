# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Parsing of in-workflow linter-suppression directives.

A repository may declare that a pinned reference is deliberately held at
an older version, so that the linter does not report it. Two authoring
forms are supported.

Form 1 -- a directive on the *immediately* preceding line::

    - uses: owner/repo@6db537b3...  # v0.2.1
      with:
        # gha-workflow-linter: allow-list-pin-ok
        config: '@8f4f0cf8...'  # v0.5.1

Form 2 -- an inline keyword appended after the version token in the
trailing comment::

    config: '@8f4f0cf8...'  # v0.5.1 allow-list-pin-ok

Either form accepts an optional free-text reason, introduced by a ``--``
token surrounded by whitespace::

    config: '@8f4f0cf8...'  # v0.5.1 allow-list-pin-ok -- upstream is broken
    # gha-workflow-linter: allow-list-pin-ok -- waiting for a release

The grammar implemented here is::

    <preceding>  ::= <ws>* "#" <ws>* "gha-workflow-linter:" <ws>+ <body>
    <inline>     ::= <version-token> <ws>+ <body>
    <body>       ::= <directives> [ <reason> ]
    <directives> ::= <directive> ( <ws>+ <directive> )*
    <directive>  ::= "allow-list-pin-ok"
    <reason>     ::= <ws>+ "--" <ws>+ <free text>

Tokens that are neither the version nor a recognised directive are kept
verbatim so that a rewrite of the comment (see :func:`render_comment`)
never discards author content.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re

__all__ = [
    "Directive",
    "ParsedComment",
    "Suppression",
    "SuppressionSource",
    "find_suppression",
    "parse_preceding_directive",
    "parse_trailing_comment",
    "render_comment",
]


class Directive(str, Enum):
    """A recognised linter-suppression directive."""

    ALLOW_LIST_PIN_OK = "allow-list-pin-ok"


class SuppressionSource(str, Enum):
    """Where a directive was authored."""

    PRECEDING_LINE = "preceding_line"
    INLINE_COMMENT = "inline_comment"


@dataclass(frozen=True)
class ParsedComment:
    """A trailing comment split into version, directives and reason."""

    version: str | None
    directives: frozenset[Directive]
    reason: str | None
    unrecognised: tuple[str, ...]


@dataclass(frozen=True)
class Suppression:
    """An effective suppression resolved for a single pinned line."""

    directives: frozenset[Directive]
    source: SuppressionSource
    reason: str | None


#: Marker introducing a preceding-line directive comment. Matched
#: case-sensitively, at any indentation.
_PRECEDING_RE = re.compile(
    r"^\s*#\s*gha-workflow-linter:\s+(?P<body>.*)$",
)

#: A ``--`` token acting as the reason introducer. Both sides must be
#: whitespace, so ``--fix`` or ``a--b`` remain ordinary tokens.
_REASON_RE = re.compile(r"\s--\s")

#: Lookup from directive keyword to enum member.
_DIRECTIVES_BY_VALUE: dict[str, Directive] = {
    directive.value: directive for directive in Directive
}


def _strip_comment_markers(comment: str) -> str:
    """Remove leading ``#`` characters and surrounding whitespace.

    Accepts a comment body with or without its leading marker, so that
    ``"# v0.5.1"``, ``"## v0.5.1"`` and ``"v0.5.1"`` are equivalent.

    Args:
        comment: Raw comment text.

    Returns:
        The comment text with every leading ``#`` and any surrounding
        whitespace removed.
    """
    text = comment.strip()
    while text.startswith("#"):
        text = text[1:].strip()
    return text


def _split_reason(text: str) -> tuple[str, str | None]:
    """Split a body into its token portion and its optional reason.

    Only the first whitespace-delimited ``--`` introduces the reason, so
    a reason may itself contain ``--``. A trailing ``--`` with no text
    after it is not a reason introducer and is left as a token.

    Args:
        text: Comment body with any comment markers already removed.

    Returns:
        A ``(tokens_text, reason)`` tuple. ``reason`` is ``None`` when
        the body carries no reason.
    """
    match = _REASON_RE.search(text)
    if match is None:
        return text, None
    reason = text[match.end() :].strip()
    if not reason:
        return text, None
    return text[: match.start()], reason


def _classify_tokens(
    tokens: list[str],
) -> tuple[frozenset[Directive], tuple[str, ...]]:
    """Partition tokens into recognised directives and everything else.

    Args:
        tokens: Whitespace-separated tokens from a comment body.

    Returns:
        A ``(directives, unrecognised)`` tuple. ``unrecognised`` keeps
        the original order and spelling of the tokens it holds.
    """
    directives: set[Directive] = set()
    unrecognised: list[str] = []
    for token in tokens:
        directive = _DIRECTIVES_BY_VALUE.get(token)
        if directive is not None:
            directives.add(directive)
        else:
            unrecognised.append(token)
    return frozenset(directives), tuple(unrecognised)


def parse_trailing_comment(comment: str | None) -> ParsedComment:
    """Parse a trailing comment body (with or without a leading ``#``).

    The version token, when present, is always the first token; a
    comment consisting solely of directives therefore has no version.

    Args:
        comment: Trailing comment text, or ``None`` when the line
            carries no comment.

    Returns:
        The parsed comment. Absent parts are ``None`` or empty.
    """
    if comment is None:
        return ParsedComment(
            version=None,
            directives=frozenset(),
            reason=None,
            unrecognised=(),
        )

    text = _strip_comment_markers(comment)
    body, reason = _split_reason(text)
    tokens = body.split()

    version: str | None = None
    if tokens and tokens[0] not in _DIRECTIVES_BY_VALUE:
        version = tokens[0]
        tokens = tokens[1:]

    directives, unrecognised = _classify_tokens(tokens)
    return ParsedComment(
        version=version,
        directives=directives,
        reason=reason,
        unrecognised=unrecognised,
    )


def parse_preceding_directive(line: str) -> Suppression | None:
    """Parse a standalone ``# gha-workflow-linter: ...`` comment line.

    Indentation is irrelevant: the comment may sit at any column. The
    marker is matched case-sensitively.

    Args:
        line: The complete source line to inspect.

    Returns:
        The suppression the line declares, or ``None`` when the line is
        not a directive comment or declares no recognised directive.
    """
    match = _PRECEDING_RE.match(line)
    if match is None:
        return None

    body, reason = _split_reason(match.group("body").strip())
    directives, _unrecognised = _classify_tokens(body.split())
    if not directives:
        return None

    return Suppression(
        directives=directives,
        source=SuppressionSource.PRECEDING_LINE,
        reason=reason,
    )


def find_suppression(
    *, comment: str | None, preceding_line: str | None
) -> Suppression | None:
    """Resolve the effective suppression for a pinned line.

    The preceding-line form is only honoured when ``preceding_line`` is
    the *immediately* preceding line. Callers are responsible for
    supplying it (or ``None`` when the previous line is blank or is not
    a comment).

    Both forms may be present; that is not an error. The directive sets
    are unioned, the source is reported as
    :attr:`SuppressionSource.INLINE_COMMENT`, and the inline reason wins
    when both carry one.

    Args:
        comment: Trailing comment on the pinned line, if any.
        preceding_line: The immediately preceding source line, if any.

    Returns:
        The effective suppression, or ``None`` when neither form
        declares a recognised directive.
    """
    inline = parse_trailing_comment(comment)
    preceding = (
        parse_preceding_directive(preceding_line)
        if preceding_line is not None
        else None
    )

    if inline.directives and preceding is not None:
        reason = inline.reason
        if reason is None:
            reason = preceding.reason
        return Suppression(
            directives=inline.directives | preceding.directives,
            source=SuppressionSource.INLINE_COMMENT,
            reason=reason,
        )
    if inline.directives:
        return Suppression(
            directives=inline.directives,
            source=SuppressionSource.INLINE_COMMENT,
            reason=inline.reason,
        )
    return preceding


def render_comment(parsed: ParsedComment, *, version: str | None) -> str:
    """Re-render a parsed comment with a (possibly new) version token.

    Preserves directives, unrecognised tokens and reason text, so a
    version bump never loses author content. Parts are emitted in the
    order ``<version> <directives...> <unrecognised...> -- <reason>``,
    separated by single spaces, with absent parts omitted. Directives
    render in alphabetical order of their keyword, for stable output.

    Args:
        parsed: The previously parsed comment.
        version: Version token to emit, or ``None`` to emit none.

    Returns:
        The comment body, without the leading ``#``.
    """
    parts: list[str] = []
    if version is not None:
        parts.append(version)
    parts.extend(sorted(directive.value for directive in parsed.directives))
    parts.extend(parsed.unrecognised)
    if parsed.reason is not None:
        parts.append("--")
        parts.append(parsed.reason)
    return " ".join(parts)
