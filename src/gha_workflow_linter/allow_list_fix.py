# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""In-place remediation of stale allow-list pins.

:mod:`gha_workflow_linter.allow_list_check` decides *what* is wrong with
a pin. This module performs the one repair that follows from it: move
the ref, correct the version comment, and change nothing else.

    config: '@18d9c4446bea555d0783e850f6d295f844fe8f67'  # v0.1.1
    config: '@bf6642f68d58c1b81bbe993e676d6cc339ac3654'  # v0.12.2

The rewrite is a **surgical substring replacement** on the pin's own
source line, never a reconstruction of it from parsed fields. That
distinction is the whole design (§10.1), and it is not fussiness:
:meth:`~gha_workflow_linter.action_call_fix.AutoFixer._build_fixed_line`
rebuilds, and so normalises comment spacing to the ``two_space_comments``
preference as a side effect of an unrelated repair. These edits become
review-ready pull requests, where a reformatted neighbouring comment is
noise a reviewer has to read past. So:

* The quote style survives because the quotes are never touched. SHAs and
  version tags contain no character needing an escape, so there is no
  re-quoting to do.
* The spacing before ``#`` survives because the ``#`` is never touched.
  Three spaces stay three spaces.
* Both comment positions -- a YAML comment outside the quotes, and a
  comment inside the scalar that the consuming action strips itself --
  are rewritten where they sit, never moved.
* Suppression directives and any ``-- reason`` tail survive, because the
  comment body is round-tripped through
  :func:`~gha_workflow_linter.directives.parse_trailing_comment` and
  :func:`~gha_workflow_linter.directives.render_comment`. Dropping a
  suppression while repairing something else would silently re-enable the
  churn its author suppressed.

House style applies to exactly one thing: a comment that does not exist
yet. New content has no author intent to preserve, so it is added with
the project's default two-space separation.

Four conditions stop a rewrite before it starts, each recorded in
:attr:`FixOutcome.skipped` with its reason: a suppressed finding (checked
first, and never rewritten), a multi-line scalar, a finding with no
target commit, and a line whose text no longer matches what the scanner
recorded.

Writes go through :func:`~gha_workflow_linter.file_edit.replace_lines`,
one call per file, so a file is rewritten atomically and keeps its line
endings. Two findings claiming the same line is a bug in the caller's
pipeline rather than a condition to paper over, so it raises
:class:`DuplicateFixError` (§10.3).
"""

from __future__ import annotations

import dataclasses
import logging
from typing import TYPE_CHECKING

from .allow_list_scanner import CommentPosition, QuoteStyle
from .allow_list_spec import SpecError, render_spec, split_comment
from .directives import parse_trailing_comment, render_comment
from .file_edit import replace_lines

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from pathlib import Path

    from .allow_list_check import AllowListFinding
    from .allow_list_scanner import AllowListPin

__all__ = [
    "COMMENT_SEPARATOR",
    "REASON_COMMENT_CHANGED",
    "REASON_COMMENT_NOT_FOUND",
    "REASON_INVALID_REF",
    "REASON_MULTILINE",
    "REASON_NO_TARGET",
    "REASON_SPEC_NOT_FOUND",
    "REASON_SUPPRESSED",
    "AppliedFix",
    "DuplicateFixError",
    "FixOutcome",
    "apply_fixes",
]

logger = logging.getLogger(__name__)

#: Separation between a value and a comment this module *adds*. Existing
#: comments keep whatever separation their author chose; only new content
#: follows the project default of two spaces.
COMMENT_SEPARATOR = "  "

#: Recorded when a directive covers the finding. Suppression is checked
#: before every other condition, so a suppressed pin is never rewritten
#: even when it is also unfixable for some other reason.
REASON_SUPPRESSED = "an allow-list-pin-ok directive covers this finding"

#: Recorded for a scalar spanning several lines. The scanner reports
#: those with ``auto_fixable=False`` and they are never rewritten.
REASON_MULTILINE = "the value is a multi-line scalar"

#: Recorded when the finding names no commit to move to, which leaves
#: nothing to write.
REASON_NO_TARGET = "the finding names no target commit"

#: Recorded when the spec text the scanner captured is absent from the
#: line it captured with it, which means the file changed underneath the
#: scan or the scalar carries YAML escapes.
REASON_SPEC_NOT_FOUND = "the spec is not present on its recorded source line"

#: Recorded when the target commit is not a usable git ref. Defensive:
#: a resolved release always yields a SHA.
REASON_INVALID_REF = "the target commit is not a valid git ref"

#: Recorded when the pin claims a comment that the line does not carry.
REASON_COMMENT_NOT_FOUND = "the version comment is not present on its line"

#: Recorded when the comment on the line no longer says what the scanner
#: recorded, so rewriting it would overwrite something unexamined.
REASON_COMMENT_CHANGED = "the version comment no longer matches the scan"

#: Quote character of each quoted style. Absent for an unquoted scalar.
_QUOTE_CHARACTERS: dict[QuoteStyle, str] = {
    QuoteStyle.SINGLE: "'",
    QuoteStyle.DOUBLE: '"',
}

#: Whitespace permitted around a comment marker.
_BLANK = " \t"


class DuplicateFixError(RuntimeError):
    """Two findings claimed the same line of the same file.

    Attributes:
        file_path: The file both findings named.
        line_number: The 1-based line both findings named.
    """

    def __init__(self, file_path: Path, line_number: int) -> None:
        """Initialise the error.

        Args:
            file_path: The file both findings named.
            line_number: The 1-based line both findings named.
        """
        self.file_path = file_path
        self.line_number = line_number
        super().__init__(
            f"Two allow-list fixes claim line {line_number} of "
            f"{file_path}; one would be silently discarded"
        )


@dataclasses.dataclass(frozen=True)
class AppliedFix:
    """One finding that was written back to its file.

    Attributes:
        finding: The finding the rewrite resolved.
        line_number: 1-based line that was rewritten.
        old_line: The line as it was on disk, without its terminator.
        new_line: The line as written, without its terminator.
    """

    finding: AllowListFinding
    line_number: int
    old_line: str
    new_line: str


@dataclasses.dataclass(frozen=True)
class FixOutcome:
    """Everything one remediation pass did, and declined to do.

    Attributes:
        applied: The rewrites performed, in the order the findings were
            supplied.
        skipped: Each finding that was not rewritten, paired with the
            reason, in the order the findings were supplied.
    """

    applied: list[AppliedFix]
    skipped: list[tuple[AllowListFinding, str]]


@dataclasses.dataclass(frozen=True)
class _Edit:
    """One substitution within a single source line.

    Attributes:
        start: 0-based index of the first character replaced.
        end: 0-based index just past the last character replaced; equal
            to ``start`` for a pure insertion.
        text: Replacement text.
    """

    start: int
    end: int
    text: str


@dataclasses.dataclass(frozen=True)
class _Planned:
    """A rewrite computed but not yet written.

    Attributes:
        finding: The finding the rewrite resolves.
        new_line: Replacement content, without a line terminator.
    """

    finding: AllowListFinding
    new_line: str


class _Unfixable(Exception):
    """Internal signal that one finding cannot be rewritten.

    Attributes:
        reason: Why the finding was declined, for
            :attr:`FixOutcome.skipped`.
    """

    def __init__(self, reason: str) -> None:
        """Initialise the signal.

        Args:
            reason: Why the finding was declined.
        """
        self.reason = reason
        super().__init__(reason)


def apply_fixes(findings: Iterable[AllowListFinding]) -> FixOutcome:
    """Rewrite every fixable finding in place.

    Findings are grouped by file and each file is rewritten with a single
    atomic :func:`~gha_workflow_linter.file_edit.replace_lines` call, so
    a file is either fully updated or untouched. A file all of whose
    findings were skipped is not opened at all, and its modification time
    does not change.

    Args:
        findings: The findings to remediate, in any order. Ones that
            cannot or must not be rewritten are reported rather than
            raised.

    Returns:
        The rewrites performed and the findings declined, each in the
        order the findings were supplied.

    Raises:
        DuplicateFixError: Two findings named the same line of the same
            file, so applying both would silently discard one.
        ValueError: A file no longer has the line a finding names, which
            means it changed after it was scanned.
        OSError: A file could not be read or rewritten. Files handled
            before it keep their rewrites; the failing file is unchanged.
    """
    plans, skipped = _plan_fixes(findings)
    return FixOutcome(applied=_write_plans(plans), skipped=skipped)


def _plan_fixes(
    findings: Iterable[AllowListFinding],
) -> tuple[
    dict[Path, dict[int, _Planned]],
    list[tuple[AllowListFinding, str]],
]:
    """Compute the replacement line for every fixable finding.

    Nothing is written here, so a :class:`DuplicateFixError` leaves every
    file untouched rather than half of them rewritten.

    Args:
        findings: The findings to remediate.

    Returns:
        A ``(plans, skipped)`` tuple. ``plans`` maps each file to its
        planned rewrites by 1-based line number, both mappings in
        first-seen order.

    Raises:
        DuplicateFixError: Two findings named the same line of the same
            file.
    """
    plans: dict[Path, dict[int, _Planned]] = {}
    skipped: list[tuple[AllowListFinding, str]] = []

    for finding in findings:
        pin = finding.pin
        try:
            new_line = _rewrite_line(finding)
        except _Unfixable as declined:
            logger.debug(
                f"Not fixing {pin.file_path}:{pin.line_number}: "
                f"{declined.reason}"
            )
            skipped.append((finding, declined.reason))
            continue

        by_line = plans.setdefault(pin.file_path, {})
        if pin.line_number in by_line:
            raise DuplicateFixError(pin.file_path, pin.line_number)
        by_line[pin.line_number] = _Planned(finding=finding, new_line=new_line)

    return plans, skipped


def _write_plans(plans: dict[Path, dict[int, _Planned]]) -> list[AppliedFix]:
    """Write each file's planned rewrites in one atomic call.

    Args:
        plans: Planned rewrites, keyed by file and 1-based line number.

    Returns:
        One :class:`AppliedFix` per planned rewrite, in planning order.
        ``old_line`` is the content that was actually on disk, which is
        what a caller should render in a diff.

    Raises:
        ValueError: A file no longer has a line a plan names.
        OSError: A file could not be read or rewritten.
    """
    applied: list[AppliedFix] = []
    for path, by_line in plans.items():
        changes = replace_lines(
            path,
            {number: plan.new_line for number, plan in by_line.items()},
        )
        by_number = {change.line_number: change for change in changes}
        for number, plan in by_line.items():
            change = by_number[number]
            applied.append(
                AppliedFix(
                    finding=plan.finding,
                    line_number=number,
                    old_line=change.old_line,
                    new_line=change.new_line,
                )
            )
    return applied


def _rewrite_line(finding: AllowListFinding) -> str:
    """Build the replacement for one finding's source line.

    Args:
        finding: The finding to remediate.

    Returns:
        The complete replacement line, without a terminator.

    Raises:
        _Unfixable: The finding must not, or cannot, be rewritten.
    """
    pin = finding.pin
    if finding.suppressed:
        raise _Unfixable(REASON_SUPPRESSED)
    if not pin.auto_fixable:
        raise _Unfixable(REASON_MULTILINE)
    if finding.target_sha is None:
        raise _Unfixable(REASON_NO_TARGET)

    start, end = _locate_spec(pin)
    edits = [_ref_edit(pin, start, end, finding.target_sha)]
    comment = _comment_edit(pin, end, finding.target_version)
    if comment is not None:
        edits.append(comment)
    return _apply_edits(pin.raw_line, edits)


def _locate_spec(pin: AllowListPin) -> tuple[int, int]:
    """Find the spec text within the pin's source line.

    The search starts at the scalar's own column, so a spec that also
    appears earlier on the line -- in a comment, say -- cannot be matched
    by accident.

    Args:
        pin: The pin to locate.

    Returns:
        The half-open ``(start, end)`` span of the spec text.

    Raises:
        _Unfixable: The spec is not present on the recorded line.
    """
    spec_text = pin.raw_value.strip()
    if not spec_text:
        raise _Unfixable(REASON_SPEC_NOT_FOUND)
    start = pin.raw_line.find(spec_text, max(pin.column, 0))
    if start < 0:
        raise _Unfixable(REASON_SPEC_NOT_FOUND)
    return start, start + len(spec_text)


def _ref_edit(
    pin: AllowListPin,
    start: int,
    end: int,
    target_sha: str,
) -> _Edit:
    """Build the edit that moves the spec's ref to the target commit.

    :func:`~gha_workflow_linter.allow_list_spec.render_spec` re-emits the
    repository and subpath parts exactly as the author wrote them, so the
    rendered spec differs from the original only from the final ``@``
    onwards. Trimming the shared prefix therefore reduces the edit to the
    ref itself -- and to appending ``@<sha>`` when the author wrote no
    ref at all.

    Args:
        pin: The pin being repaired.
        start: Index the spec text starts at.
        end: Index just past the spec text.
        target_sha: Commit the pin should name.

    Returns:
        The edit to apply to the line.

    Raises:
        _Unfixable: ``target_sha`` is not a valid git ref.
    """
    try:
        rendered = render_spec(pin.spec, ref=target_sha)
    except SpecError as error:
        logger.debug(f"Cannot render spec with ref '{target_sha}': {error}")
        raise _Unfixable(REASON_INVALID_REF) from error

    shared = _shared_prefix(pin.raw_line[start:end], rendered)
    return _Edit(start=start + shared, end=end, text=rendered[shared:])


def _shared_prefix(left: str, right: str) -> int:
    """Return how many leading characters two strings have in common.

    Args:
        left: First string.
        right: Second string.

    Returns:
        The length of the common prefix, zero when there is none.
    """
    limit = min(len(left), len(right))
    index = 0
    while index < limit and left[index] == right[index]:
        index += 1
    return index


def _comment_edit(
    pin: AllowListPin,
    spec_end: int,
    target_version: str | None,
) -> _Edit | None:
    """Build the edit that corrects (or adds) the version comment.

    A pin with no comment gains one, separated by
    :data:`COMMENT_SEPARATOR`, at the end of its line -- past any
    trailing whitespace, which is left exactly where its author put it.
    An existing comment has only its body replaced, so the ``#``, the
    spacing on either side of it and, for an in-scalar comment, the
    closing quote are all untouched.

    Args:
        pin: The pin being repaired.
        spec_end: Index just past the spec text on the line.
        target_version: Release tag to name, or ``None`` when the target
            has no tag, in which case the comment is left entirely
            alone rather than stripped of a version it still needs.

    Returns:
        The edit to apply, or ``None`` when the comment needs no change.

    Raises:
        _Unfixable: The pin records a comment that its line does not
            carry, or carries with different content.
    """
    if target_version is None:
        return None

    if pin.comment_position is CommentPosition.NONE:
        end_of_line = len(pin.raw_line)
        return _Edit(
            start=end_of_line,
            end=end_of_line,
            text=f"{COMMENT_SEPARATOR}# {target_version}",
        )

    start, end = _locate_comment_body(pin, spec_end)
    parsed = parse_trailing_comment(pin.raw_line[start:end])
    if parsed.version != pin.version_comment:
        raise _Unfixable(REASON_COMMENT_CHANGED)
    return _Edit(
        start=start,
        end=end,
        text=render_comment(parsed, version=target_version),
    )


def _locate_comment_body(pin: AllowListPin, spec_end: int) -> tuple[int, int]:
    """Find the body of the pin's trailing comment on its line.

    The body excludes the ``#``, the whitespace on either side of it and,
    for an in-scalar comment, the closing quote, so replacing it cannot
    disturb any of them.

    Args:
        pin: The pin being repaired.
        spec_end: Index just past the spec text on the line.

    Returns:
        The half-open ``(start, end)`` span of the comment body.

    Raises:
        _Unfixable: The line carries no comment after the spec, or the
            in-scalar comment's closing quote cannot be found.
    """
    line = pin.raw_line
    tail = line[spec_end:]
    before, comment = split_comment(tail)
    marker = tail.find("#", len(before))
    if not comment or marker < 0:
        raise _Unfixable(REASON_COMMENT_NOT_FOUND)

    start = spec_end + marker + 1
    while start < len(line) and line[start] in _BLANK:
        start += 1

    end = _comment_body_end(pin, start)
    while end > start and line[end - 1] in _BLANK:
        end -= 1
    return start, end


def _comment_body_end(pin: AllowListPin, body_start: int) -> int:
    """Return where the comment body stops, before any trailing text.

    A YAML comment runs to the end of the line. A comment inside the
    scalar stops at the closing quote, which is the last one on the line:
    a quote after it would itself be inside the comment, and a quote
    within the comment body would have to be escaped to survive the YAML
    parse that produced this pin.

    Args:
        pin: The pin being repaired.
        body_start: Index the comment body starts at.

    Returns:
        Index just past the last character of the body.

    Raises:
        _Unfixable: The scalar is quoted but its closing quote is not
            after the comment body, so the line is not the shape the
            scan recorded.
    """
    if pin.comment_position is not CommentPosition.IN_SCALAR:
        return len(pin.raw_line)

    quote = _QUOTE_CHARACTERS.get(pin.quote_style)
    closing = -1 if quote is None else pin.raw_line.rfind(quote)
    if closing < body_start:
        raise _Unfixable(REASON_COMMENT_NOT_FOUND)
    return closing


def _apply_edits(line: str, edits: Sequence[_Edit]) -> str:
    """Apply non-overlapping substitutions to one line.

    Edits are applied from the right so that each one's indices still
    refer to the text they were computed against.

    Args:
        line: The source line, without its terminator.
        edits: The substitutions to make. They must not overlap.

    Returns:
        The rewritten line.
    """
    result = line
    for edit in sorted(edits, key=lambda item: item.start, reverse=True):
        result = result[: edit.start] + edit.text + result[edit.end :]
    return result
