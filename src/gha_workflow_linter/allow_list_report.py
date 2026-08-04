# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Rendering of allow-list findings, for humans and for machines.

Two renderers sit side by side here because they answer to different
audiences and must not drift apart:

* :func:`render_text` writes a Rich report styled after the existing
  stale-actions block, deduplicated so that a workflow carrying fifteen
  identical pins produces one readable paragraph rather than fifteen.
* :func:`build_json` returns the ``allow_list`` object of the
  ``--format json`` document (design section 9.4), including suppressed
  findings, so a machine consumer sees the whole picture without needing
  ``--show-suppressed``.

Neither renderer decides anything. Severity, suppression and resolution
status arrive already settled on the
:class:`~gha_workflow_linter.allow_list_check.AllowListOutcome`; what
varies here is only what reaches the terminal.

Deduplication groups findings by ``(kind, current_sha, target_sha)``
within each file, mirroring ``cli._print_deduplicated_action_refs``. The
group's source lines are listed together, so nothing is hidden -- the
repetition is what disappears, not the information.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .console import console
from .models import AllowListFindingKind

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from pathlib import Path

    from .allow_list_check import AllowListFinding, AllowListOutcome

__all__ = [
    "build_json",
    "render_text",
]

#: Sections, in the order they are printed. Defect kinds come first: a
#: comment that lies is wrong now, whereas a stale pin merely could be
#: newer.
_SECTION_ORDER: tuple[AllowListFindingKind, ...] = (
    AllowListFindingKind.COMMENT_MISMATCH,
    AllowListFindingKind.STALE,
    AllowListFindingKind.UNPINNED,
    AllowListFindingKind.UNRESOLVABLE,
    AllowListFindingKind.INVALID_SPEC,
)

#: Heading and Rich style for each section.
_SECTIONS: dict[AllowListFindingKind, tuple[str, str]] = {
    AllowListFindingKind.COMMENT_MISMATCH: (
        "Allow-list pins with incorrect version comments ⚠️",
        "yellow",
    ),
    AllowListFindingKind.STALE: ("Stale allow-list pins ⚠️", "yellow"),
    AllowListFindingKind.UNPINNED: (
        "Allow-list pins not pinned to a commit SHA ℹ️",
        "cyan",
    ),
    AllowListFindingKind.UNRESOLVABLE: (
        "Allow-list pins naming an unknown commit ⚠️",
        "red",
    ),
    AllowListFindingKind.INVALID_SPEC: (
        "Malformed allow-list pins ❌",
        "red",
    ),
}

#: Kinds ``--update-allow-list`` can repair, and therefore the kinds
#: whose presence justifies advertising it.
_FIXABLE: frozenset[AllowListFindingKind] = frozenset(
    {
        AllowListFindingKind.STALE,
        AllowListFindingKind.COMMENT_MISMATCH,
        AllowListFindingKind.UNPINNED,
    }
)

#: Characters of a SHA shown before the ellipsis. Enough to identify a
#: commit at a glance, short enough to keep a pin on one line.
_SHA_DISPLAY_LENGTH = 8

#: Summary buckets always present, in the order design section 9.4 lists
#: them. Kinds outside this set gain a bucket only if they occur.
_SUMMARY_KINDS: tuple[AllowListFindingKind, ...] = (
    AllowListFindingKind.STALE,
    AllowListFindingKind.COMMENT_MISMATCH,
    AllowListFindingKind.UNPINNED,
)


def _relative(file_path: Path, root: Path) -> str:
    """Render a path relative to the scan root, with POSIX separators.

    Args:
        file_path: The path to render.
        root: The base the path should be relative to.

    Returns:
        The relative path, or the original path when it lies outside
        ``root``. Separators are always ``/`` so that reports and JSON
        compare equal across platforms.
    """
    try:
        return file_path.relative_to(root).as_posix()
    except ValueError:
        return file_path.as_posix()


def _short_sha(sha: str) -> str:
    """Abbreviate a commit SHA for display.

    Args:
        sha: The full SHA.

    Returns:
        The first :data:`_SHA_DISPLAY_LENGTH` characters followed by an
        ellipsis, or the SHA unchanged when it is already short.
    """
    if len(sha) <= _SHA_DISPLAY_LENGTH:
        return sha
    return f"{sha[:_SHA_DISPLAY_LENGTH]}…"


def _quoted(finding: AllowListFinding, ref: str) -> str:
    """Render a ref in the quoting style its pin was written with.

    Args:
        finding: The finding whose pin supplies the quoting style.
        ref: The ref text to quote, without its leading ``@``.

    Returns:
        The quoted ``@<ref>`` text.
    """
    quote = {"single": "'", "double": '"'}.get(
        finding.pin.quote_style.value, ""
    )
    return f"{quote}@{ref}{quote}"


def _current_text(finding: AllowListFinding) -> str:
    """Render the "as written" half of one finding.

    Args:
        finding: The finding to render.

    Returns:
        Text of the form ``config: '@18d9c444…'  # v0.1.1``. The comment
        is omitted when the pin carries none.
    """
    key = finding.pin.key_path[-1] if finding.pin.key_path else "config"
    ref = finding.pin.spec.ref
    shown = _short_sha(ref) if finding.current_sha else ref
    text = f"{key}: {_quoted(finding, shown)}"
    comment = finding.pin.version_comment
    if comment:
        text = f"{text}  # {comment}"
    return text


def _target_text(finding: AllowListFinding) -> str:
    """Render the "should be" half of one finding.

    Args:
        finding: The finding to render.

    Returns:
        Text of the form ``'@bf6642f6…'  # v0.12.2   (org/repo)``.
    """
    sha = finding.target_sha or ""
    text = f"→ {_quoted(finding, _short_sha(sha))}"
    if finding.target_version:
        text = f"{text}  # {finding.target_version}"
    return f"{text}   ({finding.host_repo})"


def _line_label(lines: Sequence[int]) -> str:
    """Render the line-number label of one deduplicated group.

    Args:
        lines: The distinct source lines the group covers, ascending.

    Returns:
        ``line 116`` for a single line, ``lines 116, 292, 349``
        otherwise.
    """
    numbers = ", ".join(str(number) for number in lines)
    return f"line {numbers}" if len(lines) == 1 else f"lines {numbers}"


def _group_findings(
    findings: Iterable[AllowListFinding],
) -> dict[tuple[str, str | None, str | None], list[AllowListFinding]]:
    """Group findings by ``(kind, current_sha, target_sha)``.

    Args:
        findings: Findings from a single file.

    Returns:
        Mapping of group key to its findings, in first-seen order.
    """
    groups: dict[
        tuple[str, str | None, str | None], list[AllowListFinding]
    ] = {}
    for finding in findings:
        key = (finding.kind.value, finding.current_sha, finding.target_sha)
        groups.setdefault(key, []).append(finding)
    return groups


def _by_file(
    findings: Iterable[AllowListFinding], root: Path
) -> dict[str, list[AllowListFinding]]:
    """Group findings by their file, keyed by the displayed path.

    Args:
        findings: The findings to group.
        root: Base for relative paths.

    Returns:
        Mapping of relative path to its findings, in first-seen order.
    """
    files: dict[str, list[AllowListFinding]] = {}
    for finding in findings:
        path = _relative(finding.pin.file_path, root)
        files.setdefault(path, []).append(finding)
    return files


def _print_group(
    group: list[AllowListFinding], *, style: str, reasons: bool
) -> None:
    """Print one deduplicated group of findings.

    Args:
        group: Findings sharing a kind, a current SHA and a target SHA.
        style: Rich style for the "as written" line.
        reasons: Whether to print the suppression reasons the group
            carries.
    """
    lines = sorted({finding.pin.line_number for finding in group})
    label = _line_label(lines)
    pad = " " * len(label)
    first = group[0]

    console.print(f"    [{style}]{label}[/{style}]   {_current_text(first)}")
    console.print(f"    {pad}   [green]{_target_text(first)}[/green]")

    if not reasons:
        return
    seen: list[str] = []
    for finding in group:
        reason = finding.pin.suppression_reason or "no reason given"
        if reason not in seen:
            seen.append(reason)
            console.print(f"    {pad}   [dim]suppressed: {reason}[/dim]")


def _print_section(
    title: str,
    style: str,
    findings: list[AllowListFinding],
    *,
    root: Path,
    reasons: bool = False,
) -> None:
    """Print one titled section of findings, grouped by file.

    Args:
        title: Section heading.
        style: Rich style for the heading and the "as written" lines.
        findings: The findings in this section.
        root: Base for relative paths.
        reasons: Whether to print suppression reasons.
    """
    console.print(f"[bold {style}]{title}[/bold {style}]\n")
    for path, file_findings in _by_file(findings, root).items():
        console.print(f"  [bold]{path}[/bold]")
        for group in _group_findings(file_findings).values():
            _print_group(group, style=style, reasons=reasons)
        console.print()


def _print_unresolved(outcome: AllowListOutcome) -> None:
    """Print a notice for every host repository that failed to resolve.

    Args:
        outcome: The check outcome.
    """
    for repo_key, reason in outcome.unresolved.items():
        console.print(
            f"[yellow]Allow-list check skipped for {repo_key}: "
            f"{reason}[/yellow]\n"
        )


def _print_suppression_summary(
    outcome: AllowListOutcome, *, root: Path, show_suppressed: bool
) -> None:
    """Print the always-on suppression summary, and optionally detail.

    A suppression that becomes invisible forever is a suppression nobody
    audits, so the one-line count is emitted whenever any suppression is
    active, regardless of ``show_suppressed``.

    Args:
        outcome: The check outcome.
        root: Base for relative paths.
        show_suppressed: Whether to list each suppressed pin as a notice
            with its reason.
    """
    suppressed = [finding for finding in outcome.findings if finding.suppressed]
    if not suppressed:
        return

    if show_suppressed:
        _print_section(
            "Suppressed allow-list pins ℹ️",
            "dim",
            suppressed,
            root=root,
            reasons=True,
        )

    files = {finding.pin.file_path for finding in suppressed}
    noun = "pin" if len(suppressed) == 1 else "pins"
    file_noun = "file" if len(files) == 1 else "files"
    summary = (
        f"{len(suppressed)} allow-list {noun} suppressed "
        f"({len(files)} {file_noun})"
    )
    if not show_suppressed:
        summary = f"{summary} — use --show-suppressed for detail"
    console.print(f"[dim]{summary}[/dim]\n")


def render_text(
    outcome: AllowListOutcome,
    *,
    root: Path,
    show_suppressed: bool,
    update_hint: bool,
) -> None:
    """Write the human-readable allow-list report to the shared console.

    Nothing is printed when the check did not run, or when it ran and
    found nothing: silence is the success signal, matching the rest of
    the linter's report.

    Args:
        outcome: The check outcome.
        root: Repository root, so paths print relative to it.
        show_suppressed: List suppressed pins as notices with their
            reasons. Never changes what the caller returns.
        update_hint: Advertise ``--update-allow-list`` when repairable
            findings remain. Callers pass ``False`` once remediation has
            already run.
    """
    if not outcome.checked:
        return

    _print_unresolved(outcome)

    visible = outcome.unsuppressed
    for kind in _SECTION_ORDER:
        group = [finding for finding in visible if finding.kind is kind]
        if not group:
            continue
        title, style = _SECTIONS[kind]
        _print_section(title, style, group, root=root)

    _print_suppression_summary(
        outcome, root=root, show_suppressed=show_suppressed
    )

    if update_hint and any(finding.kind in _FIXABLE for finding in visible):
        console.print(
            "[cyan]  Run with [bold]--update-allow-list[/bold] to apply "
            "these changes 💡[/cyan]\n"
        )


def _finding_json(
    finding: AllowListFinding, *, root: Path, fixed: bool
) -> dict[str, Any]:
    """Render one finding as a JSON object.

    Args:
        finding: The finding to render.
        root: Base for the relative ``file`` path.
        fixed: Whether remediation rewrote this finding's line.

    Returns:
        The finding object of design section 9.4.
    """
    return {
        "file": _relative(finding.pin.file_path, root),
        "line": finding.pin.line_number,
        "kind": finding.kind.value,
        "severity": finding.severity.value,
        "current_sha": finding.current_sha,
        "current_version": finding.pin.version_comment,
        "target_sha": finding.target_sha,
        "target_version": finding.target_version,
        "suppressed": finding.suppressed,
        "fixed": fixed,
    }


def _summary_json(outcome: AllowListOutcome) -> dict[str, int]:
    """Count findings per kind, plus the suppressed and fixed totals.

    The per-kind buckets count **unsuppressed** findings only, so
    ``stale`` reads as "stale pins that count". Suppressed findings are
    counted once, together, under ``suppressed``; the two therefore sum
    to the length of ``findings``.

    Args:
        outcome: The check outcome.

    Returns:
        The summary object, with the buckets of design section 9.4
        always present even when zero.
    """
    counts = {kind.value: 0 for kind in _SUMMARY_KINDS}
    for finding in outcome.findings:
        if finding.suppressed:
            continue
        counts[finding.kind.value] = counts.get(finding.kind.value, 0) + 1

    counts["suppressed"] = outcome.suppressed_count
    counts["fixed"] = outcome.fixed_count
    return counts


def build_json(outcome: AllowListOutcome, *, root: Path) -> dict[str, Any]:
    """Build the ``allow_list`` object of the JSON report.

    Suppressed findings are always included, carrying
    ``"suppressed": true``, so a machine consumer sees everything the
    ``--show-suppressed`` flag would reveal.

    Args:
        outcome: The check outcome.
        root: Repository root, so paths appear relative to it.

    Returns:
        A single-key dictionary, ready to merge into the report
        document. ``hosts`` holds only the repositories that resolved;
        the rest appear in ``unresolved`` with their reason, which is
        what a caller needs to distinguish "clean" from "could not
        check".
    """
    return {
        "allow_list": {
            "checked": outcome.checked,
            "resolved": outcome.resolved,
            "hosts": {
                repo_key: {
                    "latest_version": release.tag,
                    "latest_sha": release.commit_sha,
                }
                for repo_key, release in outcome.hosts.items()
                if release is not None
            },
            "unresolved": dict(outcome.unresolved),
            "findings": [
                _finding_json(
                    finding, root=root, fixed=outcome.was_fixed(finding)
                )
                for finding in outcome.findings
            ],
            "summary": _summary_json(outcome),
        }
    }
