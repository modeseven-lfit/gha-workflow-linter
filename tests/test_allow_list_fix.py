# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for in-place remediation of stale allow-list pins.

Every assertion here is made against ``read_bytes()`` on a real file
written into ``tmp_path``, because the whole point of the fixer is what
the *bytes* look like afterwards. A test that compared parsed fields
would pass for a rewrite that silently reformatted a comment, moved it
out of a scalar, or re-quoted a value -- the three failures the design
of :mod:`gha_workflow_linter.allow_list_fix` exists to prevent.

Pins come from the real scanner and findings from the real classifier
wherever possible, so the columns, quoting and comment positions under
test are the ones the pipeline actually produces. Hand-built pins appear
only where a defect must be simulated that the scanner cannot emit.

The SHAs are real: ``18d9c444`` is ``v0.1.1`` of
``lfreleng-actions/.github``, the version most of the estate is pinned
to, and ``bf6642f6`` is ``v0.12.2``, the peeled commit of its annotated
tag.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest import mock

import pytest

from gha_workflow_linter import allow_list_fix, file_edit
from gha_workflow_linter.allow_list_check import (
    AllowListFinding,
    classify_pins,
)
from gha_workflow_linter.allow_list_fix import (
    REASON_COMMENT_CHANGED,
    REASON_COMMENT_NOT_FOUND,
    REASON_INVALID_REF,
    REASON_MULTILINE,
    REASON_NO_TARGET,
    REASON_SPEC_NOT_FOUND,
    REASON_SUPPRESSED,
    DuplicateFixError,
    apply_fixes,
)
from gha_workflow_linter.allow_list_scanner import (
    AllowListPin,
    AllowListScanner,
    CommentPosition,
    QuoteStyle,
)
from gha_workflow_linter.allow_list_spec import resolve_spec
from gha_workflow_linter.directives import Directive, SuppressionSource
from gha_workflow_linter.latest_release import LatestRelease
from gha_workflow_linter.models import (
    AllowListFindingKind,
    Config,
    Severity,
)

if TYPE_CHECKING:
    from pathlib import Path

WORKFLOW_ORG = "lfreleng-actions"
HOST_REPO = f"{WORKFLOW_ORG}/.github"

#: v0.1.1: what the estate is pinned to.
STALE_SHA = "18d9c4446bea555d0783e850f6d295f844fe8f67"
STALE_TAG = "v0.1.1"

#: v0.12.2: the peeled commit of the current release's annotated tag.
CURRENT_SHA = "bf6642f68d58c1b81bbe993e676d6cc339ac3654"
CURRENT_TAG = "v0.12.2"

#: v0.5.1: a second stale release, for multi-pin files.
OTHER_SHA = "8f4f0cf83e6a015957e83261ed379fd811fc060e"
OTHER_TAG = "v0.5.1"

#: The action each fixture step calls. Never an allow-list candidate;
#: it is here so the fixtures are shaped like real workflows.
USES_SHA = "6db537b3e6d060c3287c5a3ce2c28b55b0af330d"

#: The explicit-path form of a coordinate, written out in full.
EXPLICIT = (
    "lfreleng-actions//.github/harden-runner/lfreleng-actions/allow_list.txt"
)

TARGET = LatestRelease(tag=CURRENT_TAG, commit_sha=CURRENT_SHA)

ALLOW = Directive.ALLOW_LIST_PIN_OK

HEADER = "\n".join(
    [
        "---",
        "name: Fixture",
        "",
        "on:",
        "  workflow_dispatch:",
        "",
        "jobs:",
        "  build:",
        "    runs-on: ubuntu-24.04",
        "    steps:",
        "",
    ]
)

STEP = f"      - uses: lfreleng-actions/harden-runner-block-action@{USES_SHA}\n        with:\n"


def build_source(*steps: str) -> str:
    """Assemble a workflow whose steps carry the given source blocks.

    Args:
        steps: One block per step, each holding the step's ``config``
            line and any comment line above it, without a trailing
            newline.

    Returns:
        The complete file content, ending in a single newline.
    """
    return HEADER + "".join(f"{STEP}{step}\n" for step in steps)


def write_workflow(
    tmp_path: Path,
    *steps: str,
    name: str = "workflow.yaml",
    newline: str = "\n",
    final_newline: bool = True,
) -> Path:
    """Write a workflow fixture with byte-exact content.

    Args:
        tmp_path: Directory to write into.
        steps: One source block per step.
        name: Filename to write.
        newline: Line terminator to use throughout.
        final_newline: Whether the file ends with a terminator.

    Returns:
        The path written.
    """
    text = build_source(*steps)
    if not final_newline:
        text = text[:-1]
    path = tmp_path / name
    path.write_bytes(text.replace("\n", newline).encode())
    return path


def findings_for(
    path: Path, latest: LatestRelease = TARGET
) -> list[AllowListFinding]:
    """Scan and classify one file, exactly as the pipeline does.

    Args:
        path: File to scan.
        latest: Target release of the host repository.

    Returns:
        The findings, in scan order.
    """
    scanner = AllowListScanner(Config(), WORKFLOW_ORG)
    pins = scanner.scan_file(path)
    return classify_pins(pins, {HOST_REPO: latest}, verify=False)


def fix_file(path: Path) -> allow_list_fix.FixOutcome:
    """Scan, classify and remediate one file.

    Args:
        path: File to remediate.

    Returns:
        The outcome of the remediation pass.
    """
    return apply_fixes(findings_for(path))


def config_line(
    value: str,
    *,
    quote: str = "'",
    spacing: str = "  ",
    comment: str | None = STALE_TAG,
    indent: str = "          ",
) -> str:
    """Compose one ``config:`` source line.

    Args:
        value: The scalar's content, without quotes.
        quote: Quote character, or ``""`` for a plain scalar.
        spacing: Whitespace between the scalar and the ``#``.
        comment: Comment body, or ``None`` for no comment.
        indent: Leading whitespace.

    Returns:
        The line, without a terminator.
    """
    line = f"{indent}config: {quote}{value}{quote}"
    if comment is not None:
        line = f"{line}{spacing}# {comment}"
    return line


def make_pin(
    *,
    raw_line: str,
    raw_value: str,
    file_path: Path,
    line_number: int = 12,
    column: int = 18,
    quote_style: QuoteStyle = QuoteStyle.SINGLE,
    version_comment: str | None = STALE_TAG,
    comment_position: CommentPosition = CommentPosition.YAML,
    directives: frozenset[Directive] = frozenset(),
    auto_fixable: bool = True,
) -> AllowListPin:
    """Build a pin directly, bypassing the scanner.

    Used only for defects the scanner cannot produce, such as a line
    that no longer holds the value recorded against it.

    Args:
        raw_line: The source line the pin claims.
        raw_value: The scalar, comment removed.
        file_path: File the pin sits in.
        line_number: 1-based source line.
        column: 0-based column of the scalar's first character.
        quote_style: Quoting of the scalar.
        version_comment: Version token of the trailing comment.
        comment_position: Which position carries the comment.
        directives: Suppression directives in force.
        auto_fixable: ``False`` for a multi-line scalar.

    Returns:
        The pin.
    """
    return AllowListPin(
        file_path=file_path,
        line_number=line_number,
        column=column,
        key_path=("jobs", "build", "steps", "0", "with", "config"),
        raw_line=raw_line,
        raw_value=raw_value,
        quote_style=quote_style,
        version_comment=version_comment,
        comment_position=comment_position,
        directives=directives,
        suppressed_by=(
            SuppressionSource.INLINE_COMMENT if directives else None
        ),
        suppression_reason=None,
        spec=resolve_spec(raw_value.strip(), workflow_org=WORKFLOW_ORG),
        auto_fixable=auto_fixable,
    )


def make_finding(
    pin: AllowListPin,
    *,
    kind: AllowListFindingKind = AllowListFindingKind.STALE,
    target_sha: str | None = CURRENT_SHA,
    target_version: str | None = CURRENT_TAG,
    suppressed: bool = False,
) -> AllowListFinding:
    """Build a finding directly, bypassing the classifier.

    Args:
        pin: The pin the finding concerns.
        kind: What is wrong with it.
        target_sha: Commit the pin should name.
        target_version: Release tag that commit belongs to.
        suppressed: Whether a directive applies.

    Returns:
        The finding.
    """
    return AllowListFinding(
        pin=pin,
        kind=kind,
        severity=Severity.WARNING,
        message="synthetic finding",
        current_sha=pin.spec.ref,
        target_sha=target_sha,
        target_version=target_version,
        suppressed=suppressed,
    )


def reasons(outcome: allow_list_fix.FixOutcome) -> list[str]:
    """Return just the skip reasons from an outcome.

    Args:
        outcome: The outcome to summarise.

    Returns:
        One reason per skipped finding, in order.
    """
    return [reason for _finding, reason in outcome.skipped]


def lines_of(path: Path) -> list[str]:
    """Return a file's lines, terminators removed.

    Args:
        path: File to read.

    Returns:
        The lines, without terminators.
    """
    return path.read_text(encoding="utf-8").splitlines()


class TestSpecForms:
    """Both coordinate forms move their ref and nothing else."""

    def test_shorthand_form(self, tmp_path: Path) -> None:
        """``'@<sha>'`` keeps its shorthand and gains the new SHA."""
        path = write_workflow(tmp_path, config_line(f"@{STALE_SHA}"))

        outcome = fix_file(path)

        assert len(outcome.applied) == 1
        assert (
            path.read_bytes()
            == build_source(
                config_line(f"@{CURRENT_SHA}", comment=CURRENT_TAG)
            ).encode()
        )

    def test_explicit_path_form(self, tmp_path: Path) -> None:
        """A full coordinate keeps every part before the ``@``."""
        path = write_workflow(tmp_path, config_line(f"{EXPLICIT}@{STALE_SHA}"))

        fix_file(path)

        assert (
            path.read_bytes()
            == build_source(
                config_line(f"{EXPLICIT}@{CURRENT_SHA}", comment=CURRENT_TAG)
            ).encode()
        )

    def test_only_the_ref_and_version_change(self, tmp_path: Path) -> None:
        """The two rewritten tokens are the only difference."""
        before = config_line(f"{EXPLICIT}@{STALE_SHA}")
        path = write_workflow(tmp_path, before)

        fix_file(path)

        after = lines_of(path)[-1]
        assert (
            after.replace(CURRENT_SHA, STALE_SHA).replace(
                CURRENT_TAG, STALE_TAG
            )
            == before
        )


class TestQuoteStyles:
    """The author's quoting is never rewritten."""

    def test_single_quotes_survive(self, tmp_path: Path) -> None:
        """A single-quoted scalar stays single quoted."""
        path = write_workflow(tmp_path, config_line(f"@{STALE_SHA}"))

        fix_file(path)

        assert lines_of(path)[-1] == config_line(
            f"@{CURRENT_SHA}", comment=CURRENT_TAG
        )

    def test_double_quotes_survive(self, tmp_path: Path) -> None:
        """A double-quoted scalar stays double quoted."""
        path = write_workflow(tmp_path, config_line(f"@{STALE_SHA}", quote='"'))

        fix_file(path)

        assert lines_of(path)[-1] == config_line(
            f"@{CURRENT_SHA}", quote='"', comment=CURRENT_TAG
        )

    def test_plain_scalar_is_not_quoted(self, tmp_path: Path) -> None:
        """An unquoted scalar does not acquire quotes."""
        path = write_workflow(
            tmp_path, config_line(f"{EXPLICIT}@{STALE_SHA}", quote="")
        )

        fix_file(path)

        assert lines_of(path)[-1] == config_line(
            f"{EXPLICIT}@{CURRENT_SHA}", quote="", comment=CURRENT_TAG
        )


class TestCommentSpacing:
    """Whatever separates the value from the ``#`` is left alone."""

    @pytest.mark.parametrize("spacing", [" ", "  ", "   "])
    def test_spacing_before_the_hash_survives(
        self, tmp_path: Path, spacing: str
    ) -> None:
        """One, two and three spaces all round-trip."""
        path = write_workflow(
            tmp_path, config_line(f"@{STALE_SHA}", spacing=spacing)
        )

        fix_file(path)

        assert lines_of(path)[-1] == config_line(
            f"@{CURRENT_SHA}", spacing=spacing, comment=CURRENT_TAG
        )

    def test_spacing_after_the_hash_survives(self, tmp_path: Path) -> None:
        """Padding between the ``#`` and the version is not squeezed."""
        line = f"          config: '@{STALE_SHA}'  #   {STALE_TAG}"
        path = write_workflow(tmp_path, line)

        fix_file(path)

        assert lines_of(path)[-1] == (
            f"          config: '@{CURRENT_SHA}'  #   {CURRENT_TAG}"
        )


class TestCommentPositions:
    """Each position is rewritten where it sits, never moved."""

    def test_yaml_comment_stays_outside_the_quotes(
        self, tmp_path: Path
    ) -> None:
        """A comment after the closing quote stays after it."""
        path = write_workflow(tmp_path, config_line(f"@{STALE_SHA}"))

        fix_file(path)

        assert lines_of(path)[-1].endswith(f"'  # {CURRENT_TAG}")

    def test_in_scalar_comment_stays_inside_the_quotes(
        self, tmp_path: Path
    ) -> None:
        """A comment inside the scalar is rewritten in place."""
        line = f'          config: "@{STALE_SHA} # {STALE_TAG}"'
        path = write_workflow(tmp_path, line)

        fix_file(path)

        assert lines_of(path)[-1] == (
            f'          config: "@{CURRENT_SHA} # {CURRENT_TAG}"'
        )

    def test_in_scalar_comment_wins_over_a_yaml_one(
        self, tmp_path: Path
    ) -> None:
        """With both present, only the one the action sees is rewritten."""
        line = f"          config: '@{STALE_SHA} # {STALE_TAG}'  # {OTHER_TAG}"
        path = write_workflow(tmp_path, line)

        fix_file(path)

        assert lines_of(path)[-1] == (
            f"          config: '@{CURRENT_SHA} # {CURRENT_TAG}'  # {OTHER_TAG}"
        )

    def test_missing_comment_is_added(self, tmp_path: Path) -> None:
        """A pin with no comment gains one, two spaces out."""
        path = write_workflow(
            tmp_path, config_line(f"@{STALE_SHA}", comment=None)
        )

        fix_file(path)

        assert lines_of(path)[-1] == (
            f"          config: '@{CURRENT_SHA}'  # {CURRENT_TAG}"
        )

    def test_added_comment_keeps_trailing_whitespace(
        self, tmp_path: Path
    ) -> None:
        """Trailing whitespace is not consumed by the new comment."""
        line = f"          config: '@{STALE_SHA}'   "
        path = write_workflow(tmp_path, line)

        fix_file(path)

        assert lines_of(path)[-1] == (
            f"          config: '@{CURRENT_SHA}'     # {CURRENT_TAG}"
        )


class TestDirectivesSurvive:
    """A repair never discards authored suppression content."""

    def test_directive_and_reason_are_kept(self, tmp_path: Path) -> None:
        """Only the version token changes; the tail carries through.

        The finding is a ``COMMENT_MISMATCH``, which
        ``allow-list-pin-ok`` does not suppress, so the directive is
        present on a pin that is nonetheless rewritten -- exactly the
        case in which losing it would silently re-enable churn.
        """
        comment = f"{STALE_TAG} allow-list-pin-ok -- upstream is broken"
        path = write_workflow(
            tmp_path, config_line(f"@{CURRENT_SHA}", comment=comment)
        )

        outcome = fix_file(path)

        assert [finding.kind for finding in _findings(outcome)] == [
            AllowListFindingKind.COMMENT_MISMATCH
        ]
        assert (
            path.read_bytes()
            == build_source(
                config_line(
                    f"@{CURRENT_SHA}",
                    comment=(
                        f"{CURRENT_TAG} allow-list-pin-ok -- upstream is broken"
                    ),
                )
            ).encode()
        )

    def test_unrecognised_tokens_are_kept(self, tmp_path: Path) -> None:
        """A token the parser does not know is not thrown away."""
        path = write_workflow(
            tmp_path,
            config_line(f"@{STALE_SHA}", comment=f"{STALE_TAG} (pinned)"),
        )

        fix_file(path)

        assert lines_of(path)[-1].endswith(f"# {CURRENT_TAG} (pinned)")


class TestSuppression:
    """A suppressed pin is never written at all."""

    def test_suppressed_pin_leaves_the_file_untouched(
        self, tmp_path: Path
    ) -> None:
        """Neither the bytes nor the modification time change."""
        comment = f"{STALE_TAG} allow-list-pin-ok -- deliberate"
        path = write_workflow(
            tmp_path, config_line(f"@{STALE_SHA}", comment=comment)
        )
        before = path.read_bytes()
        mtime = path.stat().st_mtime_ns

        outcome = fix_file(path)

        assert outcome.applied == []
        assert reasons(outcome) == [REASON_SUPPRESSED]
        assert path.read_bytes() == before
        assert path.stat().st_mtime_ns == mtime

    def test_suppression_is_checked_before_anything_else(
        self, tmp_path: Path
    ) -> None:
        """A suppressed finding is skipped for that reason, not another."""
        pin = make_pin(
            raw_line="nothing like the value",
            raw_value=f"@{STALE_SHA}",
            file_path=tmp_path / "absent.yaml",
            directives=frozenset({ALLOW}),
            auto_fixable=False,
        )

        outcome = apply_fixes([make_finding(pin, suppressed=True)])

        assert reasons(outcome) == [REASON_SUPPRESSED]


class TestSkipped:
    """Everything the fixer declines, and why."""

    def test_multiline_scalar_is_skipped(self, tmp_path: Path) -> None:
        """A block scalar is reported but never rewritten."""
        block = f"          config: >-\n            {EXPLICIT}@{STALE_SHA}"
        path = write_workflow(tmp_path, block)
        before = path.read_bytes()

        outcome = fix_file(path)

        assert reasons(outcome) == [REASON_MULTILINE]
        assert path.read_bytes() == before

    def test_finding_without_a_target_is_skipped(self, tmp_path: Path) -> None:
        """There is nothing to write, so nothing is written."""
        path = write_workflow(tmp_path, config_line(f"@{STALE_SHA}"))
        before = path.read_bytes()
        pin = make_pin(
            raw_line=config_line(f"@{STALE_SHA}"),
            raw_value=f"@{STALE_SHA}",
            file_path=path,
        )

        outcome = apply_fixes([make_finding(pin, target_sha=None)])

        assert reasons(outcome) == [REASON_NO_TARGET]
        assert path.read_bytes() == before

    def test_absent_spec_is_skipped(self, tmp_path: Path) -> None:
        """A line that no longer holds the value is left alone."""
        pin = make_pin(
            raw_line="          config: something else entirely",
            raw_value=f"@{STALE_SHA}",
            file_path=tmp_path / "workflow.yaml",
        )

        outcome = apply_fixes([make_finding(pin)])

        assert reasons(outcome) == [REASON_SPEC_NOT_FOUND]

    def test_spec_before_the_column_is_not_matched(
        self, tmp_path: Path
    ) -> None:
        """The search starts at the scalar, so an earlier copy is ignored."""
        pin = make_pin(
            raw_line=f"          # was @{STALE_SHA}",
            raw_value=f"@{STALE_SHA}",
            file_path=tmp_path / "workflow.yaml",
            column=40,
        )

        outcome = apply_fixes([make_finding(pin)])

        assert reasons(outcome) == [REASON_SPEC_NOT_FOUND]

    def test_invalid_target_ref_is_skipped(self, tmp_path: Path) -> None:
        """A target that is not a usable ref is refused, not written."""
        path = write_workflow(tmp_path, config_line(f"@{STALE_SHA}"))
        before = path.read_bytes()
        pin = make_pin(
            raw_line=config_line(f"@{STALE_SHA}"),
            raw_value=f"@{STALE_SHA}",
            file_path=path,
        )

        outcome = apply_fixes([make_finding(pin, target_sha="not a ref!")])

        assert reasons(outcome) == [REASON_INVALID_REF]
        assert path.read_bytes() == before

    def test_absent_comment_is_skipped(self, tmp_path: Path) -> None:
        """A pin claiming a comment its line lacks is left alone."""
        pin = make_pin(
            raw_line=config_line(f"@{STALE_SHA}", comment=None),
            raw_value=f"@{STALE_SHA}",
            file_path=tmp_path / "workflow.yaml",
        )

        outcome = apply_fixes([make_finding(pin)])

        assert reasons(outcome) == [REASON_COMMENT_NOT_FOUND]

    def test_unfindable_closing_quote_is_skipped(self, tmp_path: Path) -> None:
        """An in-scalar comment with no closing quote is not guessed at."""
        pin = make_pin(
            raw_line=f"          config: @{STALE_SHA} # {STALE_TAG}",
            raw_value=f"@{STALE_SHA}",
            file_path=tmp_path / "workflow.yaml",
            column=18,
            quote_style=QuoteStyle.NONE,
            comment_position=CommentPosition.IN_SCALAR,
        )

        outcome = apply_fixes([make_finding(pin)])

        assert reasons(outcome) == [REASON_COMMENT_NOT_FOUND]

    def test_changed_comment_is_skipped(self, tmp_path: Path) -> None:
        """A comment that says something else is not overwritten."""
        pin = make_pin(
            raw_line=config_line(f"@{STALE_SHA}"),
            raw_value=f"@{STALE_SHA}",
            file_path=tmp_path / "workflow.yaml",
            version_comment="v9.9.9",
        )

        outcome = apply_fixes([make_finding(pin)])

        assert reasons(outcome) == [REASON_COMMENT_CHANGED]

    def test_target_without_a_version_leaves_the_comment(
        self, tmp_path: Path
    ) -> None:
        """The ref moves; an unnameable version does not blank the comment."""
        path = write_workflow(tmp_path, config_line(f"@{STALE_SHA}"))
        pin = make_pin(
            raw_line=config_line(f"@{STALE_SHA}"),
            raw_value=f"@{STALE_SHA}",
            file_path=path,
            line_number=len(lines_of(path)),
        )

        outcome = apply_fixes([make_finding(pin, target_version=None)])

        assert len(outcome.applied) == 1
        assert lines_of(path)[-1] == config_line(f"@{CURRENT_SHA}")


class TestWholeFiles:
    """Everything outside the two rewritten tokens survives."""

    def test_several_pins_are_fixed_in_one_pass(self, tmp_path: Path) -> None:
        """Three shapes in one file, all correct afterwards."""
        path = write_workflow(
            tmp_path,
            config_line(f"@{STALE_SHA}"),
            config_line(f"{EXPLICIT}@{OTHER_SHA}", quote='"', spacing="   "),
            config_line(f"@{OTHER_SHA}", comment=None),
        )

        outcome = fix_file(path)

        assert len(outcome.applied) == 3
        assert (
            path.read_bytes()
            == build_source(
                config_line(f"@{CURRENT_SHA}", comment=CURRENT_TAG),
                config_line(
                    f"{EXPLICIT}@{CURRENT_SHA}",
                    quote='"',
                    spacing="   ",
                    comment=CURRENT_TAG,
                ),
                config_line(f"@{CURRENT_SHA}", comment=CURRENT_TAG),
            ).encode()
        )

    def test_one_write_per_file(self, tmp_path: Path) -> None:
        """Every pin in a file funnels into a single atomic write."""
        path = write_workflow(
            tmp_path,
            config_line(f"@{STALE_SHA}"),
            config_line(f"@{OTHER_SHA}", comment=OTHER_TAG),
            config_line(f"@{STALE_SHA}"),
        )
        real = file_edit.replace_lines

        with mock.patch.object(
            allow_list_fix, "replace_lines", wraps=real
        ) as writer:
            outcome = apply_fixes(findings_for(path))

        assert len(outcome.applied) == 3
        assert writer.call_count == 1

    def test_unusual_indentation_survives(self, tmp_path: Path) -> None:
        """Indentation is untargeted text and is preserved exactly."""
        path = write_workflow(
            tmp_path,
            config_line(f"@{STALE_SHA}", indent="              "),
        )

        fix_file(path)

        assert lines_of(path)[-1].startswith("              config:")

    def test_untouched_lines_are_byte_identical(self, tmp_path: Path) -> None:
        """No line other than the pin's differs."""
        path = write_workflow(tmp_path, config_line(f"@{STALE_SHA}"))
        before = lines_of(path)

        fix_file(path)

        after = lines_of(path)
        assert before[:-1] == after[:-1]
        assert before[-1] != after[-1]

    def test_two_files_are_each_rewritten(self, tmp_path: Path) -> None:
        """Findings are grouped by file, not merged across them."""
        first = write_workflow(
            tmp_path, config_line(f"@{STALE_SHA}"), name="first.yaml"
        )
        second = write_workflow(
            tmp_path, config_line(f"@{OTHER_SHA}"), name="second.yaml"
        )

        outcome = apply_fixes(findings_for(first) + findings_for(second))

        assert len(outcome.applied) == 2
        expected = build_source(
            config_line(f"@{CURRENT_SHA}", comment=CURRENT_TAG)
        ).encode()
        assert first.read_bytes() == expected
        assert second.read_bytes() == expected


class TestLineEndings:
    """The writer's guarantees, exercised through the fixer."""

    def test_crlf_file_stays_crlf(self, tmp_path: Path) -> None:
        """No line gains or loses a carriage return."""
        path = write_workflow(
            tmp_path, config_line(f"@{STALE_SHA}"), newline="\r\n"
        )

        fix_file(path)

        expected = build_source(
            config_line(f"@{CURRENT_SHA}", comment=CURRENT_TAG)
        ).replace("\n", "\r\n")
        assert path.read_bytes() == expected.encode()

    def test_file_without_a_final_newline_does_not_gain_one(
        self, tmp_path: Path
    ) -> None:
        """The pin is the last line, and it stays unterminated."""
        path = write_workflow(
            tmp_path, config_line(f"@{STALE_SHA}"), final_newline=False
        )

        fix_file(path)

        expected = build_source(
            config_line(f"@{CURRENT_SHA}", comment=CURRENT_TAG)
        )[:-1]
        assert path.read_bytes() == expected.encode()


class TestDuplicateLines:
    """Two edits for one line is a bug, and must be loud."""

    def test_two_findings_on_one_line_raise(self, tmp_path: Path) -> None:
        """The collision is refused rather than silently resolved."""
        path = write_workflow(tmp_path, config_line(f"@{STALE_SHA}"))
        findings = findings_for(path)

        with pytest.raises(DuplicateFixError) as raised:
            apply_fixes(findings + findings)

        assert raised.value.file_path == path
        assert raised.value.line_number == findings[0].pin.line_number

    def test_nothing_is_written_when_a_collision_is_found(
        self, tmp_path: Path
    ) -> None:
        """Planning completes before any file is opened."""
        first = write_workflow(
            tmp_path, config_line(f"@{STALE_SHA}"), name="first.yaml"
        )
        second = write_workflow(
            tmp_path, config_line(f"@{OTHER_SHA}"), name="second.yaml"
        )
        before = first.read_bytes()
        clash = findings_for(second)

        with pytest.raises(DuplicateFixError):
            apply_fixes(findings_for(first) + clash + clash)

        assert first.read_bytes() == before


class TestOutcome:
    """What the caller gets back."""

    def test_applied_reports_both_sides_of_the_edit(
        self, tmp_path: Path
    ) -> None:
        """``old_line`` is what was on disk, ``new_line`` what replaced it."""
        path = write_workflow(tmp_path, config_line(f"@{STALE_SHA}"))
        findings = findings_for(path)

        outcome = apply_fixes(findings)

        applied = outcome.applied[0]
        assert applied.finding is findings[0]
        assert applied.line_number == findings[0].pin.line_number
        assert applied.old_line == config_line(f"@{STALE_SHA}")
        assert applied.new_line == config_line(
            f"@{CURRENT_SHA}", comment=CURRENT_TAG
        )

    def test_order_follows_the_findings(self, tmp_path: Path) -> None:
        """Applied and skipped both keep the caller's order."""
        path = write_workflow(
            tmp_path,
            config_line(f"@{STALE_SHA}"),
            f"          config: >-\n            {EXPLICIT}@{STALE_SHA}",
            config_line(f"@{OTHER_SHA}", comment=OTHER_TAG),
        )

        outcome = fix_file(path)

        assert [fix.line_number for fix in outcome.applied] == [13, 20]
        assert reasons(outcome) == [REASON_MULTILINE]

    def test_no_findings_is_a_no_op(self) -> None:
        """An empty run touches nothing and reports nothing."""
        outcome = apply_fixes([])

        assert outcome.applied == []
        assert outcome.skipped == []


def _findings(outcome: allow_list_fix.FixOutcome) -> list[AllowListFinding]:
    """Return the findings behind an outcome's applied fixes.

    Args:
        outcome: The outcome to summarise.

    Returns:
        One finding per applied fix, in order.
    """
    return [fix.finding for fix in outcome.applied]
