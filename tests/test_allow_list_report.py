# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for the two allow-list renderers.

Text and JSON answer to different audiences, and the standing risk is
that they drift: a suppressed pin that vanishes from the terminal must
still appear in the JSON, and a deduplicated text block must not lose a
line number. Both properties are asserted here.

The shared console is replaced with one writing to a buffer at a fixed
width, so the assertions are about what the renderer emits rather than
about how a terminal happened to wrap it.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from gha_workflow_linter import allow_list_report
from gha_workflow_linter.allow_list_check import (
    AllowListFinding,
    AllowListOutcome,
    classify_pins,
)
from gha_workflow_linter.allow_list_report import build_json, render_text
from gha_workflow_linter.allow_list_scanner import (
    AllowListPin,
    CommentPosition,
    QuoteStyle,
)
from gha_workflow_linter.allow_list_spec import resolve_spec
from gha_workflow_linter.directives import Directive, SuppressionSource
from gha_workflow_linter.latest_release import LatestRelease

WORKFLOW_ORG = "lfreleng-actions"
HOST_REPO = f"{WORKFLOW_ORG}/.github"

STALE_SHA = "18d9c4446bea555d0783e850f6d295f844fe8f67"
STALE_TAG = "v0.1.1"
CURRENT_SHA = "bf6642f68d58c1b81bbe993e676d6cc339ac3654"
CURRENT_TAG = "v0.12.2"

LATEST = LatestRelease(tag=CURRENT_TAG, commit_sha=CURRENT_SHA)
ALLOW = Directive.ALLOW_LIST_PIN_OK

ROOT = Path("/repo")
WORKFLOW = ROOT / ".github" / "workflows" / "zizmor-sarif-publish.yaml"
OTHER = ROOT / ".github" / "workflows" / "other.yaml"


@pytest.fixture
def buffer(monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
    """Replace the shared console with a wide, buffered one.

    Args:
        monkeypatch: Fixture used to install the replacement.

    Returns:
        The buffer the renderer writes to.
    """
    stream = io.StringIO()
    monkeypatch.setattr(
        allow_list_report,
        "console",
        Console(file=stream, width=200, force_terminal=False, no_color=True),
    )
    return stream


def make_pin(
    *,
    ref: str = STALE_SHA,
    version_comment: str | None = STALE_TAG,
    line_number: int = 116,
    file_path: Path = WORKFLOW,
    directives: frozenset[Directive] = frozenset(),
    reason: str | None = None,
    quote_style: QuoteStyle = QuoteStyle.SINGLE,
) -> AllowListPin:
    """Build a pin without going through the scanner.

    Args:
        ref: The ref the pin names.
        version_comment: Version token of the trailing comment.
        line_number: 1-based source line.
        file_path: File the pin sits in.
        directives: Suppression directives in force.
        reason: Free text the suppression carried.
        quote_style: Quoting the scalar was written with.

    Returns:
        The pin.
    """
    return AllowListPin(
        file_path=file_path,
        line_number=line_number,
        column=10,
        key_path=("jobs", "publish", "steps", "0", "with", "config"),
        raw_line=f"          config: '@{ref}'  # {version_comment}",
        raw_value=f"@{ref}",
        quote_style=quote_style,
        version_comment=version_comment,
        comment_position=CommentPosition.YAML,
        directives=directives,
        suppressed_by=(
            SuppressionSource.INLINE_COMMENT if directives else None
        ),
        suppression_reason=reason,
        spec=resolve_spec(f"@{ref}", workflow_org=WORKFLOW_ORG),
        auto_fixable=True,
    )


def make_outcome(
    pins: list[AllowListPin],
    *,
    verify: bool = False,
    hosts: dict[str, LatestRelease | None] | None = None,
    unresolved: dict[str, str] | None = None,
    checked: bool = True,
) -> AllowListOutcome:
    """Classify pins and wrap the findings in an outcome.

    Args:
        pins: The pins to classify.
        verify: Whether enforcement was requested.
        hosts: Latest release of each host repository.
        unresolved: Hosts that could not be resolved, with reasons.
        checked: Whether the check ran at all.

    Returns:
        The outcome.
    """
    resolved: dict[str, LatestRelease | None] = (
        {HOST_REPO: LATEST} if hosts is None else hosts
    )
    findings = classify_pins(pins, resolved, verify=verify)
    return AllowListOutcome(
        findings=findings,
        hosts=resolved,
        unresolved={} if unresolved is None else unresolved,
        suppressed_count=sum(1 for f in findings if f.suppressed),
        checked=checked,
    )


def allow_list(outcome: AllowListOutcome) -> dict[str, Any]:
    """Return the ``allow_list`` object of the JSON report.

    Args:
        outcome: The outcome to render.

    Returns:
        The single object the document carries.
    """
    document = build_json(outcome, root=ROOT)
    assert set(document) == {"allow_list"}
    section: dict[str, Any] = document["allow_list"]
    return section


class TestTextDeduplication:
    """One block per ``(kind, current_sha, target_sha)`` per file."""

    def test_identical_pins_collapse_to_one_block(
        self, buffer: io.StringIO
    ) -> None:
        """Fifteen identical pins must read as one paragraph."""
        pins = [make_pin(line_number=100 + n) for n in range(15)]
        render_text(
            make_outcome(pins),
            root=ROOT,
            show_suppressed=False,
            update_hint=False,
        )
        text = buffer.getvalue()

        assert text.count("→") == 1
        assert text.count("18d9c444…") == 1

    def test_every_line_number_is_listed(self, buffer: io.StringIO) -> None:
        """Deduplication removes repetition, never information."""
        pins = [make_pin(line_number=n) for n in (349, 116, 292)]
        render_text(
            make_outcome(pins),
            root=ROOT,
            show_suppressed=False,
            update_hint=False,
        )

        assert "lines 116, 292, 349" in buffer.getvalue()

    def test_a_single_pin_uses_the_singular_label(
        self, buffer: io.StringIO
    ) -> None:
        """The design's own example is a single line."""
        render_text(
            make_outcome([make_pin(line_number=116)]),
            root=ROOT,
            show_suppressed=False,
            update_hint=False,
        )
        text = buffer.getvalue()

        assert "line 116   config: '@18d9c444…'  # v0.1.1" in text
        assert "→ '@bf6642f6…'  # v0.12.2   (lfreleng-actions/.github)" in text

    def test_files_are_reported_separately(self, buffer: io.StringIO) -> None:
        """Deduplication is per file, not across the repository."""
        pins = [
            make_pin(line_number=116, file_path=WORKFLOW),
            make_pin(line_number=116, file_path=OTHER),
        ]
        render_text(
            make_outcome(pins),
            root=ROOT,
            show_suppressed=False,
            update_hint=False,
        )
        text = buffer.getvalue()

        assert ".github/workflows/zizmor-sarif-publish.yaml" in text
        assert ".github/workflows/other.yaml" in text
        assert text.count("→") == 2

    def test_distinct_targets_do_not_merge(self, buffer: io.StringIO) -> None:
        """Two different current SHAs are two different problems."""
        pins = [
            make_pin(line_number=116),
            make_pin(
                line_number=200,
                ref="8f4f0cf83e6a015957e83261ed379fd811fc060e",
                version_comment="v0.5.1",
            ),
        ]
        render_text(
            make_outcome(pins),
            root=ROOT,
            show_suppressed=False,
            update_hint=False,
        )

        assert buffer.getvalue().count("→") == 2

    def test_paths_are_relative_to_the_root(self, buffer: io.StringIO) -> None:
        """Absolute paths in a report are noise."""
        render_text(
            make_outcome([make_pin()]),
            root=ROOT,
            show_suppressed=False,
            update_hint=False,
        )
        text = buffer.getvalue()

        assert "  .github/workflows/zizmor-sarif-publish.yaml" in text
        assert "/repo/.github" not in text


class TestTextSections:
    """Each kind gets its own heading."""

    def test_stale_heading(self, buffer: io.StringIO) -> None:
        """The heading of the design's example report."""
        render_text(
            make_outcome([make_pin()]),
            root=ROOT,
            show_suppressed=False,
            update_hint=False,
        )

        assert "Stale allow-list pins" in buffer.getvalue()

    def test_comment_mismatch_has_its_own_section(
        self, buffer: io.StringIO
    ) -> None:
        """A lying comment is not a footnote to staleness."""
        pins = [
            make_pin(),
            make_pin(
                line_number=200, ref=CURRENT_SHA, version_comment=STALE_TAG
            ),
        ]
        render_text(
            make_outcome(pins),
            root=ROOT,
            show_suppressed=False,
            update_hint=False,
        )
        text = buffer.getvalue()

        assert "incorrect version comments" in text
        assert "Stale allow-list pins" in text

    def test_unpinned_shows_the_ref_it_names(self, buffer: io.StringIO) -> None:
        """There is no SHA to abbreviate, so the ref is shown instead."""
        render_text(
            make_outcome([make_pin(ref="main", version_comment=None)]),
            root=ROOT,
            show_suppressed=False,
            update_hint=False,
        )
        text = buffer.getvalue()

        assert "config: '@main'" in text
        assert "not pinned to a commit SHA" in text

    def test_quoting_style_is_preserved(self, buffer: io.StringIO) -> None:
        """An unquoted scalar is rendered unquoted."""
        render_text(
            make_outcome([make_pin(quote_style=QuoteStyle.NONE)]),
            root=ROOT,
            show_suppressed=False,
            update_hint=False,
        )

        assert "config: @18d9c444…" in buffer.getvalue()

    def test_nothing_is_printed_when_the_check_did_not_run(
        self, buffer: io.StringIO
    ) -> None:
        """Silence, not a misleading all-clear."""
        render_text(
            make_outcome([], checked=False),
            root=ROOT,
            show_suppressed=False,
            update_hint=True,
        )

        assert buffer.getvalue() == ""

    def test_nothing_is_printed_when_everything_is_current(
        self, buffer: io.StringIO
    ) -> None:
        """A clean run stays quiet, as the rest of the linter does."""
        render_text(
            make_outcome(
                [make_pin(ref=CURRENT_SHA, version_comment=CURRENT_TAG)]
            ),
            root=ROOT,
            show_suppressed=False,
            update_hint=True,
        )

        assert buffer.getvalue() == ""


class TestUpdateHint:
    """The ``--update-allow-list`` advertisement."""

    def test_hint_is_printed_when_repairable_findings_remain(
        self, buffer: io.StringIO
    ) -> None:
        """The reader is told what to do next."""
        render_text(
            make_outcome([make_pin()]),
            root=ROOT,
            show_suppressed=False,
            update_hint=True,
        )

        assert "--update-allow-list" in buffer.getvalue()

    def test_hint_is_withheld_on_request(self, buffer: io.StringIO) -> None:
        """A caller that has already run the fixer suppresses it."""
        render_text(
            make_outcome([make_pin()]),
            root=ROOT,
            show_suppressed=False,
            update_hint=False,
        )

        assert "--update-allow-list" not in buffer.getvalue()

    def test_hint_is_withheld_when_only_suppressed_pins_remain(
        self, buffer: io.StringIO
    ) -> None:
        """A suppressed pin is invisible to remediation, so say nothing."""
        render_text(
            make_outcome([make_pin(directives=frozenset({ALLOW}))]),
            root=ROOT,
            show_suppressed=False,
            update_hint=True,
        )

        assert "--update-allow-list" not in buffer.getvalue()


class TestSuppressionVisibility:
    """Suppressions must not become invisible forever."""

    def test_suppressed_pins_are_not_listed_by_default(
        self, buffer: io.StringIO
    ) -> None:
        """The default report shows what needs action."""
        render_text(
            make_outcome([make_pin(directives=frozenset({ALLOW}))]),
            root=ROOT,
            show_suppressed=False,
            update_hint=False,
        )
        text = buffer.getvalue()

        assert "Stale allow-list pins" not in text
        assert "18d9c444…" not in text

    def test_the_summary_line_is_always_emitted(
        self, buffer: io.StringIO
    ) -> None:
        """The exact wording of design section 7.4."""
        pins = [
            make_pin(line_number=10, directives=frozenset({ALLOW})),
            make_pin(line_number=20, directives=frozenset({ALLOW})),
            make_pin(
                line_number=30,
                file_path=OTHER,
                directives=frozenset({ALLOW}),
            ),
        ]
        render_text(
            make_outcome(pins),
            root=ROOT,
            show_suppressed=False,
            update_hint=False,
        )

        assert (
            "3 allow-list pins suppressed (2 files) — use "
            "--show-suppressed for detail" in buffer.getvalue()
        )

    def test_the_summary_line_is_singular_for_one_pin(
        self, buffer: io.StringIO
    ) -> None:
        """Counting is not an excuse for bad English."""
        render_text(
            make_outcome([make_pin(directives=frozenset({ALLOW}))]),
            root=ROOT,
            show_suppressed=False,
            update_hint=False,
        )

        assert "1 allow-list pin suppressed (1 file)" in buffer.getvalue()

    def test_no_summary_when_nothing_is_suppressed(
        self, buffer: io.StringIO
    ) -> None:
        """A quiet mechanism when it is not in use."""
        render_text(
            make_outcome([make_pin()]),
            root=ROOT,
            show_suppressed=False,
            update_hint=False,
        )

        assert "suppressed" not in buffer.getvalue()

    def test_show_suppressed_lists_them_with_reasons(
        self, buffer: io.StringIO
    ) -> None:
        """A suppression carries its own justification."""
        render_text(
            make_outcome(
                [
                    make_pin(
                        directives=frozenset({ALLOW}),
                        reason="blocked on ONAP mirror rollout",
                    )
                ]
            ),
            root=ROOT,
            show_suppressed=True,
            update_hint=False,
        )
        text = buffer.getvalue()

        assert "Suppressed allow-list pins" in text
        assert "suppressed: blocked on ONAP mirror rollout" in text
        assert "--show-suppressed for detail" not in text

    def test_show_suppressed_reports_a_missing_reason(
        self, buffer: io.StringIO
    ) -> None:
        """A directive without a reason is still auditable."""
        render_text(
            make_outcome([make_pin(directives=frozenset({ALLOW}))]),
            root=ROOT,
            show_suppressed=True,
            update_hint=False,
        )

        assert "suppressed: no reason given" in buffer.getvalue()


class TestUnresolvedRendering:
    """Resolution failure is reported, never silently swallowed."""

    def test_the_reason_is_printed(self, buffer: io.StringIO) -> None:
        """ "Could not check" must never read as "nothing to report"."""
        render_text(
            make_outcome(
                [],
                hosts={HOST_REPO: None},
                unresolved={HOST_REPO: "rate limited"},
            ),
            root=ROOT,
            show_suppressed=False,
            update_hint=False,
        )
        text = buffer.getvalue()

        assert f"Allow-list check skipped for {HOST_REPO}" in text
        assert "rate limited" in text


class TestJsonShape:
    """The document of design section 9.4, exactly."""

    def test_top_level_keys(self) -> None:
        """The object carries exactly the documented keys."""
        payload = allow_list(make_outcome([make_pin()]))

        assert list(payload) == [
            "checked",
            "resolved",
            "hosts",
            "unresolved",
            "findings",
            "summary",
        ]

    def test_host_entry_shape(self) -> None:
        """Each resolved host names its version and its commit."""
        payload = allow_list(make_outcome([make_pin()]))

        assert payload["hosts"] == {
            HOST_REPO: {
                "latest_version": CURRENT_TAG,
                "latest_sha": CURRENT_SHA,
            }
        }

    def test_finding_entry_shape(self) -> None:
        """Every documented field, with the documented values."""
        payload = allow_list(make_outcome([make_pin()]))

        assert payload["findings"] == [
            {
                "file": ".github/workflows/zizmor-sarif-publish.yaml",
                "line": 116,
                "kind": "stale",
                "severity": "warning",
                "current_sha": STALE_SHA,
                "current_version": STALE_TAG,
                "target_sha": CURRENT_SHA,
                "target_version": CURRENT_TAG,
                "suppressed": False,
                "fixed": False,
            }
        ]

    def test_summary_shape(self) -> None:
        """The buckets are present, in order, even when zero."""
        pins = [make_pin(line_number=n) for n in (116, 292, 349)]
        payload = allow_list(make_outcome(pins))

        assert payload["summary"] == {
            "stale": 3,
            "comment_mismatch": 0,
            "unpinned": 0,
            "suppressed": 0,
            "fixed": 0,
        }
        assert list(payload["summary"]) == [
            "stale",
            "comment_mismatch",
            "unpinned",
            "suppressed",
            "fixed",
        ]

    def test_severity_reflects_enforcement(self) -> None:
        """Promotion under ``verify`` reaches the JSON."""
        payload = allow_list(make_outcome([make_pin()], verify=True))

        assert payload["findings"][0]["severity"] == "error"

    def test_unpinned_findings_carry_no_current_sha(self) -> None:
        """``null`` is the honest answer when the pin names no commit."""
        payload = allow_list(
            make_outcome([make_pin(ref="main", version_comment=None)])
        )
        finding = payload["findings"][0]

        assert finding["kind"] == "unpinned"
        assert finding["current_sha"] is None
        assert finding["current_version"] is None

    def test_checked_is_false_when_the_check_did_not_run(self) -> None:
        """An empty findings list is not a clean bill of health."""
        payload = allow_list(make_outcome([], checked=False))

        assert payload["checked"] is False
        assert payload["findings"] == []

    def test_unresolved_hosts_are_named_with_their_reason(self) -> None:
        """``resolved`` alone does not say which host failed."""
        payload = allow_list(
            make_outcome(
                [make_pin()],
                hosts={HOST_REPO: None},
                unresolved={HOST_REPO: "rate limited"},
            )
        )

        assert payload["resolved"] is False
        assert payload["hosts"] == {}
        assert payload["unresolved"] == {HOST_REPO: "rate limited"}
        assert payload["findings"] == []


class TestJsonSuppression:
    """Suppressed findings are hidden from the exit code, not the JSON."""

    def test_suppressed_findings_are_always_present(self) -> None:
        """Machine consumers see the full picture without a flag."""
        payload = allow_list(
            make_outcome(
                [make_pin(directives=frozenset({ALLOW}), reason="deliberate")]
            )
        )

        assert len(payload["findings"]) == 1
        assert payload["findings"][0]["suppressed"] is True

    def test_suppressed_findings_are_not_counted_as_failures(self) -> None:
        """The kind buckets count what actually needs action."""
        pins = [
            make_pin(line_number=10, directives=frozenset({ALLOW})),
            make_pin(line_number=20),
        ]
        payload = allow_list(make_outcome(pins))

        assert payload["summary"]["stale"] == 1
        assert payload["summary"]["suppressed"] == 1
        assert len(payload["findings"]) == 2

    def test_suppressed_findings_keep_their_default_severity(self) -> None:
        """Enforcement must not defeat a suppression, even in JSON."""
        payload = allow_list(
            make_outcome([make_pin(directives=frozenset({ALLOW}))], verify=True)
        )

        assert payload["findings"][0]["severity"] == "warning"

    def test_a_wholly_suppressed_run_reports_no_failures(self) -> None:
        """Design section 9.3: all stale pins suppressed means exit 0."""
        outcome = make_outcome(
            [make_pin(directives=frozenset({ALLOW}))], verify=True
        )
        payload = allow_list(outcome)

        assert outcome.unsuppressed == []
        assert payload["summary"]["stale"] == 0
        assert payload["summary"]["suppressed"] == 1


class TestFindingHelpers:
    """Small conveniences the CLI leans on."""

    def test_findings_report_their_host_repository(self) -> None:
        """The report prints the host beside every target."""
        findings: list[AllowListFinding] = classify_pins(
            [make_pin()], {HOST_REPO: LATEST}, verify=False
        )

        assert findings[0].host_repo == HOST_REPO
