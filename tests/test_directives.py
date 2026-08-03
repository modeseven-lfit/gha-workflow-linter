# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for linter-suppression directive parsing and rendering."""

from __future__ import annotations

import pytest

from gha_workflow_linter.directives import (
    Directive,
    ParsedComment,
    Suppression,
    SuppressionSource,
    find_suppression,
    parse_preceding_directive,
    parse_trailing_comment,
    render_comment,
)

ALLOW = Directive.ALLOW_LIST_PIN_OK


class TestParseTrailingComment:
    """Parsing of the trailing comment on a pinned line."""

    def test_version_only_comment(self) -> None:
        """The common case: a bare version token, no directives."""
        parsed = parse_trailing_comment("# v0.5.1")
        assert parsed == ParsedComment(
            version="v0.5.1",
            directives=frozenset(),
            reason=None,
            unrecognised=(),
        )

    def test_inline_directive_after_version(self) -> None:
        """A directive may follow the version token."""
        parsed = parse_trailing_comment("# v0.5.1 allow-list-pin-ok")
        assert parsed.version == "v0.5.1"
        assert parsed.directives == frozenset({ALLOW})
        assert parsed.reason is None
        assert parsed.unrecognised == ()

    def test_directive_only_comment_has_no_version(self) -> None:
        """A comment that is only a directive yields no version."""
        parsed = parse_trailing_comment("# allow-list-pin-ok")
        assert parsed.version is None
        assert parsed.directives == frozenset({ALLOW})

    def test_none_comment(self) -> None:
        """``None`` parses to a wholly empty result."""
        parsed = parse_trailing_comment(None)
        assert parsed == ParsedComment(
            version=None,
            directives=frozenset(),
            reason=None,
            unrecognised=(),
        )

    @pytest.mark.parametrize("comment", ["", "   ", "#", "#   ", "##"])
    def test_empty_comment_variants(self, comment: str) -> None:
        """Empty (or marker-only) comments carry nothing."""
        parsed = parse_trailing_comment(comment)
        assert parsed.version is None
        assert parsed.directives == frozenset()
        assert parsed.reason is None
        assert parsed.unrecognised == ()

    @pytest.mark.parametrize(
        "comment",
        [
            "# v0.5.1",
            "v0.5.1",
            "#v0.5.1",
            "## v0.5.1",
            "   #   v0.5.1   ",
        ],
    )
    def test_leading_markers_and_whitespace_are_optional(
        self, comment: str
    ) -> None:
        """Leading ``#`` characters and whitespace are insignificant."""
        assert parse_trailing_comment(comment).version == "v0.5.1"

    def test_repeated_directive_collapses(self) -> None:
        """Directives are a set, so repetition is harmless."""
        parsed = parse_trailing_comment(
            "# v1.2.3 allow-list-pin-ok allow-list-pin-ok"
        )
        assert parsed.directives == frozenset({ALLOW})
        assert parsed.unrecognised == ()


class TestReasonParsing:
    """Splitting of the optional ``--`` introduced reason."""

    def test_reason_after_directive(self) -> None:
        """Text after ``--`` becomes the reason, stripped."""
        parsed = parse_trailing_comment(
            "# v0.5.1 allow-list-pin-ok -- blocked on ONAP mirror rollout"
        )
        assert parsed.version == "v0.5.1"
        assert parsed.directives == frozenset({ALLOW})
        assert parsed.reason == "blocked on ONAP mirror rollout"

    def test_reason_may_contain_a_double_dash(self) -> None:
        """Only the first ``--`` introduces the reason."""
        parsed = parse_trailing_comment(
            "# v0.5.1 allow-list-pin-ok -- blocked -- see issue 42"
        )
        assert parsed.reason == "blocked -- see issue 42"

    def test_reason_surrounding_whitespace_is_stripped(self) -> None:
        """Extra whitespace around the reason is discarded."""
        parsed = parse_trailing_comment(
            "# v0.5.1 allow-list-pin-ok  --   why not   "
        )
        assert parsed.reason == "why not"

    @pytest.mark.parametrize(
        "comment",
        [
            "# v0.5.1 allow-list-pin-ok --fix",
            "# v0.5.1 allow-list-pin-ok a--b",
        ],
    )
    def test_double_dash_without_whitespace_is_not_a_reason(
        self, comment: str
    ) -> None:
        """``--`` must be whitespace-delimited to introduce a reason."""
        parsed = parse_trailing_comment(comment)
        assert parsed.reason is None
        assert parsed.directives == frozenset({ALLOW})
        assert len(parsed.unrecognised) == 1

    def test_trailing_double_dash_with_no_text_is_a_token(self) -> None:
        """A dangling ``--`` introduces nothing and is preserved."""
        parsed = parse_trailing_comment("# v0.5.1 allow-list-pin-ok --")
        assert parsed.reason is None
        assert parsed.unrecognised == ("--",)

    def test_reason_without_directives(self) -> None:
        """A reason parses even when no directive is present."""
        parsed = parse_trailing_comment("# v0.5.1 -- just a note")
        assert parsed.version == "v0.5.1"
        assert parsed.directives == frozenset()
        assert parsed.reason == "just a note"


class TestUnrecognisedTokens:
    """Verbatim preservation of tokens the linter does not know."""

    def test_unrecognised_tokens_keep_order(self) -> None:
        """Unknown tokens are kept verbatim, in their original order."""
        parsed = parse_trailing_comment("# v0.5.1 zeta allow-list-pin-ok alpha")
        assert parsed.version == "v0.5.1"
        assert parsed.directives == frozenset({ALLOW})
        assert parsed.unrecognised == ("zeta", "alpha")

    def test_unrecognised_tokens_do_not_suppress(self) -> None:
        """Unknown tokens are ignored for suppression purposes."""
        suppression = find_suppression(
            comment="# v0.5.1 allow-list-pin-nope",
            preceding_line=None,
        )
        assert suppression is None

    def test_case_variant_directive_is_unrecognised(self) -> None:
        """Directive keywords are matched case-sensitively."""
        parsed = parse_trailing_comment("# v0.5.1 ALLOW-LIST-PIN-OK")
        assert parsed.directives == frozenset()
        assert parsed.unrecognised == ("ALLOW-LIST-PIN-OK",)


class TestParsePrecedingDirective:
    """Parsing of a standalone directive comment line."""

    @pytest.mark.parametrize(
        "line",
        [
            "# gha-workflow-linter: allow-list-pin-ok",
            "    # gha-workflow-linter: allow-list-pin-ok",
            "\t\t# gha-workflow-linter: allow-list-pin-ok",
            "        #   gha-workflow-linter:   allow-list-pin-ok  ",
        ],
    )
    def test_indentation_is_irrelevant(self, line: str) -> None:
        """A directive comment may sit at any column."""
        suppression = parse_preceding_directive(line)
        assert suppression == Suppression(
            directives=frozenset({ALLOW}),
            source=SuppressionSource.PRECEDING_LINE,
            reason=None,
        )

    def test_reason_on_preceding_line(self) -> None:
        """The preceding form accepts a reason too."""
        suppression = parse_preceding_directive(
            "  # gha-workflow-linter: allow-list-pin-ok -- upstream fix"
        )
        assert suppression is not None
        assert suppression.reason == "upstream fix"
        assert suppression.source is SuppressionSource.PRECEDING_LINE

    @pytest.mark.parametrize(
        "line",
        [
            "  config: '@8f4f0cf'  # v0.5.1",
            "",
            "   ",
            "# just an ordinary comment",
            "# allow-list-pin-ok",
            "# gha-workflow-linter:allow-list-pin-ok",
            "# gha-workflow-linter: unknown-directive",
            "# gha-workflow-linter: -- only a reason",
            "# gha-workflow-linter:",
        ],
    )
    def test_non_directive_lines_return_none(self, line: str) -> None:
        """Lines without a usable marker and directive yield ``None``."""
        assert parse_preceding_directive(line) is None

    @pytest.mark.parametrize(
        "line",
        [
            "# GHA-WORKFLOW-LINTER: allow-list-pin-ok",
            "# Gha-Workflow-Linter: allow-list-pin-ok",
        ],
    )
    def test_marker_is_case_sensitive(self, line: str) -> None:
        """A wrong-case marker is not recognised."""
        assert parse_preceding_directive(line) is None

    def test_unrecognised_tokens_alongside_directive(self) -> None:
        """Unknown tokens do not prevent a valid directive."""
        suppression = parse_preceding_directive(
            "# gha-workflow-linter: allow-list-pin-ok extra-token"
        )
        assert suppression is not None
        assert suppression.directives == frozenset({ALLOW})


class TestFindSuppression:
    """Resolution of the effective suppression for a pinned line."""

    def test_inline_form_only(self) -> None:
        """The inline form suppresses on its own."""
        suppression = find_suppression(
            comment="# v0.5.1 allow-list-pin-ok",
            preceding_line="  with:",
        )
        assert suppression == Suppression(
            directives=frozenset({ALLOW}),
            source=SuppressionSource.INLINE_COMMENT,
            reason=None,
        )

    def test_preceding_form_only(self) -> None:
        """The preceding form suppresses on its own."""
        suppression = find_suppression(
            comment="# v0.5.1",
            preceding_line="    # gha-workflow-linter: allow-list-pin-ok",
        )
        assert suppression == Suppression(
            directives=frozenset({ALLOW}),
            source=SuppressionSource.PRECEDING_LINE,
            reason=None,
        )

    def test_both_forms_prefer_inline_source(self) -> None:
        """Both forms together union directives and prefer inline."""
        suppression = find_suppression(
            comment="# v0.5.1 allow-list-pin-ok",
            preceding_line="# gha-workflow-linter: allow-list-pin-ok",
        )
        assert suppression is not None
        assert suppression.source is SuppressionSource.INLINE_COMMENT
        assert suppression.directives == frozenset({ALLOW})

    def test_both_forms_inline_reason_wins(self) -> None:
        """When both carry a reason, the inline one is reported."""
        suppression = find_suppression(
            comment="# v0.5.1 allow-list-pin-ok -- inline reason",
            preceding_line=(
                "# gha-workflow-linter: allow-list-pin-ok -- other reason"
            ),
        )
        assert suppression is not None
        assert suppression.reason == "inline reason"

    def test_both_forms_falls_back_to_preceding_reason(self) -> None:
        """A reason on the preceding line is used when inline has none."""
        suppression = find_suppression(
            comment="# v0.5.1 allow-list-pin-ok",
            preceding_line=(
                "# gha-workflow-linter: allow-list-pin-ok -- mirror rollout"
            ),
        )
        assert suppression is not None
        assert suppression.reason == "mirror rollout"

    def test_version_only_comment_does_not_suppress(self) -> None:
        """The overwhelmingly common case yields no suppression."""
        assert find_suppression(comment="# v0.5.1", preceding_line=None) is None

    @pytest.mark.parametrize("comment", [None, "", "# "])
    def test_absent_comment_does_not_suppress(
        self, comment: str | None
    ) -> None:
        """Missing or empty comments yield no suppression."""
        assert find_suppression(comment=comment, preceding_line=None) is None

    def test_preceding_line_none_is_accepted(self) -> None:
        """A ``None`` preceding line is simply ignored."""
        suppression = find_suppression(
            comment="# v0.5.1 allow-list-pin-ok",
            preceding_line=None,
        )
        assert suppression is not None
        assert suppression.source is SuppressionSource.INLINE_COMMENT

    def test_non_comment_preceding_line_does_not_suppress(self) -> None:
        """Only a directive comment on the previous line counts."""
        assert (
            find_suppression(
                comment="# v0.5.1",
                preceding_line="        config: '@8f4f0cf'  # v0.5.1",
            )
            is None
        )


class TestRenderComment:
    """Re-rendering of a parsed comment."""

    def test_render_version_only(self) -> None:
        """A version-only comment renders as the bare token."""
        parsed = parse_trailing_comment("# v0.5.1")
        assert render_comment(parsed, version="v0.5.1") == "v0.5.1"

    def test_render_omits_absent_version(self) -> None:
        """A ``None`` version emits nothing in its place."""
        parsed = parse_trailing_comment("# allow-list-pin-ok")
        assert render_comment(parsed, version=None) == "allow-list-pin-ok"

    def test_render_has_no_leading_hash(self) -> None:
        """Rendering returns the body, not the comment marker."""
        parsed = parse_trailing_comment("# v0.5.1 allow-list-pin-ok")
        assert not render_comment(parsed, version="v0.5.1").startswith("#")

    def test_render_ordering(self) -> None:
        """Parts render as version, directives, unknowns, then reason."""
        parsed = parse_trailing_comment(
            "# v0.5.1 zeta allow-list-pin-ok alpha -- why"
        )
        assert render_comment(parsed, version="v0.5.1") == (
            "v0.5.1 allow-list-pin-ok zeta alpha -- why"
        )

    def test_render_version_bump(self) -> None:
        """A version bump keeps directives and reason intact."""
        parsed = parse_trailing_comment("# v0.5.1 allow-list-pin-ok -- why")
        rendered = render_comment(parsed, version="v0.12.2")
        assert rendered == "v0.12.2 allow-list-pin-ok -- why"

        reparsed = parse_trailing_comment(rendered)
        assert reparsed.version == "v0.12.2"
        assert reparsed.directives == parsed.directives
        assert reparsed.reason == parsed.reason
        assert reparsed.unrecognised == parsed.unrecognised

    def test_render_directives_are_ordered_stably(self) -> None:
        """Directives render alphabetically by keyword."""
        parsed = ParsedComment(
            version="v1.0.0",
            directives=frozenset(Directive),
            reason=None,
            unrecognised=(),
        )
        expected = " ".join(["v1.0.0", *sorted(d.value for d in Directive)])
        assert render_comment(parsed, version="v1.0.0") == expected


@pytest.mark.parametrize(
    "comment",
    [
        "",
        "# v0.5.1",
        "# allow-list-pin-ok",
        "# v0.5.1 allow-list-pin-ok",
        "# v0.5.1 allow-list-pin-ok -- blocked on ONAP mirror rollout",
        "# v0.5.1 allow-list-pin-ok -- blocked -- see issue 42",
        "# v0.5.1 zeta allow-list-pin-ok alpha",
        "# v0.5.1 zeta allow-list-pin-ok alpha -- because",
        "# v0.5.1 --fix",
        "# v0.5.1 allow-list-pin-ok --",
        "## v0.5.1 allow-list-pin-ok",
    ],
)
def test_round_trip_preserves_content(comment: str) -> None:
    """Rendering a parsed comment preserves everything it carried."""
    parsed = parse_trailing_comment(comment)
    rendered = render_comment(parsed, version=parsed.version)
    reparsed = parse_trailing_comment(rendered)

    assert reparsed.version == parsed.version
    assert reparsed.directives == parsed.directives
    assert reparsed.reason == parsed.reason
    assert reparsed.unrecognised == parsed.unrecognised


@pytest.mark.parametrize(
    "comment",
    [
        "# v0.5.1",
        "# v0.5.1 allow-list-pin-ok",
        "# v0.5.1 allow-list-pin-ok -- reason text",
        "# v0.5.1 zeta allow-list-pin-ok",
    ],
)
def test_round_trip_across_version_bump(comment: str) -> None:
    """A version bump is the only difference a re-render introduces."""
    parsed = parse_trailing_comment(comment)
    rendered = render_comment(parsed, version="v9.9.9")
    reparsed = parse_trailing_comment(rendered)

    assert reparsed.version == "v9.9.9"
    assert reparsed.directives == parsed.directives
    assert reparsed.reason == parsed.reason
    assert reparsed.unrecognised == parsed.unrecognised
