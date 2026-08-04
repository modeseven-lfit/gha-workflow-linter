# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for allow-list pin detection.

The fixtures under ``tests/fixtures/allow_list`` carry shapes copied from
the real estate, so the line and column assertions below are assertions
about workflows people actually wrote. Where a test names a line number
it is 1-based, matching :attr:`AllowListPin.line_number`.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml

from gha_workflow_linter.allow_list_scanner import (
    DEFAULT_KEY_PATTERNS,
    AllowListPin,
    AllowListScanner,
    CommentPosition,
    QuoteStyle,
)
from gha_workflow_linter.directives import Directive, SuppressionSource
from gha_workflow_linter.models import Config

FIXTURES = Path(__file__).parent / "fixtures" / "allow_list"

#: Org owning every fixture workflow. The shorthand '@<sha>' form takes
#: its host org from here.
WORKFLOW_ORG = "lfreleng-actions"

ALLOW = Directive.ALLOW_LIST_PIN_OK

SHA_V0_1_1 = "18d9c4446bea555d0783e850f6d295f844fe8f67"
SHA_V0_5_1 = "8f4f0cf83e6a015957e83261ed379fd811fc060e"
SHA_V0_12_2 = "bf6642f68d58c1b81bbe993e676d6cc339ac3654"


@pytest.fixture
def scanner() -> AllowListScanner:
    """Return a scanner with default configuration and patterns."""
    return AllowListScanner(Config(), WORKFLOW_ORG)


def scan(scanner: AllowListScanner, name: str) -> list[AllowListPin]:
    """Scan one fixture by filename.

    Args:
        scanner: The scanner under test.
        name: Fixture filename within ``tests/fixtures/allow_list``.

    Returns:
        The pins found, in document order.
    """
    return scanner.scan_file(FIXTURES / name)


def key_paths(pins: list[AllowListPin]) -> list[str]:
    """Return each pin's key path, joined with dots.

    Args:
        pins: Pins to summarise.

    Returns:
        One dotted key path per pin, in order.
    """
    return [".".join(pin.key_path) for pin in pins]


class TestDetectionLocations:
    """All three locations of design section 5.1."""

    def test_step_with_config(self, scanner: AllowListScanner) -> None:
        """Location 1: an input named ``config`` on a step."""
        pins = scan(scanner, "internal_step_config.yaml")

        assert key_paths(pins) == ["jobs.build.steps.0.with.config"]
        assert pins[0].spec.ref == SHA_V0_1_1

    def test_workflow_call_input_default(
        self, scanner: AllowListScanner
    ) -> None:
        """Location 2: a ``workflow_call`` input default."""
        pins = scan(scanner, "workflow_call_defaults.yaml")

        assert key_paths(pins) == [
            "on.workflow_call.inputs.harden_runner_allowlist.default",
            "on.workflow_call.inputs.audit_config.default",
        ]

    def test_reusable_workflow_caller_input(
        self, scanner: AllowListScanner
    ) -> None:
        """Location 3: an input in a caller job's ``with`` block."""
        pins = scan(scanner, "reusable_caller.yaml")

        assert key_paths(pins) == ["jobs.call.with.harden_runner_allowlist"]
        assert pins[0].spec.path_explicit is True

    def test_step_index_is_the_sequence_position(
        self, scanner: AllowListScanner
    ) -> None:
        """Steps are addressed by index, as decimal strings."""
        pins = scan(scanner, "comment_positions.yaml")

        assert [pin.key_path[3] for pin in pins] == ["0", "1", "2", "3", "4"]


class TestYamlOneOneTriggerKey:
    """The bare ``on:`` key, which YAML 1.1 resolves to a boolean."""

    def test_pins_found_under_a_bare_on_key(
        self, scanner: AllowListScanner
    ) -> None:
        """Detection survives the retagging of ``on``.

        ``tests/test_scanner_yaml_tree`` documents the behaviour: the
        composed key node keeps its raw text but carries the *bool* tag,
        and a document constructed with ``yaml.safe_load`` has the key
        ``True``. The walk matches raw text, so location 2 is reached.
        """
        path = FIXTURES / "workflow_call_defaults.yaml"
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))

        # Confirm the hazard is real for this fixture, not assumed.
        assert isinstance(loaded, dict)
        assert True in loaded
        assert "on" not in loaded

        pins = scanner.scan_file(path)
        assert pins
        assert all(pin.key_path[0] == "on" for pin in pins)

    def test_quoted_on_key_behaves_identically(
        self, scanner: AllowListScanner, tmp_path: Path
    ) -> None:
        """Quoting ``on`` keeps the string tag and changes nothing."""
        path = tmp_path / "quoted-on.yaml"
        path.write_text(
            "---\n"
            '"on":\n'
            "  workflow_call:\n"
            "    inputs:\n"
            "      harden_runner_allowlist:\n"
            "        type: string\n"
            f"        default: '@{SHA_V0_1_1}'  # v0.1.1\n",
            encoding="utf-8",
        )

        pins = scanner.scan_file(path)

        assert key_paths(pins) == [
            "on.workflow_call.inputs.harden_runner_allowlist.default"
        ]

    def test_trigger_block_without_a_mapping_is_harmless(
        self, scanner: AllowListScanner, tmp_path: Path
    ) -> None:
        """``on: [push]`` and ``on: push`` yield nothing, not an error."""
        for text in ("on: [push]\n", "on: push\n"):
            path = tmp_path / "trigger.yaml"
            path.write_text(f"---\n{text}", encoding="utf-8")

            assert scanner.scan_file(path) == []


class TestRecogniserPredicate:
    """Recognition where the key name is the author's choice."""

    def test_conventional_filename_needs_no_registry(
        self, scanner: AllowListScanner
    ) -> None:
        """A python-audit pin is found with no code change.

        Design section 5.4: consumers are data, not code. This pin sits
        under a key matching none of the default patterns, so the only
        thing that identifies it is the conventional filename at the end
        of the path the author wrote. Nothing here knows what
        ``python-audit`` is.
        """
        pins = scan(scanner, "workflow_call_defaults.yaml")
        audit = pins[1]

        assert audit.key_path[-2] == "audit_config"
        assert not any(
            pattern.strip("*") in "audit_config"
            for pattern in DEFAULT_KEY_PATTERNS
        )
        assert audit.spec.candidates == (
            ".github/python-audit/lfreleng-actions/allow_list.txt",
        )

    def test_key_name_pattern_recognises_shorthand(
        self, scanner: AllowListScanner, tmp_path: Path
    ) -> None:
        """A shorthand default qualifies on its key name alone."""
        path = tmp_path / "shorthand-default.yaml"
        path.write_text(
            "---\n"
            "on:\n"
            "  workflow_call:\n"
            "    inputs:\n"
            "      harden_runner_allow-list:\n"
            "        type: string\n"
            f"        default: '@{SHA_V0_12_2}'  # v0.12.2\n",
            encoding="utf-8",
        )

        pins = scanner.scan_file(path)

        assert len(pins) == 1
        assert pins[0].spec.ref == SHA_V0_12_2

    def test_key_name_matching_is_case_insensitive(
        self, scanner: AllowListScanner, tmp_path: Path
    ) -> None:
        """``HardenRunnerAllowList`` matches ``*allowlist*``."""
        path = tmp_path / "mixed-case.yaml"
        path.write_text(
            "---\n"
            "jobs:\n"
            "  call:\n"
            "    uses: org/repo/.github/workflows/w.yaml@main\n"
            "    with:\n"
            f"      HardenRunnerAllowList: '@{SHA_V0_1_1}'\n",
            encoding="utf-8",
        )

        assert len(scanner.scan_file(path)) == 1

    def test_parsable_scalar_under_unrelated_key_is_not_a_pin(
        self, scanner: AllowListScanner
    ) -> None:
        """A default that merely parses is not thereby a coordinate.

        ``build_timeout: '30'`` resolves cleanly -- an org taking every
        default -- so testing the resolved candidate chain would accept
        it. The predicate tests what the author *wrote* instead.
        """
        pins = scan(scanner, "workflow_call_defaults.yaml")

        assert "build_timeout" not in str(key_paths(pins))

    def test_key_patterns_are_configurable(self, tmp_path: Path) -> None:
        """A caller may supply its own key-name patterns."""
        path = tmp_path / "custom-key.yaml"
        path.write_text(
            "---\n"
            "jobs:\n"
            "  call:\n"
            "    uses: org/repo/.github/workflows/w.yaml@main\n"
            "    with:\n"
            f"      egress_policy_source: '@{SHA_V0_1_1}'\n",
            encoding="utf-8",
        )

        default_scanner = AllowListScanner(Config(), WORKFLOW_ORG)
        custom = AllowListScanner(
            Config(), WORKFLOW_ORG, key_patterns=["*egress*"]
        )

        assert default_scanner.scan_file(path) == []
        assert len(custom.scan_file(path)) == 1

    def test_filename_is_configurable(self, tmp_path: Path) -> None:
        """The conventional filename may be overridden."""
        path = tmp_path / "custom-filename.yaml"
        path.write_text(
            "---\n"
            "jobs:\n"
            "  call:\n"
            "    uses: org/repo/.github/workflows/w.yaml@main\n"
            "    with:\n"
            "      policy: 'lfreleng-actions"
            f"//.github/harden-runner/endpoints.txt@{SHA_V0_12_2}'\n",
            encoding="utf-8",
        )

        default_scanner = AllowListScanner(Config(), WORKFLOW_ORG)
        custom = AllowListScanner(
            Config(), WORKFLOW_ORG, filename="endpoints.txt"
        )

        assert default_scanner.scan_file(path) == []
        assert len(custom.scan_file(path)) == 1

    def test_step_config_needs_no_recogniser(
        self, scanner: AllowListScanner, tmp_path: Path
    ) -> None:
        """Location 1 is anchored structurally, not by key pattern."""
        path = tmp_path / "anchored.yaml"
        path.write_text(
            "---\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: org/action@main\n"
            "        with:\n"
            "          config: 'lfreleng-actions@main'\n",
            encoding="utf-8",
        )

        pins = scanner.scan_file(path)

        assert len(pins) == 1
        assert pins[0].spec.ref == "main"


class TestSkipRules:
    """Design section 5.2: what never becomes a finding."""

    def test_github_expression_is_skipped(
        self, scanner: AllowListScanner, caplog: pytest.LogCaptureFixture
    ) -> None:
        """``${{ ... }}`` is resolved at run time and is not a pin."""
        with caplog.at_level(logging.DEBUG):
            pins = scan(scanner, "reusable_caller.yaml")

        assert "jobs.expression.steps.0.with.config" not in key_paths(pins)
        assert "GitHub expression" in caplog.text

    def test_unparsable_scalar_is_skipped_silently(
        self, scanner: AllowListScanner, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A value failing the grammar is a skip, never a finding.

        Design section 5.4 is explicit that the failure mode for an
        unrelated ``config:`` value is a skip. ``'3.11'`` cannot be an
        org, so it is dropped with a debug log and nothing more.
        """
        with caplog.at_level(logging.DEBUG):
            pins = scan(scanner, "workflow_call_defaults.yaml")

        assert len(pins) == 2
        assert "not a config spec" in caplog.text

    def test_unrelated_step_config_is_skipped(
        self, scanner: AllowListScanner, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Another action's ``config:`` input produces no finding."""
        with caplog.at_level(logging.DEBUG):
            assert scan(scanner, "no_pins.yaml") == []

        assert "not a config spec" in caplog.text

    def test_empty_workflow_org_skips_the_shorthand_form(
        self, tmp_path: Path
    ) -> None:
        """Without an org the shorthand cannot resolve, so it is skipped."""
        path = tmp_path / "shorthand.yaml"
        path.write_text(
            "---\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: org/action@main\n"
            "        with:\n"
            f"          config: '@{SHA_V0_1_1}'\n",
            encoding="utf-8",
        )

        assert AllowListScanner(Config(), "").scan_file(path) == []
        assert (
            len(AllowListScanner(Config(), WORKFLOW_ORG).scan_file(path)) == 1
        )


class TestSourceAnchors:
    """Line, column and raw-line recovery."""

    def test_line_numbers_are_one_based(
        self, scanner: AllowListScanner
    ) -> None:
        """The anchor names the line an editor would show."""
        path = FIXTURES / "internal_step_config.yaml"
        pin = scanner.scan_file(path)[0]
        lines = path.read_text(encoding="utf-8").splitlines()

        assert pin.line_number == 20
        assert lines[pin.line_number - 1] == pin.raw_line
        assert pin.raw_line.lstrip().startswith("config:")

    def test_column_is_zero_based_at_the_opening_quote(
        self, scanner: AllowListScanner
    ) -> None:
        """A quoted scalar's column is its quote, not its first char."""
        pin = scan(scanner, "internal_step_config.yaml")[0]

        assert pin.column == 18
        assert pin.raw_line[pin.column] == "'"

    def test_raw_value_excludes_the_in_scalar_comment(
        self, scanner: AllowListScanner
    ) -> None:
        """Form B's comment is not part of the recorded value."""
        pin = scan(scanner, "comment_positions.yaml")[1]

        assert pin.raw_value == f"@{SHA_V0_5_1}"
        assert "#" not in pin.raw_value

    def test_file_path_is_recorded(self, scanner: AllowListScanner) -> None:
        """Each pin knows which file it came from."""
        path = FIXTURES / "internal_step_config.yaml"

        assert scanner.scan_file(path)[0].file_path == path

    def test_multi_line_scalar_is_not_auto_fixable(
        self, scanner: AllowListScanner
    ) -> None:
        """A block scalar is recorded and reported, never rewritten."""
        pins = scan(scanner, "comment_positions.yaml")
        folded = pins[4]

        assert folded.auto_fixable is False
        assert folded.line_number == 41
        assert folded.raw_line.strip() == "config: >-"
        assert folded.spec.ref == SHA_V0_12_2

    def test_single_line_scalars_are_auto_fixable(
        self, scanner: AllowListScanner
    ) -> None:
        """Everything that fits on one line can be rewritten."""
        pins = scan(scanner, "comment_positions.yaml")

        assert [pin.auto_fixable for pin in pins[:4]] == [True] * 4


class TestQuoteStyles:
    """Quoting inferred from the source text at the anchor."""

    def test_single_double_and_unquoted(
        self, scanner: AllowListScanner
    ) -> None:
        """All three styles are distinguished."""
        pins = scan(scanner, "comment_positions.yaml")

        assert [pin.quote_style for pin in pins[:3]] == [
            QuoteStyle.SINGLE,
            QuoteStyle.DOUBLE,
            QuoteStyle.NONE,
        ]

    def test_block_scalar_reports_no_quoting(
        self, scanner: AllowListScanner
    ) -> None:
        """A block scalar's start mark is its indicator, not a quote."""
        assert scan(scanner, "comment_positions.yaml")[4].quote_style is (
            QuoteStyle.NONE
        )


class TestCommentPositions:
    """Design section 2: the version comment sits in one of two places."""

    def test_yaml_comment_outside_the_quotes(
        self, scanner: AllowListScanner
    ) -> None:
        """Form A, which every pin in the estate uses."""
        pin = scan(scanner, "comment_positions.yaml")[0]

        assert pin.comment_position is CommentPosition.YAML
        assert pin.version_comment == "v0.1.1"

    def test_in_scalar_comment_inside_the_quotes(
        self, scanner: AllowListScanner
    ) -> None:
        """Form B, which the action's own parser strips."""
        pin = scan(scanner, "comment_positions.yaml")[1]

        assert pin.comment_position is CommentPosition.IN_SCALAR
        assert pin.version_comment == "v0.5.1"
        assert pin.spec.comment == "v0.5.1"

    def test_no_comment_at_all(self, scanner: AllowListScanner) -> None:
        """A pin need not carry a version comment."""
        pin = scan(scanner, "comment_positions.yaml")[2]

        assert pin.comment_position is CommentPosition.NONE
        assert pin.version_comment is None

    def test_in_scalar_comment_wins_when_both_are_present(
        self, scanner: AllowListScanner
    ) -> None:
        """The comment the action sees is the effective one."""
        pin = scan(scanner, "comment_positions.yaml")[3]

        assert pin.comment_position is CommentPosition.IN_SCALAR
        assert pin.version_comment == "v0.5.1"
        assert pin.raw_line.endswith("# v0.2.1")

    def test_in_scalar_separator_may_be_a_tab(
        self, scanner: AllowListScanner, tmp_path: Path
    ) -> None:
        """The separator rule is the action's: spaces or tabs."""
        path = tmp_path / "tab.yaml"
        path.write_text(
            "---\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: org/action@main\n"
            "        with:\n"
            f"          config: '@{SHA_V0_1_1}\t# v0.1.1'\n",
            encoding="utf-8",
        )

        pin = scanner.scan_file(path)[0]

        assert pin.raw_value == f"@{SHA_V0_1_1}"
        assert pin.comment_position is CommentPosition.IN_SCALAR
        assert pin.version_comment == "v0.1.1"

    def test_single_space_before_the_yaml_comment(
        self, scanner: AllowListScanner, tmp_path: Path
    ) -> None:
        """One space is enough to start a comment outside the quotes."""
        path = tmp_path / "one-space.yaml"
        path.write_text(
            "---\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: org/action@main\n"
            "        with:\n"
            f"          config: '@{SHA_V0_1_1}' # v0.1.1\n",
            encoding="utf-8",
        )

        pin = scanner.scan_file(path)[0]

        assert pin.comment_position is CommentPosition.YAML
        assert pin.version_comment == "v0.1.1"


class TestSuppression:
    """Design section 7.4: both directive forms, and neither."""

    def test_preceding_line_directive(self, scanner: AllowListScanner) -> None:
        """Form 1 binds to the immediately following line."""
        pin = scan(scanner, "suppression.yaml")[0]

        assert pin.directives == frozenset({ALLOW})
        assert pin.suppressed_by is SuppressionSource.PRECEDING_LINE
        assert pin.suppression_reason == "waiting for a release"

    def test_inline_keyword_directive(self, scanner: AllowListScanner) -> None:
        """Form 2 follows the version token in the trailing comment."""
        pin = scan(scanner, "suppression.yaml")[1]

        assert pin.directives == frozenset({ALLOW})
        assert pin.suppressed_by is SuppressionSource.INLINE_COMMENT
        assert pin.suppression_reason == "upstream is broken"
        assert pin.version_comment == "v0.5.1"

    def test_both_forms_together(self, scanner: AllowListScanner) -> None:
        """Both forms are idempotent; the inline reason wins."""
        pin = scan(scanner, "suppression.yaml")[2]

        assert pin.directives == frozenset({ALLOW})
        assert pin.suppressed_by is SuppressionSource.INLINE_COMMENT
        assert pin.suppression_reason == "inline reason"

    def test_directive_in_the_in_scalar_comment(
        self, scanner: AllowListScanner
    ) -> None:
        """Either comment position may carry the keyword."""
        pin = scan(scanner, "suppression.yaml")[3]

        assert pin.directives == frozenset({ALLOW})
        assert pin.suppressed_by is SuppressionSource.INLINE_COMMENT
        assert pin.version_comment == "v0.5.1"

    def test_blank_line_breaks_the_binding(
        self, scanner: AllowListScanner
    ) -> None:
        """Form 1 must be the *immediately* preceding line."""
        pin = scan(scanner, "suppression.yaml")[4]

        assert pin.directives == frozenset()
        assert pin.suppressed_by is None

    def test_unsuppressed_pin(self, scanner: AllowListScanner) -> None:
        """No directive means no suppression and no reason."""
        pin = scan(scanner, "suppression.yaml")[5]

        assert pin.directives == frozenset()
        assert pin.suppressed_by is None
        assert pin.suppression_reason is None

    def test_directive_on_the_yaml_comment_when_a_scalar_one_exists(
        self, scanner: AllowListScanner, tmp_path: Path
    ) -> None:
        """A directive outside the quotes still suppresses."""
        path = tmp_path / "either.yaml"
        path.write_text(
            "---\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: org/action@main\n"
            "        with:\n"
            f"          config: '@{SHA_V0_1_1} # v0.1.1'"
            "  # allow-list-pin-ok\n",
            encoding="utf-8",
        )

        pin = scanner.scan_file(path)[0]

        assert pin.directives == frozenset({ALLOW})
        assert pin.comment_position is CommentPosition.IN_SCALAR
        assert pin.version_comment == "v0.1.1"

    def test_preceding_directive_ignores_indentation(
        self, scanner: AllowListScanner, tmp_path: Path
    ) -> None:
        """YAML permits comments at any column, so alignment is moot."""
        path = tmp_path / "indent.yaml"
        path.write_text(
            "---\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: org/action@main\n"
            "        with:\n"
            "# gha-workflow-linter: allow-list-pin-ok\n"
            f"          config: '@{SHA_V0_1_1}'\n",
            encoding="utf-8",
        )

        assert scanner.scan_file(path)[0].directives == frozenset({ALLOW})


class TestFailureModes:
    """Nothing about a bad file may raise."""

    def test_file_with_no_pins(self, scanner: AllowListScanner) -> None:
        """An ordinary workflow yields an empty list."""
        assert scan(scanner, "no_pins.yaml") == []

    def test_invalid_yaml_yields_no_pins(
        self,
        scanner: AllowListScanner,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A file that fails to parse is reported and skipped."""
        path = tmp_path / "broken.yaml"
        path.write_text("name: Test\non: [push\njobs: {\n", encoding="utf-8")

        with caplog.at_level(logging.WARNING):
            assert scanner.scan_file(path) == []

        assert "Invalid YAML" in caplog.text

    def test_missing_file_yields_no_pins(
        self, scanner: AllowListScanner, tmp_path: Path
    ) -> None:
        """A path that does not exist is not an error."""
        assert scanner.scan_file(tmp_path / "absent.yaml") == []

    def test_empty_file_yields_no_pins(
        self, scanner: AllowListScanner, tmp_path: Path
    ) -> None:
        """An empty document composes to nothing at all."""
        path = tmp_path / "empty.yaml"
        path.write_text("", encoding="utf-8")

        assert scanner.scan_file(path) == []

    def test_non_mapping_document_yields_no_pins(
        self, scanner: AllowListScanner, tmp_path: Path
    ) -> None:
        """A document that is a sequence is walked without complaint."""
        path = tmp_path / "sequence.yaml"
        path.write_text("---\n- one\n- two\n", encoding="utf-8")

        assert scanner.scan_file(path) == []

    def test_malformed_job_shapes_yield_no_pins(
        self, scanner: AllowListScanner, tmp_path: Path
    ) -> None:
        """Unexpected node types below ``jobs`` are stepped over."""
        path = tmp_path / "malformed.yaml"
        path.write_text(
            "---\njobs: not-a-mapping\n",
            encoding="utf-8",
        )

        assert scanner.scan_file(path) == []


class TestScanFiles:
    """The multi-file entry point."""

    def test_only_files_with_pins_appear(
        self, scanner: AllowListScanner
    ) -> None:
        """Files without pins are omitted from the mapping."""
        paths = [
            FIXTURES / "internal_step_config.yaml",
            FIXTURES / "no_pins.yaml",
            FIXTURES / "workflow_call_defaults.yaml",
        ]

        results = scanner.scan_files(paths)

        assert list(results) == [paths[0], paths[2]]
        assert len(results[paths[2]]) == 2

    def test_empty_input(self, scanner: AllowListScanner) -> None:
        """No files means no results."""
        assert scanner.scan_files([]) == {}
