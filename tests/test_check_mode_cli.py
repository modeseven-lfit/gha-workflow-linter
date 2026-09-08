# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for the per-check mode options and their deprecated aliases.

Two properties matter here and are easy to lose. A mode given on the
command line must settle the *whole* behaviour of its check, and a check
that did not run must never be reported as clean.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from gha_workflow_linter.check_modes import CheckMode
from gha_workflow_linter.cli import (
    _apply_check_modes,
    _check_modes,
    _mode_from_action_call_flags,
    _mode_from_allow_list_flags,
    _stage_ran,
    app,
)
from gha_workflow_linter.exceptions import ConfigurationError
from gha_workflow_linter.models import CLIOptions, Config
from tests.conftest import strip_ansi

if TYPE_CHECKING:
    from pathlib import Path

WORKFLOW = """name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""


def _workspace(root: Path) -> Path:
    """Write one workflow carrying an unpinned reference.

    Args:
        root: Directory to build the repository layout under.

    Returns:
        The directory to point the linter at.
    """
    workflow = root / ".github" / "workflows" / "test.yaml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(WORKFLOW)
    return root


def _off(workspace: Path) -> list[str]:
    """Build an invocation with every check switched off.

    Args:
        workspace: Directory to point the linter at.

    Returns:
        The command-line arguments.
    """
    return [
        "lint",
        str(workspace),
        "--action-calls",
        "off",
        "--allow-list",
        "off",
    ]


class TestLegacyFlagsDescribeThemselvesAsModes:
    """The booleans are read back as a mode, not reimplemented as one.

    Deriving in this direction is what preserves every existing
    precedence rule between the command line and the configuration file
    without restating any of it.
    """

    def test_defaults_are_fix_and_report(self) -> None:
        config = Config()
        assert _mode_from_action_call_flags(config) is CheckMode.FIX
        assert _mode_from_allow_list_flags(config) is CheckMode.REPORT

    def test_disabled_fixer_is_report(self) -> None:
        config = Config(auto_fix=False)
        assert _mode_from_action_call_flags(config) is CheckMode.REPORT

    def test_updating_fixer_is_update(self) -> None:
        config = Config(auto_fix=True, update_actions=True)
        assert _mode_from_action_call_flags(config) is CheckMode.UPDATE

    def test_updating_without_a_fixer_is_report(self) -> None:
        """``update_actions`` only ever acted through the fixer.

        Reporting this as ``update`` would name work that never
        happened, which is the confusion modes exist to remove.
        """
        config = Config(auto_fix=False, update_actions=True)
        assert _mode_from_action_call_flags(config) is CheckMode.REPORT

    def test_disabled_allow_list_is_off(self) -> None:
        config = Config()
        config.allow_list.enabled = False
        assert _mode_from_allow_list_flags(config) is CheckMode.OFF

    def test_updating_allow_list_is_update(self) -> None:
        config = Config()
        config.allow_list.update = True
        assert _mode_from_allow_list_flags(config) is CheckMode.UPDATE


class TestAModeSettlesTheWholeBehaviour:
    """A mode is authoritative: the booleans are derived from it."""

    @pytest.mark.parametrize(
        ("mode", "auto_fix", "update_actions"),
        [
            (CheckMode.OFF, False, False),
            (CheckMode.REPORT, False, False),
            (CheckMode.FIX, True, False),
            (CheckMode.UPDATE, True, True),
        ],
    )
    def test_action_call_modes_derive_the_flags(
        self, mode: CheckMode, auto_fix: bool, update_actions: bool
    ) -> None:
        """Args:
        mode: The mode requested.
        auto_fix: The fixer setting it should imply.
        update_actions: The update setting it should imply.
        """
        config = Config()
        _apply_check_modes(config, CLIOptions(action_calls_mode=mode))

        assert config.action_calls_mode is mode
        assert config.auto_fix is auto_fix
        assert config.update_actions is update_actions

    def test_a_mode_overrides_a_contradictory_legacy_setting(self) -> None:
        """The command line said 'report'; the file said 'update'."""
        config = Config(auto_fix=True, update_actions=True)
        _apply_check_modes(
            config, CLIOptions(action_calls_mode=CheckMode.REPORT)
        )

        assert config.auto_fix is False
        assert config.update_actions is False

    def test_allow_list_off_disables_the_check(self) -> None:
        config = Config()
        _apply_check_modes(config, CLIOptions(allow_list_mode=CheckMode.OFF))

        assert config.allow_list.enabled is False
        assert config.allow_list.update is False

    def test_allow_list_update_enables_remediation(self) -> None:
        config = Config()
        _apply_check_modes(config, CLIOptions(allow_list_mode=CheckMode.UPDATE))

        assert config.allow_list.enabled is True
        assert config.allow_list.update is True

    def test_an_unsupported_rung_is_refused(self) -> None:
        """Refused outright rather than quietly downgraded to update."""
        config = Config()
        with pytest.raises(ConfigurationError, match="does not support"):
            _apply_check_modes(
                config, CLIOptions(allow_list_mode=CheckMode.FIX)
            )

    def test_report_does_not_yet_detect_staleness(self) -> None:
        """Records a known gap, so the fix has something to flip.

        Currency detection lives inside the fixer, which ``report``
        disables because it must not write. So the two axes are not yet
        independent in that direction, and the docstring says so.

        When detection is split from remediation, this assertion fails
        and should be replaced by one asserting the opposite -- which is
        the point of writing it down rather than leaving the gap in a
        comment.
        """
        config = Config()
        _apply_check_modes(
            config, CLIOptions(action_calls_mode=CheckMode.REPORT)
        )

        # The fixer is what detects outdated calls, and report disables it.
        assert config.auto_fix is False
        assert CheckMode.REPORT.runs
        assert not CheckMode.REPORT.remediates

    def test_no_mode_leaves_the_legacy_settings_alone(self) -> None:
        config = Config(auto_fix=False)
        _apply_check_modes(config, CLIOptions())

        assert config.auto_fix is False
        assert config.action_calls_mode is CheckMode.REPORT


class TestOffMeansTheCheckDoesNotRun:
    """And, crucially, is not reported as having passed."""

    def test_it_does_not_claim_the_calls_are_valid(
        self, temp_dir: Path
    ) -> None:
        """The failure this whole design exists to prevent.

        With validation skipped there are no errors to report, which is
        byte-identical to a clean repository unless the run says which
        it was.

        Args:
            temp_dir: Scratch directory for the workspace.
        """
        result = CliRunner().invoke(app, _off(_workspace(temp_dir)))
        output = strip_ansi(result.output)

        assert result.exit_code == 0
        assert "All action calls are valid" not in output
        assert "Action-call checking is off" in output

    def test_the_document_records_every_mode(self, temp_dir: Path) -> None:
        """Args:
        temp_dir: Scratch directory for the workspace.
        """
        result = CliRunner().invoke(
            app, [*_off(_workspace(temp_dir)), "--format", "json"]
        )
        document = json.loads(result.output)

        assert document["checks"] == {
            "action-calls": {"mode": "off", "ran": False},
            "allow-list": {"mode": "off", "ran": False},
        }

    def test_it_makes_no_network_request(
        self, temp_dir: Path, request: pytest.FixtureRequest
    ) -> None:
        """Both checks off must reach nothing at all.

        A token is supplied deliberately. Without one the suite's
        ``isolate_github_credentials`` fixture leaves the tool on the Git
        backend, which has no pre-flight -- so an unauthenticated run
        would pass this test while an authenticated one still issued a
        rate-limit request before the disabled checks declined to run.

        Args:
            temp_dir: Scratch directory for the workspace.
            request: Used to read what the guard recorded.
        """
        result = CliRunner().invoke(
            app,
            [
                *_off(_workspace(temp_dir)),
                "--github-token",
                "ghp_0000000000000000000000000000000000000000",
                "--validation-method",
                "github-api",
            ],
        )

        assert result.exit_code == 0
        assert getattr(request.node, "network_attempts", []) == []

    def test_off_leaves_the_file_alone(self, temp_dir: Path) -> None:
        """The fixer is part of the check, not a stage beside it.

        Args:
            temp_dir: Scratch directory for the workspace.
        """
        workspace = _workspace(temp_dir)
        workflow = workspace / ".github" / "workflows" / "test.yaml"

        CliRunner().invoke(app, _off(workspace))

        assert workflow.read_text() == WORKFLOW

    def test_a_skipped_check_is_not_reported_as_having_run(self) -> None:
        """A throttle skips every stage while leaving the modes alone.

        Deriving ``ran`` from the mode would produce a document claiming
        checks ran that did not -- the same confusion the block exists
        to prevent, arriving by a different route.
        """
        config = Config()
        _apply_check_modes(config, CLIOptions())

        ordinary = _check_modes(
            config, action_calls_ran=True, allow_list_ran=True
        )
        throttled = _check_modes(
            config,
            action_calls_ran=_stage_ran(config.action_calls_mode, True),
            allow_list_ran=_stage_ran(config.allow_list.mode, True),
        )

        assert ordinary["action-calls"] == {"mode": "fix", "ran": True}
        assert ordinary["allow-list"] == {"mode": "report", "ran": True}

        # Same modes, nothing executed.
        assert throttled["action-calls"] == {"mode": "fix", "ran": False}
        assert throttled["allow-list"] == {"mode": "report", "ran": False}

    def test_stage_ran_is_false_when_the_mode_is_off(self) -> None:
        assert _stage_ran(CheckMode.FIX, False) is True
        assert _stage_ran(CheckMode.OFF, False) is False
        assert _stage_ran(CheckMode.FIX, True) is False

    def test_a_short_circuit_does_not_claim_the_allow_list_ran(
        self, temp_dir: Path
    ) -> None:
        """A repository with no workflows returns before that stage.

        ``_run_one_repository`` short-circuits on an empty scan, so the
        allow-list check never looks at the pins it would have checked.
        The action-call check did run -- it scanned, and found nothing
        to validate, which is a real clean result rather than a skipped
        one.

        Args:
            temp_dir: An empty directory, so the scan finds nothing.
        """
        result = CliRunner().invoke(
            app, ["lint", str(temp_dir), "--format", "json"]
        )
        checks = json.loads(result.output)["checks"]

        assert checks["allow-list"]["ran"] is False
        assert checks["action-calls"]["ran"] is True


class TestDeprecatedSpellingsStillWork:
    """Superseded flags keep working, and say what replaced them."""

    def test_bare_allow_list_now_requires_a_mode(self, temp_dir: Path) -> None:
        """The one deliberate incompatibility, pinned so it stays deliberate.

        ``--allow-list`` was a boolean pair, so the bare spelling meant
        "enable". Click cannot express an option whose value is
        optional, so the bare form is now a usage error. ``--allow-list
        report`` says the same thing and ``--no-allow-list`` is
        untouched, which leaves only one affected invocation: a bare
        ``--allow-list`` overriding a config file that disabled the
        check.

        Args:
            temp_dir: Scratch directory to lint.
        """
        result = CliRunner().invoke(
            app, ["lint", str(temp_dir), "--allow-list"]
        )

        assert result.exit_code != 0
        assert "requires an argument" in strip_ansi(result.output)

    def test_no_allow_list_is_unaffected(self, temp_dir: Path) -> None:
        """The negative spelling keeps working as a flag.

        Args:
            temp_dir: Scratch directory to lint.
        """
        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--no-allow-list",
                "--action-calls",
                "off",
                "--format",
                "json",
            ],
        )
        document = json.loads(result.output)

        assert document["checks"]["allow-list"]["mode"] == "off"

    def test_a_superseded_flag_names_its_replacement(
        self, temp_dir: Path
    ) -> None:
        """Args:
        temp_dir: Scratch directory for the workspace.
        """
        result = CliRunner().invoke(
            app,
            ["lint", str(temp_dir), "--no-auto-fix", "--allow-list", "off"],
        )
        output = strip_ansi(result.output)

        assert "--no-auto-fix is deprecated" in output
        assert "--action-calls report" in output

    def test_a_mode_beside_a_superseded_flag_says_which_won(
        self, temp_dir: Path
    ) -> None:
        """Silently discarding a flag the caller passed is the trap.

        Args:
            temp_dir: Scratch directory for the workspace.
        """
        result = CliRunner().invoke(app, [*_off(temp_dir), "--no-auto-fix"])
        output = strip_ansi(result.output)

        assert "ignored here" in output
        assert "--action-calls was given" in output

    def test_contradictory_legacy_flags_each_name_their_own_replacement(
        self, temp_dir: Path
    ) -> None:
        """A notice must describe its own spelling, not the resolution.

        With ``--no-update-actions --auto-latest`` the canonical flag
        wins, so the run repairs without advancing. A notice derived
        from that resolved value told the caller to write
        ``--action-calls update`` -- the opposite of what they get.

        Args:
            temp_dir: Scratch directory to lint.
        """
        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--no-update-actions",
                "--auto-latest",
                "--allow-list",
                "off",
            ],
        )
        output = strip_ansi(result.output)

        assert "--no-update-actions is deprecated" in output
        assert "--auto-latest is deprecated" in output
        # Neither spelling is reported as the other.
        assert "--update-actions is deprecated" not in output.replace(
            "--no-update-actions is deprecated", ""
        )

    def test_quiet_suppresses_the_notices(self, temp_dir: Path) -> None:
        """Args:
        temp_dir: Scratch directory for the workspace.
        """
        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--no-auto-fix",
                "--allow-list",
                "off",
                "--quiet",
            ],
        )

        assert "deprecated" not in strip_ansi(result.output)
