# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for the per-check mode ladder and capability declarations."""

from __future__ import annotations

import pytest

from gha_workflow_linter.check_modes import (
    ACTION_CALLS,
    ALLOW_LIST,
    SPECS,
    CheckId,
    CheckMode,
    CheckSpec,
    spec_for,
)
from gha_workflow_linter.exceptions import ConfigurationError


class TestTheLadderEscalatesIntervention:
    """Each rung does everything the one below it does.

    The properties are the whole interface: callers ask ``mode.runs``
    rather than comparing against enum members, so a new rung changes
    one file.
    """

    def test_off_does_nothing(self) -> None:
        assert not CheckMode.OFF.runs
        assert not CheckMode.OFF.remediates
        assert not CheckMode.OFF.advances_version

    def test_report_runs_but_never_writes(self) -> None:
        assert CheckMode.REPORT.runs
        assert not CheckMode.REPORT.remediates
        assert not CheckMode.REPORT.advances_version

    def test_fix_writes_without_advancing(self) -> None:
        """The distinction the whole ladder turns on.

        ``fix`` repairs a reference so it correctly names what it
        already named; ``update`` moves it somewhere newer.
        """
        assert CheckMode.FIX.runs
        assert CheckMode.FIX.remediates
        assert not CheckMode.FIX.advances_version

    def test_update_writes_and_advances(self) -> None:
        assert CheckMode.UPDATE.runs
        assert CheckMode.UPDATE.remediates
        assert CheckMode.UPDATE.advances_version

    @pytest.mark.parametrize(
        "mode",
        [CheckMode.OFF, CheckMode.REPORT, CheckMode.FIX, CheckMode.UPDATE],
    )
    def test_remediation_implies_running(self, mode: CheckMode) -> None:
        """Args:
        mode: The rung under test.
        """
        if mode.remediates:
            assert mode.runs

    @pytest.mark.parametrize(
        "mode",
        [CheckMode.OFF, CheckMode.REPORT, CheckMode.FIX, CheckMode.UPDATE],
    )
    def test_advancing_implies_remediating(self, mode: CheckMode) -> None:
        """Args:
        mode: The rung under test.
        """
        if mode.advances_version:
            assert mode.remediates


class TestEnforcementIsNotOnTheLadder:
    """The guard against re-collapsing the two axes.

    Making ``fix`` imply enforcement would turn every default run with
    one outdated action from exit 0 into exit 5, because the action-call
    default *is* ``fix``. Nothing on the mode may describe enforcement.
    """

    def test_no_mode_carries_an_enforcement_property(self) -> None:
        # vars() rather than dir(): CheckMode subclasses str, so dir()
        # reports every inherited string method too.
        exposed = {
            name
            for name, value in vars(CheckMode).items()
            if isinstance(value, property)
        }
        assert exposed == {"advances_version", "remediates", "runs"}

    def test_the_writing_default_does_not_enforce(self) -> None:
        """Stated as a property of the spec, not of a CLI run.

        The exit-code consequence is asserted in test_exit_codes; this
        pins the premise that makes it matter.
        """
        assert ACTION_CALLS.default_mode is CheckMode.FIX
        assert ACTION_CALLS.default_mode.remediates


class TestCapabilityIsDeclaredNotImplied:
    """An unsupported rung is refused, never quietly downgraded."""

    def test_action_calls_supports_every_rung(self) -> None:
        assert ACTION_CALLS.supported_modes == frozenset(CheckMode)

    def test_allow_list_has_no_fix_rung_yet(self) -> None:
        """Repairing in place needs the pinned commit's own tag.

        ``allow_list_fix`` currently writes ``finding.target_sha``,
        which classification sets to the latest release for every kind,
        so a 'fix' would silently advance the version.
        """
        assert CheckMode.FIX not in ALLOW_LIST.supported_modes
        assert CheckMode.UPDATE in ALLOW_LIST.supported_modes

    def test_refusing_a_mode_explains_itself(self) -> None:
        with pytest.raises(ConfigurationError) as caught:
            ALLOW_LIST.validate(CheckMode.FIX)

        message = str(caught.value)
        assert "--allow-list does not support mode 'fix'" in message
        assert "not implemented yet" in message
        # The reader is told where to go next, not merely refused.
        assert "use 'update'" in message
        assert "Supported modes: off, report, update" in message

    def test_a_supported_mode_passes_through(self) -> None:
        assert ALLOW_LIST.validate(CheckMode.REPORT) is CheckMode.REPORT

    def test_choices_follow_ladder_order(self) -> None:
        """Not alphabetical: the help text should read as a ladder."""
        assert ACTION_CALLS.choices == ("off", "report", "fix", "update")
        assert ALLOW_LIST.choices == ("off", "report", "update")


class TestASpecCannotContradictItself:
    """Construction-time guards, so a bad spec never reaches a user."""

    def test_default_must_be_supported(self) -> None:
        with pytest.raises(ValueError, match="not among the supported modes"):
            CheckSpec(
                id=CheckId.ACTION_CALLS,
                flag="--x",
                supported_modes=frozenset({CheckMode.OFF}),
                default_mode=CheckMode.FIX,
            )

    def test_refusal_for_a_supported_mode_is_rejected(self) -> None:
        """A rung cannot be both offered and refused."""
        with pytest.raises(ValueError, match="refusal recorded for supported"):
            CheckSpec(
                id=CheckId.ALLOW_LIST,
                flag="--x",
                supported_modes=frozenset({CheckMode.OFF, CheckMode.FIX}),
                default_mode=CheckMode.OFF,
                refusals={CheckMode.FIX: "contradictory"},
            )


class TestTheRegistry:
    """Every check is reachable by identifier."""

    def test_every_check_has_a_spec(self) -> None:
        assert set(SPECS) == set(CheckId)

    def test_spec_ids_match_their_keys(self) -> None:
        assert all(check is spec.id for check, spec in SPECS.items())

    def test_flags_match_their_identifiers(self) -> None:
        """The option name is the check name, so help reads consistently."""
        assert all(spec.flag == f"--{spec.id.value}" for spec in SPECS.values())

    def test_lookup_returns_the_registered_spec(self) -> None:
        assert spec_for(CheckId.ALLOW_LIST) is ALLOW_LIST
