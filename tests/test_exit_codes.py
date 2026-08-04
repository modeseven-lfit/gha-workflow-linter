# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for centralised exit codes and exit-code determination.

These tests pin the contract documented in ``docs/ALLOW_LIST_FEATURE.md``
section 8. In particular they guard the invariant that presentation
flags never change the process exit status -- a defect that previously
allowed ``lint``, ``lint --quiet`` and ``lint --format json`` to disagree
about the same repository state.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest import mock

import pytest

from gha_workflow_linter import exit_codes
from gha_workflow_linter.allow_list_scanner import CommentPosition, QuoteStyle
from gha_workflow_linter.cache import ValidationCache
from gha_workflow_linter.cli import (
    _AutoFixOutcome,
    _determine_exit_code,
    _has_outdated_actions,
    _ValidationOutcome,
)
from gha_workflow_linter.models import (
    ActionCall,
    ActionCallType,
    AllowListConfig,
    Category,
    CLIOptions,
    Config,
    ReferenceType,
    Severity,
    ValidationError,
    ValidationResult,
    result_category,
)
from gha_workflow_linter.validator import ActionCallValidator

if TYPE_CHECKING:
    from gha_workflow_linter.allow_list_check import AllowListOutcome


class TestExitCodeConstants:
    """The documented numeric contract must not drift."""

    def test_documented_values(self) -> None:
        assert exit_codes.SUCCESS == 0
        assert exit_codes.DEFECTS_FOUND == 1
        assert exit_codes.CLI_USAGE_ERROR == 2
        assert exit_codes.ALLOW_LIST_STALE == 3
        assert exit_codes.ALLOW_LIST_UNRESOLVED == 4
        assert exit_codes.ACTIONS_OUTDATED == 5

    def test_codes_are_unique(self) -> None:
        codes = [
            exit_codes.SUCCESS,
            exit_codes.DEFECTS_FOUND,
            exit_codes.CLI_USAGE_ERROR,
            exit_codes.ALLOW_LIST_STALE,
            exit_codes.ALLOW_LIST_UNRESOLVED,
            exit_codes.ACTIONS_OUTDATED,
        ]
        assert len(codes) == len(set(codes))

    def test_usage_error_is_reserved_for_click(self) -> None:
        """Code 2 must never be produced by our own logic."""
        with pytest.raises(ValueError, match="Unknown exit code"):
            exit_codes.combine(exit_codes.CLI_USAGE_ERROR)


class TestCombine:
    """Precedence: 4 > 3 > 5 > 1 > 0."""

    def test_empty_is_success(self) -> None:
        assert exit_codes.combine() == exit_codes.SUCCESS

    def test_single_code_passes_through(self) -> None:
        assert (
            exit_codes.combine(exit_codes.DEFECTS_FOUND)
            == exit_codes.DEFECTS_FOUND
        )

    @pytest.mark.parametrize(
        ("codes", "expected"),
        [
            # Infrastructure failure outranks everything: an unresolved
            # check must never look like a clean-or-stale result.
            (
                (exit_codes.ALLOW_LIST_UNRESOLVED, exit_codes.ALLOW_LIST_STALE),
                exit_codes.ALLOW_LIST_UNRESOLVED,
            ),
            (
                (exit_codes.ALLOW_LIST_UNRESOLVED, exit_codes.DEFECTS_FOUND),
                exit_codes.ALLOW_LIST_UNRESOLVED,
            ),
            # A condition the caller specifically asked about must not be
            # masked by the generic defect code.
            (
                (exit_codes.ALLOW_LIST_STALE, exit_codes.DEFECTS_FOUND),
                exit_codes.ALLOW_LIST_STALE,
            ),
            (
                (exit_codes.ACTIONS_OUTDATED, exit_codes.DEFECTS_FOUND),
                exit_codes.ACTIONS_OUTDATED,
            ),
            (
                (exit_codes.ALLOW_LIST_STALE, exit_codes.ACTIONS_OUTDATED),
                exit_codes.ALLOW_LIST_STALE,
            ),
            (
                (exit_codes.SUCCESS, exit_codes.DEFECTS_FOUND),
                exit_codes.DEFECTS_FOUND,
            ),
            ((exit_codes.SUCCESS, exit_codes.SUCCESS), exit_codes.SUCCESS),
        ],
    )
    def test_precedence(self, codes: tuple[int, ...], expected: int) -> None:
        assert exit_codes.combine(*codes) == expected
        # Order of arguments must not matter.
        assert exit_codes.combine(*reversed(codes)) == expected

    def test_rejects_unknown_code(self) -> None:
        with pytest.raises(ValueError, match="Unknown exit code"):
            exit_codes.combine(99)


class TestDescribe:
    def test_known_codes_have_descriptions(self) -> None:
        for code in (0, 1, 2, 3, 4, 5):
            assert "Unknown" not in exit_codes.describe(code)

    def test_unknown_code(self) -> None:
        assert exit_codes.describe(42) == "Unknown exit code 42"


class TestResultCategory:
    """Defect vs currency classification (design doc section 8.4)."""

    @pytest.mark.parametrize(
        "result",
        [
            ValidationResult.INVALID_REPOSITORY,
            ValidationResult.INVALID_REFERENCE,
            ValidationResult.INVALID_PATH,
            ValidationResult.INVALID_SYNTAX,
            ValidationResult.ANNOTATED_TAG_SHA,
        ],
    )
    def test_defects(self, result: ValidationResult) -> None:
        assert result_category(result) is Category.DEFECT

    @pytest.mark.parametrize(
        "result",
        [
            ValidationResult.NOT_PINNED_TO_SHA,
            ValidationResult.TEST_REFERENCE,
        ],
    )
    def test_currency(self, result: ValidationResult) -> None:
        assert result_category(result) is Category.CURRENCY

    @pytest.mark.parametrize(
        "result",
        [ValidationResult.NETWORK_ERROR, ValidationResult.TIMEOUT],
    )
    def test_infrastructure(self, result: ValidationResult) -> None:
        assert result_category(result) is Category.INFRASTRUCTURE

    def test_valid_is_not_a_finding(self) -> None:
        assert result_category(ValidationResult.VALID) is None

    def test_every_result_is_classified(self) -> None:
        """A new ValidationResult must be classified deliberately."""
        for result in ValidationResult:
            if result is ValidationResult.VALID:
                continue
            assert result_category(result) is not None, (
                f"{result.value} has no category; add it to "
                f"_RESULT_CATEGORIES in models.py"
            )

    def test_annotated_tag_sha_is_a_defect_not_currency(self) -> None:
        """A tag-object SHA fails at run time; it is not mere staleness."""
        assert (
            result_category(ValidationResult.ANNOTATED_TAG_SHA)
            is Category.DEFECT
        )


class TestSeverity:
    def test_members(self) -> None:
        assert Severity.ERROR.value == "error"
        assert Severity.WARNING.value == "warning"
        assert Severity.NOTICE.value == "notice"


def _action_call(comment: str | None = None) -> ActionCall:
    return ActionCall(
        raw_line=f"      - uses: actions/checkout@v4  {comment or ''}",
        line_number=1,
        organization="actions",
        repository="checkout",
        reference="v4",
        comment=comment,
        call_type=ActionCallType.ACTION,
        reference_type=ReferenceType.TAG,
    )


def _validation_error(
    result: ValidationResult = ValidationResult.INVALID_REFERENCE,
    comment: str | None = None,
) -> ValidationError:
    return ValidationError(
        file_path=Path(".github/workflows/build.yaml"),
        action_call=_action_call(comment),
        result=result,
        error_message="boom",
    )


def _options(**kwargs: Any) -> CLIOptions:
    base: dict[str, Any] = {"path": Path.cwd()}
    base.update(kwargs)
    return CLIOptions(**base)


def _validation(
    errors: list[ValidationError] | None = None,
) -> _ValidationOutcome:
    """Build a real _ValidationOutcome so the types are exercised."""
    return _ValidationOutcome(
        workflow_calls={},
        validation_errors=errors or [],
        validator=ActionCallValidator(Config()),
        total_calls=len(errors or []),
    )


def _autofix(
    fixed_files: dict[Path, list[dict[str, str]]] | None = None,
    stale: dict[str, list[dict[str, Any]]] | None = None,
) -> _AutoFixOutcome:
    return _AutoFixOutcome(
        fixed_files or {},
        {"actions_moved": 0, "calls_updated": 0},
        stale or {},
    )


def _exit_code(
    options: CLIOptions,
    validation: _ValidationOutcome,
    autofix: _AutoFixOutcome,
    allow_list: AllowListOutcome | None = None,
    config: Config | None = None,
) -> int:
    """Call _determine_exit_code with a default configuration."""
    return _determine_exit_code(
        options, validation, autofix, config or Config(), allow_list
    )


class TestDetermineExitCode:
    def test_clean_run(self) -> None:
        code = _exit_code(_options(), _validation(), _autofix())
        assert code == exit_codes.SUCCESS

    def test_validation_errors_fail(self) -> None:
        code = _exit_code(
            _options(),
            _validation([_validation_error()]),
            _autofix(),
        )
        assert code == exit_codes.DEFECTS_FOUND

    def test_no_fail_on_error_suppresses_defects(self) -> None:
        code = _exit_code(
            _options(fail_on_error=False),
            _validation([_validation_error()]),
            _autofix(),
        )
        assert code == exit_codes.SUCCESS

    def test_test_references_do_not_fail(self) -> None:
        code = _exit_code(
            _options(),
            _validation([_validation_error(comment="# v4 testing")]),
            _autofix(),
        )
        assert code == exit_codes.SUCCESS

    def test_applied_fixes_fail(self) -> None:
        fixed = {
            Path("a.yaml"): [
                {"line_number": "1", "old_line": "x", "new_line": "y"}
            ]
        }
        code = _exit_code(
            _options(),
            _validation(),
            _autofix(fixed_files=fixed),
        )
        assert code == exit_codes.DEFECTS_FOUND

    def test_skipped_only_fixes_do_not_fail(self) -> None:
        fixed = {Path("a.yaml"): [{"line_number": "1", "skipped": "true"}]}
        code = _exit_code(
            _options(),
            _validation(),
            _autofix(fixed_files=fixed),
        )
        assert code == exit_codes.SUCCESS


class TestOutdatedActions:
    """--verify-actions promotes currency findings to failures."""

    STALE = {"build.yaml": [{"line": 3, "action": "actions/checkout"}]}

    def test_outdated_advisory_by_default(self) -> None:
        code = _exit_code(
            _options(),
            _validation(),
            _autofix(stale=self.STALE),
        )
        assert code == exit_codes.SUCCESS

    def test_outdated_fails_under_verify_actions(self) -> None:
        code = _exit_code(
            _options(verify_actions=True),
            _validation(),
            _autofix(stale=self.STALE),
        )
        assert code == exit_codes.ACTIONS_OUTDATED

    def test_verify_actions_clean(self) -> None:
        code = _exit_code(
            _options(verify_actions=True),
            _validation(),
            _autofix(),
        )
        assert code == exit_codes.SUCCESS

    def test_empty_stale_lists_are_not_outdated(self) -> None:
        assert not _has_outdated_actions(_autofix(stale={"build.yaml": []}))

    def test_outdated_outranks_defects(self) -> None:
        """A specifically-requested condition is not masked by code 1."""
        code = _exit_code(
            _options(verify_actions=True),
            _validation([_validation_error()]),
            _autofix(stale=self.STALE),
        )
        assert code == exit_codes.ACTIONS_OUTDATED


class TestPresentationDoesNotAffectExitCode:
    """Regression tests for the run_linter early-return bypass.

    Previously, whenever any outdated action existed, run_linter returned
    0 without consulting _determine_exit_code -- masking real defects.
    The guard was additionally gated on ``not options.quiet``, so the
    exit code depended on verbosity, and ``--format json`` (which forces
    quiet) took a different branch entirely.
    """

    STALE = {"build.yaml": [{"line": 3, "action": "actions/checkout"}]}

    def test_defect_not_masked_by_outdated_actions(self) -> None:
        """The core bug: a real error alongside an outdated action."""
        code = _exit_code(
            _options(),
            _validation([_validation_error()]),
            _autofix(stale=self.STALE),
        )
        assert code == exit_codes.DEFECTS_FOUND

    def test_applied_fixes_not_masked_by_outdated_actions(self) -> None:
        fixed = {
            Path("a.yaml"): [
                {"line_number": "1", "old_line": "x", "new_line": "y"}
            ]
        }
        code = _exit_code(
            _options(),
            _validation(),
            _autofix(fixed_files=fixed, stale=self.STALE),
        )
        assert code == exit_codes.DEFECTS_FOUND

    @pytest.mark.parametrize(
        "presentation",
        [
            {},
            {"quiet": True},
            {"verbose": True},
            {"output_format": "json", "quiet": True},
        ],
        ids=["default", "quiet", "verbose", "json"],
    )
    def test_exit_code_is_independent_of_presentation(
        self, presentation: dict[str, object]
    ) -> None:
        """lint, --quiet and --format json must agree on the code."""
        code = _exit_code(
            _options(**presentation),
            _validation([_validation_error()]),
            _autofix(stale=self.STALE),
        )
        assert code == exit_codes.DEFECTS_FOUND

    @pytest.mark.parametrize(
        "presentation",
        [
            {},
            {"quiet": True},
            {"output_format": "json", "quiet": True},
        ],
        ids=["default", "quiet", "json"],
    )
    def test_clean_run_agrees_across_presentation(
        self, presentation: dict[str, object]
    ) -> None:
        code = _exit_code(
            _options(**presentation),
            _validation(),
            _autofix(stale=self.STALE),
        )
        assert code == exit_codes.SUCCESS


def _allow_list_outcome(
    *, unsuppressed: int = 0, unresolved: bool = False
) -> AllowListOutcome:
    """Build an outcome with the given failure shape."""
    from gha_workflow_linter.allow_list_check import AllowListOutcome as _O

    findings = [_stale_finding() for _ in range(unsuppressed)]
    return _O(
        findings=findings,
        hosts={},
        unresolved={"lfreleng-actions/.github": "no releases"}
        if unresolved
        else {},
        suppressed_count=0,
        checked=True,
    )


def _stale_finding() -> Any:
    """A minimal unsuppressed STALE finding."""
    from gha_workflow_linter.allow_list_check import AllowListFinding
    from gha_workflow_linter.allow_list_scanner import AllowListPin
    from gha_workflow_linter.allow_list_spec import resolve_spec
    from gha_workflow_linter.models import AllowListFindingKind

    pin = AllowListPin(
        file_path=Path(".github/workflows/ci.yaml"),
        line_number=1,
        column=0,
        key_path=("jobs", "b", "steps", "0", "with", "config"),
        raw_line="        config: '@18d9c444'  # v0.1.1",
        raw_value="@18d9c4446bea555d0783e850f6d295f844fe8f67",
        quote_style=QuoteStyle.SINGLE,
        comment_position=CommentPosition.YAML,
        version_comment="v0.1.1",
        directives=frozenset(),
        suppressed_by=None,
        suppression_reason=None,
        spec=resolve_spec(
            "@18d9c4446bea555d0783e850f6d295f844fe8f67",
            workflow_org="lfreleng-actions",
        ),
        auto_fixable=True,
    )
    return AllowListFinding(
        pin=pin,
        kind=AllowListFindingKind.STALE,
        severity=Severity.WARNING,
        message="stale",
        current_sha="18d9c4446bea555d0783e850f6d295f844fe8f67",
        target_sha="bf6642f68d58c1b81bbe993e676d6cc339ac3654",
        target_version="v0.12.2",
        suppressed=False,
    )


class TestAllowListExitCodes:
    """Allow-list findings are advisory unless --verify-allow-list."""

    def test_stale_pins_advisory_by_default(self) -> None:
        config = Config()
        code = _exit_code(
            _options(),
            _validation(),
            _autofix(),
            _allow_list_outcome(unsuppressed=3),
            config,
        )
        assert code == exit_codes.SUCCESS

    def test_stale_pins_fail_under_verify(self) -> None:
        config = Config()
        config.allow_list.verify = True
        code = _exit_code(
            _options(),
            _validation(),
            _autofix(),
            _allow_list_outcome(unsuppressed=3),
            config,
        )
        assert code == exit_codes.ALLOW_LIST_STALE

    def test_clean_run_under_verify(self) -> None:
        config = Config()
        config.allow_list.verify = True
        code = _exit_code(
            _options(),
            _validation(),
            _autofix(),
            _allow_list_outcome(),
            config,
        )
        assert code == exit_codes.SUCCESS

    def test_unresolved_outranks_stale(self) -> None:
        """An unresolved check must never look like a clean-or-stale result."""
        config = Config()
        config.allow_list.verify = True
        code = _exit_code(
            _options(),
            _validation(),
            _autofix(),
            _allow_list_outcome(unsuppressed=3, unresolved=True),
            config,
        )
        assert code == exit_codes.ALLOW_LIST_UNRESOLVED

    def test_unresolved_advisory_without_verify(self) -> None:
        code = _exit_code(
            _options(),
            _validation(),
            _autofix(),
            _allow_list_outcome(unresolved=True),
            Config(),
        )
        assert code == exit_codes.SUCCESS

    def test_stale_outranks_generic_defects(self) -> None:
        """A specifically requested condition is not masked by code 1."""
        config = Config()
        config.allow_list.verify = True
        code = _exit_code(
            _options(),
            _validation([_validation_error()]),
            _autofix(),
            _allow_list_outcome(unsuppressed=1),
            config,
        )
        assert code == exit_codes.ALLOW_LIST_STALE


class TestAllowListStageFailure:
    """A broken check must not silently pass under --verify-allow-list.

    Regression tests for the review finding that _run_allow_list_stage
    swallowed every exception and returned None, which made
    _determine_exit_code skip the allow-list branch entirely -- so
    enforcement degraded to "pass" precisely when the check could not
    run, contradicting the documented guarantee.
    """

    @staticmethod
    def _stage(
        *, verify: bool, quiet: bool = True
    ) -> tuple[AllowListOutcome | None, Config]:
        from gha_workflow_linter.cli import _run_allow_list_stage

        config = Config()
        config.allow_list.verify = verify
        cache = ValidationCache(config.cache)
        options = _options(quiet=quiet, path=Path("/nonexistent-path-xyz"))

        with mock.patch(
            "gha_workflow_linter.cli.AllowListChecker",
            side_effect=RuntimeError("boom"),
        ):
            return _run_allow_list_stage(config, options, cache), config

    def test_advisory_mode_skips_on_failure(self) -> None:
        outcome, _ = self._stage(verify=False)
        assert outcome is None

    def test_verify_mode_reports_failure(self) -> None:
        outcome, _ = self._stage(verify=True)
        assert outcome is not None
        assert outcome.unresolved

    def test_verify_mode_exits_unresolved_on_failure(self) -> None:
        """The whole point: a broken check fails, it does not pass."""
        outcome, config = self._stage(verify=True)
        code = _exit_code(
            _options(), _validation(), _autofix(), outcome, config
        )
        assert code == exit_codes.ALLOW_LIST_UNRESOLVED

    def test_advisory_mode_exits_success_on_failure(self) -> None:
        outcome, config = self._stage(verify=False)
        code = _exit_code(
            _options(), _validation(), _autofix(), outcome, config
        )
        assert code == exit_codes.SUCCESS


class TestShowSuppressedIsConfigDriven:
    """--show-suppressed must be settable from a config file.

    Rendering previously read options.show_suppressed, so a config-file
    setting had no effect unless the CLI flag was also passed.
    """

    def test_cli_flag_reaches_config(self) -> None:
        from gha_workflow_linter.cli import _apply_cli_overrides

        config = Config()
        _apply_cli_overrides(config, _options(show_suppressed=True), None)
        assert config.allow_list.show_suppressed is True

    def test_config_value_survives_absent_flag(self) -> None:
        from gha_workflow_linter.cli import _apply_cli_overrides

        config = Config()
        config.allow_list.show_suppressed = True
        _apply_cli_overrides(config, _options(), None)
        assert config.allow_list.show_suppressed is True


class TestNoDeadConfigKnobs:
    """Config must not advertise behaviour that does nothing.

    Remediation lands in a later phase; until something implements it,
    an 'update' knob would mislead users and downstream tooling.
    """

    def test_allow_list_config_has_no_update_knob(self) -> None:
        assert "update" not in AllowListConfig.model_fields

    def test_cli_options_have_no_update_knob(self) -> None:
        assert "update_allow_list" not in CLIOptions.model_fields
