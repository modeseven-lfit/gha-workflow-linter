# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for what a single repository's run reports to its caller.

``RunOutcome`` is the seam between one repository's run and a sweep's
aggregate reporting, so the fields it carries are the only thing the
summary can describe. Two of them are easy to get subtly wrong in ways
no exit code reveals:

* ``error`` distinguishes a repository that *failed* from one that
  merely had findings. Collapsing a failed scan to a bare exit code
  made an unreadable checkout indistinguishable from a lint result --
  reporting an unusable input as an absence of problems.
* ``defects`` counts what the reader still has to deal with. Counting
  calls the auto-fixer had already rewritten showed them as fixed and
  outstanding at once, which reads as a contradiction.

Neither is observable through ``_determine_exit_code``, which is
covered separately, so both are pinned here.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest import mock

import pytest

from gha_workflow_linter import cli
from gha_workflow_linter.auto_fix import AutoFixer
from gha_workflow_linter.cache import ValidationCache
from gha_workflow_linter.cli import (
    _AutoFixOutcome,
    _emit_results,
    _repaired_locations,
    _run_one_repository,
    _ScanShortCircuit,
    _ValidationOutcome,
)
from gha_workflow_linter.models import (
    ActionCall,
    ActionCallType,
    CacheConfig,
    CLIOptions,
    Config,
    ReferenceType,
    ValidationError,
    ValidationResult,
)
from gha_workflow_linter.scanner import WorkflowScanner
from gha_workflow_linter.validator import ActionCallValidator
from tests.conftest import strip_ansi

if TYPE_CHECKING:
    from collections.abc import Iterator

#: File the synthetic validation errors are attributed to.
WORKFLOW = Path(".github/workflows/build.yaml")

#: The auto-fixer's own logger, whose level gates its live display.
AUTO_FIX_LOGGER = "gha_workflow_linter.auto_fix"


def make_validation_error(
    line: int, *, comment: str | None = None
) -> ValidationError:
    """Build one validation error at a given line.

    Args:
        line: Line the offending call sits on. Repaired calls are
            matched by ``(file, line)``, so distinct values keep them
            distinct.
        comment: Trailing comment on the call, used to mark a test
            reference.

    Returns:
        A validation error against :data:`WORKFLOW`.
    """
    return ValidationError(
        file_path=WORKFLOW,
        action_call=ActionCall(
            raw_line=f"      - uses: actions/checkout@v4  {comment or ''}",
            line_number=line,
            organization="actions",
            repository="checkout",
            reference="v4",
            comment=comment,
            call_type=ActionCallType.ACTION,
            reference_type=ReferenceType.TAG,
        ),
        result=ValidationResult.INVALID_REFERENCE,
        error_message="boom",
    )


def make_change(line: int, *, skipped: bool = False) -> dict[str, str]:
    """Build one entry of the auto-fixer's per-file change list.

    Args:
        line: Line the fixer touched.
        skipped: Whether the fixer deliberately left the line alone.

    Returns:
        A change entry shaped as ``AutoFixer`` produces it.
    """
    change = {
        "old_line": "old",
        "new_line": "new",
        "line_number": str(line),
    }
    if skipped:
        change["skipped"] = "true"
    return change


def make_autofix(
    fixed_files: dict[Path, list[dict[str, str]]] | None = None,
    write_failures: list[Path] | None = None,
    stage_error: str | None = None,
) -> _AutoFixOutcome:
    """Build an auto-fix outcome carrying the given changes.

    Args:
        fixed_files: Changes per file, or none.
        write_failures: Files whose rewrite could not be written.
        stage_error: Why the stage failed outright, or None.

    Returns:
        An outcome the run can aggregate.
    """
    return _AutoFixOutcome(
        fixed_files or {},
        {"actions_moved": 0, "calls_updated": 0},
        {},
        write_failures or [],
        stage_error,
    )


def make_validation(errors: list[ValidationError]) -> _ValidationOutcome:
    """Build a validation outcome carrying the given errors.

    Args:
        errors: Validation errors the run found.

    Returns:
        A real outcome, so the types are exercised.
    """
    return _ValidationOutcome(
        workflow_calls={},
        validation_errors=errors,
        validator=ActionCallValidator(Config()),
        total_calls=len(errors),
    )


@pytest.fixture
def quiet_run(tmp_path: Path) -> Iterator[ValidationCache]:
    """Silence the reporting stages and supply a throwaway cache.

    Reporting is covered elsewhere; what matters here is the outcome the
    run returns, so the emitters are stubbed out and the cache is
    written under ``tmp_path`` rather than the user's cache directory.

    Args:
        tmp_path: Test-scoped directory to hold the cache file.

    Yields:
        A cache safe to pass into a run.
    """
    with (
        mock.patch.object(cli, "_emit_results", return_value=None),
        mock.patch.object(cli, "_run_allow_list_stage", return_value=None),
    ):
        yield ValidationCache(CacheConfig(cache_dir=tmp_path / "cache"))


def run(cache: ValidationCache, **options: Any) -> Any:
    """Run one repository with the given options.

    Args:
        cache: Cache to pass into the run.
        **options: Overrides for the CLI options.

    Returns:
        The outcome the run produced.
    """
    base: dict[str, Any] = {"path": Path.cwd(), "quiet": True}
    base.update(options)
    return _run_one_repository(Config(), CLIOptions(**base), cache)


class TestScanFailureIsPreserved:
    """A run that stopped early says why, when there was a why."""

    def test_a_scan_failure_is_recorded_on_the_outcome(
        self, quiet_run: ValidationCache
    ) -> None:
        """A failed scan is distinguishable from a lint result.

        Args:
            quiet_run: Cache fixture, with reporting stubbed out.
        """
        with mock.patch.object(
            cli,
            "_scan_and_validate",
            return_value=_ScanShortCircuit(1, "Error scanning workflows: no"),
        ):
            outcome = run(quiet_run)

        assert outcome.exit_code == 1
        assert outcome.error == "Error scanning workflows: no"

    def test_an_empty_repository_is_not_a_failure(
        self, quiet_run: ValidationCache
    ) -> None:
        """A repository with no workflows is a clean result.

        Args:
            quiet_run: Cache fixture, with reporting stubbed out.
        """
        with mock.patch.object(
            cli, "_scan_and_validate", return_value=_ScanShortCircuit(0)
        ):
            outcome = run(quiet_run)

        assert outcome.exit_code == 0
        assert outcome.error is None


class TestMessagelessFailures:
    """A failure with nothing to say still says which failure it was.

    ``str(RuntimeError())`` is empty, so a description built from it
    alone reads as an absence of trouble -- the recurring hazard this
    work keeps meeting. Every stage that records a reason uses the same
    helper, so none of them can report a blank.
    """

    @pytest.mark.parametrize(
        ("error", "expected"),
        [
            pytest.param(RuntimeError(), "RuntimeError", id="no-message"),
            pytest.param(
                RuntimeError("disk went away"),
                "disk went away",
                id="a-message-is-preferred",
            ),
            pytest.param(ValueError(""), "ValueError", id="empty-string"),
        ],
    )
    def test_describe_exception(self, error: Exception, expected: str) -> None:
        """Every failure gets a non-empty description.

        Args:
            error: The exception to describe.
            expected: The description it must produce.
        """
        assert cli._describe_exception(error) == expected

    @pytest.mark.parametrize(
        "stage",
        ["scan", "validate"],
    )
    def test_a_messageless_scan_failure_names_its_kind(
        self,
        quiet_run: ValidationCache,
        stage: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The scan and validate handlers use the same fallback.

        Driven through the real ``_scan_and_validate`` rather than a
        stub, so the two handlers inside it are genuinely exercised.

        Args:
            quiet_run: Cache fixture, with reporting stubbed out.
            stage: Which stage to make fail.
            monkeypatch: Replaces the failing collaborator.
        """

        def explode(*_args: Any, **_kwargs: Any) -> None:
            """Fail with an exception carrying no message.

            Raises:
                RuntimeError: Always, with no message.
            """
            raise RuntimeError

        if stage == "scan":
            monkeypatch.setattr(WorkflowScanner, "scan_directory", explode)
            expected = "Error scanning workflows: RuntimeError"
        else:
            monkeypatch.setattr(
                WorkflowScanner,
                "scan_directory",
                lambda *a, **k: {WORKFLOW: {1: object()}},
            )
            monkeypatch.setattr(
                ActionCallValidator, "validate_action_calls", explode
            )
            expected = "Unexpected error validating action calls: RuntimeError"

        outcome = run(quiet_run)

        assert outcome.exit_code == 1
        assert outcome.error == expected


class TestRepairedLocations:
    """Which calls the auto-fixer actually rewrote."""

    def test_rewritten_lines_are_collected(self) -> None:
        """Every non-skipped change contributes its line."""
        autofix = make_autofix({WORKFLOW: [make_change(3), make_change(7)]})

        assert _repaired_locations(autofix) == {(WORKFLOW, 3), (WORKFLOW, 7)}

    def test_skipped_lines_are_excluded(self) -> None:
        """A line the fixer left alone was not repaired."""
        autofix = make_autofix(
            {WORKFLOW: [make_change(3), make_change(7, skipped=True)]}
        )

        assert _repaired_locations(autofix) == {(WORKFLOW, 3)}

    def test_nothing_fixed_yields_nothing(self) -> None:
        """An empty run repairs no lines."""
        assert _repaired_locations(make_autofix()) == set()


class TestDefectsCount:
    """What the summary reports as still needing attention."""

    def test_a_repaired_call_is_not_still_a_defect(
        self, quiet_run: ValidationCache
    ) -> None:
        """A call the fixer rewrote is no longer outstanding.

        Args:
            quiet_run: Cache fixture, with reporting stubbed out.
        """
        with (
            mock.patch.object(
                cli,
                "_scan_and_validate",
                return_value=make_validation(
                    [make_validation_error(1), make_validation_error(2)]
                ),
            ),
            mock.patch.object(
                cli,
                "_run_auto_fix_stage",
                return_value=make_autofix({WORKFLOW: [make_change(1)]}),
            ),
        ):
            outcome = run(quiet_run)

        assert outcome.defects == 1

    def test_an_unrepaired_call_is_still_a_defect(
        self, quiet_run: ValidationCache
    ) -> None:
        """Nothing rewritten leaves every error outstanding.

        This is the guard against simply counting nothing.

        Args:
            quiet_run: Cache fixture, with reporting stubbed out.
        """
        with (
            mock.patch.object(
                cli,
                "_scan_and_validate",
                return_value=make_validation(
                    [make_validation_error(1), make_validation_error(2)]
                ),
            ),
            mock.patch.object(
                cli, "_run_auto_fix_stage", return_value=make_autofix()
            ),
        ):
            outcome = run(quiet_run)

        assert outcome.defects == 2

    def test_a_skipped_call_is_still_a_defect(
        self, quiet_run: ValidationCache
    ) -> None:
        """The fixer declining to act does not clear the finding.

        Args:
            quiet_run: Cache fixture, with reporting stubbed out.
        """
        with (
            mock.patch.object(
                cli,
                "_scan_and_validate",
                return_value=make_validation([make_validation_error(1)]),
            ),
            mock.patch.object(
                cli,
                "_run_auto_fix_stage",
                return_value=make_autofix(
                    {WORKFLOW: [make_change(1, skipped=True)]}
                ),
            ),
        ):
            outcome = run(quiet_run)

        assert outcome.defects == 1

    def test_test_references_are_excluded(
        self, quiet_run: ValidationCache
    ) -> None:
        """Test references are advisory by convention.

        Args:
            quiet_run: Cache fixture, with reporting stubbed out.
        """
        with (
            mock.patch.object(
                cli,
                "_scan_and_validate",
                return_value=make_validation(
                    [
                        make_validation_error(1),
                        make_validation_error(2, comment="# testing"),
                    ]
                ),
            ),
            mock.patch.object(
                cli, "_run_auto_fix_stage", return_value=make_autofix()
            ),
        ):
            outcome = run(quiet_run)

        assert outcome.defects == 1


class TestWriteFailuresReachTheOutcome:
    """A failed rewrite must survive into what the sweep reports.

    Recording the failure on the fixer achieves nothing if the outcome
    the summary reads never learns of it.
    """

    def test_a_failed_rewrite_is_counted(
        self, quiet_run: ValidationCache
    ) -> None:
        """The count reaches ``RunOutcome``.

        Args:
            quiet_run: Cache fixture, with reporting stubbed out.
        """
        with (
            mock.patch.object(
                cli,
                "_scan_and_validate",
                return_value=make_validation([]),
            ),
            mock.patch.object(
                cli,
                "_run_auto_fix_stage",
                return_value=make_autofix(write_failures=[WORKFLOW]),
            ),
        ):
            outcome = run(quiet_run)

        assert outcome.write_failures == 1

    def test_a_clean_run_counts_none(self, quiet_run: ValidationCache) -> None:
        """The guard against counting a failure on every run.

        Args:
            quiet_run: Cache fixture, with reporting stubbed out.
        """
        with (
            mock.patch.object(
                cli,
                "_scan_and_validate",
                return_value=make_validation([]),
            ),
            mock.patch.object(
                cli, "_run_auto_fix_stage", return_value=make_autofix()
            ),
        ):
            outcome = run(quiet_run)

        assert outcome.write_failures == 0

    def test_a_stage_failure_is_carried(
        self, quiet_run: ValidationCache
    ) -> None:
        """A stage that failed outright reaches the outcome too.

        Args:
            quiet_run: Cache fixture, with reporting stubbed out.
        """
        with (
            mock.patch.object(
                cli,
                "_scan_and_validate",
                return_value=make_validation([]),
            ),
            mock.patch.object(
                cli,
                "_run_auto_fix_stage",
                return_value=make_autofix(stage_error="resolution exploded"),
            ),
        ):
            outcome = run(quiet_run)

        assert outcome.autofix_error == "resolution exploded"

    def test_a_clean_run_carries_no_stage_failure(
        self, quiet_run: ValidationCache
    ) -> None:
        """The guard against reporting a failure on every run.

        Args:
            quiet_run: Cache fixture, with reporting stubbed out.
        """
        with (
            mock.patch.object(
                cli,
                "_scan_and_validate",
                return_value=make_validation([]),
            ),
            mock.patch.object(
                cli, "_run_auto_fix_stage", return_value=make_autofix()
            ),
        ):
            outcome = run(quiet_run)

        assert outcome.autofix_error is None


class TestAutoFixerSilence:
    """The auto-fixer's live display is a second route to standard output.

    ``CLIOptions.quiet`` silences the scanner and the reporting stages,
    but :class:`~gha_workflow_linter.auto_fix.AutoFixer` decided whether
    to open its Rich ``Live`` display from the logger level alone. The
    CLI sets that level, so the CLI was safe; a caller of ``run_linter``
    never does, and would have found progress output inside the
    aggregate JSON document.

    The sweep's other JSON tests cannot see this, because they use
    repositories with no workflows and the fixer never runs.
    """

    @staticmethod
    def fixer(tmp_path: Path, *, quiet: bool) -> AutoFixer:
        """Build an auto-fixer with the given silence.

        A throwaway cache is supplied so the fixer does not prime the
        user's real one.

        Args:
            tmp_path: Test-scoped directory to hold the cache file.
            quiet: Whether the caller asked for silence.

        Returns:
            An auto-fixer, not entered.
        """
        config = Config(cache=CacheConfig(cache_dir=tmp_path / "cache"))
        return AutoFixer(
            config, cache=ValidationCache(config.cache), quiet=quiet
        )

    def test_a_quiet_caller_is_honoured_whatever_the_logger_says(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Explicit silence does not depend on logging configuration.

        Args:
            tmp_path: Supplies the cache directory.
            caplog: Sets the level a library caller would leave in place.
        """
        fixer = self.fixer(tmp_path, quiet=True)

        with caplog.at_level(logging.WARNING, logger=AUTO_FIX_LOGGER):
            assert fixer._show_live_updates() is False

    def test_a_talkative_caller_still_follows_the_logger(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The logger level still suppresses the display as before.

        This is the guard against silencing the fixer outright, which
        would cost every ordinary run its progress display.

        Args:
            tmp_path: Supplies the cache directory.
            caplog: Sets the logger level.
        """
        fixer = self.fixer(tmp_path, quiet=False)

        with caplog.at_level(logging.WARNING, logger=AUTO_FIX_LOGGER):
            assert fixer._show_live_updates() is True

        with caplog.at_level(logging.ERROR, logger=AUTO_FIX_LOGGER):
            assert fixer._show_live_updates() is False

    def test_the_sweep_passes_its_silence_to_the_fixer(
        self, tmp_path: Path
    ) -> None:
        """A JSON sweep must reach the fixer, not stop at the scanner.

        Only the constructor call is asserted. The stand-in cannot
        satisfy the rest of the stage, but that failure is caught and
        logged by design, so the assertion is unaffected.

        Args:
            tmp_path: Supplies the cache directory.
        """
        config = Config(cache=CacheConfig(cache_dir=tmp_path / "cache"))
        options = CLIOptions(path=tmp_path, quiet=True, output_format="json")

        with mock.patch.object(cli, "AutoFixer") as fixer_class:
            cli._run_auto_fix_stage(
                config,
                options,
                ValidationCache(config.cache),
                make_validation([make_validation_error(1)]),
            )

        assert fixer_class.call_args.kwargs["quiet"] is True

    def test_json_output_silences_the_fixer_for_a_single_run(
        self, tmp_path: Path
    ) -> None:
        """A programmatic single-repository JSON run gets no coercion.

        The command layer forces quiet for JSON output, but a caller of
        ``run_linter`` gets none of that, so the fixer's live display
        would open on standard output ahead of the document. The sweep
        already derives its own silence; the single-repository path has
        to as well.

        Args:
            tmp_path: Supplies the cache directory.
        """
        config = Config(cache=CacheConfig(cache_dir=tmp_path / "cache"))
        options = CLIOptions(path=tmp_path, quiet=False, output_format="json")

        with mock.patch.object(cli, "AutoFixer") as fixer_class:
            cli._run_auto_fix_stage(
                config,
                options,
                ValidationCache(config.cache),
                make_validation([make_validation_error(1)]),
            )

        assert fixer_class.call_args.kwargs["quiet"] is True

    def test_a_text_run_is_not_silenced(self, tmp_path: Path) -> None:
        """The guard against silencing the fixer for everyone.

        Args:
            tmp_path: Supplies the cache directory.
        """
        config = Config(cache=CacheConfig(cache_dir=tmp_path / "cache"))
        options = CLIOptions(path=tmp_path, quiet=False)

        with mock.patch.object(cli, "AutoFixer") as fixer_class:
            cli._run_auto_fix_stage(
                config,
                options,
                ValidationCache(config.cache),
                make_validation([make_validation_error(1)]),
            )

        assert fixer_class.call_args.kwargs["quiet"] is False

    def test_json_output_silences_every_display_in_the_stage(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The fixer is not the only thing that writes to stdout.

        The applied-changes listing and the stage-failure notice print
        from this stage too, so silencing the fixer alone still leaves
        commentary ahead of the JSON document.

        Args:
            tmp_path: Supplies the cache directory.
            capsys: Captures standard output.
        """
        config = Config(cache=CacheConfig(cache_dir=tmp_path / "cache"))
        options = CLIOptions(path=tmp_path, quiet=False, output_format="json")

        # A stand-in the stage cannot use, so it takes the failure path
        # and would print its notice.
        with mock.patch.object(cli, "AutoFixer"):
            outcome = cli._run_auto_fix_stage(
                config,
                options,
                ValidationCache(config.cache),
                make_validation([make_validation_error(1)]),
            )

        assert outcome.stage_error is not None
        assert capsys.readouterr().out == ""

    def test_a_text_run_still_reports_a_stage_failure(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The guard against silencing the notice for everyone.

        Args:
            tmp_path: Supplies the cache directory.
            capsys: Captures standard output.
        """
        config = Config(cache=CacheConfig(cache_dir=tmp_path / "cache"))
        options = CLIOptions(path=tmp_path, quiet=False)

        with mock.patch.object(cli, "AutoFixer"):
            cli._run_auto_fix_stage(
                config,
                options,
                ValidationCache(config.cache),
                make_validation([make_validation_error(1)]),
            )

        assert "Auto-fix failed" in strip_ansi(capsys.readouterr().out)


class TestEmitResultsCollection:
    """Whether the JSON payload is printed or handed back.

    The sweep depends on being able to take a repository's payload
    *without* it reaching standard output, since it assembles one
    document of its own. If collecting still printed, every repository
    would emit a top-level object and the aggregate document would be
    unparsable no matter how carefully the sweep built it.
    """

    @staticmethod
    def emit(*, collect_json: bool) -> dict[str, Any] | None:
        """Run the emitter over an empty result set.

        Args:
            collect_json: Whether to collect the payload rather than
                print it.

        Returns:
            Whatever the emitter returned.
        """
        scanner = mock.Mock()
        scanner.get_scan_summary.return_value = {
            "total_files": 0,
            "total_calls": 0,
        }
        return _emit_results(
            CLIOptions(path=Path.cwd(), quiet=True, output_format="json"),
            scanner,
            make_validation([]),
            make_autofix(),
            Config(),
            None,
            collect_json=collect_json,
        )

    def test_collecting_returns_the_payload_without_printing(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A collected payload never reaches standard output.

        Args:
            capsys: Captures standard output.
        """
        payload = self.emit(collect_json=True)

        assert capsys.readouterr().out == ""
        assert payload is not None
        assert "scan_summary" in payload

    def test_not_collecting_prints_the_document(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A single repository still prints its own results.

        This is the guard against silencing the ordinary JSON mode.

        Args:
            capsys: Captures standard output.
        """
        payload = self.emit(collect_json=False)

        assert payload is None
        assert "scan_summary" in json.loads(capsys.readouterr().out)
