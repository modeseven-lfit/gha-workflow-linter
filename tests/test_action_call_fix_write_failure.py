# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for the per-file rewrite failure handler in the auto-fixer.

``AutoFixer.fix_validation_errors`` applies its rewrites one file at a
time and catches a failure per file, so one unwritable file does not cost
the others their fixes. A file whose rewrite fails is absent from the
returned mapping, and therefore from the fix count, the rendered diff,
and the exit code, which keys off it.

Nothing exercised that handler before. The rewrite itself is covered by
``tests/test_file_edit.py`` and a failure of the fixing stage as a whole
by ``test_auto_fix_failure_is_reported_not_raised``; this sits between
them. Were the handler removed, broadened, or silenced, the suite would
not have noticed.

Reaching it needs the fixer to have resolved its replacements first, so
resolution is stubbed and the write is made to fail. No network access,
in keeping with the rest of the auto-fix tests.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest

from gha_workflow_linter.action_call_fix import AutoFixer
from gha_workflow_linter.models import (
    ActionCall,
    CacheConfig,
    Config,
    GitHubAPIConfig,
    LogLevel,
    ReferenceType,
    ValidationError,
    ValidationMethod,
    ValidationResult,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from contextlib import AbstractContextManager
    from pathlib import Path

#: A SHA that resolves to nothing, so the call is an invalid reference
#: and the fixer has something to repair.
BROKEN_SHA = "0" * 40

#: The commit v6.1.0 actually points at.
GOOD_SHA = "b1476f6e6eb133afa41ed8589daba6dc69b4d3f5"

REPO = "release-drafter/release-drafter"

WORKFLOW = """---
name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: {repo}@{sha}  # v6.1.0
"""

#: 1-based line of the ``uses:`` call in WORKFLOW.
USES_LINE = 7


@pytest.fixture
def config() -> Config:
    """Configuration that repairs invalid references without upgrading."""
    return Config(
        log_level=LogLevel.DEBUG,
        parallel_workers=2,
        require_pinned_sha=True,
        auto_fix=True,
        update_actions=False,
        two_space_comments=True,
        skip_actions=False,
        fix_test_calls=False,
        validation_method=ValidationMethod.GITHUB_API,
        cache=CacheConfig(enabled=False),
        github_api=GitHubAPIConfig(token="test-token"),
    )


def write_workflow(directory: Path, name: str) -> Path:
    """Write a workflow whose single action call needs repair.

    Args:
        directory: Directory to write into.
        name: File name.

    Returns:
        Path to the written file.
    """
    target = directory / name
    target.write_text(WORKFLOW.format(repo=REPO, sha=BROKEN_SHA))
    return target


def action_call() -> ActionCall:
    """Build the action call the workflow contains.

    Returns:
        The parsed call, pinned to a SHA that resolves to nothing.
    """
    organization, repository = REPO.split("/")
    return ActionCall(
        organization=organization,
        repository=repository,
        reference=BROKEN_SHA,
        reference_type=ReferenceType.COMMIT_SHA,
        comment="v6.1.0",
        raw_line=f"      - uses: {REPO}@{BROKEN_SHA}  # v6.1.0",
        line_number=USES_LINE,
    )


def validation_error(file_path: Path, call: ActionCall) -> ValidationError:
    """Build the invalid-reference error the fixer acts on.

    Args:
        file_path: Workflow the call appears in.
        call: The call itself.

    Returns:
        The validation error.
    """
    return ValidationError(
        file_path=file_path,
        action_call=call,
        result=ValidationResult.INVALID_REFERENCE,
        error_message="Invalid reference",
    )


def stubbed_resolution() -> AbstractContextManager[Any]:
    """Patch away every step of the fixer that would reach the network.

    Returns:
        A context manager stubbing version, SHA and redirect lookups.
    """
    return patch.multiple(
        AutoFixer,
        _get_latest_versions_batch=_async_value({REPO: ("v6.1.0", GOOD_SHA)}),
        _get_shas_batch=_async_value({(REPO, "v6.1.0"): GOOD_SHA}),
        _detect_repository_redirect=_async_value(None),
    )


def _async_value(value: Any) -> Any:
    """Build an async stub returning a fixed value.

    Args:
        value: What the coroutine should return.

    Returns:
        An async callable suitable for ``patch.multiple``.
    """

    async def _stub(*_args: Any, **_kwargs: Any) -> Any:
        return value

    return _stub


def failing_writer(
    failing: Path,
) -> Any:
    """Build a ``replace_lines`` stub that fails for one file only.

    Args:
        failing: The file whose rewrite should raise.

    Returns:
        A callable matching ``file_edit.replace_lines``.
    """
    from gha_workflow_linter import file_edit

    real = file_edit.replace_lines

    def _replace(path: Path, replacements: Mapping[int, str]) -> list[Any]:
        if path == failing:
            raise OSError(f"disk full writing {path}")
        return real(path, replacements)

    return _replace


def failing_apply(failing: Path) -> Any:
    """Build an ``_apply_fixes_to_file`` stub that fails for one file.

    ``_apply_fixes_to_file`` logs the same message as the handler above
    it before re-raising, so a failure raised from inside it cannot show
    which of the two emitted the log line. Raising from the method itself
    leaves the handler as the only possible source.

    Args:
        failing: The file whose rewrite should raise.

    Returns:
        An async callable matching ``AutoFixer._apply_fixes_to_file``.
    """

    async def _apply(
        _self: AutoFixer, path: Path, _line_fixes: Any
    ) -> list[Any]:
        if path == failing:
            raise OSError(f"disk full writing {path}")
        return []

    return _apply


class TestPerFileWriteFailure:
    """One unwritable file must not cost the others their fixes."""

    @pytest.mark.asyncio
    async def test_other_files_are_still_fixed(
        self, config: Config, tmp_path: Path
    ) -> None:
        # The failing file is processed first on purpose: with the
        # healthy one first, a handler that broke out of the loop
        # after a failure would still leave these assertions true.
        bad = write_workflow(tmp_path, "bad.yaml")
        good = write_workflow(tmp_path, "good.yaml")
        call = action_call()
        errors = [validation_error(bad, call), validation_error(good, call)]
        all_calls = {bad: {USES_LINE: call}, good: {USES_LINE: call}}

        with (
            stubbed_resolution(),
            patch(
                # Patch where the name is looked up, not where it is defined.
                "gha_workflow_linter.action_call_fix.replace_lines",
                failing_writer(bad),
            ),
        ):
            async with AutoFixer(config, base_path=tmp_path) as fixer:
                applied, _, _ = await fixer.fix_validation_errors(
                    errors, all_calls, check_for_updates=False
                )

        assert good in applied, "a healthy file lost its fix"
        assert bad not in applied, "a failed rewrite was reported as applied"

    @pytest.mark.asyncio
    async def test_the_failure_is_recorded_on_the_fixer(
        self, config: Config, tmp_path: Path
    ) -> None:
        """A failed rewrite must leave a trace the caller can read.

        It appears in no other tally: the planned change is absent from
        the applied fixes, and under ``--update-actions`` the call was
        never recorded as stale either, so a run that failed to write
        would otherwise look like a run with nothing to do.

        Args:
            config: Auto-fixer configuration.
            tmp_path: Directory holding the workflows.
        """
        bad = write_workflow(tmp_path, "bad.yaml")
        good = write_workflow(tmp_path, "good.yaml")
        call = action_call()
        errors = [validation_error(bad, call), validation_error(good, call)]
        all_calls = {bad: {USES_LINE: call}, good: {USES_LINE: call}}

        with (
            stubbed_resolution(),
            patch(
                "gha_workflow_linter.action_call_fix.replace_lines",
                failing_writer(bad),
            ),
        ):
            async with AutoFixer(config, base_path=tmp_path) as fixer:
                await fixer.fix_validation_errors(
                    errors, all_calls, check_for_updates=False
                )
                failures = list(fixer.write_failures)

        assert failures == [bad]

    @pytest.mark.asyncio
    async def test_a_clean_run_records_no_failure(
        self, config: Config, tmp_path: Path
    ) -> None:
        """The guard against reporting a failure for every rewrite.

        Args:
            config: Auto-fixer configuration.
            tmp_path: Directory holding the workflows.
        """
        good = write_workflow(tmp_path, "good.yaml")
        call = action_call()

        with stubbed_resolution():
            async with AutoFixer(config, base_path=tmp_path) as fixer:
                await fixer.fix_validation_errors(
                    [validation_error(good, call)],
                    {good: {USES_LINE: call}},
                    check_for_updates=False,
                )
                failures = list(fixer.write_failures)

        assert failures == []

    @pytest.mark.asyncio
    async def test_surviving_file_is_written_to_disk(
        self, config: Config, tmp_path: Path
    ) -> None:
        """The fix is real, not merely reported."""
        # The failing file is processed first on purpose: with the
        # healthy one first, a handler that broke out of the loop
        # after a failure would still leave these assertions true.
        bad = write_workflow(tmp_path, "bad.yaml")
        good = write_workflow(tmp_path, "good.yaml")
        call = action_call()
        errors = [validation_error(bad, call), validation_error(good, call)]
        all_calls = {bad: {USES_LINE: call}, good: {USES_LINE: call}}

        with (
            stubbed_resolution(),
            patch(
                "gha_workflow_linter.action_call_fix.replace_lines",
                failing_writer(bad),
            ),
        ):
            async with AutoFixer(config, base_path=tmp_path) as fixer:
                await fixer.fix_validation_errors(
                    errors, all_calls, check_for_updates=False
                )

        assert GOOD_SHA in good.read_text()
        assert BROKEN_SHA in bad.read_text(), "the failed file was modified"

    @pytest.mark.asyncio
    async def test_failure_is_logged_with_the_path(
        self,
        config: Config,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A silently dropped file would be worse than a noisy one.

        The failure is raised from ``_apply_fixes_to_file`` rather than
        from the writer beneath it, because that method logs the same
        message before re-raising: a writer-level failure would satisfy
        this assertion even with the handler's own logging removed.
        """
        # The failing file is processed first on purpose: with the
        # healthy one first, a handler that broke out of the loop
        # after a failure would still leave these assertions true.
        bad = write_workflow(tmp_path, "bad.yaml")
        good = write_workflow(tmp_path, "good.yaml")
        call = action_call()
        errors = [validation_error(bad, call), validation_error(good, call)]
        all_calls = {bad: {USES_LINE: call}, good: {USES_LINE: call}}

        with (
            caplog.at_level("ERROR"),
            stubbed_resolution(),
            patch.object(AutoFixer, "_apply_fixes_to_file", failing_apply(bad)),
        ):
            async with AutoFixer(config, base_path=tmp_path) as fixer:
                await fixer.fix_validation_errors(
                    errors, all_calls, check_for_updates=False
                )

        assert str(bad) in caplog.text
        assert "disk full" in caplog.text

    @pytest.mark.asyncio
    async def test_failure_does_not_propagate(
        self, config: Config, tmp_path: Path
    ) -> None:
        """Every file failing still returns rather than raising."""
        first = write_workflow(tmp_path, "first.yaml")
        second = write_workflow(tmp_path, "second.yaml")
        call = action_call()
        errors = [
            validation_error(first, call),
            validation_error(second, call),
        ]
        all_calls = {first: {USES_LINE: call}, second: {USES_LINE: call}}

        def _always_fails(path: Path, _replacements: Any) -> list[Any]:
            raise OSError(f"disk full writing {path}")

        with (
            stubbed_resolution(),
            patch(
                "gha_workflow_linter.action_call_fix.replace_lines",
                _always_fails,
            ),
        ):
            async with AutoFixer(config, base_path=tmp_path) as fixer:
                applied, _, _ = await fixer.fix_validation_errors(
                    errors, all_calls, check_for_updates=False
                )

        assert applied == {}
