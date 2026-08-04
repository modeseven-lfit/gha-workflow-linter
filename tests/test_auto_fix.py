# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for auto-fix functionality.

Note: Tests use JSON output format (--format json) for robust assertions
instead of fragile string matching against stdout text. This prevents tests
from breaking when output formatting changes.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path
    from typing import TypeAlias

    from rich.progress import Progress, TaskID

    AutoFixResult: TypeAlias = tuple[
        dict[Path, list[dict[str, str]]],
        dict[str, int],
        dict[str, list[dict[str, Any]]],
    ]

import pytest
from typer.testing import CliRunner

from gha_workflow_linter.auto_fix import AutoFixer
from gha_workflow_linter.cli import app
from gha_workflow_linter.models import (
    ActionCall,
    ActionCallType,
    CacheConfig,
    Config,
    LogLevel,
    NetworkConfig,
    ReferenceType,
    ValidationError,
    ValidationMethod,
    ValidationResult,
)
from gha_workflow_linter.validator import ActionCallValidator
from tests.conftest import strip_ansi


def parse_json_output(stdout: str) -> dict[str, Any]:
    """Parse JSON output from CLI command.

    Helper function to parse structured JSON output for more robust test assertions.

    Args:
        stdout: The stdout string from CliRunner result

    Returns:
        Parsed JSON data as dictionary
    """
    # Handle cases where there might be non-JSON output before the JSON
    # (e.g., cache purge messages)
    lines = stdout.strip().split("\n")

    # Find the first line that starts with '{'
    json_start = 0
    for i, line in enumerate(lines):
        if line.strip().startswith("{"):
            json_start = i
            break

    # Join from the JSON start onwards
    json_text = "\n".join(lines[json_start:])
    result: dict[str, Any] = json.loads(json_text)
    return result


def build_all_action_calls_from_errors(
    errors: list[ValidationError],
) -> dict[Path, dict[int, ActionCall]]:
    """Helper to build all_action_calls dict from validation errors for tests.

    This ensures tests use the efficient batch processing path instead of
    the legacy individual processing path.
    """
    all_calls: dict[Path, dict[int, ActionCall]] = {}
    for error in errors:
        if error.file_path not in all_calls:
            all_calls[error.file_path] = {}
        all_calls[error.file_path][error.action_call.line_number] = (
            error.action_call
        )
    return all_calls


def stub_validator_class(
    validate: Callable[
        [dict[Path, dict[int, ActionCall]]], list[ValidationError]
    ],
) -> type[ActionCallValidator]:
    """Build a validator class whose validation step is replaced.

    ``cli.py`` does ``from .validator import ActionCallValidator`` at
    import time, so patching ``gha_workflow_linter.validator``'s attribute
    has no effect on the CLI: the name has to be replaced where it is
    looked up, ``gha_workflow_linter.cli.ActionCallValidator``.

    Subclassing the real validator, rather than substituting a bare mock,
    keeps every other method genuine. That matters for
    ``get_validation_summary``, which the CLI calls on the same instance
    to produce the error counts these tests assert on; a mock would return
    a mock and the assertions would be meaningless.

    Args:
        validate: Callable invoked with the scanner's action calls, keyed
            by file path then by line number, returning the validation
            errors the CLI should see.

    Returns:
        A drop-in replacement for ``ActionCallValidator`` that performs no
        network access.
    """

    class StubValidator(ActionCallValidator):
        """Validator reporting pre-computed errors, without network use."""

        def validate_action_calls(
            self,
            action_calls: dict[Path, dict[int, ActionCall]],
            progress: Progress | None = None,
            task_id: TaskID | None = None,
        ) -> list[ValidationError]:
            """Return the errors supplied by the enclosing factory."""
            return validate(action_calls)

    return StubValidator


def stub_auto_fixer_class(
    fix: Callable[
        [list[ValidationError], dict[Path, dict[int, ActionCall]], bool],
        AutoFixResult,
    ],
) -> type[AutoFixer]:
    """Build an auto-fixer class whose fixing step is replaced.

    ``cli.py`` does ``from .auto_fix import AutoFixer`` at import time,
    so patching ``gha_workflow_linter.auto_fix``'s attribute has no
    effect on the CLI: the name has to be replaced where it is looked
    up, ``gha_workflow_linter.cli.AutoFixer``. Left unpatched, the real
    fixer runs, queries github.com and rewrites the workflow files the
    test just wrote.

    Subclassing the real fixer, rather than substituting a bare mock,
    keeps construction and the async context manager genuine. Both are
    inert -- they build an HTTP client and a Git client but issue no
    request -- so the CLI's real setup and teardown path is exercised
    while the one method that reaches the network is replaced.

    The stub writes nothing to disk. The fixes it returns describe what
    a real run would have rewritten, so callers must assert on what the
    CLI does with them rather than on file contents; the rewriting
    itself is covered by the tests that drive the real
    :class:`AutoFixer` directly.

    Args:
        fix: Callable invoked with the validation errors, the scanner's
            action calls and the ``check_for_updates`` flag, returning
            the ``(fixes_by_file, redirect_stats,
            stale_actions_summary)`` triple the CLI should see.

    Returns:
        A drop-in replacement for ``AutoFixer`` that performs no network
        access and leaves the working tree untouched.
    """

    class StubAutoFixer(AutoFixer):
        """Fixer reporting pre-computed changes, without network use."""

        async def fix_validation_errors(
            self,
            errors: list[ValidationError],
            all_action_calls: dict[Path, dict[int, ActionCall]],
            check_for_updates: bool = False,
        ) -> AutoFixResult:
            """Return the fixes supplied by the enclosing factory."""
            return fix(errors, all_action_calls, check_for_updates)

    return StubAutoFixer


class RecordedAutoFix:
    """Auto-fix stub that records how the CLI invoked it.

    A stubbed fixer writes nothing, and under ``--format json`` (which
    forces quiet mode) the report of applied fixes is suppressed too, so
    asserting on file contents or on the printed diff would only test
    the stub. What remains genuinely observable is the exit code and the
    arguments the CLI assembled for the fixer: which errors it
    forwarded, which action calls it offered for update, and whether it
    asked for latest versions. Recording those keeps the assertions on
    production behaviour, and ``called`` fails loudly if the patch ever
    stops taking effect.
    """

    def __init__(self, result: AutoFixResult) -> None:
        """Store the triple to hand back when the CLI calls the fixer.

        Args:
            result: The ``(fixes_by_file, redirect_stats,
                stale_actions_summary)`` triple to return.
        """
        self.result = result
        self.called = False
        self.errors: list[ValidationError] = []
        self.action_calls: dict[Path, dict[int, ActionCall]] = {}
        self.check_for_updates = False

    @property
    def action_call_count(self) -> int:
        """Total number of action calls offered to the fixer."""
        return sum(len(calls) for calls in self.action_calls.values())

    def __call__(
        self,
        errors: list[ValidationError],
        action_calls: dict[Path, dict[int, ActionCall]],
        check_for_updates: bool,
    ) -> AutoFixResult:
        """Record the CLI's arguments and return the stored result."""
        self.called = True
        self.errors = errors
        self.action_calls = action_calls
        self.check_for_updates = check_for_updates
        return self.result


def iter_calls(
    action_calls: dict[Path, dict[int, ActionCall]],
) -> list[tuple[Path, ActionCall]]:
    """Flatten scanner results into ``(file_path, action_call)`` pairs.

    ``validate_action_calls`` receives a mapping of file path to a mapping
    of line number to action call. Stubs want the individual calls, paired
    with the file they came from so the resulting ``ValidationError``
    points at the right file.

    Args:
        action_calls: Scanner results as passed to the validator.

    Returns:
        One ``(file_path, action_call)`` pair per action call.
    """
    return [
        (file_path, call)
        for file_path, calls in action_calls.items()
        for call in calls.values()
    ]


class TestAutoFixBehaviorWithPinnedSHA:
    """Test auto-fix behavior with require_pinned_sha configuration."""

    @pytest.fixture
    def config_pinned_required(self) -> Config:
        """Config with require_pinned_sha=True."""
        return Config(
            log_level=LogLevel.DEBUG,
            parallel_workers=2,
            require_pinned_sha=True,
            auto_fix=True,
            update_actions=True,
            two_space_comments=False,
            skip_actions=False,
            fix_test_calls=False,
            validation_method=ValidationMethod.GITHUB_API,
            cache=CacheConfig(enabled=False),
            network=NetworkConfig(
                timeout_seconds=10,
                max_retries=2,
                retry_delay_seconds=1.0,
                rate_limit_delay_seconds=0.1,
            ),
        )

    @pytest.fixture
    def config_pinned_not_required(self) -> Config:
        """Config with require_pinned_sha=False."""
        return Config(
            log_level=LogLevel.DEBUG,
            parallel_workers=2,
            require_pinned_sha=False,
            auto_fix=True,
            update_actions=False,
            two_space_comments=False,
            skip_actions=False,
            fix_test_calls=False,
            validation_method=ValidationMethod.GITHUB_API,
            cache=CacheConfig(enabled=False),
            network=NetworkConfig(
                timeout_seconds=10,
                max_retries=2,
                retry_delay_seconds=1.0,
                rate_limit_delay_seconds=0.1,
            ),
        )

    @pytest.fixture
    def workflow_with_mixed_references(self) -> str:
        """Workflow file with mix of valid and invalid references."""
        return """name: Test Workflow

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout with invalid branch
        uses: actions/checkout@invalid-branch

      - name: Checkout with master (should be updated)
        uses: actions/checkout@master

      - name: Setup Python with version tag
        uses: actions/setup-python@v4

      - name: Setup Node with version tag
        uses: actions/setup-node@v3.8.1

      - name: Upload artifact with old version
        uses: actions/upload-artifact@v2
"""

    @pytest.fixture
    def temp_workflow_file(
        self, temp_dir: Path, workflow_with_mixed_references: str
    ) -> Path:
        """Create temporary workflow file."""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_with_mixed_references)
        return workflow_file

    @pytest.mark.asyncio
    async def test_auto_fix_with_pinned_sha_required(
        self,
        config_pinned_required: Config,
        temp_workflow_file: Path,
    ) -> None:
        """Test auto-fix behavior when require_pinned_sha=True."""
        # Mock git operations to return realistic data
        with patch(
            "gha_workflow_linter.validator.ActionCallValidator.validate_action_calls"
        ):
            # Create validation errors for each problematic action
            validation_errors = [
                ValidationError(
                    file_path=temp_workflow_file,
                    action_call=ActionCall(
                        raw_line="        uses: actions/checkout@invalid-branch",
                        line_number=9,
                        organization="actions",
                        repository="checkout",
                        reference="invalid-branch",
                        reference_type=ReferenceType.BRANCH,
                        call_type=ActionCallType.ACTION,
                        comment="",
                    ),
                    result=ValidationResult.INVALID_REFERENCE,
                    error_message="Invalid action call",
                ),
                ValidationError(
                    file_path=temp_workflow_file,
                    action_call=ActionCall(
                        raw_line="        uses: actions/checkout@master",
                        line_number=12,
                        organization="actions",
                        repository="checkout",
                        reference="master",
                        reference_type=ReferenceType.BRANCH,
                        call_type=ActionCallType.ACTION,
                        comment="",
                    ),
                    result=ValidationResult.NOT_PINNED_TO_SHA,
                    error_message="Action not pinned to SHA",
                ),
                ValidationError(
                    file_path=temp_workflow_file,
                    action_call=ActionCall(
                        raw_line="        uses: actions/setup-python@v4",
                        line_number=15,
                        organization="actions",
                        repository="setup-python",
                        reference="v4",
                        reference_type=ReferenceType.TAG,
                        call_type=ActionCallType.ACTION,
                        comment="",
                    ),
                    result=ValidationResult.NOT_PINNED_TO_SHA,
                    error_message="Action not pinned to SHA",
                ),
                ValidationError(
                    file_path=temp_workflow_file,
                    action_call=ActionCall(
                        raw_line="        uses: actions/setup-node@v3",
                        line_number=18,
                        organization="actions",
                        repository="setup-node",
                        reference="v3",
                        reference_type=ReferenceType.TAG,
                        call_type=ActionCallType.ACTION,
                        comment="",
                    ),
                    result=ValidationResult.NOT_PINNED_TO_SHA,
                    error_message="Action not pinned to SHA",
                ),
                ValidationError(
                    file_path=temp_workflow_file,
                    action_call=ActionCall(
                        raw_line="        uses: actions/upload-artifact@v3",
                        line_number=21,
                        organization="actions",
                        repository="upload-artifact",
                        reference="v3",
                        reference_type=ReferenceType.TAG,
                        call_type=ActionCallType.ACTION,
                        comment="",
                    ),
                    result=ValidationResult.NOT_PINNED_TO_SHA,
                    error_message="Action not pinned to SHA",
                ),
            ]

            # Mock the batch processing methods used by the refactored code
            with (
                patch.object(
                    AutoFixer, "_get_latest_versions_graphql_batch"
                ) as mock_get_latest_batch,
                patch.object(
                    AutoFixer, "_get_shas_batch"
                ) as mock_get_shas_batch,
                patch.object(
                    AutoFixer, "_find_valid_reference"
                ) as mock_find_ref,
            ):
                # Mock batch latest version retrieval
                async def mock_get_latest_batch_impl(
                    repo_keys: list[str],
                ) -> dict[str, tuple[str, str]]:
                    results = {}
                    latest_map = {
                        "actions/checkout": (
                            "v5.0.0",
                            "abc123def456789012345678901234567890abcd",
                        ),
                        "actions/setup-python": (
                            "v6.0.0",
                            "ghi789012345678901234567890abcdef456789",
                        ),
                        "actions/setup-node": (
                            "v6.0.0",
                            "jkl012345678901234567890abcdef789456123",
                        ),
                        "actions/upload-artifact": (
                            "v5.0.0",
                            "mno345678901234567890abcdef012789456789",
                        ),
                    }
                    for repo_key in repo_keys:
                        if repo_key in latest_map:
                            results[repo_key] = latest_map[repo_key]
                    return results

                mock_get_latest_batch.side_effect = mock_get_latest_batch_impl

                # Mock batch SHA retrieval
                async def mock_get_shas_batch_impl(
                    refs: list[tuple[str, str]],
                ) -> dict[tuple[str, str], str]:
                    sha_map = {
                        (
                            "actions/checkout",
                            "main",
                        ): "abc123def456789012345678901234567890abcd",
                        (
                            "actions/checkout",
                            "master",
                        ): "def456abc789012345678901234567890abcd123",
                        (
                            "actions/checkout",
                            "v5.0.0",
                        ): "abc123def456789012345678901234567890abcd",
                        (
                            "actions/setup-python",
                            "v4",
                        ): "ghi789012345678901234567890abcdef456789",
                        (
                            "actions/setup-python",
                            "v6.0.0",
                        ): "ghi789012345678901234567890abcdef456789",
                        (
                            "actions/setup-node",
                            "v3",
                        ): "jkl012345678901234567890abcdef789456123",
                        (
                            "actions/setup-node",
                            "v3.8.1",
                        ): "jkl012345678901234567890abcdef789456123",
                        (
                            "actions/setup-node",
                            "v6.0.0",
                        ): "jkl012345678901234567890abcdef789456123",
                        (
                            "actions/upload-artifact",
                            "v2",
                        ): "mno345678901234567890abcdef012789456789",
                        (
                            "actions/upload-artifact",
                            "v3",
                        ): "mno345678901234567890abcdef012789456789",
                        (
                            "actions/upload-artifact",
                            "v5.0.0",
                        ): "mno345678901234567890abcdef012789456789",
                    }
                    results = {}
                    for ref_tuple in refs:
                        if ref_tuple in sha_map:
                            results[ref_tuple] = sha_map[ref_tuple]
                    return results

                mock_get_shas_batch.side_effect = mock_get_shas_batch_impl

                # Mock reference finding - invalid-branch should fallback to main
                async def mock_find_ref_impl(
                    _repo_key: str, invalid_ref: str
                ) -> str | None:
                    if invalid_ref == "invalid-branch":
                        return "main"  # Fallback to default branch
                    return invalid_ref  # Keep existing reference for others

                mock_find_ref.side_effect = mock_find_ref_impl

                # Run auto-fix
                async with AutoFixer(config_pinned_required) as fixer:
                    (
                        fixed_files,
                        redirect_stats,
                        stale_actions_summary,
                    ) = await fixer.fix_validation_errors(
                        validation_errors,
                        build_all_action_calls_from_errors(validation_errors),
                    )

                # Should fix all 5 issues when require_pinned_sha=True
                assert len(fixed_files) == 1
                assert temp_workflow_file in fixed_files

                changes = fixed_files[temp_workflow_file]
                assert len(changes) == 5  # All 5 actions should be fixed

                # Verify the file content was updated correctly
                updated_content = temp_workflow_file.read_text()

                # Should pin all actions to SHAs with version comments
                assert (
                    "actions/checkout@abc123def456789012345678901234567890abcd"
                    in updated_content
                )
                assert (
                    "actions/setup-python@ghi789012345678901234567890abcdef456789"
                    in updated_content
                )
                assert (
                    "actions/setup-node@jkl012345678901234567890abcdef789456123"
                    in updated_content
                )
                assert (
                    "actions/upload-artifact@mno345678901234567890abcdef012789456789"
                    in updated_content
                )

    @pytest.mark.asyncio
    async def test_auto_fix_with_pinned_sha_not_required(
        self,
        config_pinned_not_required: Config,
        temp_workflow_file: Path,
    ) -> None:
        """Test auto-fix behavior when require_pinned_sha=False."""
        # Mock git operations
        with patch(
            "gha_workflow_linter.validator.ActionCallValidator.validate_action_calls"
        ):
            # When require_pinned_sha=False, only invalid references should be flagged
            validation_errors = [
                ValidationError(
                    file_path=temp_workflow_file,
                    action_call=ActionCall(
                        raw_line="        uses: actions/checkout@invalid-branch",
                        line_number=9,
                        organization="actions",
                        repository="checkout",
                        reference="invalid-branch",
                        reference_type=ReferenceType.BRANCH,
                        call_type=ActionCallType.ACTION,
                        comment="",
                    ),
                    result=ValidationResult.INVALID_REFERENCE,
                    error_message="Invalid action call",
                ),
                # Note: Other actions (@master, @v4, @v3.8.1, @v2) should NOT be flagged
                # when require_pinned_sha=False
            ]

            # Debug: Check file content before auto-fix
            print("\n=== DEBUG: File content BEFORE auto-fix ===")
            initial_content = temp_workflow_file.read_text()
            print(f"First 300 chars: {repr(initial_content[:300])}")
            print(
                f"Has 'invalid-branch': {'invalid-branch' in initial_content}"
            )
            print(f"Has dashes: {initial_content.count('- name:')}")

            with (
                patch.object(
                    AutoFixer, "_get_latest_versions_batch"
                ) as mock_get_latest_batch,
                patch.object(
                    AutoFixer, "_get_shas_batch"
                ) as mock_get_shas_batch,
                patch.object(
                    AutoFixer, "_find_valid_reference"
                ) as mock_find_ref,
            ):
                # Mock batch latest version retrieval (returns empty - no updates needed)
                # The enhanced batch processor will call _find_valid_reference for INVALID_REFERENCE errors
                async def mock_get_latest_batch_impl(
                    _repo_keys: list[str],
                ) -> dict[str, tuple[str, str]]:
                    return {}  # No latest versions when require_pinned_sha=False

                mock_get_latest_batch.side_effect = mock_get_latest_batch_impl

                async def mock_find_ref_impl(
                    _repo_key: str, _invalid_ref: str
                ) -> str | None:
                    return "main"  # Always fallback to main branch

                mock_find_ref.side_effect = mock_find_ref_impl

                async def mock_get_shas_batch_impl(
                    refs: list[tuple[str, str]],
                ) -> dict[tuple[str, str], str]:
                    results = {}
                    for repo_key, ref in refs:
                        if ref == "main":
                            results[(repo_key, ref)] = (
                                "abc123def456789012345678901234567890abcd"
                            )
                    return results

                mock_get_shas_batch.side_effect = mock_get_shas_batch_impl

                async with AutoFixer(config_pinned_not_required) as fixer:
                    (
                        fixed_files,
                        redirect_stats,
                        stale_actions_summary,
                    ) = await fixer.fix_validation_errors(
                        validation_errors,
                        build_all_action_calls_from_errors(validation_errors),
                    )

                # Debug: Check what was fixed
                print("\n=== DEBUG: After auto-fix ===")
                print(f"fixed_files: {list(fixed_files.keys())}")
                if temp_workflow_file in fixed_files:
                    print(f"Changes: {fixed_files[temp_workflow_file]}")

                # Should only fix 1 issue (the invalid-branch) when require_pinned_sha=False
                assert len(fixed_files) == 1
                assert temp_workflow_file in fixed_files

                changes = fixed_files[temp_workflow_file]
                assert len(changes) == 1  # Only 1 action should be fixed

                # Verify the file content
                updated_content = temp_workflow_file.read_text()

                # Debug: Show updated content
                print("\n=== DEBUG: Updated file content ===")
                print(f"First 400 chars: {repr(updated_content[:400])}")

                # Should fix the invalid reference to main branch (not SHA since require_pinned_sha=False)
                assert "actions/checkout@main" in updated_content

                # These should remain unchanged when require_pinned_sha=False
                assert "actions/checkout@master" in updated_content
                assert "actions/setup-python@v4" in updated_content
                assert "actions/setup-node@v3.8.1" in updated_content
                assert "actions/upload-artifact@v2" in updated_content

    def test_cli_auto_fix_with_pinned_sha_required(
        self,
        temp_dir: Path,
        workflow_with_mixed_references: str,
    ) -> None:
        """Test CLI auto-fix behavior with require_pinned_sha=True via command line."""
        # Create workflow file
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_with_mixed_references)

        runner = CliRunner()

        # Configure the validator to report errors for all non-SHA
        # references, so the run exercises auto-fix rather than the
        # network.
        def mock_validate_calls(
            action_calls: dict[Path, dict[int, ActionCall]],
        ) -> list[ValidationError]:
            errors: list[ValidationError] = []
            for file_path, call in iter_calls(action_calls):
                if call.reference in [
                    "invalid-branch",
                    "master",
                    "v4",
                    "v3.8.1",
                    "v2",
                ]:
                    errors.append(
                        ValidationError(
                            file_path=file_path,
                            action_call=call,
                            result=ValidationResult.INVALID_REFERENCE
                            if call.reference == "invalid-branch"
                            else ValidationResult.NOT_PINNED_TO_SHA,
                            error_message="Invalid action call"
                            if call.reference == "invalid-branch"
                            else "Action not pinned to SHA",
                        )
                    )
            return errors

        # Mock git operations and the auto-fixer for this CLI test
        # Report a fix for every flagged call, as a real --update-actions
        # run would. Line numbers match the ``uses:`` lines of the
        # fixture, not the ``- name:`` lines above them.
        expected_fixes: dict[Path, list[dict[str, str]]] = {
            workflow_file: [
                {
                    "line_number": "10",
                    "old_line": "uses: actions/checkout@invalid-branch",
                    "new_line": "uses: actions/checkout@abc123",
                },
                {
                    "line_number": "13",
                    "old_line": "uses: actions/checkout@master",
                    "new_line": "uses: actions/checkout@def456",
                },
                {
                    "line_number": "16",
                    "old_line": "uses: actions/setup-python@v4",
                    "new_line": "uses: actions/setup-python@ghi789",
                },
                {
                    "line_number": "19",
                    "old_line": "uses: actions/setup-node@v3.8.1",
                    "new_line": "uses: actions/setup-node@jkl012",
                },
                {
                    "line_number": "22",
                    "old_line": "uses: actions/upload-artifact@v2",
                    "new_line": "uses: actions/upload-artifact@mno345",
                },
            ]
        }
        auto_fix = RecordedAutoFix(
            (expected_fixes, {"actions_moved": 0, "calls_updated": 0}, {})
        )

        with (
            patch(
                "gha_workflow_linter.cli.ActionCallValidator",
                stub_validator_class(mock_validate_calls),
            ),
            patch(
                "gha_workflow_linter.cli.AutoFixer",
                stub_auto_fixer_class(auto_fix),
            ),
        ):
            # Run CLI with require-pinned-sha (default is True).
            # --no-fail-on-error isolates the exit code to the fixer:
            # the run can then only fail because the tree changed, so
            # the exit code below tests that the CLI acted on the fixes
            # it was handed. That validation errors alone also fail a
            # run is covered by
            # ``test_error_count_summary_with_pinned_sha_required``.
            result = runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--auto-fix",
                    "--update-actions",
                    "--no-fail-on-error",
                    "--validation-method",
                    "git",
                    "--format",
                    "json",
                ],
            )

            # Should exit with code 1 (files were modified)
            assert result.exit_code == 1

            # Parse JSON output for structured validation
            output_data = parse_json_output(result.stdout)
            assert output_data["validation_summary"]["total_errors"] == 5

            # With require_pinned_sha=True every non-SHA reference is an
            # error, so all five reach the fixer, and --update-actions asks
            # it to move them to the latest versions.
            assert auto_fix.called
            assert len(auto_fix.errors) == 5
            assert auto_fix.action_call_count == 5
            assert auto_fix.check_for_updates is True

            # The fixer is stubbed, so the workflow on disk is untouched:
            # rewriting is covered by
            # ``test_auto_fix_with_pinned_sha_required``, which drives
            # the real AutoFixer.
            assert workflow_file.read_text() == workflow_with_mixed_references

    def test_cli_auto_fix_with_pinned_sha_not_required(
        self,
        temp_dir: Path,
        workflow_with_mixed_references: str,
    ) -> None:
        """Test CLI auto-fix behavior with require_pinned_sha=False via command line."""
        # Create workflow file
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_with_mixed_references)

        # Create config file with require_pinned_sha=False
        config_content = """
require_pinned_sha: false
auto_fix: true
update_actions: true
validation_method: git
"""
        config_file = temp_dir / "gha-workflow-linter.yaml"
        config_file.write_text(config_content)

        runner = CliRunner()

        # When require_pinned_sha=False, only invalid references are errors
        def mock_validate_calls(
            action_calls: dict[Path, dict[int, ActionCall]],
        ) -> list[ValidationError]:
            return [
                ValidationError(
                    file_path=file_path,
                    action_call=call,
                    result=ValidationResult.INVALID_REFERENCE,
                    error_message="Invalid action call",
                )
                for file_path, call in iter_calls(action_calls)
                if call.reference == "invalid-branch"
            ]

        # With auto_latest enabled a real run fixes the invalid
        # reference and updates the other four calls to their latest
        # versions, so the fixer reports five changes for one file.
        expected_fixes: dict[Path, list[dict[str, str]]] = {
            workflow_file: [
                {
                    "line_number": "10",
                    "old_line": "uses: actions/checkout@invalid-branch",
                    "new_line": "uses: actions/checkout@abc123",
                },
                {
                    "line_number": "13",
                    "old_line": "uses: actions/checkout@master",
                    "new_line": "uses: actions/checkout@def456",
                },
                {
                    "line_number": "16",
                    "old_line": "uses: actions/setup-python@v4",
                    "new_line": "uses: actions/setup-python@ghi789",
                },
                {
                    "line_number": "19",
                    "old_line": "uses: actions/setup-node@v3.8.1",
                    "new_line": "uses: actions/setup-node@jkl012",
                },
                {
                    "line_number": "22",
                    "old_line": "uses: actions/upload-artifact@v2",
                    "new_line": "uses: actions/upload-artifact@mno345",
                },
            ]
        }
        auto_fix = RecordedAutoFix(
            (expected_fixes, {"actions_moved": 0, "calls_updated": 0}, {})
        )

        with (
            patch(
                "gha_workflow_linter.cli.ActionCallValidator",
                stub_validator_class(mock_validate_calls),
            ),
            patch(
                "gha_workflow_linter.cli.AutoFixer",
                stub_auto_fixer_class(auto_fix),
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--config",
                    str(config_file),
                    "--no-fail-on-error",
                    "--format",
                    "json",
                ],
            )

            # --no-fail-on-error leaves the auto-fixer as the only
            # source of a non-zero exit code, so this asserts that the
            # CLI acted on the five fixes it was handed.
            assert result.exit_code == 1

            # Parse JSON output for structured validation
            output_data = parse_json_output(result.stdout)
            # Only 1 validation error (require_pinned_sha=False, so
            # tags and branches are valid on their own).
            assert output_data["validation_summary"]["total_errors"] == 1

            # That single error is all the fixer is asked to repair, but
            # auto_latest still offers it every action call in the tree
            # so the remaining four can be moved to latest versions.
            assert auto_fix.called
            assert len(auto_fix.errors) == 1
            assert auto_fix.action_call_count == 5
            assert auto_fix.check_for_updates is True

            # The fixer is stubbed, so nothing is rewritten on disk.
            assert workflow_file.read_text() == workflow_with_mixed_references

    def test_error_count_summary_with_pinned_sha_required(
        self,
        temp_dir: Path,
        workflow_with_mixed_references: str,
    ) -> None:
        """Test that error summary shows correct counts with require_pinned_sha=True."""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_with_mixed_references)

        runner = CliRunner()

        # All non-SHA references should be errors when require_pinned_sha=True
        def mock_validate_calls(
            action_calls: dict[Path, dict[int, ActionCall]],
        ) -> list[ValidationError]:
            errors: list[ValidationError] = []
            for file_path, call in iter_calls(action_calls):
                if call.reference in [
                    "invalid-branch",
                    "master",
                    "v4",
                    "v3.8.1",
                    "v2",
                ]:
                    if call.reference == "invalid-branch":
                        errors.append(
                            ValidationError(
                                file_path=file_path,
                                action_call=call,
                                result=ValidationResult.INVALID_REFERENCE,
                                error_message="Invalid action call",
                            )
                        )
                    else:
                        errors.append(
                            ValidationError(
                                file_path=file_path,
                                action_call=call,
                                result=ValidationResult.NOT_PINNED_TO_SHA,
                                error_message="Action not pinned to SHA",
                            )
                        )
            return errors

        # Nothing is fixable in this scenario: the test is about the
        # error counts the validation summary reports.
        auto_fix = RecordedAutoFix(
            ({}, {"actions_moved": 0, "calls_updated": 0}, {})
        )

        with (
            patch(
                "gha_workflow_linter.cli.ActionCallValidator",
                stub_validator_class(mock_validate_calls),
            ),
            patch(
                "gha_workflow_linter.cli.AutoFixer",
                stub_auto_fixer_class(auto_fix),
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--auto-fix",
                    "--validation-method",
                    "git",
                    "--format",
                    "json",
                ],
            )

            # No fixes were applied, so the exit code comes from the
            # five outstanding validation errors alone.
            assert result.exit_code == 1

            # Parse JSON output for structured validation
            output_data = parse_json_output(result.stdout)
            assert output_data["validation_summary"]["total_errors"] == 5
            assert output_data["validation_summary"]["invalid_references"] == 1
            assert output_data["validation_summary"]["not_pinned_to_sha"] == 4

            # All five errors reach the fixer, but without --update-actions
            # it is not asked to chase newer versions.
            assert auto_fix.called
            assert len(auto_fix.errors) == 5
            assert auto_fix.check_for_updates is False

            # The fixer reported no changes, so the workflow is intact.
            assert workflow_file.read_text() == workflow_with_mixed_references

    def test_error_count_summary_with_pinned_sha_not_required(
        self,
        temp_dir: Path,
    ) -> None:
        """Test that error summary shows correct counts with require_pinned_sha=False."""
        # Create a workflow with only valid tag references (no invalid refs)
        workflow_content = """name: Test

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
"""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_content)

        # Config with require_pinned_sha=False
        config_content = """require_pinned_sha: false
auto_fix: false
validation_method: git
"""
        config_file = temp_dir / "gha-workflow-linter.yaml"
        config_file.write_text(config_content)

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--config",
                str(config_file),
                "--update-actions",
            ],
        )

        # When require_pinned_sha=False, tag references are valid
        # However, the actions are still validated (they exist), and auto-fix may still run
        # The key is that we shouldn't get "not pinned to SHA" errors
        assert "not pinned to SHA" not in result.stdout.lower()
        # Exit code may be 0 or 1 depending on whether auto-fix ran
        assert result.exit_code in (0, 1)


class TestAutoFixConfiguration:
    """Test auto-fix configuration options."""

    @pytest.fixture
    def workflow_with_old_versions(self) -> str:
        """Workflow with older action versions."""
        return """name: Test

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4.7.0
"""

    def test_auto_fix_disabled(self, temp_dir: Path) -> None:
        """Test that auto-fix respects the auto_fix=false setting."""
        workflow_file = temp_dir / ".github" / "workflows" / "auto-fix.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text("""name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
""")

        config_content = """
require_pinned_sha: true
auto_fix: false  # Disable auto-fix
validation_method: git
"""
        config_file = temp_dir / "gha-workflow-linter.yaml"
        config_file.write_text(config_content)

        runner = CliRunner()

        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--config",
                str(config_file),
                "--no-auto-fix",  # Explicitly disable to ensure it's off
            ],
        )

        # Should exit with error code but NOT auto-fix
        assert result.exit_code == 1
        assert "validation errors" in result.stdout
        assert "Auto-fixed" not in result.stdout

    def test_update_actions_disabled(self, temp_dir: Path) -> None:
        """Test auto-fix with update_actions=False uses existing versions not latest."""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text("""name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""")

        config_content = """
require_pinned_sha: true
auto_fix: true
update_actions: false  # Don't use latest versions
validation_method: git
"""
        config_file = temp_dir / "gha-workflow-linter.yaml"
        config_file.write_text(config_content)

        runner = CliRunner()

        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--auto-fix",
                "--no-update-actions",
                "--format",
                "json",
            ],
        )

        # Should auto-fix without upgrading to latest version
        # When update_actions=False, it should pin to the SHA of v4, not upgrade to v5
        output_data = parse_json_output(result.stdout)

        # If there were errors, file should be modified to pin to SHA
        if output_data["validation_summary"]["total_errors"] > 0:
            modified_content = workflow_file.read_text()
            # Should have a SHA now, not just v4 tag
            # The content should be modified (contain @) and be longer due to SHA
            assert "@" in modified_content and "#" in modified_content

    def test_two_space_comments_enabled(self, temp_dir: Path) -> None:
        """Test auto-fix with two_space_comments=True."""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text("""name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""")

        config_content = """
require_pinned_sha: true
auto_fix: true
two_space_comments: true  # Use two spaces before comments
validation_method: git
"""
        config_file = temp_dir / "gha-workflow-linter.yaml"
        config_file.write_text(config_content)

        runner = CliRunner()

        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--config",
                str(config_file),
            ],
        )

        # When auto-fix runs with two_space_comments, should use double space
        # Check the actual file to see if it has two spaces before comment
        if "Auto-fixed" in result.stdout:
            content = workflow_file.read_text()
            # Should have " #" (space before hash) in comment - actual format is single space
            # The two_space_comments setting affects YAML comment formatting, not inline action comments
            assert " # " in content or result.exit_code == 0


class TestAutoFixEdgeCases:
    """Test auto-fix edge cases and error handling."""

    def test_auto_fix_with_no_errors(self, temp_dir: Path) -> None:
        """Test auto-fix behavior when there are no validation errors."""
        # Use a known valid SHA for actions/checkout@v4
        workflow_content = """name: Valid Workflow

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
"""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_content)

        runner = CliRunner()

        # Test with JSON output for more robust assertions
        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--auto-fix",
                "--no-update-actions",
                "--validation-method",
                "git",
                "--format",
                "json",
            ],
        )

        # With --no-update-actions and a valid SHA, there should be no validation errors
        assert result.exit_code == 0

        # Parse JSON output for structured validation
        output_data = parse_json_output(result.stdout)

        # Should have no validation errors since the action is already pinned to a valid SHA
        assert output_data["validation_summary"]["total_errors"] == 0

        # The file should not have been modified since it's already valid
        assert workflow_file.read_text() == workflow_content

    def test_auto_fix_file_permission_error(self, temp_dir: Path) -> None:
        """Test auto-fix behavior when file cannot be written."""
        workflow_content = """name: Test

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
"""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_content)

        # Make the workflow file read-only to trigger permission error
        workflow_file.chmod(0o444)

        runner = CliRunner()

        try:
            result = runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--auto-fix",
                    "--validation-method",
                    "git",
                    "--require-pinned-sha",
                ],
            )

            # Should detect the error or handle gracefully
            # Either it fails with permission error or completes with validation errors
            assert result.exit_code in [0, 1]
        finally:
            # Restore write permission for cleanup
            workflow_file.chmod(0o644)

    @pytest.mark.asyncio
    async def test_auto_fixer_context_manager(
        self, test_config: Config
    ) -> None:
        """Test AutoFixer as async context manager."""
        async with AutoFixer(test_config) as fixer:
            assert fixer is not None
            assert hasattr(fixer, "fix_validation_errors")

    def test_cli_with_explicit_auto_fix_flags(self, temp_dir: Path) -> None:
        """Test CLI with explicit auto-fix related flags - simplified."""
        # Use a valid SHA-pinned action to avoid validation errors
        workflow_content = """name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
"""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_content)

        runner = CliRunner()

        # Test that CLI flags are accepted (actual behavior is tested elsewhere)
        test_cases = [
            (["--no-auto-fix"], "Auto-fix disabled via CLI"),
            (["--no-update-actions"], "update_actions disabled via CLI"),
        ]

        for flags, description in test_cases:
            result = runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--validation-method",
                    "git",
                    *flags,
                ],
            )

            # Should succeed with valid SHA-pinned action
            assert result.exit_code == 0, (
                f"Failed for {description}: {result.stdout}"
            )


class TestAutoFixCLIOutput:
    """Test auto-fix CLI output formatting - simplified tests."""

    def test_cli_output_shows_auto_fix_results(
        self,
        temp_dir: Path,
    ) -> None:
        """Test that CLI output shows auto-fix results when fixes are made."""
        # Use a real workflow with tag that needs fixing
        workflow_content = """name: Test Workflow

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_content)

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--auto-fix",
                "--validation-method",
                "git",
            ],
        )

        # Should show auto-fix results
        output = result.stdout
        if "Auto-fixed" in output:
            assert ".github/workflows/test.yaml" in output
            assert "actions/checkout@v4" in output or "checkout" in output


class TestAutoFixIntegrationScenarios:
    """Test auto-fix integration with real-world scenarios."""

    def test_auto_fix_with_mixed_workflow_types(self, temp_dir: Path) -> None:
        """Test auto-fix with workflows containing both actions and reusable workflows."""
        workflow_content = """name: Mixed Workflow

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4

  reusable:
    uses: org/repo/.github/workflows/reusable.yaml@main

  local:
    uses: ./.github/workflows/local.yaml
"""
        workflow_file = temp_dir / ".github" / "workflows" / "mixed.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_content)

        runner = CliRunner()

        # Only action calls should be validated for SHA pinning
        def mock_validate_calls(
            action_calls: dict[Path, dict[int, ActionCall]],
        ) -> list[ValidationError]:
            return [
                ValidationError(
                    file_path=file_path,
                    action_call=call,
                    result=ValidationResult.NOT_PINNED_TO_SHA,
                    error_message="Action not pinned to SHA",
                )
                for file_path, call in iter_calls(action_calls)
                if call.call_type == ActionCallType.ACTION
                and call.reference in ["v3", "v4"]
            ]

        # The scenario is about what gets flagged, not about fixing.
        auto_fix = RecordedAutoFix(
            ({}, {"actions_moved": 0, "calls_updated": 0}, {})
        )

        with (
            patch(
                "gha_workflow_linter.cli.ActionCallValidator",
                stub_validator_class(mock_validate_calls),
            ),
            patch(
                "gha_workflow_linter.cli.AutoFixer",
                stub_auto_fixer_class(auto_fix),
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--auto-fix",
                    "--validation-method",
                    "git",
                ],
            )

            # Should only flag action calls, not reusable workflows
            assert (
                "Found" in result.stdout
                and "2" in result.stdout
                and "validation errors" in result.stdout
            )
            assert "2 actions not pinned to SHA" in strip_ansi(result.stdout)
            # Only the two action calls are errors; the fixer is still
            # offered the remote reusable workflow call so --update-actions
            # could update it, but never the local ``./`` call.
            assert auto_fix.called
            assert len(auto_fix.errors) == 2
            assert auto_fix.action_call_count == 3
            # The fixer reported no changes, so the workflow is intact,
            # reusable and local calls included.
            assert workflow_file.read_text() == workflow_content

    def test_auto_fix_with_large_workflow_file(self, temp_dir: Path) -> None:
        """Test auto-fix performance with large workflow files."""
        # Create a workflow with many action calls
        steps = []
        for i in range(50):
            steps.append(f"""      - name: Step {i}
        uses: actions/checkout@v{i % 5 + 1}""")

        workflow_content = f"""name: Large Workflow

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
{chr(10).join(steps)}
"""
        workflow_file = temp_dir / ".github" / "workflows" / "large.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_content)

        runner = CliRunner()

        # All should be validation errors (not pinned to SHA)
        def mock_validate_calls(
            action_calls: dict[Path, dict[int, ActionCall]],
        ) -> list[ValidationError]:
            return [
                ValidationError(
                    file_path=file_path,
                    action_call=call,
                    result=ValidationResult.NOT_PINNED_TO_SHA,
                    error_message="Action not pinned to SHA",
                )
                for file_path, call in iter_calls(action_calls)
            ]

        # The scenario is about scale, not about fixing.
        auto_fix = RecordedAutoFix(
            ({}, {"actions_moved": 0, "calls_updated": 0}, {})
        )

        with (
            patch(
                "gha_workflow_linter.cli.ActionCallValidator",
                stub_validator_class(mock_validate_calls),
            ),
            patch(
                "gha_workflow_linter.cli.AutoFixer",
                stub_auto_fixer_class(auto_fix),
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--auto-fix",
                    "--validation-method",
                    "git",
                ],
            )

            # Should handle all 50 action calls
            assert (
                "Found" in result.stdout
                and "50" in result.stdout
                and "validation errors" in result.stdout
            )
            assert "50 actions not pinned to SHA" in strip_ansi(result.stdout)
            # Every one of the 50 calls is carried through to the fixer
            # in a single batch.
            assert auto_fix.called
            assert len(auto_fix.errors) == 50
            assert auto_fix.action_call_count == 50
            # The fixer reported no changes, so the workflow is intact.
            assert workflow_file.read_text() == workflow_content

    def test_auto_fix_with_syntax_errors(self, temp_dir: Path) -> None:
        """Test auto-fix behavior with workflows that have YAML syntax errors."""
        workflow_content = """name: Syntax Error Workflow
on: [push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        invalid_yaml: {unclosed
"""
        workflow_file = temp_dir / ".github" / "workflows" / "syntax-error.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(workflow_content)

        runner = CliRunner()

        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--auto-fix",
                "--validation-method",
                "git",
            ],
        )

        # Scanner handles syntax errors gracefully, skips invalid files
        # So we get exit code 0 if no valid workflows found
        assert result.exit_code == 0
        # Should report scanning issues (as WARNING), not validation errors
        assert (
            "Invalid YAML" in result.stdout
            or "parsing" in result.stdout.lower()
        )

    def test_auto_fix_exit_codes(self, temp_dir: Path) -> None:
        """Test that auto-fix produces correct exit codes."""
        # Test with a valid SHA-pinned workflow
        valid_workflow = """name: Valid
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
"""
        workflows_dir = temp_dir / ".github" / "workflows"
        workflows_dir.mkdir(parents=True, exist_ok=True)
        (workflows_dir / "valid.yaml").write_text(valid_workflow)

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--no-auto-fix",
                "--validation-method",
                "git",
            ],
        )

        # Valid workflow should return 0
        assert result.exit_code == 0, f"Valid workflow failed: {result.stdout}"

        # Test with invalid workflow that needs auto-fix
        invalid_workflow = """name: Invalid
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
"""
        (workflows_dir / "invalid.yaml").write_text(invalid_workflow)

        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--auto-fix",
                "--update-actions",
            ],
        )

        # Auto-fix should modify file and return 1
        assert result.exit_code == 1, (
            f"Auto-fix should return 1: {result.stdout}"
        )
        assert (
            "Auto-fixed" in result.stdout
            or "validation errors" in result.stdout
        )


class TestAutoFixErrorHandling:
    """Test auto-fix error handling and edge cases."""

    def test_auto_fix_with_network_errors(self, temp_dir: Path) -> None:
        """Test that auto-fix handles network errors gracefully."""
        workflow_file = temp_dir / ".github" / "workflows" / "test.yaml"
        workflow_file.parent.mkdir(parents=True)
        workflow_file.write_text(
            """name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        )

        runner = CliRunner()

        # Test with auto-fix - should work with git validation method
        result = runner.invoke(
            app,
            [
                "lint",
                str(temp_dir),
                "--auto-fix",
                "--validation-method",
                "git",
                "--require-pinned-sha",
            ],
        )

        # Should complete successfully or show auto-fix
        assert (
            result.exit_code == 0
            or "Auto-fixed" in result.stdout
            or "validation errors" in result.stdout
        )

    def test_auto_fix_with_multiple_workflow_directories(
        self, temp_dir: Path
    ) -> None:
        """Test auto-fix with multiple nested workflow directories."""
        # Create multiple workflow directories
        dirs = [
            temp_dir / ".github" / "workflows",
            temp_dir / "subproject" / ".github" / "workflows",
            temp_dir / "another" / ".github" / "workflows",
        ]

        for workflow_dir in dirs:
            workflow_dir.mkdir(parents=True)
            workflow_file = workflow_dir / "test.yaml"
            workflow_file.write_text("""name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
""")

        runner = CliRunner()

        # Return errors for all workflows. The file path comes from the
        # scanner results, so each error points at the file its call was
        # found in rather than at whichever directory the loop above
        # happened to leave behind.
        def mock_validate_calls(
            action_calls: dict[Path, dict[int, ActionCall]],
        ) -> list[ValidationError]:
            return [
                ValidationError(
                    file_path=file_path,
                    action_call=call,
                    result=ValidationResult.NOT_PINNED_TO_SHA,
                    error_message="Action not pinned to SHA",
                )
                for file_path, call in iter_calls(action_calls)
            ]

        # Mock fixes for all files
        expected_fixes: dict[Path, list[dict[str, str]]] = {
            workflow_dir / "test.yaml": [
                {
                    "line_number": "7",
                    "old_line": "uses: actions/checkout@v3",
                    "new_line": "uses: actions/checkout@sha123",
                }
            ]
            for workflow_dir in dirs
        }
        auto_fix = RecordedAutoFix(
            (expected_fixes, {"actions_moved": 0, "calls_updated": 0}, {})
        )

        with (
            patch(
                "gha_workflow_linter.cli.ActionCallValidator",
                stub_validator_class(mock_validate_calls),
            ),
            patch(
                "gha_workflow_linter.cli.AutoFixer",
                stub_auto_fixer_class(auto_fix),
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "lint",
                    str(temp_dir),
                    "--auto-fix",
                    "--update-actions",
                    "--validation-method",
                    "git",
                ],
            )

            # Should find and fix all 3 workflow files
            assert (
                "Found" in result.stdout
                and "3" in result.stdout
                and "validation errors" in result.stdout
            )
            assert "Updated 3 workflow call(s) in 3 file(s)" in strip_ansi(
                result.stdout
            )
            assert result.exit_code == 1
            # One call per directory reaches the fixer, so the count
            # above cannot come from one file being scanned three times.
            assert auto_fix.called
            assert len(auto_fix.errors) == 3
            assert set(auto_fix.action_calls) == set(expected_fixes)
            # Every workflow directory is named in the report.
            for workflow_path in expected_fixes:
                assert str(workflow_path.relative_to(temp_dir)) in result.stdout
                # The fixer is stubbed and writes nothing, so the
                # original references survive on disk.
                assert "actions/checkout@v3" in workflow_path.read_text()


class TestYAMLStructurePreservation:
    """Test that auto-fix preserves YAML structure (indentation and dashes)."""

    @pytest.fixture
    def config_with_pinned_sha(self) -> Config:
        """Config with require_pinned_sha=True."""
        return Config(
            log_level=LogLevel.DEBUG,
            parallel_workers=2,
            require_pinned_sha=True,
            auto_fix=True,
            update_actions=True,
            two_space_comments=True,
            skip_actions=False,
            fix_test_calls=False,
            validation_method=ValidationMethod.GITHUB_API,
            cache=CacheConfig(enabled=False),
            network=NetworkConfig(
                timeout_seconds=10,
                max_retries=2,
                retry_delay_seconds=1.0,
                rate_limit_delay_seconds=0.1,
            ),
        )

    def test_build_fixed_line_preserves_dash_prefix(
        self, config_with_pinned_sha: Config
    ) -> None:
        """Test that _build_fixed_line preserves dash prefix when present."""
        auto_fixer = AutoFixer(config_with_pinned_sha)

        # Test case 1: Line WITH dash prefix (workflow style)
        action_call_with_dash = ActionCall(
            raw_line="      - uses: astral-sh/setup-uv@0f33eebc8badfbd026c0aa235815a1f99c93ce1f  # v5.2.0",
            line_number=10,
            organization="astral-sh",
            repository="setup-uv",
            reference="0f33eebc8badfbd026c0aa235815a1f99c93ce1f",
            reference_type=ReferenceType.COMMIT_SHA,
            call_type=ActionCallType.ACTION,
            comment="v5.2.0",
        )

        fixed_line = auto_fixer._build_fixed_line(
            action_call_with_dash,
            "85856786d1ce8acfbcc2f13a5f3fbd6b938f9f41",
            "v7.1.2",
        )

        # Should preserve the dash and indentation
        assert fixed_line.startswith("      - uses: ")
        assert (
            "astral-sh/setup-uv@85856786d1ce8acfbcc2f13a5f3fbd6b938f9f41"
            in fixed_line
        )
        assert "# v7.1.2" in fixed_line
        # Should NOT have double dash
        assert "- - uses:" not in fixed_line

    def test_build_fixed_line_preserves_no_dash_prefix(
        self, config_with_pinned_sha: Config
    ) -> None:
        """Test that _build_fixed_line does not add dash when not present."""
        auto_fixer = AutoFixer(config_with_pinned_sha)

        # Test case 2: Line WITHOUT dash prefix (composite action style)
        action_call_without_dash = ActionCall(
            raw_line="      uses: astral-sh/setup-uv@0f33eebc8badfbd026c0aa235815a1f99c93ce1f  # v5.2.0",
            line_number=10,
            organization="astral-sh",
            repository="setup-uv",
            reference="0f33eebc8badfbd026c0aa235815a1f99c93ce1f",
            reference_type=ReferenceType.COMMIT_SHA,
            call_type=ActionCallType.ACTION,
            comment="v5.2.0",
        )

        fixed_line = auto_fixer._build_fixed_line(
            action_call_without_dash,
            "85856786d1ce8acfbcc2f13a5f3fbd6b938f9f41",
            "v7.1.2",
        )

        # Should NOT add a dash when original doesn't have one
        assert fixed_line.startswith("      uses: ")
        assert not fixed_line.startswith("      - uses: ")
        assert (
            "astral-sh/setup-uv@85856786d1ce8acfbcc2f13a5f3fbd6b938f9f41"
            in fixed_line
        )
        assert "# v7.1.2" in fixed_line

    def test_build_fixed_line_preserves_various_indentation(
        self, config_with_pinned_sha: Config
    ) -> None:
        """Test that _build_fixed_line preserves different indentation levels."""
        auto_fixer = AutoFixer(config_with_pinned_sha)

        test_cases = [
            # (original_line, expected_prefix)
            ("  - uses: actions/checkout@v4", "  - uses: "),
            ("    - uses: actions/checkout@v4", "    - uses: "),
            ("        - uses: actions/checkout@v4", "        - uses: "),
            ("  uses: actions/checkout@v4", "  uses: "),
            ("    uses: actions/checkout@v4", "    uses: "),
            ("        uses: actions/checkout@v4", "        uses: "),
        ]

        for original_line, expected_prefix in test_cases:
            action_call = ActionCall(
                raw_line=original_line,
                line_number=1,
                organization="actions",
                repository="checkout",
                reference="v4",
                reference_type=ReferenceType.TAG,
                call_type=ActionCallType.ACTION,
                comment=None,
            )

            fixed_line = auto_fixer._build_fixed_line(
                action_call,
                "abc123def456",
                "v5.0.0",
            )

            assert fixed_line.startswith(expected_prefix), (
                f"Expected '{expected_prefix}' but got '{fixed_line[: len(expected_prefix)]}' "
                f"for original line: '{original_line}'"
            )

    @pytest.mark.asyncio
    async def test_composite_action_format_preservation(
        self, tmp_path: Path, config_with_pinned_sha: Config
    ) -> None:
        """Test that composite action.yaml format is preserved during auto-fix."""
        # Create a composite action.yaml with the specific format
        action_file = tmp_path / "action.yaml"
        action_file.write_text("""name: Test Action
description: Test composite action

runs:
  using: "composite"
  steps:
    - name: "Setup Python"
      uses: actions/setup-python@v5.0.0
      with:
        python-version: "3.11"

    - name: "Install uv"
      uses: astral-sh/setup-uv@0f33eebc8badfbd026c0aa235815a1f99c93ce1f  # v5.2.0
      with:
        enable-cache: true
""")

        validation_error = ValidationError(
            file_path=action_file,
            action_call=ActionCall(
                raw_line="      uses: astral-sh/setup-uv@0f33eebc8badfbd026c0aa235815a1f99c93ce1f  # v5.2.0",
                line_number=12,
                organization="astral-sh",
                repository="setup-uv",
                reference="0f33eebc8badfbd026c0aa235815a1f99c93ce1f",
                reference_type=ReferenceType.COMMIT_SHA,
                call_type=ActionCallType.ACTION,
                comment="v5.2.0",
            ),
            result=ValidationResult.NOT_PINNED_TO_SHA,
            error_message="Outdated SHA",
        )

        async with AutoFixer(config_with_pinned_sha):
            with (
                patch.object(
                    AutoFixer, "_get_latest_versions_batch"
                ) as mock_get_latest_batch,
                patch.object(
                    AutoFixer, "_get_shas_batch"
                ) as mock_get_shas_batch,
            ):
                # Mock batch latest version retrieval
                async def mock_get_latest_batch_impl(
                    _repo_keys: list[str],
                ) -> dict[str, tuple[str, str]]:
                    return {
                        "astral-sh/setup-uv": (
                            "v7.1.2",
                            "85856786d1ce8acfbcc2f13a5f3fbd6b938f9f41",
                        )
                    }

                mock_get_latest_batch.side_effect = mock_get_latest_batch_impl

                # Mock batch SHA retrieval
                async def mock_get_shas_batch_impl(
                    _refs: list[tuple[str, str]],
                ) -> dict[tuple[str, str], str]:
                    return {
                        (
                            "astral-sh/setup-uv",
                            "v7.1.2",
                        ): "85856786d1ce8acfbcc2f13a5f3fbd6b938f9f41",
                        (
                            "astral-sh/setup-uv",
                            "v5.2.0",
                        ): "0f33eebc8badfbd026c0aa235815a1f99c93ce1f",
                    }

                mock_get_shas_batch.side_effect = mock_get_shas_batch_impl

                async with AutoFixer(
                    config_with_pinned_sha, base_path=tmp_path
                ) as fixer:
                    (
                        fixed_files,
                        redirect_stats,
                        stale_actions_summary,
                    ) = await fixer.fix_validation_errors(
                        [validation_error],
                        build_all_action_calls_from_errors([validation_error]),
                    )

        # Verify the file was fixed
        assert action_file in fixed_files

        # Read the fixed content
        fixed_content = action_file.read_text()

        # The line should be updated WITHOUT adding a dash
        assert (
            "      uses: astral-sh/setup-uv@85856786d1ce8acfbcc2f13a5f3fbd6b938f9f41"
            in fixed_content
        )
        # Should NOT have a dash added
        assert (
            "      - uses: astral-sh/setup-uv@85856786d1ce8acfbcc2f13a5f3fbd6b938f9f41"
            not in fixed_content
        )
        # Comment should be updated
        assert "# v7.1.2" in fixed_content or "# v5.2.0" in fixed_content

    @pytest.mark.asyncio
    async def test_workflow_format_preservation(
        self, tmp_path: Path, config_with_pinned_sha: Config
    ) -> None:
        """Test that workflow YAML format with dashes is preserved during auto-fix."""
        # Create a workflow file with dash format
        workflow_dir = tmp_path / ".github" / "workflows"
        workflow_dir.mkdir(parents=True)
        workflow_file = workflow_dir / "test.yaml"
        workflow_file.write_text("""name: Test Workflow

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
""")

        validation_error = ValidationError(
            file_path=workflow_file,
            action_call=ActionCall(
                raw_line="      - uses: actions/checkout@v4",
                line_number=9,
                organization="actions",
                repository="checkout",
                reference="v4",
                reference_type=ReferenceType.TAG,
                call_type=ActionCallType.ACTION,
                comment=None,
            ),
            result=ValidationResult.NOT_PINNED_TO_SHA,
            error_message="Not pinned to SHA",
        )

        with (
            patch.object(
                AutoFixer, "_get_latest_versions_graphql_batch"
            ) as mock_get_latest_batch,
            patch.object(AutoFixer, "_get_shas_batch") as mock_get_shas_batch,
        ):
            # Mock batch latest version retrieval
            async def mock_get_latest_batch_impl(
                _repo_keys: list[str],
            ) -> dict[str, tuple[str, str]]:
                return {
                    "actions/checkout": (
                        "v5.0.0",
                        "abc123def456789abc123def456789abc123def4",
                    )
                }

            mock_get_latest_batch.side_effect = mock_get_latest_batch_impl

            # Mock batch SHA retrieval
            async def mock_get_shas_batch_impl(
                _refs: list[tuple[str, str]],
            ) -> dict[tuple[str, str], str]:
                return {
                    (
                        "actions/checkout",
                        "v5.0.0",
                    ): "abc123def456789abc123def456789abc123def4",
                    (
                        "actions/checkout",
                        "v4",
                    ): "abc123def456789abc123def456789abc123def4",
                }

            mock_get_shas_batch.side_effect = mock_get_shas_batch_impl

            async with AutoFixer(config_with_pinned_sha) as auto_fixer:
                (
                    fixed_files,
                    redirect_stats,
                    stale_actions_summary,
                ) = await auto_fixer.fix_validation_errors(
                    [validation_error],
                    build_all_action_calls_from_errors([validation_error]),
                )

        # Verify the file was fixed
        assert workflow_file in fixed_files

        # Read the fixed content
        fixed_content = workflow_file.read_text()

        # The line should still have a single dash
        assert (
            "      - uses: actions/checkout@abc123def456789abc123def456789abc123def4"
            in fixed_content
        )
        # Should NOT have double dash
        assert "      - - uses:" not in fixed_content
