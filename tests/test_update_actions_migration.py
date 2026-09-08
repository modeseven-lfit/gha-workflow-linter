# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for the --auto-latest to --update-actions migration.

``--auto-latest`` was renamed once a second updatable thing existed: with
both action pins and allow-list pins in play, "latest" no longer said
which. The old spelling keeps working so scripts and CI configurations do
not break, and these tests pin that promise from both directions -- the
old name still works, and the new one wins when both are given.
"""

from __future__ import annotations

from pathlib import Path  # noqa: TC003 - used at runtime by fixtures

import pytest
from typer.testing import CliRunner

from gha_workflow_linter.cli import _resolve_update_actions, app
from gha_workflow_linter.config import ConfigManager
from gha_workflow_linter.models import Config
from tests.conftest import strip_ansi


class TestFlagResolution:
    """--update-actions and the deprecated --auto-latest."""

    @pytest.mark.parametrize(
        ("update_actions", "auto_latest", "expected"),
        [
            (None, None, None),
            (True, None, True),
            (False, None, False),
            (None, True, True),
            (None, False, False),
            # Both given: the canonical flag wins, so adding the new name
            # to an existing invocation gets what it asked for.
            (True, False, True),
            (False, True, False),
        ],
    )
    def test_resolution(
        self,
        update_actions: bool | None,
        auto_latest: bool | None,
        expected: bool | None,
    ) -> None:
        assert _resolve_update_actions(update_actions, auto_latest) is expected

    def test_deprecated_flag_resolves_without_a_notice(self) -> None:
        """Resolution is pure; _warn_deprecated_check_flags reports.

        Notices used to come from here as well, which meant a caller
        writing --auto-latest was sent to --update-actions by one and
        onwards to --action-calls update by the next. One owner, one
        notice, naming the spelling actually used.
        """
        assert _resolve_update_actions(None, True) is True

    def test_the_notice_names_the_spelling_used(self, tmp_path: Path) -> None:
        """--auto-latest points straight at its replacement.

        Args:
            tmp_path: Scratch directory to lint.
        """
        result = CliRunner().invoke(
            app,
            ["lint", str(tmp_path), "--auto-latest", "--allow-list", "off"],
        )

        text = strip_ansi(result.output)
        assert "--auto-latest is deprecated" in text
        assert "--action-calls update" in text
        # The spelling that was never given must not appear as one.
        assert "--update-actions is deprecated" not in text

    def test_resolution_is_always_silent(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Both spellings, neither reporting: notices live elsewhere.

        Args:
            capsys: Captures anything this would wrongly emit.
        """
        _resolve_update_actions(True, None)
        _resolve_update_actions(None, True)

        assert capsys.readouterr().err == ""


class TestBothFlagsAreAccepted:
    """Neither spelling may be rejected by the argument parser."""

    @pytest.mark.parametrize(
        "flag",
        [
            "--update-actions",
            "--no-update-actions",
            "--auto-latest",
            "--no-auto-latest",
        ],
    )
    def test_flag_parses(self, flag: str, tmp_path: Path) -> None:
        from gha_workflow_linter.cli import app

        result = CliRunner().invoke(
            app, ["lint", str(tmp_path), flag, "--no-allow-list"]
        )

        assert "No such option" not in result.output

    def test_help_lists_both(self) -> None:
        from gha_workflow_linter.cli import app

        raw = CliRunner().invoke(app, ["lint", "--help"]).stdout
        text = strip_ansi(raw).lower()

        assert "update-actions" in text
        assert "auto-latest" in text
        assert "deprecated" in text


class TestConfigKeyMigration:
    """The config file key follows the same rules as the flag."""

    def test_new_key_loads(self, tmp_path: Path) -> None:
        target = tmp_path / "cfg.yaml"
        target.write_text("update_actions: true\n")

        assert ConfigManager().load_config(target).update_actions is True

    def test_deprecated_key_still_loads(self, tmp_path: Path) -> None:
        target = tmp_path / "cfg.yaml"
        target.write_text("auto_latest: true\n")

        assert ConfigManager().load_config(target).update_actions is True

    def test_deprecated_key_warns(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        target = tmp_path / "cfg.yaml"
        target.write_text("auto_latest: true\n")

        with caplog.at_level("WARNING"):
            ConfigManager().load_config(target)

        assert "auto_latest" in caplog.text
        assert "update_actions" in caplog.text

    def test_new_key_wins_when_both_present(self, tmp_path: Path) -> None:
        target = tmp_path / "cfg.yaml"
        target.write_text("auto_latest: true\nupdate_actions: false\n")

        assert ConfigManager().load_config(target).update_actions is False

    def test_new_key_does_not_warn(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        target = tmp_path / "cfg.yaml"
        target.write_text("update_actions: true\n")

        with caplog.at_level("WARNING"):
            ConfigManager().load_config(target)

        assert "deprecated" not in caplog.text

    def test_default_is_off(self) -> None:
        assert Config().update_actions is False

    def test_generated_template_uses_the_new_name(self, tmp_path: Path) -> None:
        """A freshly generated config must not teach the old spelling."""
        written = ConfigManager().save_default_config(tmp_path / "cfg.yaml")
        text = written.read_text()

        assert "update_actions:" in text
        assert "auto_latest:" not in text
