# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for cooldown-aware version selection in the auto-fixer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from typing import TYPE_CHECKING, Any

from gha_workflow_linter import cli
from gha_workflow_linter.auto_fix import (
    AutoFixer,
)
from gha_workflow_linter.models import Config
from gha_workflow_linter.version_utils import (
    _parse_iso_datetime,
    _select_version_with_cooldown,
)

if TYPE_CHECKING:
    from pathlib import Path

NOW = datetime(2026, 6, 12, tzinfo=timezone.utc)


def _days_ago(days: int) -> datetime:
    return NOW - timedelta(days=days)


def _iso_days_ago(days: int) -> str:
    return _days_ago(days).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_fixer(cooldown_days: int) -> AutoFixer:
    """Build an AutoFixer without running its heavyweight ``__init__``.

    The cooldown selection helpers only rely on ``config`` and ``logger``,
    so we bypass the cache priming and network client setup.
    """
    fixer = AutoFixer.__new__(AutoFixer)
    fixer.config = Config(cooldown_days=cooldown_days)
    fixer.logger = logging.getLogger("test.cooldown")
    return fixer


class TestParseIsoDatetime:
    """Tests for ISO-8601 timestamp parsing."""

    def test_parses_zulu_suffix(self) -> None:
        parsed = _parse_iso_datetime("2026-01-02T03:04:05Z")
        assert parsed == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    def test_parses_explicit_offset(self) -> None:
        parsed = _parse_iso_datetime("2026-01-02T03:04:05+00:00")
        assert parsed is not None
        assert parsed.tzinfo is not None

    def test_returns_none_for_empty(self) -> None:
        assert _parse_iso_datetime(None) is None
        assert _parse_iso_datetime("") is None

    def test_returns_none_for_garbage(self) -> None:
        assert _parse_iso_datetime("not-a-date") is None


class TestSelectVersionWithCooldown:
    """Tests for the cooldown selection algorithm."""

    def test_disabled_cooldown_returns_newest(self) -> None:
        candidates: list[tuple[str, str, datetime | None]] = [
            ("v3", "sha3", _days_ago(1)),
            ("v2", "sha2", _days_ago(30)),
        ]
        assert _select_version_with_cooldown(candidates, 0) == ("v3", "sha3")

    def test_negative_cooldown_returns_newest(self) -> None:
        candidates: list[tuple[str, str, datetime | None]] = [
            ("v3", "sha3", _days_ago(1))
        ]
        assert _select_version_with_cooldown(candidates, -5) == ("v3", "sha3")

    def test_skips_versions_inside_window(self) -> None:
        candidates: list[tuple[str, str, datetime | None]] = [
            ("v3", "sha3", _days_ago(2)),  # too new
            ("v2", "sha2", _days_ago(10)),  # eligible
            ("v1", "sha1", _days_ago(40)),
        ]
        assert _select_version_with_cooldown(candidates, 7, now=NOW) == (
            "v2",
            "sha2",
        )

    def test_newest_eligible_when_all_old(self) -> None:
        candidates: list[tuple[str, str, datetime | None]] = [
            ("v3", "sha3", _days_ago(8)),
            ("v2", "sha2", _days_ago(20)),
        ]
        assert _select_version_with_cooldown(candidates, 7, now=NOW) == (
            "v3",
            "sha3",
        )

    def test_boundary_exactly_at_cutoff_is_eligible(self) -> None:
        candidates: list[tuple[str, str, datetime | None]] = [
            ("v1", "sha1", _days_ago(7))
        ]
        assert _select_version_with_cooldown(candidates, 7, now=NOW) == (
            "v1",
            "sha1",
        )

    def test_returns_none_when_all_too_new(self) -> None:
        candidates: list[tuple[str, str, datetime | None]] = [
            ("v3", "sha3", _days_ago(1)),
            ("v2", "sha2", _days_ago(3)),
        ]
        assert _select_version_with_cooldown(candidates, 7, now=NOW) is None

    def test_skips_unknown_dates_under_cooldown(self) -> None:
        candidates: list[tuple[str, str, datetime | None]] = [
            ("v3", "sha3", None),  # unknown date, cannot verify
            ("v2", "sha2", _days_ago(30)),
        ]
        assert _select_version_with_cooldown(candidates, 7, now=NOW) == (
            "v2",
            "sha2",
        )

    def test_returns_none_for_empty(self) -> None:
        assert _select_version_with_cooldown([], 7) is None


class TestSelectCooldownVersionGraphql:
    """Tests for GraphQL cooldown selection wiring on the AutoFixer."""

    def test_skips_release_inside_window(self) -> None:
        fixer = _make_fixer(7)
        repo_data: dict[str, Any] = {
            "latestRelease": {
                "tagName": "v3",
                "publishedAt": _iso_days_ago(2),
                "tagCommit": {"oid": "sha3"},
            }
        }
        all_tags = [("v3", "sha3"), ("v2", "sha2")]
        tag_dates: dict[str, datetime | None] = {
            "v3": _days_ago(2),
            "v2": _days_ago(20),
        }
        assert fixer._select_cooldown_version_graphql(
            repo_data, all_tags, tag_dates, now=NOW
        ) == ("v2", "sha2")

    def test_selects_release_when_old_enough(self) -> None:
        fixer = _make_fixer(7)
        repo_data: dict[str, Any] = {
            "latestRelease": {
                "tagName": "v3",
                "publishedAt": _iso_days_ago(30),
                "tagCommit": {"oid": "sha3"},
            }
        }
        all_tags = [("v3", "sha3"), ("v2", "sha2")]
        tag_dates: dict[str, datetime | None] = {
            "v3": _days_ago(30),
            "v2": _days_ago(60),
        }
        assert fixer._select_cooldown_version_graphql(
            repo_data, all_tags, tag_dates, now=NOW
        ) == ("v3", "sha3")

    def test_prefers_more_specific_tag_for_sha(self) -> None:
        fixer = _make_fixer(7)
        repo_data: dict[str, Any] = {}
        # v8 and v8.0.0 point at the same commit; the more specific tag wins.
        all_tags = [("v8", "sha8"), ("v8.0.0", "sha8")]
        tag_dates: dict[str, datetime | None] = {
            "v8": _days_ago(30),
            "v8.0.0": _days_ago(30),
        }
        assert fixer._select_cooldown_version_graphql(
            repo_data, all_tags, tag_dates, now=NOW
        ) == ("v8.0.0", "sha8")

    def test_returns_none_when_no_tags(self) -> None:
        fixer = _make_fixer(7)
        assert (
            fixer._select_cooldown_version_graphql({}, [], {}, now=NOW) is None
        )


class TestResolveCooldownDays:
    """Tests for the CLI cooldown resolution precedence."""

    def test_explicit_flag_takes_precedence(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        # Even with a Dependabot config present, the explicit value wins.
        github_dir = tmp_path / ".github"
        github_dir.mkdir()
        (github_dir / "dependabot.yml").write_text(
            "version: 2\nupdates:\n  - package-ecosystem: github-actions\n"
            "    directory: /\n    cooldown:\n      default-days: 7\n",
            encoding="utf-8",
        )
        printed: list[str] = []
        monkeypatch.setattr(
            "gha_workflow_linter.cli.console.print",
            lambda *args, **kwargs: printed.append(str(args[0])),
        )
        result = cli._resolve_cooldown_days(
            3, tmp_path, quiet=False, output_format="text"
        )
        assert result == 3
        # No Dependabot message when the flag is explicit.
        assert printed == []

    def test_falls_back_to_dependabot(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        github_dir = tmp_path / ".github"
        github_dir.mkdir()
        (github_dir / "dependabot.yml").write_text(
            "version: 2\nupdates:\n  - package-ecosystem: github-actions\n"
            "    directory: /\n    cooldown:\n      default-days: 7\n",
            encoding="utf-8",
        )
        printed: list[str] = []
        monkeypatch.setattr(
            "gha_workflow_linter.cli.console.print",
            lambda *args, **kwargs: printed.append(str(args[0])),
        )
        result = cli._resolve_cooldown_days(
            None, tmp_path, quiet=False, output_format="text"
        )
        assert result == 7
        assert len(printed) == 1
        assert "[7]" in printed[0]
        assert "dependabot configuration" in printed[0]

    def test_defaults_to_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        printed: list[str] = []
        monkeypatch.setattr(
            "gha_workflow_linter.cli.console.print",
            lambda *args, **kwargs: printed.append(str(args[0])),
        )
        result = cli._resolve_cooldown_days(
            None, tmp_path, quiet=False, output_format="text"
        )
        assert result == 0
        assert printed == []

    def test_quiet_suppresses_message(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        github_dir = tmp_path / ".github"
        github_dir.mkdir()
        (github_dir / "dependabot.yml").write_text(
            "version: 2\nupdates:\n  - package-ecosystem: github-actions\n"
            "    directory: /\n    cooldown:\n      default-days: 7\n",
            encoding="utf-8",
        )
        printed: list[str] = []
        monkeypatch.setattr(
            "gha_workflow_linter.cli.console.print",
            lambda *args, **kwargs: printed.append(str(args[0])),
        )
        result = cli._resolve_cooldown_days(
            None, tmp_path, quiet=True, output_format="text"
        )
        assert result == 7
        assert printed == []
