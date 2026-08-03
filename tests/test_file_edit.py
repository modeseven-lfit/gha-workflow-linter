# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for atomic, terminator-preserving line replacement."""

from __future__ import annotations

import os
import stat
import tempfile
from typing import TYPE_CHECKING, Any, Literal

import pytest

from gha_workflow_linter.file_edit import LineChange, replace_lines

if TYPE_CHECKING:
    from pathlib import Path

UTF8_BOM = b"\xef\xbb\xbf"


def write_bytes(path: Path, name: str, content: bytes) -> Path:
    """Create ``name`` under ``path`` with exactly ``content``."""
    target = path / name
    target.write_bytes(content)
    return target


def directory_entries(path: Path) -> list[str]:
    """Return the sorted names of every entry in ``path``."""
    return sorted(entry.name for entry in path.iterdir())


class TestBasicReplacement:
    """Straightforward single and multi-line substitutions."""

    def test_replaces_a_single_line(self, tmp_path: Path) -> None:
        """Only the requested line changes."""
        target = write_bytes(tmp_path, "wf.yaml", b"one\ntwo\nthree\n")

        changes = replace_lines(target, {2: "TWO"})

        assert target.read_bytes() == b"one\nTWO\nthree\n"
        assert changes == [
            LineChange(line_number=2, old_line="two", new_line="TWO")
        ]

    def test_replaces_multiple_lines(self, tmp_path: Path) -> None:
        """Every requested line changes and the rest are untouched."""
        target = write_bytes(tmp_path, "wf.yaml", b"a\nb\nc\nd\n")

        changes = replace_lines(target, {1: "A", 3: "C"})

        assert target.read_bytes() == b"A\nb\nC\nd\n"
        assert [change.line_number for change in changes] == [1, 3]

    def test_replaces_first_and_last_line(self, tmp_path: Path) -> None:
        """The boundary line numbers are both valid."""
        target = write_bytes(tmp_path, "wf.yaml", b"first\nmiddle\nlast\n")

        replace_lines(target, {1: "FIRST", 3: "LAST"})

        assert target.read_bytes() == b"FIRST\nmiddle\nLAST\n"

    def test_replaces_the_only_line(self, tmp_path: Path) -> None:
        """A single-line file is handled like any other."""
        target = write_bytes(tmp_path, "wf.yaml", b"solo\n")

        replace_lines(target, {1: "SOLO"})

        assert target.read_bytes() == b"SOLO\n"

    def test_preserves_non_ascii_content(self, tmp_path: Path) -> None:
        """UTF-8 content round-trips through the rewrite."""
        original = "café\nnaïve\n".encode()
        target = write_bytes(tmp_path, "wf.yaml", original)

        changes = replace_lines(target, {1: "résumé"})

        assert target.read_bytes() == "résumé\nnaïve\n".encode()
        assert changes[0].old_line == "café"

    def test_replacement_may_be_empty(self, tmp_path: Path) -> None:
        """Blanking a line leaves its terminator in place."""
        target = write_bytes(tmp_path, "wf.yaml", b"one\ntwo\n")

        replace_lines(target, {1: ""})

        assert target.read_bytes() == b"\ntwo\n"

    def test_removes_its_temporary_file(self, tmp_path: Path) -> None:
        """A successful rewrite leaves no debris behind."""
        target = write_bytes(tmp_path, "wf.yaml", b"one\ntwo\n")

        replace_lines(target, {1: "ONE"})

        assert directory_entries(tmp_path) == ["wf.yaml"]


class TestLineEndings:
    """Each line keeps the terminator it started with."""

    def test_lf_file_stays_lf(self, tmp_path: Path) -> None:
        """A pure LF file is not converted."""
        target = write_bytes(tmp_path, "wf.yaml", b"one\ntwo\nthree\n")

        replace_lines(target, {2: "TWO"})

        assert target.read_bytes() == b"one\nTWO\nthree\n"

    def test_crlf_file_stays_crlf(self, tmp_path: Path) -> None:
        """A pure CRLF file is not silently normalised to LF."""
        target = write_bytes(tmp_path, "wf.yaml", b"one\r\ntwo\r\nthree\r\n")

        changes = replace_lines(target, {2: "TWO"})

        assert target.read_bytes() == b"one\r\nTWO\r\nthree\r\n"
        assert changes[0].old_line == "two"

    def test_cr_only_file_stays_cr_only(self, tmp_path: Path) -> None:
        """Classic Mac line endings survive too."""
        target = write_bytes(tmp_path, "wf.yaml", b"one\rtwo\rthree\r")

        replace_lines(target, {2: "TWO"})

        assert target.read_bytes() == b"one\rTWO\rthree\r"

    def test_mixed_endings_are_preserved_per_line(self, tmp_path: Path) -> None:
        """Every line keeps its own terminator, not the file's first."""
        target = write_bytes(tmp_path, "wf.yaml", b"crlf\r\nlf\ncr\rnone")

        changes = replace_lines(
            target, {1: "CRLF", 2: "LF", 3: "CR", 4: "NONE"}
        )

        assert target.read_bytes() == b"CRLF\r\nLF\nCR\rNONE"
        assert [change.old_line for change in changes] == [
            "crlf",
            "lf",
            "cr",
            "none",
        ]

    def test_untouched_lines_keep_their_endings(self, tmp_path: Path) -> None:
        """Lines outside the replacement set are byte-identical."""
        target = write_bytes(tmp_path, "wf.yaml", b"keep\r\nchange\nkeep\r")

        replace_lines(target, {2: "CHANGED"})

        assert target.read_bytes() == b"keep\r\nCHANGED\nkeep\r"


class TestTrailingNewline:
    """The file's trailing-newline state is never altered."""

    def test_missing_final_newline_is_not_added(self, tmp_path: Path) -> None:
        """Replacing the unterminated last line does not terminate it."""
        target = write_bytes(tmp_path, "wf.yaml", b"one\ntwo")

        changes = replace_lines(target, {2: "TWO"})

        assert target.read_bytes() == b"one\nTWO"
        assert changes[0].old_line == "two"

    def test_missing_final_newline_survives_earlier_edit(
        self, tmp_path: Path
    ) -> None:
        """Editing an earlier line does not terminate the last one."""
        target = write_bytes(tmp_path, "wf.yaml", b"one\ntwo")

        replace_lines(target, {1: "ONE"})

        assert target.read_bytes() == b"ONE\ntwo"

    def test_trailing_newline_is_kept(self, tmp_path: Path) -> None:
        """A terminated last line stays terminated."""
        target = write_bytes(tmp_path, "wf.yaml", b"one\ntwo\n")

        replace_lines(target, {2: "TWO"})

        assert target.read_bytes() == b"one\nTWO\n"

    def test_trailing_crlf_is_kept(self, tmp_path: Path) -> None:
        """A terminated last CRLF line keeps its full terminator."""
        target = write_bytes(tmp_path, "wf.yaml", b"one\r\ntwo\r\n")

        replace_lines(target, {2: "TWO"})

        assert target.read_bytes() == b"one\r\nTWO\r\n"

    def test_single_line_without_newline(self, tmp_path: Path) -> None:
        """A one-line, unterminated file gains nothing."""
        target = write_bytes(tmp_path, "wf.yaml", b"solo")

        replace_lines(target, {1: "SOLO"})

        assert target.read_bytes() == b"SOLO"


class TestByteOrderMark:
    """A UTF-8 BOM is preserved and never introduced."""

    def test_bom_is_preserved(self, tmp_path: Path) -> None:
        """The BOM is written back exactly once, at the start."""
        target = write_bytes(tmp_path, "wf.yaml", UTF8_BOM + b"one\ntwo\n")

        replace_lines(target, {2: "TWO"})

        assert target.read_bytes() == UTF8_BOM + b"one\nTWO\n"

    def test_bom_is_excluded_from_reported_content(
        self, tmp_path: Path
    ) -> None:
        """The BOM is not leaked into the first line's content."""
        target = write_bytes(tmp_path, "wf.yaml", UTF8_BOM + b"one\ntwo\n")

        changes = replace_lines(target, {1: "ONE"})

        assert changes[0].old_line == "one"
        assert target.read_bytes() == UTF8_BOM + b"ONE\ntwo\n"

    def test_bom_is_not_introduced(self, tmp_path: Path) -> None:
        """A file without a BOM does not acquire one."""
        target = write_bytes(tmp_path, "wf.yaml", b"one\ntwo\n")

        replace_lines(target, {1: "ONE"})

        assert not target.read_bytes().startswith(UTF8_BOM)


class TestValidation:
    """Invalid input is rejected before the file is rewritten."""

    @pytest.mark.parametrize("line_number", [0, -1, -100, 4, 99])
    def test_out_of_range_line_number_raises(
        self, tmp_path: Path, line_number: int
    ) -> None:
        """Line numbers outside ``1..len(lines)`` are refused."""
        original = b"one\ntwo\nthree\n"
        target = write_bytes(tmp_path, "wf.yaml", original)

        with pytest.raises(ValueError, match="out of range"):
            replace_lines(target, {line_number: "NOPE"})

        assert target.read_bytes() == original

    def test_out_of_range_rejects_the_whole_batch(self, tmp_path: Path) -> None:
        """One bad line number prevents every replacement."""
        original = b"one\ntwo\n"
        target = write_bytes(tmp_path, "wf.yaml", original)

        with pytest.raises(ValueError, match="out of range"):
            replace_lines(target, {1: "ONE", 5: "FIVE"})

        assert target.read_bytes() == original

    def test_any_line_number_raises_for_empty_file(
        self, tmp_path: Path
    ) -> None:
        """An empty file has no lines to replace."""
        target = write_bytes(tmp_path, "wf.yaml", b"")

        with pytest.raises(ValueError, match="0 line"):
            replace_lines(target, {1: "ONE"})

    @pytest.mark.parametrize(
        "replacement",
        ["a\nb", "trailing\n", "\ncarriage", "a\r\nb", "a\rb"],
    )
    def test_embedded_newline_raises(
        self, tmp_path: Path, replacement: str
    ) -> None:
        """A replacement must be exactly one line."""
        original = b"one\ntwo\n"
        target = write_bytes(tmp_path, "wf.yaml", original)

        with pytest.raises(ValueError, match="embedded line terminator"):
            replace_lines(target, {1: replacement})

        assert target.read_bytes() == original

    def test_embedded_newline_reports_the_line_number(
        self, tmp_path: Path
    ) -> None:
        """The error identifies the offending replacement."""
        target = write_bytes(tmp_path, "wf.yaml", b"one\ntwo\n")

        with pytest.raises(ValueError, match="line 2"):
            replace_lines(target, {2: "bad\nvalue"})

    def test_missing_file_raises_os_error(self, tmp_path: Path) -> None:
        """A nonexistent path surfaces the underlying OS error."""
        with pytest.raises(OSError):
            replace_lines(tmp_path / "absent.yaml", {1: "ONE"})


class TestEmptyReplacements:
    """An empty mapping is a legal no-op."""

    def test_returns_empty_list(self, tmp_path: Path) -> None:
        """Nothing to do means nothing reported."""
        target = write_bytes(tmp_path, "wf.yaml", b"one\ntwo\n")

        assert replace_lines(target, {}) == []

    def test_does_not_touch_the_file(self, tmp_path: Path) -> None:
        """Content and mtime are both left alone."""
        target = write_bytes(tmp_path, "wf.yaml", b"one\ntwo\n")
        before = target.stat()

        replace_lines(target, {})

        after = target.stat()
        assert target.read_bytes() == b"one\ntwo\n"
        assert after.st_mtime_ns == before.st_mtime_ns
        assert directory_entries(tmp_path) == ["wf.yaml"]

    def test_does_not_require_the_file_to_exist(self, tmp_path: Path) -> None:
        """The no-op short-circuits before any I/O."""
        assert replace_lines(tmp_path / "absent.yaml", {}) == []


class PartialWriter:
    """Handle wrapper that fails midway through ``writelines``."""

    def __init__(self, handle: Any) -> None:
        self._handle = handle

    def __enter__(self) -> PartialWriter:
        return self

    def __exit__(self, *exc_info: object) -> Literal[False]:
        self._handle.close()
        return False

    def writelines(self, lines: list[str]) -> None:
        """Write the first line only, then fail as a full disk would."""
        for line in lines[:1]:
            self._handle.write(line)
        raise OSError("simulated disk full")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._handle, name)


class TestAtomicity:
    """Failures leave the original intact and no debris behind."""

    @pytest.fixture
    def target(self, tmp_path: Path) -> Path:
        """A small workflow file used by the failure-injection tests."""
        return write_bytes(tmp_path, "wf.yaml", b"one\ntwo\nthree\n")

    def test_partial_write_leaves_original_unchanged(
        self,
        tmp_path: Path,
        target: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A crash mid-write never truncates the user's file."""
        real_fdopen = os.fdopen
        calls = {"count": 0}

        def failing_fdopen(*args: Any, **kwargs: Any) -> Any:
            calls["count"] += 1
            handle = real_fdopen(*args, **kwargs)
            if calls["count"] > 1:
                return handle
            return PartialWriter(handle)

        monkeypatch.setattr(os, "fdopen", failing_fdopen)

        with pytest.raises(OSError, match="simulated disk full"):
            replace_lines(target, {2: "TWO"})

        assert target.read_bytes() == b"one\ntwo\nthree\n"
        assert directory_entries(tmp_path) == ["wf.yaml"]

    def test_failed_rename_leaves_original_unchanged(
        self,
        tmp_path: Path,
        target: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A failed publish step is cleaned up completely."""

        def failing_replace(*_args: Any, **_kwargs: Any) -> None:
            raise OSError("simulated rename failure")

        monkeypatch.setattr(os, "replace", failing_replace)

        with pytest.raises(OSError, match="simulated rename failure"):
            replace_lines(target, {2: "TWO"})

        assert target.read_bytes() == b"one\ntwo\nthree\n"
        assert directory_entries(tmp_path) == ["wf.yaml"]

    def test_cleanup_failure_does_not_mask_the_error(
        self,
        target: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The original error propagates even if cleanup fails."""

        def failing_replace(*_args: Any, **_kwargs: Any) -> None:
            raise OSError("simulated rename failure")

        def failing_unlink(*_args: Any, **_kwargs: Any) -> None:
            raise OSError("simulated unlink failure")

        monkeypatch.setattr(os, "replace", failing_replace)
        monkeypatch.setattr(os, "unlink", failing_unlink)

        with pytest.raises(OSError, match="simulated rename failure"):
            replace_lines(target, {2: "TWO"})

        assert target.read_bytes() == b"one\ntwo\nthree\n"

    def test_temporary_file_is_created_beside_the_original(
        self,
        tmp_path: Path,
        target: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``os.replace`` must not cross a filesystem boundary."""
        observed: list[str] = []
        real_mkstemp = tempfile.mkstemp

        def recording_mkstemp(*args: Any, **kwargs: Any) -> Any:
            observed.append(str(kwargs["dir"]))
            return real_mkstemp(*args, **kwargs)

        monkeypatch.setattr(tempfile, "mkstemp", recording_mkstemp)

        replace_lines(target, {1: "ONE"})

        assert observed == [str(tmp_path)]


class TestPermissions:
    """The original file mode survives the rename."""

    @pytest.mark.parametrize("mode", [0o600, 0o644, 0o664])
    def test_mode_is_preserved(self, tmp_path: Path, mode: int) -> None:
        """A rewritten file keeps the permissions it had."""
        target = write_bytes(tmp_path, "wf.yaml", b"one\ntwo\n")
        target.chmod(mode)

        replace_lines(target, {1: "ONE"})

        assert stat.S_IMODE(target.stat().st_mode) == mode

    def test_executable_bit_is_preserved(self, tmp_path: Path) -> None:
        """Even unusual modes are copied onto the replacement."""
        target = write_bytes(tmp_path, "script.sh", b"#!/bin/sh\nexit 0\n")
        target.chmod(0o755)

        replace_lines(target, {2: "exit 1"})

        assert stat.S_IMODE(target.stat().st_mode) == 0o755
        assert target.read_bytes() == b"#!/bin/sh\nexit 1\n"


class TestReturnedChanges:
    """The reported changes describe exactly what happened."""

    def test_changes_are_sorted_by_line_number(self, tmp_path: Path) -> None:
        """Ordering does not depend on the mapping's insertion order."""
        target = write_bytes(tmp_path, "wf.yaml", b"a\nb\nc\nd\ne\n")

        changes = replace_lines(target, {5: "E", 1: "A", 3: "C"})

        assert [change.line_number for change in changes] == [1, 3, 5]

    def test_changes_describe_old_and_new_content(self, tmp_path: Path) -> None:
        """Terminators are excluded from both sides of the change."""
        target = write_bytes(tmp_path, "wf.yaml", b"a\r\nb\r\n")

        changes = replace_lines(target, {1: "A", 2: "B"})

        assert changes == [
            LineChange(line_number=1, old_line="a", new_line="A"),
            LineChange(line_number=2, old_line="b", new_line="B"),
        ]

    def test_unchanged_content_is_still_reported(self, tmp_path: Path) -> None:
        """A no-op replacement still yields a ``LineChange``."""
        target = write_bytes(tmp_path, "wf.yaml", b"same\nother\n")

        changes = replace_lines(target, {1: "same"})

        assert changes == [
            LineChange(line_number=1, old_line="same", new_line="same")
        ]
        assert target.read_bytes() == b"same\nother\n"

    def test_change_count_matches_replacement_count(
        self, tmp_path: Path
    ) -> None:
        """One change is reported per requested line."""
        target = write_bytes(tmp_path, "wf.yaml", b"a\nb\nc\n")

        changes = replace_lines(target, {1: "A", 2: "B", 3: "C"})

        assert len(changes) == 3

    def test_line_change_is_frozen(self) -> None:
        """``LineChange`` instances are immutable value objects."""
        change = LineChange(line_number=1, old_line="a", new_line="A")

        with pytest.raises(AttributeError):
            change.line_number = 2  # type: ignore[misc]
