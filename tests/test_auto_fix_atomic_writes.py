# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Byte-level regression tests for auto-fix file rewriting.

``AutoFixer._apply_fixes_to_file`` used to read a workflow file with
``readlines()``, mutate a few entries, and write the result back over the
same path. That approach truncated the original before the replacement
was durable, discarded CRLF line endings via universal newlines, and
appended an unconditional ``"\\n"`` to every rewritten line.

These tests drive the method against real files under ``tmp_path`` and
assert on ``read_bytes()``, so they pin the byte-for-byte behaviour the
migration onto :func:`~gha_workflow_linter.file_edit.replace_lines`
guarantees rather than the text the linter happens to render.
"""

from __future__ import annotations

import builtins
import os
import stat
from typing import TYPE_CHECKING, Any, Literal

import pytest

from gha_workflow_linter.auto_fix import AutoFixer
from gha_workflow_linter.models import Config

if TYPE_CHECKING:
    from pathlib import Path

UTF8_BOM = b"\xef\xbb\xbf"

CHECKOUT_OLD = (
    "      - uses: actions/checkout@v4"  # unpinned, the thing being fixed
)
CHECKOUT_NEW = (
    "      - uses: actions/checkout@"
    "08c6903cd8c0fde910a37f88322edcfb5dd907a8  # v4.0.0"
)


@pytest.fixture
def fixer() -> AutoFixer:
    """An auto-fixer built for direct, offline use of the file rewriter."""
    return AutoFixer(Config())


def write_bytes(path: Path, name: str, content: bytes) -> Path:
    """Create ``name`` under ``path`` containing exactly ``content``.

    Args:
        path: Directory to create the file in.
        name: File name.
        content: Exact bytes to write.

    Returns:
        Path to the newly created file.
    """
    target = path / name
    target.write_bytes(content)
    return target


def directory_entries(path: Path) -> list[str]:
    """Return the sorted names of every entry in ``path``.

    Args:
        path: Directory to list.

    Returns:
        Sorted entry names, including any temporary-file debris.
    """
    return sorted(entry.name for entry in path.iterdir())


class PartialWriter:
    """Handle wrapper that fails midway through ``writelines``."""

    def __init__(self, handle: Any) -> None:
        """Wrap ``handle`` so writes stop after the first line.

        Args:
            handle: Real file object to delegate to.
        """
        self._handle = handle

    def __enter__(self) -> PartialWriter:
        """Return self so the wrapper works as a context manager.

        Returns:
            This wrapper.
        """
        return self

    def __exit__(self, *exc_info: object) -> Literal[False]:
        """Close the wrapped handle and let the exception propagate.

        Args:
            *exc_info: Standard exception triple, unused.

        Returns:
            ``False``, so any in-flight exception is not suppressed.
        """
        self._handle.close()
        return False

    def writelines(self, lines: list[str]) -> None:
        """Write the first line only, then fail as a full disk would.

        Args:
            lines: Complete file content to write.

        Raises:
            OSError: Always, after a deliberately partial write.
        """
        for line in lines[:1]:
            self._handle.write(line)
        raise OSError("simulated disk full")

    def __getattr__(self, name: str) -> Any:
        """Delegate every other attribute to the wrapped handle.

        Args:
            name: Attribute being looked up.

        Returns:
            The corresponding attribute of the wrapped handle.
        """
        return getattr(self._handle, name)


def _is_write_mode(args: tuple[Any, ...], kwargs: dict[str, Any]) -> bool:
    """Report whether an ``open``-style call requests write access.

    Args:
        args: Positional arguments the call was made with.
        kwargs: Keyword arguments the call was made with.

    Returns:
        ``True`` if the mode grants write access, ``False`` otherwise.
    """
    mode = kwargs.get("mode", args[1] if len(args) > 1 else "r")
    return any(flag in str(mode) for flag in ("w", "a", "+", "x"))


def install_failing_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every writable file handle fail after one line.

    A rewrite obtains its writable handle either from ``open(path, "w")``
    -- as the historical in-place implementation did -- or from
    :func:`os.fdopen` on a temporary file, as the atomic implementation
    does. Wrapping both means the injected failure does not presuppose
    which strategy is in use, so this test genuinely distinguishes a
    truncating write from an atomic one. Read-mode handles are left
    alone.

    Args:
        monkeypatch: Fixture used to install and later undo the patches.
    """
    real_open = builtins.open
    real_fdopen = os.fdopen

    def failing_open(*args: Any, **kwargs: Any) -> Any:
        handle = real_open(*args, **kwargs)
        if _is_write_mode(args, kwargs):
            return PartialWriter(handle)
        return handle

    def failing_fdopen(*args: Any, **kwargs: Any) -> Any:
        handle = real_fdopen(*args, **kwargs)
        if _is_write_mode(args, kwargs):
            return PartialWriter(handle)
        return handle

    monkeypatch.setattr(builtins, "open", failing_open)
    monkeypatch.setattr(os, "fdopen", failing_fdopen)


class TestLineEndings:
    """Rewrites keep each line's original terminator."""

    @pytest.mark.asyncio
    async def test_crlf_file_stays_crlf(
        self, fixer: AutoFixer, tmp_path: Path
    ) -> None:
        """Fixing one line does not convert a CRLF file to LF."""
        target = write_bytes(
            tmp_path,
            "workflow.yaml",
            b"steps:\r\n" + CHECKOUT_OLD.encode() + b"\r\n" + b"  end\r\n",
        )

        await fixer._apply_fixes_to_file(
            target, {2: (CHECKOUT_OLD, CHECKOUT_NEW)}
        )

        assert target.read_bytes() == (
            b"steps:\r\n" + CHECKOUT_NEW.encode() + b"\r\n" + b"  end\r\n"
        )

    @pytest.mark.asyncio
    async def test_mixed_line_endings_survive(
        self, fixer: AutoFixer, tmp_path: Path
    ) -> None:
        """Each line keeps whichever terminator it already had."""
        target = write_bytes(
            tmp_path,
            "workflow.yaml",
            b"lf\ncrlf\r\ncr\rlast\n",
        )

        await fixer._apply_fixes_to_file(target, {2: ("crlf", "CRLF")})

        assert target.read_bytes() == b"lf\nCRLF\r\ncr\rlast\n"

    @pytest.mark.asyncio
    async def test_cr_only_line_keeps_its_terminator(
        self, fixer: AutoFixer, tmp_path: Path
    ) -> None:
        """A classic-Mac terminator is not rewritten to LF."""
        target = write_bytes(tmp_path, "workflow.yaml", b"one\rtwo\r")

        await fixer._apply_fixes_to_file(target, {1: ("one", "ONE")})

        assert target.read_bytes() == b"ONE\rtwo\r"


class TestTrailingNewline:
    """A missing final newline is never invented."""

    @pytest.mark.asyncio
    async def test_missing_final_newline_is_not_added(
        self, fixer: AutoFixer, tmp_path: Path
    ) -> None:
        """Fixing the last line of a file without one adds nothing."""
        target = write_bytes(
            tmp_path,
            "workflow.yaml",
            b"steps:\n" + CHECKOUT_OLD.encode(),
        )

        await fixer._apply_fixes_to_file(
            target, {2: (CHECKOUT_OLD, CHECKOUT_NEW)}
        )

        assert target.read_bytes() == b"steps:\n" + CHECKOUT_NEW.encode()

    @pytest.mark.asyncio
    async def test_existing_final_newline_is_kept(
        self, fixer: AutoFixer, tmp_path: Path
    ) -> None:
        """A file that ends with a newline still does afterwards."""
        target = write_bytes(
            tmp_path,
            "workflow.yaml",
            b"steps:\n" + CHECKOUT_OLD.encode() + b"\n",
        )

        await fixer._apply_fixes_to_file(
            target, {2: (CHECKOUT_OLD, CHECKOUT_NEW)}
        )

        assert target.read_bytes() == (
            b"steps:\n" + CHECKOUT_NEW.encode() + b"\n"
        )


class TestAtomicity:
    """A failed rewrite leaves the original file untouched."""

    @pytest.mark.asyncio
    async def test_failed_write_leaves_file_byte_identical(
        self,
        fixer: AutoFixer,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A full disk mid-write must not corrupt the workflow."""
        original = b"steps:\n" + CHECKOUT_OLD.encode() + b"\n  end\n"
        target = write_bytes(tmp_path, "workflow.yaml", original)
        install_failing_writes(monkeypatch)

        with pytest.raises(OSError, match="simulated disk full"):
            await fixer._apply_fixes_to_file(
                target, {2: (CHECKOUT_OLD, CHECKOUT_NEW)}
            )

        assert target.read_bytes() == original
        assert directory_entries(tmp_path) == ["workflow.yaml"]

    @pytest.mark.asyncio
    async def test_failed_rename_leaves_file_byte_identical(
        self,
        fixer: AutoFixer,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A failure to publish is cleaned up completely."""
        original = b"steps:\n" + CHECKOUT_OLD.encode() + b"\n"
        target = write_bytes(tmp_path, "workflow.yaml", original)

        def failing_replace(*_args: Any, **_kwargs: Any) -> None:
            raise OSError("simulated rename failure")

        monkeypatch.setattr(os, "replace", failing_replace)

        with pytest.raises(OSError, match="simulated rename failure"):
            await fixer._apply_fixes_to_file(
                target, {2: (CHECKOUT_OLD, CHECKOUT_NEW)}
            )

        assert target.read_bytes() == original
        assert directory_entries(tmp_path) == ["workflow.yaml"]


class TestFileProperties:
    """Encoding markers and permissions round-trip unchanged."""

    @pytest.mark.asyncio
    async def test_utf8_bom_survives(
        self, fixer: AutoFixer, tmp_path: Path
    ) -> None:
        """A byte order mark is neither stripped nor duplicated."""
        target = write_bytes(
            tmp_path,
            "workflow.yaml",
            UTF8_BOM + b"steps:\n" + CHECKOUT_OLD.encode() + b"\n",
        )

        changes = await fixer._apply_fixes_to_file(
            target, {2: (CHECKOUT_OLD, CHECKOUT_NEW)}
        )

        assert target.read_bytes() == (
            UTF8_BOM + b"steps:\n" + CHECKOUT_NEW.encode() + b"\n"
        )
        assert changes[0]["old_line"] == CHECKOUT_OLD

    @pytest.mark.asyncio
    async def test_file_permissions_survive(
        self, fixer: AutoFixer, tmp_path: Path
    ) -> None:
        """The rewritten file keeps the original's mode bits."""
        target = write_bytes(tmp_path, "workflow.yaml", b"one\ntwo\n")
        target.chmod(0o600)

        await fixer._apply_fixes_to_file(target, {1: ("one", "ONE")})

        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert target.read_bytes() == b"ONE\ntwo\n"

    @pytest.mark.asyncio
    async def test_non_ascii_content_round_trips(
        self, fixer: AutoFixer, tmp_path: Path
    ) -> None:
        """UTF-8 content elsewhere in the file is not mangled."""
        original = "# naïve\nold\n".encode()
        target = write_bytes(tmp_path, "workflow.yaml", original)

        await fixer._apply_fixes_to_file(target, {2: ("old", "néw")})

        assert target.read_bytes() == "# naïve\nnéw\n".encode()


class TestReturnedChanges:
    """The reported changes match what landed on disk."""

    @pytest.mark.asyncio
    async def test_multiple_lines_in_one_call(
        self, fixer: AutoFixer, tmp_path: Path
    ) -> None:
        """Every requested line is rewritten and reported once."""
        target = write_bytes(tmp_path, "workflow.yaml", b"a\nb\nc\nd\n")

        changes = await fixer._apply_fixes_to_file(
            target, {3: ("c", "C"), 1: ("a", "A")}
        )

        assert target.read_bytes() == b"A\nb\nC\nd\n"
        assert changes == [
            {"line_number": "1", "old_line": "a", "new_line": "A"},
            {"line_number": "3", "old_line": "c", "new_line": "C"},
        ]

    @pytest.mark.asyncio
    async def test_old_line_reflects_disk_content(
        self, fixer: AutoFixer, tmp_path: Path
    ) -> None:
        """A stale caller-supplied ``old_line`` cannot skew the diff."""
        target = write_bytes(tmp_path, "workflow.yaml", b"actual\nsecond\n")

        changes = await fixer._apply_fixes_to_file(
            target, {1: ("stale expectation", "fixed")}
        )

        assert changes == [
            {"line_number": "1", "old_line": "actual", "new_line": "fixed"}
        ]

    @pytest.mark.asyncio
    async def test_old_line_excludes_the_terminator(
        self, fixer: AutoFixer, tmp_path: Path
    ) -> None:
        """Reported content never carries a stray ``\\r`` or ``\\n``."""
        target = write_bytes(tmp_path, "workflow.yaml", b"one\r\ntwo\r\n")

        changes = await fixer._apply_fixes_to_file(target, {1: ("one", "ONE")})

        assert changes[0]["old_line"] == "one"
        assert changes[0]["new_line"] == "ONE"

    @pytest.mark.asyncio
    async def test_untouched_lines_are_byte_identical(
        self, fixer: AutoFixer, tmp_path: Path
    ) -> None:
        """Only the targeted line differs from the original bytes."""
        original = (
            b"---\n"
            # REUSE-IgnoreStart
            b"# SPDX-License-Identifier: Apache-2.0\r\n"
            # REUSE-IgnoreEnd
            b"jobs:\n"
            + CHECKOUT_OLD.encode()
            + b"\r\n"
            + b"  trailing\twhitespace   \n"
        )
        target = write_bytes(tmp_path, "workflow.yaml", original)

        await fixer._apply_fixes_to_file(
            target, {4: (CHECKOUT_OLD, CHECKOUT_NEW)}
        )

        rewritten = target.read_bytes()
        assert rewritten.split(b"\n")[0] == original.split(b"\n")[0]
        # REUSE-IgnoreStart
        assert b"# SPDX-License-Identifier: Apache-2.0\r\n" in rewritten
        # REUSE-IgnoreEnd
        assert rewritten.endswith(b"  trailing\twhitespace   \n")
        assert CHECKOUT_NEW.encode() + b"\r\n" in rewritten


class TestNoOpAndErrors:
    """Edge cases around empty and invalid fix mappings."""

    @pytest.mark.asyncio
    async def test_empty_fixes_do_not_touch_the_file(
        self, fixer: AutoFixer, tmp_path: Path
    ) -> None:
        """No fixes means no write, and no modification-time change."""
        original = b"steps:\n" + CHECKOUT_OLD.encode() + b"\n"
        target = write_bytes(tmp_path, "workflow.yaml", original)
        os.utime(target, (1_000_000, 1_000_000))
        before = target.stat().st_mtime_ns

        changes = await fixer._apply_fixes_to_file(target, {})

        assert changes == []
        assert target.read_bytes() == original
        assert target.stat().st_mtime_ns == before
        assert directory_entries(tmp_path) == ["workflow.yaml"]

    @pytest.mark.asyncio
    async def test_out_of_range_line_leaves_file_unchanged(
        self, fixer: AutoFixer, tmp_path: Path
    ) -> None:
        """An impossible line number aborts the whole rewrite."""
        original = b"one\ntwo\n"
        target = write_bytes(tmp_path, "workflow.yaml", original)

        with pytest.raises(ValueError, match="out of range"):
            await fixer._apply_fixes_to_file(
                target, {1: ("one", "ONE"), 9: ("nine", "NINE")}
            )

        assert target.read_bytes() == original
        assert directory_entries(tmp_path) == ["workflow.yaml"]
