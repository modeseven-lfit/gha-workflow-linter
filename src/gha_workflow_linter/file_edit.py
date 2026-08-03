# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Atomic, byte-faithful replacement of individual lines in a text file.

Rewriting a user's workflow file in place is deceptively easy to get
wrong. The naive approach -- read the file with ``readlines()``, mutate a
few entries, then reopen the same path with ``open(path, "w")`` -- has
three distinct defects:

1. It is not atomic. Truncating the original before the replacement
   content is durable means an interrupted process (a crash, a signal, a
   full filesystem) leaves the file empty or half written.
2. It loses line endings. Text mode enables universal newlines, so a
   CRLF file is read as if it were LF and written back as LF, producing a
   diff on every line of the file.
3. It invents a trailing newline. Appending ``"\\n"`` to every rewritten
   line adds a final newline to a file that deliberately lacked one.

:func:`replace_lines` is the shared, correct alternative. It preserves
each line's own terminator, the file's trailing-newline state, a UTF-8
BOM, and the original file mode, and it publishes the result with a
single :func:`os.replace` so a reader sees either the old file or the new
one and never a partial write.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import os
import shutil
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

__all__ = ["LineChange", "replace_lines"]

# UTF-8 byte order mark. Some editors (and most Windows tooling) prefix
# files with it; ``utf-8-sig`` strips it on read and re-emits it on write,
# keeping it out of the line content reported back to callers.
_UTF8_BOM = b"\xef\xbb\xbf"

# Ordered longest-first so ``\r\n`` is never mistaken for a bare ``\r``.
_LINE_TERMINATORS: tuple[str, ...] = ("\r\n", "\n", "\r")

# Characters that Python's universal newline handling treats as line
# boundaries, and which therefore may not appear inside a replacement.
_NEWLINE_CHARACTERS: tuple[str, ...] = ("\n", "\r")


@dataclass(frozen=True)
class LineChange:
    """A single line rewritten by :func:`replace_lines`.

    Attributes:
        line_number: 1-based number of the replaced line.
        old_line: Previous content of the line, without its terminator.
        new_line: Replacement content, without its terminator.
    """

    line_number: int
    old_line: str
    new_line: str


def replace_lines(
    path: Path,
    replacements: Mapping[int, str],
) -> list[LineChange]:
    """Rewrite specific lines atomically, preserving each terminator.

    The file is read whole, the requested lines are substituted, and the
    result is written to a temporary file in the same directory before
    being moved over the original with :func:`os.replace`. Should any
    step fail, the temporary file is removed and the original is left
    byte-for-byte unchanged.

    Every replaced line keeps the terminator it already had (``\\r\\n``,
    ``\\n``, ``\\r``, or none at all for a final line without one), so a
    CRLF file stays CRLF, a mixed-ending file survives intact, and a file
    without a trailing newline does not gain one.

    Args:
        path: File to rewrite.
        replacements: Mapping of 1-based line number to the replacement
            content for that line, excluding any line terminator. An
            empty mapping is a no-op: the file is not opened or touched.

    Returns:
        One :class:`LineChange` per entry in ``replacements``, sorted by
        line number, with terminators excluded from both the old and the
        new content. A replacement whose content matches the existing
        line is still reported.

    Raises:
        ValueError: If a replacement contains an embedded line
            terminator, or if a line number is below 1 or beyond the last
            line of the file.
        OSError: If the file cannot be read, or the replacement cannot be
            written or moved into place.
    """
    if not replacements:
        return []

    _validate_replacement_content(replacements)

    encoding = _detect_encoding(path)
    with open(path, encoding=encoding, newline="") as handle:
        lines = handle.readlines()

    _validate_line_numbers(replacements, len(lines))

    changes: list[LineChange] = []
    for line_number in sorted(replacements):
        old_line, terminator = _split_terminator(lines[line_number - 1])
        new_line = replacements[line_number]
        lines[line_number - 1] = new_line + terminator
        changes.append(
            LineChange(
                line_number=line_number,
                old_line=old_line,
                new_line=new_line,
            )
        )

    _write_atomically(path, lines, encoding)
    return changes


def _validate_replacement_content(replacements: Mapping[int, str]) -> None:
    """Reject replacements that span more than a single line.

    Args:
        replacements: Mapping of 1-based line number to replacement
            content.

    Raises:
        ValueError: If any replacement contains ``\\n`` or ``\\r``.
    """
    for line_number in sorted(replacements):
        new_line = replacements[line_number]
        if any(char in new_line for char in _NEWLINE_CHARACTERS):
            raise ValueError(
                f"Replacement for line {line_number} contains an embedded "
                "line terminator; each replacement must be exactly one line"
            )


def _validate_line_numbers(
    replacements: Mapping[int, str],
    line_count: int,
) -> None:
    """Check that every requested line exists in the file.

    Args:
        replacements: Mapping of 1-based line number to replacement
            content.
        line_count: Number of lines the file actually contains.

    Raises:
        ValueError: If a line number is below 1 or above ``line_count``.
    """
    for line_number in sorted(replacements):
        if line_number < 1 or line_number > line_count:
            raise ValueError(
                f"Line number {line_number} is out of range for a file "
                f"with {line_count} line(s)"
            )


def _detect_encoding(path: Path) -> str:
    """Return the codec that round-trips the file's BOM state.

    Args:
        path: File to inspect.

    Returns:
        ``"utf-8-sig"`` when the file starts with a UTF-8 byte order
        mark, otherwise ``"utf-8"``. Both read and write use the returned
        codec, so a BOM is preserved and one is never introduced.

    Raises:
        OSError: If the file cannot be opened or read.
    """
    with open(path, "rb") as handle:
        prefix = handle.read(len(_UTF8_BOM))
    return "utf-8-sig" if prefix == _UTF8_BOM else "utf-8"


def _split_terminator(line: str) -> tuple[str, str]:
    """Separate a line's content from its terminator.

    Args:
        line: Line as read with ``newline=""``, so its terminator (if
            any) is present and untranslated.

    Returns:
        A ``(content, terminator)`` tuple. ``terminator`` is the empty
        string for a final line that ends without one.
    """
    for terminator in _LINE_TERMINATORS:
        if line.endswith(terminator):
            return line[: -len(terminator)], terminator
    return line, ""


def _write_atomically(
    path: Path,
    lines: list[str],
    encoding: str,
) -> None:
    """Publish new file content with a single atomic rename.

    The temporary file is created in the same directory as ``path`` so
    that :func:`os.replace` stays within one filesystem and is therefore
    atomic. The original's permission bits are copied onto the temporary
    file first, because replacing the path with a freshly created
    ``mkstemp`` file would otherwise reset the mode to ``0o600``.

    Args:
        path: File to overwrite.
        lines: Complete file content, each element carrying its own
            terminator.
        encoding: Codec to write with, as chosen by
            :func:`_detect_encoding`.

    Raises:
        OSError: If the temporary file cannot be written, have its mode
            copied, or be moved into place. The temporary file is removed
            and ``path`` is left unchanged.
    """
    descriptor, temporary_path = tempfile.mkstemp(
        dir=os.fspath(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(
            descriptor, "w", encoding=encoding, newline=""
        ) as handle:
            handle.writelines(lines)
            handle.flush()
            os.fsync(handle.fileno())
        shutil.copymode(path, temporary_path)
        os.replace(temporary_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary_path)
        raise
