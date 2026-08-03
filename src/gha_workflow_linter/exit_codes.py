# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Centralised process exit codes and the rules that select them.

The linter distinguishes three kinds of finding (see
:class:`~gha_workflow_linter.models.Category`):

* ``DEFECT`` -- wrong now; always counts towards the exit code.
* ``CURRENCY`` -- correct but could be newer; advisory unless the caller
  opts in with a ``--verify-*`` flag.
* ``INFRASTRUCTURE`` -- the check could not run; never reported as a
  pass when enforcement was requested.

Exit codes:

===== ========================= ================================================
Code  Name                      Meaning
===== ========================= ================================================
0     SUCCESS                   No failing findings.
1     DEFECTS_FOUND             Defect findings, or files modified by a fixer.
2     *reserved*                Click/Typer CLI usage error. Never assigned.
3     ALLOW_LIST_STALE          ``--verify-allow-list`` and stale pins remain.
4     ALLOW_LIST_UNRESOLVED     ``--verify-allow-list`` and no latest release.
5     ACTIONS_OUTDATED          ``--verify-actions`` and outdated calls remain.
===== ========================= ================================================

Precedence is ``4 > 3 > 5 > 1 > 0``. An infrastructure failure must never
be reported as a clean-or-stale result, and a condition the caller
specifically asked about must not be masked by the generic ``1``.
"""

from __future__ import annotations

from typing import Final

SUCCESS: Final = 0
"""No failing findings."""

DEFECTS_FOUND: Final = 1
"""Defect findings were reported, or a fixer modified files."""

RUNTIME_ERROR: Final = DEFECTS_FOUND
"""The run itself failed: bad configuration, aborted validation, or an
unexpected exception.

Shares the value of :data:`DEFECTS_FOUND` because the tool has always
exited ``1`` for both conditions. Separating them would break callers
that test for ``1``, so the split is deferred to a future major release.
The distinct name exists so call sites state which condition they mean,
and so the eventual split is a one-line change here rather than an audit
of every ``raise``.
"""

CLI_USAGE_ERROR: Final = 2
"""Reserved by Click/Typer for command-line usage errors.

Never assign this value; it is declared so the reservation is explicit
and testable.
"""

ALLOW_LIST_STALE: Final = 3
"""``--verify-allow-list`` was requested and stale pins remain."""

ALLOW_LIST_UNRESOLVED: Final = 4
"""``--verify-allow-list`` was requested but the latest release of the
allow-list host repository could not be resolved."""

ACTIONS_OUTDATED: Final = 5
"""``--verify-actions`` was requested and outdated action calls remain."""


# Ordered most to least significant. The first condition that holds
# decides the exit code.
_PRECEDENCE: Final[tuple[int, ...]] = (
    ALLOW_LIST_UNRESOLVED,
    ALLOW_LIST_STALE,
    ACTIONS_OUTDATED,
    DEFECTS_FOUND,
    SUCCESS,
)


def combine(*codes: int) -> int:
    """Combine exit codes according to the documented precedence.

    Args:
        *codes: Exit codes contributed by individual stages. Values of
            ``SUCCESS`` are ignored unless every code is ``SUCCESS``.

    Returns:
        The most significant exit code, or ``SUCCESS`` when no code
        indicates a failure.

    Raises:
        ValueError: If any code is not a recognised exit code.
    """
    unknown = [code for code in codes if code not in _PRECEDENCE]
    if unknown:
        raise ValueError(f"Unknown exit code(s): {sorted(set(unknown))}")

    for candidate in _PRECEDENCE:
        if candidate in codes:
            return candidate
    return SUCCESS


def describe(code: int) -> str:
    """Return a short human-readable description of an exit code.

    Args:
        code: The exit code to describe.

    Returns:
        A one-line description, or a generic string for unknown codes.
    """
    return _DESCRIPTIONS.get(code, f"Unknown exit code {code}")


_DESCRIPTIONS: Final[dict[int, str]] = {
    SUCCESS: "Success",
    DEFECTS_FOUND: "Defects found, or files modified",
    CLI_USAGE_ERROR: "Command-line usage error",
    ALLOW_LIST_STALE: "Stale allow-list pins",
    ALLOW_LIST_UNRESOLVED: "Allow-list latest release unresolved",
    ACTIONS_OUTDATED: "Outdated action calls",
}


__all__ = [
    "ACTIONS_OUTDATED",
    "ALLOW_LIST_STALE",
    "ALLOW_LIST_UNRESOLVED",
    "CLI_USAGE_ERROR",
    "DEFECTS_FOUND",
    "RUNTIME_ERROR",
    "SUCCESS",
    "combine",
    "describe",
]
