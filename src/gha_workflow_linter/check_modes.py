# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""What each check does about what it finds.

The linter runs several independent checks, and every one of them has
the same four questions asked of it: run at all, report only, repair, or
repair and advance. :class:`CheckMode` names those four answers once, so
a check declares its behaviour with a single option rather than a
cluster of booleans whose combinations mostly mean nothing.

The modes form a ladder of escalating *intervention*::

    off  <  report  <  fix  <  update

Each rung does everything the one before it does:

* ``off`` -- the check does not run: nothing is validated, resolved,
  reported or written on its behalf, and it cannot contribute to the
  exit code. Workflow *discovery* is shared rather than owned by any one
  check, so the scan still happens: it is what reports an unreadable
  path, and what the allow-list check reads. ``off`` disables the
  check's own work, not the run's.
* ``report`` -- the check runs and reports. It never writes.
* ``fix`` -- as ``report``, and repairs what is wrong *without changing
  which version a reference names*. Pinning ``@v4`` to the commit SHA of
  v4, peeling an annotated tag object to its commit, and correcting a
  version comment that disagrees with its SHA are all repairs: the
  reference keeps naming what it named before, correctly. The one
  exception is a reference that no longer resolves at all, which cannot
  stay where it is and so moves to the latest release.
* ``update`` -- as ``fix``, and additionally advances references to
  newer releases.

Enforcement is deliberately **not** on this ladder. Whether a finding
fails the run is a separate axis, carried by the ``--verify-*`` flags
and by :class:`~gha_workflow_linter.models.Category`:

===========  =====================  ============================
Mode         Writes to files?       Currency findings fail?
===========  =====================  ============================
``off``      no                     n/a -- the check never ran
``report``   no                     only under ``--verify-*``
``fix``      yes, without advancing only under ``--verify-*``
``update``   yes, advancing         only under ``--verify-*``
===========  =====================  ============================

Collapsing the two axes was tried and does not work. ``fix`` answers
*change my files*; ``verify`` answers *fail my build*. Neither implies
the other, both are wanted together (``--auto-fix --verify-actions`` has
always been valid), and ordering them on one ladder would make the
default mode ``fix`` enforce currency -- turning every clean run with a
single outdated action from exit ``0`` into exit ``5``.

Defect findings are unaffected by either axis. They are wrong now, they
always count towards the exit code, and no mode downgrades them; see
:mod:`gha_workflow_linter.exit_codes`.

.. note::

   The two axes are not yet fully independent in one direction.
   Currency *detection* currently lives inside the fixer, which
   ``report`` disables because it must not write -- so
   ``--action-calls report --verify-action-calls`` reports no outdated
   calls and cannot fail on them. ``fix`` and ``update`` detect and
   enforce correctly. Separating detection from remediation is the
   change that closes this, and it is deliberately not folded in here:
   it alters what an existing ``--no-auto-fix`` run reports.

A check need not offer every rung. :class:`CheckSpec` declares which it
supports, so an unsupported one is refused at parse time with a reason
rather than silently doing something else.
"""

from __future__ import annotations

import dataclasses
from enum import Enum
from typing import TYPE_CHECKING, Final

from .exceptions import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "ACTION_CALLS",
    "ALLOW_LIST",
    "SPECS",
    "CheckId",
    "CheckMode",
    "CheckSpec",
    "spec_for",
]


class CheckId(str, Enum):
    """The checks the linter can run.

    Values are the user-facing names, matching the command-line option
    that selects each check's mode.
    """

    ACTION_CALLS = "action-calls"
    ALLOW_LIST = "allow-list"


class CheckMode(str, Enum):
    """What a check does about what it finds.

    See the module docstring for the ladder and for why enforcement is
    not part of it.
    """

    OFF = "off"
    REPORT = "report"
    FIX = "fix"
    UPDATE = "update"

    @property
    def runs(self) -> bool:
        """Whether the check executes at all.

        Returns:
            True for every mode but ``off``.
        """
        return self is not CheckMode.OFF

    @property
    def remediates(self) -> bool:
        """Whether the check may write to files.

        Returns:
            True for ``fix`` and ``update``.
        """
        return self in (CheckMode.FIX, CheckMode.UPDATE)

    @property
    def advances_version(self) -> bool:
        """Whether remediation may move a reference to a newer release.

        ``fix`` repairs in place and leaves the version alone; only
        ``update`` moves forward. A broken reference that no longer
        resolves is the documented exception, since it cannot stay.

        Returns:
            True for ``update`` alone.
        """
        return self is CheckMode.UPDATE


@dataclasses.dataclass(frozen=True)
class CheckSpec:
    """Which modes one check offers, and what it defaults to.

    Capability is data rather than code: a check that cannot remediate
    declares that here, so the rung is absent from ``--help`` and
    refused at parse time. The alternative -- accepting the mode and
    quietly doing less -- is the failure this whole design exists to
    prevent.

    Attributes:
        id: The check this describes.
        flag: The command-line option that selects its mode.
        supported_modes: Every mode the check implements.
        default_mode: The mode used when the caller names none.
        refusals: Why each unsupported mode is unavailable, keyed by
            mode. Used verbatim in the error message, so entries read as
            the second half of a sentence.
    """

    id: CheckId
    flag: str
    supported_modes: frozenset[CheckMode]
    default_mode: CheckMode
    refusals: Mapping[CheckMode, str] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        """Reject a spec that contradicts itself.

        Raises:
            ValueError: If the default mode is not itself supported, or
                a refusal is recorded for a supported mode.
        """
        if self.default_mode not in self.supported_modes:
            raise ValueError(
                f"{self.flag}: default mode {self.default_mode.value!r} "
                f"is not among the supported modes"
            )
        contradictory = sorted(
            mode.value for mode in self.refusals if mode in self.supported_modes
        )
        if contradictory:
            raise ValueError(
                f"{self.flag}: refusal recorded for supported mode(s) "
                f"{contradictory}"
            )

    @property
    def choices(self) -> tuple[str, ...]:
        """The supported modes, in ladder order, for help text.

        Returns:
            Mode values ordered ``off``, ``report``, ``fix``, ``update``,
            omitting any the check does not support.
        """
        return tuple(
            mode.value for mode in _LADDER if mode in self.supported_modes
        )

    def validate(self, mode: CheckMode) -> CheckMode:
        """Confirm this check offers the given mode.

        Args:
            mode: The mode the caller asked for.

        Returns:
            The mode unchanged, so this can wrap an assignment.

        Raises:
            ConfigurationError: When the check does not support it. The
                message carries the recorded reason when there is one,
                because "unsupported" without a reason sends the reader
                to the source.
        """
        if mode in self.supported_modes:
            return mode

        reason = self.refusals.get(mode)
        detail = f": {reason}" if reason else ""
        supported = ", ".join(self.choices)
        raise ConfigurationError(
            f"{self.flag} does not support mode {mode.value!r}{detail}. "
            f"Supported modes: {supported}"
        )


#: Ladder order, used for help text and for comparing rungs. Declared
#: once here rather than relying on definition order in the enum, so the
#: ordering is stated where the ladder is documented.
_LADDER: Final[tuple[CheckMode, ...]] = (
    CheckMode.OFF,
    CheckMode.REPORT,
    CheckMode.FIX,
    CheckMode.UPDATE,
)


ACTION_CALLS: Final = CheckSpec(
    id=CheckId.ACTION_CALLS,
    flag="--action-calls",
    supported_modes=frozenset(
        {CheckMode.OFF, CheckMode.REPORT, CheckMode.FIX, CheckMode.UPDATE}
    ),
    default_mode=CheckMode.FIX,
)
"""Validation of ``uses:`` references in workflows and action files."""


ALLOW_LIST: Final = CheckSpec(
    id=CheckId.ALLOW_LIST,
    flag="--allow-list",
    supported_modes=frozenset(
        {CheckMode.OFF, CheckMode.REPORT, CheckMode.UPDATE}
    ),
    default_mode=CheckMode.REPORT,
    refusals={
        CheckMode.FIX: (
            "repairing an allow-list pin without advancing its version is "
            "not implemented yet, because correcting a comment in place "
            "needs the pinned commit's own tag rather than the latest "
            "release; use 'update'"
        )
    },
)
"""Detection of stale ``harden-runner`` egress allow-list pins.

Advisory by default: the pins follow an ``lfreleng-actions`` convention
rather than GitHub-native syntax, so a stale one must not break a build
that did not ask about it.
"""


SPECS: Final[Mapping[CheckId, CheckSpec]] = {
    ACTION_CALLS.id: ACTION_CALLS,
    ALLOW_LIST.id: ALLOW_LIST,
}
"""Every check, by identifier."""


def spec_for(check: CheckId) -> CheckSpec:
    """Return the specification of one check.

    Args:
        check: The check to describe.

    Returns:
        Its specification.
    """
    return SPECS[check]
