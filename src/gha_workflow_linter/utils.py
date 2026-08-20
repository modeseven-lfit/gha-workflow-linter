# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Utility functions shared across modules."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .patterns import ActionCallPatterns

if TYPE_CHECKING:
    from .models import ActionCall


def has_test_comment(action_call: ActionCall) -> bool:
    """
    Check if an action call has 'test' in its comment (case-insensitive).

    This function checks for the word 'test' at the beginning of a word boundary,
    which matches 'test', 'testing', 'tested', etc., but not substrings like
    'latest' or 'contest'.

    Args:
        action_call: The action call to check

    Returns:
        True if the comment contains 'test' as a word prefix, False otherwise

    Examples:
        >>> # Returns True for:
        >>> # - "# test"
        >>> # - "# Testing"
        >>> # - "# TEST version"
        >>> # - "# testing new feature"
        >>> # Returns False for:
        >>> # - "# latest"
        >>> # - "# v4"
        >>> # - "# stable"
    """
    if not action_call.comment:
        return False
    # Remove the leading '#' and whitespace, then check for 'test' as a word prefix
    comment_text = action_call.comment.lstrip("#").strip()
    # Use word boundary to match 'test' at start of word (includes testing, tested, etc.)
    return bool(re.search(r"\btest", comment_text, re.IGNORECASE))


def comment_text(action_call: ActionCall) -> str | None:
    """Return an action call's comment without its marker or padding.

    Args:
        action_call: The call whose comment to read.

    Returns:
        The comment text, or ``None`` when the call carries none.
    """
    if not action_call.comment:
        return None
    return action_call.comment.strip().lstrip("#").strip()


def version_or_none(text: str | None) -> str | None:
    """Return the text when it names a clean version, otherwise ``None``.

    Only a tag the version grammar accepts is usable as *ordering*
    evidence. Anything else must not be parsed as one:
    :func:`~gha_workflow_linter.version_utils._parse_version` discards a
    ``-`` suffix, so a date comment such as ``2026-08-19`` would read as
    version 2026 and outrank every real release.

    Args:
        text: A reference, comment or tag, or ``None``.

    Returns:
        The text unchanged when it is a clean version tag, else ``None``.
    """
    if text and ActionCallPatterns.VERSION_TAG_PATTERN.match(text):
        return text
    return None


def pinned_version(action_call: ActionCall, comment: str | None) -> str | None:
    """Determine which released version an action call currently pins.

    Two sources answer, in order of authority:

    * The reference itself, when it is a clean version tag. That is what
      the workflow actually resolves at run time, so nothing outranks it.
    * The version comment beside a SHA pin. A comment can lie, but the
      auto-fixer diverts a *provably* wrong one to its mismatched-SHA
      repair before asking this, so what arrives here is either verified
      or unverifiable. Treating an unverifiable comment as the truth is
      the fail-safe reading, given the answer is used to refuse a
      rewrite: a missed update is a far smaller harm than a downgrade.

    Args:
        action_call: The call under consideration.
        comment: Its version comment, already stripped of ``#`` and
            surrounding whitespace, or ``None`` when it carries none.

    Returns:
        The version tag the call pins, or ``None`` when neither source
        names one -- a branch, a floating ref, or a SHA with no version
        comment.
    """
    return version_or_none(action_call.reference) or version_or_none(comment)
