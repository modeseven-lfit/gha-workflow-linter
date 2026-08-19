# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Discovery and parsing of Dependabot cooldown configuration.

GitHub Dependabot supports a ``cooldown`` stanza that delays opening
dependency-bump pull requests until a release has been available for a
minimum number of days. This guards against supply-chain attacks and
hastily-retracted releases.

This module locates the repository's ``.github/dependabot.yml`` (or
``.yaml``) file by walking up the directory hierarchy from a starting
path -- stopping at the enclosing repository root, since a cooldown is
that repository's own release policy -- then extracts the
``cooldown.default-days`` value so the linter can apply the same policy
when updating action calls.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import TYPE_CHECKING

import yaml

from .multi_repo import is_repository

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# Ecosystem name Dependabot uses for GitHub Actions updates. We prefer the
# cooldown configured for this ecosystem because that is what governs the
# action-call updates this linter performs.
_GITHUB_ACTIONS_ECOSYSTEM = "github-actions"

# Candidate file names, in the order Dependabot itself resolves them.
_DEPENDABOT_FILENAMES = ("dependabot.yml", "dependabot.yaml")


@dataclass(frozen=True)
class DependabotCooldown:
    """Result of resolving a Dependabot cooldown value.

    Attributes:
        days: The ``cooldown.default-days`` value that was parsed.
        source: Path to the ``dependabot.yml``/``.yaml`` file the value
            was read from.
        ecosystem: The ``package-ecosystem`` the cooldown was taken from.
    """

    days: int
    source: Path
    ecosystem: str


def find_dependabot_config(start_path: Path) -> Path | None:
    """Locate the nearest ``.github/dependabot.{yml,yaml}`` file.

    Walks up the directory hierarchy from ``start_path`` (or its parent if
    ``start_path`` is a file) until a Dependabot configuration file is
    found, a repository root is passed, or the filesystem root is
    reached.

    The search stops at a repository root because a cooldown is that
    repository's own release policy. Without the boundary, a checkout
    lacking a Dependabot file inherits whatever directory happens to
    contain it -- so a multi-repository sweep whose container carries a
    configuration would silently apply it to every repository beneath,
    and a lone checkout would answer differently depending on where it
    was cloned.

    Args:
        start_path: Path to begin searching from (typically the directory
            being linted).

    Returns:
        Path to the Dependabot configuration file, or ``None`` if no file
        is found at or below the enclosing repository root.
    """
    start = start_path.resolve()
    search_dir = start if start.is_dir() else start.parent

    for directory in (search_dir, *search_dir.parents):
        github_dir = directory / ".github"
        if github_dir.is_dir():
            for filename in _DEPENDABOT_FILENAMES:
                candidate = github_dir / filename
                if candidate.is_file():
                    return candidate
        # Checked after this directory's own configuration, so a
        # repository root's file is still found -- it is ascending
        # *past* the root that leaks policy across the boundary.
        if is_repository(directory):
            break

    return None


def _extract_cooldown_days(
    config_path: Path,
) -> tuple[int, str] | None:
    """Parse ``cooldown.default-days`` from a Dependabot config file.

    Prefers the cooldown configured for the ``github-actions`` ecosystem,
    falling back to the first ecosystem that declares a cooldown.

    Args:
        config_path: Path to the Dependabot configuration file.

    Returns:
        A ``(days, ecosystem)`` tuple, or ``None`` if no cooldown is
        configured or the file cannot be parsed.
    """
    try:
        with open(config_path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as exc:
        logger.debug(
            "Could not read Dependabot config %s: %s", config_path, exc
        )
        return None

    if not isinstance(data, dict):
        return None

    updates = data.get("updates")
    if not isinstance(updates, list):
        return None

    fallback: tuple[int, str] | None = None

    for update in updates:
        if not isinstance(update, dict):
            continue
        cooldown = update.get("cooldown")
        if not isinstance(cooldown, dict):
            continue
        days = cooldown.get("default-days")
        if not isinstance(days, int) or isinstance(days, bool) or days < 0:
            continue

        ecosystem = str(update.get("package-ecosystem", ""))
        if ecosystem == _GITHUB_ACTIONS_ECOSYSTEM:
            return days, ecosystem
        if fallback is None:
            fallback = (days, ecosystem)

    return fallback


def resolve_cooldown(start_path: Path) -> DependabotCooldown | None:
    """Resolve the Dependabot cooldown applicable to ``start_path``.

    Args:
        start_path: Path being linted; used to locate the repository's
            Dependabot configuration.

    Returns:
        A :class:`DependabotCooldown` describing the parsed value, or
        ``None`` when no usable cooldown configuration is found.
    """
    config_path = find_dependabot_config(start_path)
    if config_path is None:
        return None

    extracted = _extract_cooldown_days(config_path)
    if extracted is None:
        return None

    days, ecosystem = extracted
    return DependabotCooldown(
        days=days, source=config_path, ecosystem=ecosystem
    )
