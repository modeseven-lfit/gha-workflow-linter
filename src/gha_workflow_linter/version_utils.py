# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Pure helpers for parsing and selecting action version tags.

These functions are extracted from :mod:`auto_fix` so the version-parsing
and cooldown-selection logic can be reasoned about and tested in isolation,
independently of the ``AutoFixer`` orchestration and its network clients.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _parse_version(tag: str) -> tuple[int, int, int]:
    """Extract major, minor, patch from a version tag for sorting.

    Args:
        tag: A version tag (e.g., 'v4.31.0', 'v4.31', '1.2.3', '0.9')

    Returns:
        A tuple of (major, minor, patch) as integers

    Raises:
        ValueError: If version segments contain non-numeric characters
    """
    # Strip optional 'v' prefix and any pre-release/metadata suffixes
    version = tag.lstrip("v").split("-")[0].split("+")[0]
    parts = version.split(".")

    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
    except ValueError as e:
        raise ValueError(
            f"Invalid version tag '{tag}': version segments must be numeric. "
            f"Found non-numeric value in '{version}'"
        ) from e

    return (major, minor, patch)


def _is_downgrade(current_tag: str, target_tag: str) -> bool:
    """Report whether replacing one version tag with another goes backwards.

    A resolved "latest" version is only ever the newest release *as of
    the moment it was discovered*. A cached answer can therefore be older
    than the version a file already pins, because Dependabot, Renovate, a
    human or an earlier sweep can advance a pin inside the cache TTL. A
    downgrade is materially worse than a stale pin -- it reverts a
    supply-chain fix nobody asked to revert -- so callers use this to
    refuse the rewrite rather than apply it.

    Equality is deliberately not a downgrade: the same version may be
    re-pinned to pick up a moved tag, and
    :func:`_parse_version` ignores prerelease suffixes, so a comparison
    it cannot separate must not block a legitimate rewrite.

    Args:
        current_tag: The version the file pins now.
        target_tag: The version the run proposes to move it to.

    Returns:
        ``True`` only when ``current_tag`` is provably the higher
        version. An unparsable tag on either side answers ``False``:
        without two comparable versions there is no established
        direction, and inventing one would block ordinary rewrites.
    """
    try:
        return _parse_version(current_tag) > _parse_version(target_tag)
    except ValueError:
        return False


def _get_version_specificity(tag: str) -> int:
    """
    Get the specificity level of a version tag.

    Returns the number of non-empty dot-separated version segments: e.g.
    3 for 'v1.2.3', 2 for 'v1.2', 1 for 'v1', 0 for 'v', and 4 for
    'v1.2.3.4'. Higher is more specific, which helps prefer v8.0.0 over
    v8 when both point to the same SHA.
    """
    version = tag.lstrip("v").split("-")[0].split("+")[0]
    parts = version.split(".")
    return len([p for p in parts if p])


def _find_most_specific_version_tag(
    tag: str, sha: str, all_tags: list[tuple[str, str]]
) -> str:
    """
    Find the most specific semantic version tag for a given SHA.

    For example, if we get 'v8' but 'v8.0.0' also points to the same SHA,
    return 'v8.0.0' as it's more specific.

    Args:
        tag: The tag we found (e.g., 'v8')
        sha: The commit SHA
        all_tags: List of (tag_name, sha) tuples from the repository

    Returns:
        The most specific version tag pointing to the same SHA
    """
    # Find all tags pointing to the same SHA
    matching_tags = [t for t, s in all_tags if s == sha]

    if not matching_tags:
        return tag

    try:
        base_version = _parse_version(tag)
    except ValueError:
        return tag

    # Find all tags with the same base version
    same_version_tags = []
    for t in matching_tags:
        try:
            if _parse_version(t) == base_version:
                same_version_tags.append(t)
        except ValueError:
            continue

    if not same_version_tags:
        return tag

    # Sort by specificity (most specific first)
    sorted_by_specificity = sorted(
        same_version_tags, key=_get_version_specificity, reverse=True
    )

    return sorted_by_specificity[0]


def _parse_iso_datetime(value: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp into a timezone-aware ``datetime``.

    GitHub returns timestamps such as ``2026-01-02T03:04:05Z``. The
    trailing ``Z`` is normalised to ``+00:00`` so ``fromisoformat`` can
    parse it on all supported Python versions.

    Args:
        value: An ISO-8601 timestamp string, or ``None``.

    Returns:
        A timezone-aware ``datetime`` (UTC if no offset was provided), or
        ``None`` if the value is missing or cannot be parsed.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _select_version_with_cooldown(
    candidates: list[tuple[str, str, datetime | None]],
    cooldown_days: int,
    now: datetime | None = None,
) -> tuple[str, str] | None:
    """Pick the newest eligible ``(tag, sha)`` honouring a cooldown window.

    The cooldown enforces a Dependabot-style policy: a release must have
    been available for at least ``cooldown_days`` days before it is
    eligible to be selected. This protects against deploying actions that
    were recently retracted, superseded, or compromised by a supply-chain
    attack.

    Args:
        candidates: ``(tag, sha, published)`` tuples ordered newest-first.
            ``published`` may be ``None`` when a release date is unknown.
        cooldown_days: Minimum age in days. Values ``<= 0`` disable the
            cooldown and simply return the newest candidate.
        now: Reference time (defaults to the current UTC time); primarily
            an injection point for tests.

    Returns:
        The first eligible ``(tag, sha)`` tuple, or ``None`` when no
        candidate satisfies the cooldown. When the cooldown is active and
        a candidate's release date is unknown, it is skipped because its
        age cannot be verified.
    """
    if not candidates:
        return None

    if cooldown_days <= 0:
        tag, sha, _ = candidates[0]
        return (tag, sha)

    reference = now or datetime.now(timezone.utc)
    cutoff = reference - timedelta(days=cooldown_days)

    for tag, sha, published in candidates:
        if published is None:
            # Cannot verify the release age; skip under an active cooldown.
            continue
        if published <= cutoff:
            return (tag, sha)

    return None
