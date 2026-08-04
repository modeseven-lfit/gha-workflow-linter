# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Classification of detected allow-list pins against their host repos.

:mod:`gha_workflow_linter.allow_list_scanner` finds the pins and
:mod:`gha_workflow_linter.allow_list_resolver` answers "what is the
latest release of this host repository?". This module is the join
between the two: it turns a pin plus a resolved latest release into a
:class:`AllowListFinding`, or into nothing at all when the pin is
current.

Three rules decide the kind, and they are exhaustive for this phase
(design section 7.2):

* The ref is not a 40-character hexadecimal SHA -- a branch, a tag, or
  the implicit ``HEAD`` -- so the pin floats: ``UNPINNED``.
* The ref is a SHA the host repository has moved *beyond*: ``STALE``.
* The ref *is* the latest release's commit, but the version comment
  names a different version: ``COMMENT_MISMATCH``. A comment that lies
  misleads every subsequent human reviewer, so it is a finding in its
  own right rather than a detail of ``STALE``.

Staleness has a **direction**, and the second rule is not simply "the
SHA differs from the target". A cooldown deliberately selects an older
release than the newest one in existence -- with a seven-day window,
``lfreleng-actions/.github`` resolves to v0.7.0 while the whole v0.12.x
series is still warming -- so a pin already sitting at v0.12.2 is *ahead*
of the target, not behind it. Reporting that as stale would advise a
downgrade in the name of freshness. Direction is therefore established
by placing the pinned commit in the host repository's own commit-to-tag
map (``LatestRelease.commit_tags``) and comparing versions numerically,
never by reading the version comment, which is exactly the thing section
7.2 assumes can lie. A pin that is at or ahead of the target produces no
finding at all; a commit belonging to no known release keeps its
``STALE`` classification, because its position cannot be established and
the target is then the best advice available.

``INVALID_SPEC`` and ``UNRESOLVABLE`` are deliberately **not produced
here**, because neither can be substantiated with the information this
phase has:

* ``INVALID_SPEC`` would require the scanner to hand over scalars that
  failed the grammar. It does not: its module docstring states that an
  unparsable scalar is skipped wherever it is found, and
  :class:`~gha_workflow_linter.allow_list_scanner.AllowListPin` has no
  representation for a spec that did not resolve. Reporting one needs
  the orchestrator to know which action consumes the input, which is
  future work.
* ``UNRESOLVABLE`` would require proving that a SHA is absent from the
  host repository. Resolving the latest release does not perform that
  lookup, and inferring absence from "it is not the latest commit"
  would report every deliberately-lagging pin as broken.

Both kinds are nonetheless handled defensively -- they have severities
and categories -- so that adding the lookups later is a matter of
producing the finding, not of teaching the rest of the pipeline what it
means.

Resolution failure is fail-soft (design section 6.4). When a host
repository's latest release cannot be resolved, **no findings are
produced for the pins naming it** and the host is recorded in
:attr:`AllowListOutcome.unresolved` with the reason. Whether that is
fatal is the caller's decision: in default mode it is a notice, and
under ``--verify-allow-list`` it is exit code ``4``. This module never
decides it.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import re
import subprocess
from typing import TYPE_CHECKING

from .allow_list_resolver import AllowListResolver
from .allow_list_scanner import AllowListScanner
from .allow_list_spec import ORG_RE
from .directives import Directive
from .models import (
    SUPPRESSIBLE_ALLOW_LIST_KINDS,
    AllowListFindingKind,
    Category,
    Severity,
    allow_list_category,
)
from .version_utils import _parse_version

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from pathlib import Path

    from .allow_list_scanner import AllowListPin
    from .cache import ValidationCache
    from .latest_release import LatestRelease
    from .models import Config

__all__ = [
    "ORG_ENV_VAR",
    "REMOTE_PRECEDENCE",
    "UNRESOLVED_REASON",
    "AllowListChecker",
    "AllowListFinding",
    "AllowListOutcome",
    "classify_pins",
    "host_key",
    "resolve_workflow_org",
]

#: Environment variable GitHub Actions sets to the owner of the running
#: repository. Second in the precedence order of design section 6.3.
ORG_ENV_VAR = "GITHUB_REPOSITORY_OWNER"

#: Git remotes consulted, in order. ``upstream`` deliberately outranks
#: ``origin``: contributors work from personal forks, and the pins track
#: the upstream org's ``.github`` repository. A fork owner would resolve
#: to a ``.github`` repository that does not exist.
REMOTE_PRECEDENCE: tuple[str, ...] = ("upstream", "origin")

#: Seconds allowed for the ``git remote get-url`` probe. Reading a local
#: config file is instantaneous; the bound only guards against a
#: pathological environment.
_GIT_TIMEOUT_SECONDS = 10

#: A checkout-able commit SHA: exactly 40 hexadecimal characters.
_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)

#: Suffix Git remote URLs conventionally carry.
_GIT_URL_SUFFIX = ".git"

#: Recorded against every host repository whose latest release could not
#: be resolved. The resolver is fail-soft and reports ``None`` without
#: distinguishing the cause, so the reason enumerates the possibilities
#: rather than claiming one of them.
UNRESOLVED_REASON = (
    "the latest release could not be resolved (no token, no network, "
    "no releases, or an active cooldown excluded every candidate)"
)

#: Severity each kind carries when enforcement was not requested
#: (design section 7.2). ``INVALID_SPEC`` is an error even by default
#: because it is a local correctness problem with no network dependency.
_DEFAULT_SEVERITIES: dict[AllowListFindingKind, Severity] = {
    AllowListFindingKind.STALE: Severity.WARNING,
    AllowListFindingKind.COMMENT_MISMATCH: Severity.WARNING,
    AllowListFindingKind.UNPINNED: Severity.NOTICE,
    AllowListFindingKind.UNRESOLVABLE: Severity.WARNING,
    AllowListFindingKind.INVALID_SPEC: Severity.ERROR,
}


@dataclasses.dataclass(frozen=True)
class AllowListFinding:
    """One thing wrong with one detected allow-list pin.

    Attributes:
        pin: The pin the finding concerns, carrying its source anchor.
        kind: What is wrong with it.
        severity: How it is reported. Suppressed findings keep their
            default severity even under enforcement.
        message: Human-readable description, safe to print verbatim.
        current_sha: The commit the pin names, or ``None`` when the pin
            does not name a commit at all (``UNPINNED``).
        target_sha: The commit the pin should name.
        target_version: The release tag ``target_sha`` belongs to.
        suppressed: Whether an ``allow-list-pin-ok`` directive applies.
            Suppressed findings are still reported -- machine consumers
            see the full picture -- but never fail a run.
    """

    pin: AllowListPin
    kind: AllowListFindingKind
    severity: Severity
    message: str
    current_sha: str | None
    target_sha: str | None
    target_version: str | None
    suppressed: bool

    @property
    def category(self) -> Category:
        """The defect/currency category of this finding.

        Returns:
            The category implied by :attr:`kind`.
        """
        return allow_list_category(self.kind)

    @property
    def host_repo(self) -> str:
        """The ``owner/repo`` the pin reads its allow-list from.

        Returns:
            The host repository key.
        """
        return host_key(self.pin)


@dataclasses.dataclass(frozen=True)
class AllowListOutcome:
    """Everything one allow-list check produced.

    Attributes:
        findings: Every finding, suppressed ones included, in scan
            order.
        hosts: Latest release of each distinct host repository, or
            ``None`` where resolution failed.
        unresolved: Host repositories that could not be resolved, mapped
            to the reason. Non-empty means the check was incomplete, and
            the caller decides whether that is fatal.
        suppressed_count: How many of ``findings`` are suppressed.
        checked: ``False`` when the check was disabled or no pin was
            found, so no conclusion may be drawn from an empty
            ``findings``.
    """

    findings: list[AllowListFinding]
    hosts: dict[str, LatestRelease | None]
    unresolved: dict[str, str]
    suppressed_count: int
    checked: bool

    @property
    def resolved(self) -> bool:
        """Whether every host repository consulted was resolved.

        Returns:
            ``True`` when no host is recorded in :attr:`unresolved`.
        """
        return not self.unresolved

    @property
    def unsuppressed(self) -> list[AllowListFinding]:
        """The findings that may affect the exit code.

        Returns:
            Every finding without an applicable suppression, in scan
            order.
        """
        return [finding for finding in self.findings if not finding.suppressed]


def host_key(pin: AllowListPin) -> str:
    """Return the ``owner/repo`` key of a pin's host repository.

    Args:
        pin: The pin to key.

    Returns:
        The host repository key, for example
        ``lfreleng-actions/.github``.
    """
    return f"{pin.spec.host_org}/{pin.spec.repo}"


def _git_remote_url(root: Path, remote: str) -> str:
    """Read one Git remote's URL from a working tree.

    Args:
        root: Directory inside the repository to interrogate.
        remote: Remote name, for example ``upstream``.

    Returns:
        The URL, or ``""`` when the directory is not a repository, the
        remote does not exist, or Git is unavailable. Never raises.
    """
    command = ["git", "-C", str(root), "remote", "get-url", remote]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip()


def _owner_from_remote_url(url: str) -> str:
    """Extract the repository owner from a Git remote URL.

    Handles the three forms in everyday use: an HTTPS URL, an SSH URL,
    and the scp-like ``git@host:owner/repo``. A trailing ``.git`` and
    trailing slashes are ignored.

    Args:
        url: The remote URL.

    Returns:
        The owner, or ``""`` when the URL names no owner or the owner is
        not a valid GitHub org name (a local-path remote, for example).
    """
    text = url.strip().rstrip("/")
    if text.endswith(_GIT_URL_SUFFIX):
        text = text[: -len(_GIT_URL_SUFFIX)]
    if "://" not in text and ":" in text:
        # scp-like syntax; everything before ':' is user@host.
        text = text.split(":", 1)[1]

    segments = [segment for segment in text.split("/") if segment]
    if len(segments) < 2:
        return ""

    owner = segments[-2]
    return owner if ORG_RE.match(owner) else ""


def resolve_workflow_org(root: Path, *, configured: str = "") -> str:
    """Determine the org that owns the workflows being scanned.

    The shorthand ``@<sha>`` pin form names no host org and takes it from
    here, so this answers "whose ``.github`` repository do these pins
    read?". Precedence follows design section 6.3:

    1. ``configured`` -- the config key, itself fed by the CLI flag.
    2. The ``GITHUB_REPOSITORY_OWNER`` environment variable.
    3. The owner of the ``upstream`` Git remote.
    4. The owner of the ``origin`` Git remote.

    ``upstream`` deliberately outranks ``origin``: contributors work from
    personal forks whose owner has no ``.github`` repository at all.

    Args:
        root: Directory of the repository being scanned. Used only for
            the Git remote probes.
        configured: Explicit org from configuration. Returned verbatim
            when non-empty, without validation, because an explicit
            setting is a statement of intent.

    Returns:
        The org name, or ``""`` when it cannot be determined. An empty
        result is not an error: the scanner then skips shorthand pins,
        which is the documented behaviour of design section 6.4.
    """
    explicit = configured.strip()
    if explicit:
        return explicit

    from_env = os.environ.get(ORG_ENV_VAR, "").strip()
    if from_env and ORG_RE.match(from_env):
        return from_env

    for remote in REMOTE_PRECEDENCE:
        url = _git_remote_url(root, remote)
        if not url:
            continue
        owner = _owner_from_remote_url(url)
        if owner:
            return owner

    return ""


def _normalise_version(text: str) -> str:
    """Reduce a version token to a comparable form.

    A single leading ``v`` is optional by convention, so ``v0.12.2`` and
    ``0.12.2`` name the same release and must not be reported as a
    mismatch. Comparison is case-insensitive.

    Args:
        text: A version token, from a comment or a release tag.

    Returns:
        The normalised token.
    """
    stripped = text.strip()
    if stripped[:1] in {"v", "V"}:
        stripped = stripped[1:]
    return stripped.lower()


def _comment_disagrees(comment: str | None, tag: str) -> bool:
    """Report whether a version comment contradicts a release tag.

    Args:
        comment: The pin's version comment, or ``None`` when it carries
            none. A pin with no comment cannot lie.
        tag: The latest release tag.

    Returns:
        ``True`` when the comment names a different version.
    """
    if comment is None:
        return False
    return _normalise_version(comment) != _normalise_version(tag)


def _pin_is_at_or_ahead(ref: str, latest: LatestRelease) -> bool:
    """Report whether a pinned commit sits at or beyond the target.

    A cooldown makes the resolved target a floor rather than a ceiling:
    it is the newest release old enough to be trusted, which may be
    several releases behind the newest release that exists. A pin on a
    release at or beyond that floor is current, and moving it to the
    target would be a downgrade.

    The pinned commit is placed through the host repository's
    commit-to-tag map rather than through the pin's version comment,
    which may name any version its author last typed.

    Args:
        ref: The commit SHA the pin names.
        latest: The host repository's resolved target release.

    Returns:
        ``True`` when the pinned commit belongs to a known release whose
        version is greater than or equal to the target's. ``False`` when
        it belongs to no known release, and whenever the target carries
        no commit map -- a cache-restored record, which the resolver only
        produces when no cooldown applied and the target really is the
        newest release.
    """
    pinned_tag = latest.tag_for_commit(ref)
    if pinned_tag is None:
        return False

    try:
        return _parse_version(pinned_tag) >= _parse_version(latest.tag)
    except ValueError:  # pragma: no cover - eligibility rejects such tags
        return False


def _finding_kind(
    pin: AllowListPin, latest: LatestRelease
) -> AllowListFindingKind | None:
    """Classify one pin against its host repository's target release.

    Args:
        pin: The pin to classify.
        latest: The host repository's target release.

    Returns:
        The finding kind, or ``None`` when the pin is current -- either
        because it names the target commit and its comment agrees, or
        because it names a release at or ahead of the target.
    """
    ref = pin.spec.ref
    if not _SHA_RE.match(ref):
        return AllowListFindingKind.UNPINNED
    if ref.lower() != latest.commit_sha.lower():
        if _pin_is_at_or_ahead(ref, latest):
            return None
        return AllowListFindingKind.STALE
    if _comment_disagrees(pin.version_comment, latest.tag):
        return AllowListFindingKind.COMMENT_MISMATCH
    return None


def _is_suppressed(pin: AllowListPin, kind: AllowListFindingKind) -> bool:
    """Report whether an ``allow-list-pin-ok`` directive covers a kind.

    The directive asserts "this pin is deliberately at this version",
    which is a statement about currency, not about correctness. It
    therefore silences only the kinds in
    :data:`~gha_workflow_linter.models.SUPPRESSIBLE_ALLOW_LIST_KINDS`.

    Args:
        pin: The pin, carrying any directives found on or above it.
        kind: The finding kind under consideration.

    Returns:
        ``True`` when the pin carries the directive *and* the kind is
        suppressible.
    """
    if kind not in SUPPRESSIBLE_ALLOW_LIST_KINDS:
        return False
    return Directive.ALLOW_LIST_PIN_OK in pin.directives


def _severity(
    kind: AllowListFindingKind, *, suppressed: bool, verify: bool
) -> Severity:
    """Choose the severity of one finding.

    Args:
        kind: The finding kind.
        suppressed: Whether a directive applies. A suppressed finding is
            never promoted: enforcement must not defeat a suppression.
        verify: Whether enforcement was requested.

    Returns:
        The severity to report.
    """
    if verify and not suppressed:
        return Severity.ERROR
    return _DEFAULT_SEVERITIES[kind]


def _message(
    pin: AllowListPin, latest: LatestRelease, kind: AllowListFindingKind
) -> str:
    """Compose the human-readable description of one finding.

    Args:
        pin: The pin the finding concerns.
        latest: The host repository's latest release.
        kind: The finding kind.

    Returns:
        A single-sentence description naming the host repository.
    """
    host = host_key(pin)
    if kind is AllowListFindingKind.UNPINNED:
        return (
            f"Allow-list pin references '{pin.spec.ref}' rather than a "
            f"commit SHA; {host} is at {latest.tag}"
        )
    if kind is AllowListFindingKind.COMMENT_MISMATCH:
        return (
            f"Version comment says '{pin.version_comment}' but the "
            f"pinned commit is {latest.tag} of {host}"
        )
    return (
        f"Allow-list pin is stale; {host} is at {latest.tag} "
        f"({latest.commit_sha})"
    )


def _build_finding(
    pin: AllowListPin,
    latest: LatestRelease,
    kind: AllowListFindingKind,
    *,
    verify: bool,
) -> AllowListFinding:
    """Assemble a finding from a classified pin.

    Args:
        pin: The pin the finding concerns.
        latest: The host repository's latest release.
        kind: The finding kind.
        verify: Whether enforcement was requested.

    Returns:
        The finding.
    """
    suppressed = _is_suppressed(pin, kind)
    ref = pin.spec.ref
    return AllowListFinding(
        pin=pin,
        kind=kind,
        severity=_severity(kind, suppressed=suppressed, verify=verify),
        message=_message(pin, latest, kind),
        current_sha=ref if _SHA_RE.match(ref) else None,
        target_sha=latest.commit_sha,
        target_version=latest.tag,
        suppressed=suppressed,
    )


def classify_pins(
    pins: Sequence[AllowListPin],
    hosts: dict[str, LatestRelease | None],
    *,
    verify: bool,
) -> list[AllowListFinding]:
    """Classify every pin against its host repository's latest release.

    Pins whose host could not be resolved produce no findings at all.
    Guessing under uncertainty is the one behaviour a linter must not
    have; the unresolved host is recorded separately instead.

    Args:
        pins: The detected pins, in scan order.
        hosts: Latest release of each host repository, or ``None``.
        verify: Whether enforcement was requested, promoting every
            unsuppressed finding to an error.

    Returns:
        The findings, in scan order.
    """
    findings: list[AllowListFinding] = []
    for pin in pins:
        latest = hosts.get(host_key(pin))
        if latest is None:
            continue
        kind = _finding_kind(pin, latest)
        if kind is None:
            continue
        findings.append(_build_finding(pin, latest, kind, verify=verify))
    return findings


class AllowListChecker:
    """Scan, resolve and classify allow-list pins in one pass.

    Attributes:
        config: Linter configuration, supplying the allow-list settings
            and the resolution backend.
        cache: Validation cache reused for latest-release storage, so a
            repeated run within the TTL costs no API calls.
    """

    def __init__(self, config: Config, cache: ValidationCache) -> None:
        """Initialise the checker.

        Args:
            config: Linter configuration.
            cache: Validation cache passed through to the resolver.
        """
        self.config = config
        self.cache = cache
        self.logger = logging.getLogger(__name__)

    async def check(
        self, paths: Iterable[Path], root: Path
    ) -> AllowListOutcome:
        """Check every allow-list pin in the given files.

        Each distinct host repository is resolved exactly once, however
        many pins name it.

        Args:
            paths: Workflow or action files to scan. Discovery is the
                caller's concern.
            root: Repository root, used to infer the workflow org from
                the Git remotes when configuration and environment do
                not supply it.

        Returns:
            The outcome. ``checked`` is ``False`` when the check is
            disabled or no pin was found, so an empty ``findings`` is
            never mistaken for a clean result.
        """
        settings = self.config.allow_list
        if not settings.enabled:
            self.logger.debug("Allow-list check disabled by configuration")
            return _empty_outcome()

        pins = self._scan(paths, root)
        if not pins:
            self.logger.debug("No allow-list pins found")
            return _empty_outcome()

        # Distinct host repositories only: twenty pins naming the same
        # '.github' repository must cost exactly one lookup, and the
        # de-duplication is stated here rather than relied upon inside
        # the resolver.
        repo_keys = list(dict.fromkeys(host_key(pin) for pin in pins))
        hosts = await AllowListResolver(self.config, self.cache).resolve(
            repo_keys
        )
        unresolved = {
            repo_key: UNRESOLVED_REASON
            for repo_key, release in hosts.items()
            if release is None
        }
        for repo_key in unresolved:
            self.logger.warning(
                f"Allow-list check skipped for {repo_key}: {UNRESOLVED_REASON}"
            )

        findings = classify_pins(pins, hosts, verify=settings.verify)
        return AllowListOutcome(
            findings=findings,
            hosts=hosts,
            unresolved=unresolved,
            suppressed_count=sum(1 for f in findings if f.suppressed),
            checked=True,
        )

    def _scan(self, paths: Iterable[Path], root: Path) -> list[AllowListPin]:
        """Detect every allow-list pin in the given files.

        Args:
            paths: Files to scan.
            root: Repository root, for workflow-org inference.

        Returns:
            The pins found, flattened into scan order.
        """
        settings = self.config.allow_list
        org = resolve_workflow_org(root, configured=settings.org)
        if not org:
            self.logger.debug(
                "Workflow org could not be determined; shorthand "
                "'@<sha>' pins will be skipped"
            )

        scanner = AllowListScanner(
            self.config,
            org,
            key_patterns=settings.key_patterns,
            filename=settings.filename,
        )
        return [
            pin
            for file_pins in scanner.scan_files(paths).values()
            for pin in file_pins
        ]


def _empty_outcome() -> AllowListOutcome:
    """Build the outcome of a check that did not run.

    Returns:
        An outcome with ``checked`` set to ``False`` and no findings.
    """
    return AllowListOutcome(
        findings=[],
        hosts={},
        unresolved={},
        suppressed_count=0,
        checked=False,
    )
