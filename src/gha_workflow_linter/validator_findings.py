# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Reference-level findings and the remediation messages they produce.

Both validation backends report a bare boolean per reference. That is all
the pass/fail decision needs, but it discards *why* a reference failed, so
a SHA that names an annotated tag object is indistinguishable from a
reference that simply does not exist — even though the two need very
different advice. :class:`ReferenceFinding` carries the specific verdict
plus the context needed to say what to use instead.

This module holds the whole of that concern: constructing findings from
backend results and recorded tag peels, narrowing a failure to its most
specific known :class:`~gha_workflow_linter.models.ValidationResult`, and
rendering the human-readable message for a result. It is kept separate
from :mod:`gha_workflow_linter.validator` because none of it needs the
validator's state — no clients, no cache, no configuration — and because
messaging changes far more often than the orchestration around it.

Nothing here imports :mod:`gha_workflow_linter.validator`; the dependency
runs one way only.
"""

from __future__ import annotations

from collections.abc import Mapping
import dataclasses
from typing import TYPE_CHECKING, Any

from .models import (
    ActionCall,
    Category,
    ReferenceType,
    ValidationError,
    ValidationResult,
    result_category,
)
from .paths import action_subpath, base_repository

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from .git_refs import AnnotatedTagPeel

__all__ = [
    "SPECIFIC_REF_RESULTS",
    "ReferenceFinding",
    "build_validation_errors",
    "cache_verdict",
    "client_peels",
    "get_error_message",
    "merge_cached_findings",
    "peel_findings",
    "specific_ref_result",
]


@dataclasses.dataclass(frozen=True)
class ReferenceFinding:
    """Why a reference failed validation, with remediation context.

    Both validation backends report a bare boolean per reference, which is
    all the pass/fail decision needs but throws away *why* a reference
    failed. This record carries the specific verdict alongside it so an
    annotated tag-object SHA is not reported as a generic invalid
    reference, together with the context needed to say what to use instead.

    Attributes:
        result: The specific validation result. Never
            ``ValidationResult.VALID``; findings exist only for failures.
        peel: For ``ANNOTATED_TAG_SHA``, the tag and commit behind the
            pinned tag object. None when unavailable (for example when the
            finding was restored from cache).
        message: A pre-rendered error message, used when a cached finding
            is replayed and the peel itself was not persisted.
    """

    result: ValidationResult
    peel: AnnotatedTagPeel | None = None
    message: str | None = None


#: Reference-level verdicts that are more specific than the generic
#: ``INVALID_REFERENCE`` and are definite enough to persist in the cache.
#: ``INVALID_REFERENCE`` itself is omitted because it is the fallback the
#: absence of a finding already implies.
SPECIFIC_REF_RESULTS: frozenset[ValidationResult] = frozenset(
    {ValidationResult.ANNOTATED_TAG_SHA}
)

#: Static, context-free message per validation result. A result absent
#: from this mapping falls back to a generic string.
_RESULT_MESSAGES: dict[ValidationResult, str] = {
    ValidationResult.INVALID_REPOSITORY: "Repository not found",
    ValidationResult.INVALID_REFERENCE: "Invalid branch, tag, or commit SHA",
    ValidationResult.INVALID_PATH: "Subdirectory action path not found at reference",
    ValidationResult.INVALID_SYNTAX: "Invalid action call syntax",
    ValidationResult.NETWORK_ERROR: "Network error during validation",
    ValidationResult.TIMEOUT: "Timeout during validation",
    ValidationResult.NOT_PINNED_TO_SHA: "Action not pinned to commit SHA",
    ValidationResult.TEST_REFERENCE: "Test action reference",
    ValidationResult.ANNOTATED_TAG_SHA: (
        "Reference is an annotated tag object SHA, not a commit; "
        "GitHub Actions cannot check this out"
    ),
}


def client_peels(
    client: object,
) -> Mapping[tuple[str, str], AnnotatedTagPeel]:
    """Read the annotated tag peels a validation backend recorded.

    Both backends expose ``annotated_tag_peels``, but it is an optional
    enrichment rather than part of the validation contract: a client
    that does not surface a real mapping simply yields no remediation
    context, and reporting falls back to the generic verdict.

    Args:
        client: The validation backend to read peels from.

    Returns:
        The backend's peel mapping, or an empty mapping.
    """
    peels = getattr(client, "annotated_tag_peels", None)
    return peels if isinstance(peels, Mapping) else {}


def peel_findings(
    ref_results: dict[tuple[str, str], bool],
    peels: Mapping[tuple[str, str], AnnotatedTagPeel],
) -> dict[tuple[str, str], ReferenceFinding]:
    """Build ``ANNOTATED_TAG_SHA`` findings from recorded peels.

    Args:
        ref_results: Pass/fail verdict per ``(repo_key, ref)``.
        peels: Peels the backend recorded for tag-object SHAs.

    Returns:
        A finding for every failing reference that names a tag object.
    """
    return {
        repo_ref: ReferenceFinding(
            result=ValidationResult.ANNOTATED_TAG_SHA, peel=peel
        )
        for repo_ref, peel in peels.items()
        if not ref_results.get(repo_ref, False)
    }


def specific_ref_result(
    finding: ReferenceFinding | None,
) -> ValidationResult:
    """Narrow a reference failure to its most specific known result.

    Infrastructure failures (a network error or timeout affecting one
    repository, rather than aborting the whole run) are surfaced as
    themselves. Collapsing them to ``INVALID_REFERENCE`` would tell the
    reader their reference is wrong when the check merely could not run,
    and would leave the summary's ``network_errors`` and ``timeouts``
    counters permanently at zero. Caching already refuses these results
    via ``result_category(...) is Category.INFRASTRUCTURE``, so a
    transient failure is retried rather than persisted as a verdict.

    Args:
        finding: The recorded failure, if any.

    Returns:
        The specific result when one was recorded, otherwise the generic
        ``INVALID_REFERENCE``.
    """
    if finding is None:
        return ValidationResult.INVALID_REFERENCE
    if finding.result in SPECIFIC_REF_RESULTS:
        return finding.result
    if result_category(finding.result) is Category.INFRASTRUCTURE:
        return finding.result
    return ValidationResult.INVALID_REFERENCE


def get_error_message(
    result: ValidationResult,
    finding: ReferenceFinding | None = None,
) -> str:
    """Get human-readable error message for validation result.

    Args:
        result: ValidationResult enum value.
        finding: Optional context for a reference-level failure. When
            it carries a peel (or a message replayed from cache) the
            ``ANNOTATED_TAG_SHA`` message names the tag and the commit
            to use instead; otherwise the static message is returned.

    Returns:
        Error message string.
    """
    if result == ValidationResult.ANNOTATED_TAG_SHA and finding is not None:
        if finding.peel is not None:
            return (
                f"Reference is the SHA of the annotated tag object for "
                f"{finding.peel.tag}, not a commit. GitHub Actions "
                f"cannot check out a tag object. Use the peeled commit "
                f"instead: {finding.peel.commit_sha}"
            )
        if finding.message:
            return finding.message

    return _RESULT_MESSAGES.get(result, "Unknown validation error")


def merge_cached_findings(
    ref_findings: dict[tuple[str, str], ReferenceFinding],
    cached_results: dict[tuple[str, str], Any],
) -> None:
    """Fold cached reference-level failures into the fresh findings.

    A verdict such as ``ANNOTATED_TAG_SHA`` is definite and therefore
    cached, so a cache hit must reproduce the same specific result and
    message rather than degrading to a generic invalid reference. The
    peel itself is not persisted; the rendered message is.

    Args:
        ref_findings: Findings from this run, updated in place. Fresh
            entries win, since a cached ref is never re-validated.
        cached_results: Cached entries keyed by ``(repo, ref)``.

    Returns:
        None. ``ref_findings`` is mutated in place.
    """
    for key, cached_entry in cached_results.items():
        result = cached_entry.result
        if key in ref_findings or result not in SPECIFIC_REF_RESULTS:
            continue
        ref_findings[key] = ReferenceFinding(
            result=result, message=cached_entry.error_message
        )


def cache_verdict(
    repo: str,
    ref: str,
    finding: ReferenceFinding | None,
    repo_valid: bool,
    ref_valid: bool,
    subpath_valid: bool,
) -> tuple[ValidationResult, str | None]:
    """Derive the result and message to persist for one validated ref.

    The stages report repository, reference and subpath validity
    independently; this collapses them into the single verdict a cache
    entry carries, naming the repository, reference or subpath that
    actually failed so a cache replay reads as well as a live run.

    Args:
        repo: Repository key, including any action subpath.
        ref: The branch, tag or SHA that was validated.
        finding: Specific reference failure, if one was recorded.
        repo_valid: Whether the repository validated.
        ref_valid: Whether the reference validated.
        subpath_valid: Whether the action subpath validated. Refs without
            a subpath are always valid here.

    Returns:
        Tuple of the verdict and its error message, the message being
        None when the verdict is ``ValidationResult.VALID``.
    """
    if repo_valid and ref_valid and subpath_valid:
        return ValidationResult.VALID, None
    if not repo_valid:
        return (
            ValidationResult.INVALID_REPOSITORY,
            f"Repository {repo} not found or not accessible",
        )
    if not ref_valid:
        result = specific_ref_result(finding)
        return result, (
            get_error_message(result, finding)
            if result != ValidationResult.INVALID_REFERENCE
            else f"Reference {ref} not found in repository {repo}"
        )
    return (
        ValidationResult.INVALID_PATH,
        f"Subdirectory path '{action_subpath(repo)}' not found in "
        f"{base_repository(repo)} at {ref}",
    )


def build_validation_errors(
    validation_results: dict[str, ValidationResult],
    call_locations: dict[str, list[tuple[Path, ActionCall]]],
    unique_calls: dict[str, ActionCall],
    ref_key: Callable[[ActionCall], tuple[str, str]],
    require_pinned_sha: bool,
    ref_findings: dict[tuple[str, str], ReferenceFinding] | None = None,
) -> list[ValidationError]:
    """Turn per-call validation results into ``ValidationError`` records.

    Args:
        validation_results: Per-call verdicts keyed by call key.
        call_locations: Where each call key appears in the workflows.
        unique_calls: The deduplicated calls, keyed by call key.
        ref_key: Maps a call to the ``(repo_key, ref)`` the reference
            stages keyed their results by. Supplied by the caller because
            deriving it depends on how a call names its repository.
        require_pinned_sha: Whether a valid call that is not pinned to a
            commit SHA should additionally be reported as an error.
        ref_findings: Specific reference failures keyed by
            ``(repo_key, ref)``, used to render a remediation message
            (for example the peeled commit behind a tag object).

    Returns:
        List of validation errors, one per occurrence of a failing call.
    """
    findings = ref_findings or {}
    errors: list[ValidationError] = []
    for call_key, result in validation_results.items():
        if result != ValidationResult.VALID:
            for file_path, action_call in call_locations[call_key]:
                finding = findings.get(ref_key(action_call))
                errors.append(
                    ValidationError(
                        file_path=file_path,
                        action_call=action_call,
                        result=result,
                        error_message=get_error_message(result, finding),
                    )
                )

    if require_pinned_sha:
        for call_key, action_call in unique_calls.items():
            if (
                validation_results.get(call_key) == ValidationResult.VALID
                and action_call.reference_type != ReferenceType.COMMIT_SHA
            ):
                for file_path, actual_action_call in call_locations[call_key]:
                    errors.append(
                        ValidationError(
                            file_path=file_path,
                            action_call=actual_action_call,
                            result=ValidationResult.NOT_PINNED_TO_SHA,
                            error_message=get_error_message(
                                ValidationResult.NOT_PINNED_TO_SHA
                            ),
                        )
                    )
    return errors
