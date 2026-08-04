# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Detection of allow-list pins in workflow and action YAML.

An allow-list pin is a ``uses:``-style coordinate naming a file in a
host repository, written as the value of an ordinary workflow input.
Dependabot cannot see those coordinates, so they drift. Finding them is
the first half of the job; this module is that half, and nothing more --
it performs no network, cache or filesystem work beyond reading the file
it was asked to scan.

Detection runs in two stages, as set out in section 5.1 of
``docs/ALLOW_LIST_FEATURE.md``.

**Stage 1, structural identification.** The composed YAML node tree from
:meth:`~gha_workflow_linter.scanner.WorkflowScanner.compose_workflow_file`
is walked, and candidate scalars are collected from three locations:

1. ``jobs.<job>.steps[*].with.config`` -- the shared resolver's input is
   always named ``config``, so this location is anchored by structure.
2. ``on.workflow_call.inputs.<name>.default``.
3. ``jobs.<job>.with.<name>`` -- a reusable-workflow caller.

Locations 2 and 3 carry an arbitrary key name, so a scalar found there
qualifies only when the recogniser predicate accepts it: it must parse
under the grammar in :mod:`gha_workflow_linter.allow_list_spec` *and*
either name the conventional allow-list filename explicitly or sit under
a key whose name matches :data:`DEFAULT_KEY_PATTERNS`.

**Stage 2, lexical extraction.** Comments are lexical and do not survive
composition, so each candidate's source line is read back and the
version comment, quoting style and suppression directives are recovered
from it. Every pin therefore carries an exact anchor -- 1-based line,
0-based column -- that a later fixer can rewrite without re-parsing.

There is deliberately **no per-consumer registry** (section 5.4). Every
allow-list consumer shares one grammar, one resolver and one host
repository, and staleness never depends on the consumer family, so
detection keys on syntax alone. A new consumer is covered on the day it
appears, with no code change here.

The two-position comment problem (section 2) is handled throughout: the
version comment may be a YAML comment *outside* the quotes, which PyYAML
discards, or an in-scalar comment *inside* them, which the action's own
``split_comment`` strips. Both are recognised, the in-scalar form takes
precedence when both are present, and :attr:`AllowListPin.comment_position`
records which form was found so a rewrite can preserve it.

Note:
    A scalar that fails to parse under the grammar is skipped with a
    debug log wherever it is found, including the anchored ``config``
    location. Section 5.4 is explicit that the failure mode for an
    unrelated ``config:`` value must be a skip rather than a false
    finding, and :class:`AllowListPin` has no representation for a spec
    that did not resolve. Reporting a genuinely broken coordinate as
    ``INVALID_SPEC`` (section 7.2) belongs to the orchestrator, which
    knows which action consumes the input.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import fnmatch
import logging
from typing import TYPE_CHECKING

import yaml

from .allow_list_spec import (
    DEFAULT_FILENAME,
    SpecError,
    resolve_spec,
    split_comment,
)
from .directives import find_suppression, parse_trailing_comment
from .scanner import WorkflowScanner

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence
    from pathlib import Path

    from .allow_list_spec import ResolvedSpec
    from .directives import Directive, Suppression, SuppressionSource
    from .models import Config

__all__ = [
    "DEFAULT_KEY_PATTERNS",
    "AllowListPin",
    "AllowListScanner",
    "CommentPosition",
    "QuoteStyle",
]

#: Key-name patterns recognised as allow-list coordinates where the key
#: name is arbitrary (locations 2 and 3). Matched with :mod:`fnmatch`,
#: case-insensitively. ``allow_list`` and ``allowlist`` are distinct
#: spellings under glob matching, so both are listed.
DEFAULT_KEY_PATTERNS: tuple[str, ...] = (
    "*allow_list*",
    "*allowlist*",
    "*allow-list*",
)

#: Marker introducing a GitHub expression. A value holding one is
#: resolved at run time and is not a pin.
_EXPRESSION_MARKER = "${{"


class QuoteStyle(str, Enum):
    """How a scalar is quoted in the source."""

    NONE = "none"
    SINGLE = "single"
    DOUBLE = "double"


class CommentPosition(str, Enum):
    """Which of the two comment positions carried the version.

    Attributes:
        NONE: The pin has no trailing comment in either position.
        YAML: A YAML comment, with the ``#`` outside the quotes. PyYAML
            discards it, and the action never sees it. Every pin in the
            current estate uses this form.
        IN_SCALAR: A comment inside the quotes, part of the scalar,
            stripped by the action's own ``split_comment``.
    """

    NONE = "none"
    YAML = "yaml"
    IN_SCALAR = "in_scalar"


@dataclass(frozen=True)
class AllowListPin:
    """A detected allow-list coordinate in a workflow file.

    Attributes:
        file_path: File the pin was found in.
        line_number: 1-based line of the scalar's first character.
        column: 0-based column of the scalar's first character. For a
            quoted scalar this is the opening quote, not the first
            character of the value.
        key_path: Document path to the scalar, with sequence indices
            rendered as decimal strings, for example
            ``("jobs", "build", "steps", "0", "with", "config")``.
        raw_line: The source line, without its line ending.
        raw_value: The scalar as written, with any in-scalar comment
            removed and surrounding whitespace left intact.
        quote_style: Quoting inferred from the source text at ``column``.
        version_comment: Version token of the effective trailing comment,
            or ``None`` when there is no comment or it carries only
            directives.
        comment_position: Which position the effective comment came from.
        directives: Suppression directives in force for this pin. Empty
            when none apply.
        suppressed_by: Where the suppression was authored, or ``None``
            when the pin is not suppressed.
        suppression_reason: Free text the suppression carried, if any.
        spec: The coordinate resolved into lookup components.
        auto_fixable: ``False`` for a scalar spanning several lines,
            which is recorded and reported but never rewritten.
    """

    file_path: Path
    line_number: int
    column: int
    key_path: tuple[str, ...]
    raw_line: str
    raw_value: str
    quote_style: QuoteStyle
    version_comment: str | None
    comment_position: CommentPosition
    directives: frozenset[Directive]
    suppressed_by: SuppressionSource | None
    suppression_reason: str | None
    spec: ResolvedSpec
    auto_fixable: bool


@dataclass(frozen=True)
class _Candidate:
    """A scalar the structural walk offered for recognition.

    Attributes:
        node: The scalar node, carrying the source marks.
        key_path: Document path to the scalar.
        key_name: Name of the mapping key holding the scalar.
        anchored: True when the location itself identifies the input
            (``with.config`` on a step), so the recogniser predicate for
            arbitrary key names does not apply.
    """

    node: yaml.nodes.ScalarNode
    key_path: tuple[str, ...]
    key_name: str
    anchored: bool


@dataclass(frozen=True)
class _Lexical:
    """Facts recovered from the source line rather than the node tree.

    Attributes:
        raw_line: The source line, without its line ending.
        quote_style: Quoting inferred at the scalar's start column.
        auto_fixable: False when the scalar spans several lines.
        comments: The trailing comments found, most authoritative first.
            Empty when the pin carries no comment at all.
        position: Which position the first comment came from.
    """

    raw_line: str
    quote_style: QuoteStyle
    auto_fixable: bool
    comments: tuple[str, ...]
    position: CommentPosition


def _key_text(node: yaml.nodes.ScalarNode) -> str:
    """Return a key node's raw text.

    Args:
        node: A scalar key node.

    Returns:
        The key exactly as written in the source. This is deliberately
        the raw text rather than a constructed value: under YAML 1.1 a
        bare ``on:`` key resolves to the boolean ``True``, but the
        composed node still holds ``"on"``.
    """
    return str(node.value)


def _mapping_pairs(
    node: yaml.nodes.Node | None,
) -> list[tuple[yaml.nodes.ScalarNode, yaml.nodes.Node]]:
    """Return a node's ``(key, value)`` pairs when it is a mapping.

    Args:
        node: Any node, or ``None``.

    Returns:
        The mapping's pairs in document order, restricted to those with
        a scalar key. An empty list for any other node, so a caller can
        walk a malformed or unexpected document without guarding every
        step.
    """
    if not isinstance(node, yaml.nodes.MappingNode):
        return []
    pairs: list[tuple[yaml.nodes.ScalarNode, yaml.nodes.Node]] = []
    for key_node, value_node in node.value:
        if isinstance(key_node, yaml.nodes.ScalarNode):
            pairs.append((key_node, value_node))
    return pairs


def _child(node: yaml.nodes.Node | None, key: str) -> yaml.nodes.Node | None:
    """Return the value node of ``key`` within a mapping node.

    Args:
        node: The mapping to look in, or ``None``.
        key: Raw key text to match, compared exactly.

    Returns:
        The value node, or ``None`` when the node is not a mapping or
        holds no such key.
    """
    for key_node, value_node in _mapping_pairs(node):
        if _key_text(key_node) == key:
            return value_node
    return None


def _is_trigger_key(node: yaml.nodes.ScalarNode) -> bool:
    """Report whether a top-level key is the workflow trigger block.

    Under YAML 1.1, which ``SafeLoader`` implements, ``on`` is a boolean
    spelling: a document constructed with ``yaml.safe_load`` has the key
    ``True``, not ``"on"``. Walking the *composed* tree sidesteps that,
    because the key node keeps its raw text and only its tag changes.
    Matching on the raw text is therefore both correct and immune to the
    retagging; the tag is deliberately not consulted.

    Args:
        node: A top-level key node.

    Returns:
        True when the key is ``on`` in any capitalisation.
    """
    return _key_text(node).lower() == "on"


def _collect_step_configs(
    steps_node: yaml.nodes.Node | None, job: str
) -> Iterator[_Candidate]:
    """Yield ``with.config`` scalars from a job's steps (location 1).

    Args:
        steps_node: The job's ``steps`` node, or ``None``.
        job: Job name, for the key path.

    Yields:
        One candidate per step carrying a scalar ``with.config``.
    """
    if not isinstance(steps_node, yaml.nodes.SequenceNode):
        return
    for index, step in enumerate(steps_node.value):
        config = _child(_child(step, "with"), "config")
        if isinstance(config, yaml.nodes.ScalarNode):
            yield _Candidate(
                node=config,
                key_path=(
                    "jobs",
                    job,
                    "steps",
                    str(index),
                    "with",
                    "config",
                ),
                key_name="config",
                anchored=True,
            )


def _collect_job_inputs(
    with_node: yaml.nodes.Node | None, job: str
) -> Iterator[_Candidate]:
    """Yield a reusable-workflow caller's inputs (location 3).

    Args:
        with_node: The job's ``with`` node, or ``None``.
        job: Job name, for the key path.

    Yields:
        One candidate per scalar input. Recognition happens later.
    """
    for key_node, value_node in _mapping_pairs(with_node):
        if isinstance(value_node, yaml.nodes.ScalarNode):
            name = _key_text(key_node)
            yield _Candidate(
                node=value_node,
                key_path=("jobs", job, "with", name),
                key_name=name,
                anchored=False,
            )


def _collect_jobs(jobs_node: yaml.nodes.Node | None) -> Iterator[_Candidate]:
    """Yield every candidate beneath the ``jobs`` block.

    Args:
        jobs_node: The document's ``jobs`` node, or ``None``.

    Yields:
        Candidates from locations 1 and 3, job by job.
    """
    for key_node, job_node in _mapping_pairs(jobs_node):
        job = _key_text(key_node)
        yield from _collect_step_configs(_child(job_node, "steps"), job)
        yield from _collect_job_inputs(_child(job_node, "with"), job)


def _collect_input_defaults(
    on_node: yaml.nodes.Node | None, on_key: str
) -> Iterator[_Candidate]:
    """Yield ``workflow_call`` input defaults (location 2).

    Args:
        on_node: The trigger block's value node, or ``None``. A trigger
            block written as a scalar or a sequence yields nothing.
        on_key: The trigger key exactly as written, for the key path.

    Yields:
        One candidate per input carrying a scalar default.
    """
    inputs = _child(_child(on_node, "workflow_call"), "inputs")
    for key_node, input_node in _mapping_pairs(inputs):
        default = _child(input_node, "default")
        if isinstance(default, yaml.nodes.ScalarNode):
            name = _key_text(key_node)
            yield _Candidate(
                node=default,
                key_path=(on_key, "workflow_call", "inputs", name, "default"),
                key_name=name,
                anchored=False,
            )


def _collect_candidates(root: yaml.nodes.Node) -> list[_Candidate]:
    """Walk a composed document for all three detection locations.

    Args:
        root: Root node of the composed tree.

    Returns:
        Every candidate scalar, in document order.
    """
    candidates: list[_Candidate] = []
    for key_node, value_node in _mapping_pairs(root):
        if _is_trigger_key(key_node):
            candidates.extend(
                _collect_input_defaults(value_node, _key_text(key_node))
            )
        elif _key_text(key_node) == "jobs":
            candidates.extend(_collect_jobs(value_node))
    return candidates


def _quote_style(raw_line: str, column: int) -> QuoteStyle:
    """Infer a scalar's quoting from the source text.

    Args:
        raw_line: The source line holding the scalar.
        column: 0-based column the scalar starts at.

    Returns:
        The quoting style. A block scalar, whose start mark points at
        its ``|`` or ``>`` indicator, reports :attr:`QuoteStyle.NONE`.
    """
    if column < 0 or column >= len(raw_line):
        return QuoteStyle.NONE
    character = raw_line[column]
    if character == "'":
        return QuoteStyle.SINGLE
    if character == '"':
        return QuoteStyle.DOUBLE
    return QuoteStyle.NONE


def _yaml_comment(raw_line: str, end_column: int) -> str | None:
    """Recover a YAML comment written after a scalar on its own line.

    The same rule the action applies inside the scalar is applied here:
    the ``#`` must be preceded by at least one space or tab, so a ``#``
    abutting the value does not start a comment.

    Args:
        raw_line: The source line holding the scalar.
        end_column: 0-based column just past the scalar's last
            character, which for a quoted scalar is just past its
            closing quote.

    Returns:
        The comment text without its marker, or ``None`` when the line
        carries no comment after the scalar.
    """
    _, comment = split_comment(raw_line[end_column:])
    return comment or None


def _preceding_comment_line(lines: Sequence[str], index: int) -> str | None:
    """Return the immediately preceding line when it is a comment.

    A preceding-line directive binds to exactly one pin, so a blank line
    or any content between the two breaks the binding.

    Args:
        lines: The file's lines, without line endings.
        index: 0-based index of the pinned line.

    Returns:
        The preceding line, or ``None`` when there is none or it is not
        a comment.
    """
    if index <= 0 or index > len(lines):
        return None
    previous = lines[index - 1]
    return previous if previous.lstrip().startswith("#") else None


def _matches_key_pattern(name: str, patterns: Sequence[str]) -> bool:
    """Report whether a key name matches any configured pattern.

    Args:
        name: The mapping key holding the scalar.
        patterns: fnmatch patterns.

    Returns:
        True when any pattern matches, compared case-insensitively.
        :func:`fnmatch.fnmatchcase` is used over both lowered operands
        so the verdict does not vary with the host filesystem.
    """
    lowered = name.lower()
    return any(
        fnmatch.fnmatchcase(lowered, pattern.lower()) for pattern in patterns
    )


def _names_conventional_filename(spec: ResolvedSpec, filename: str) -> bool:
    """Report whether the author *wrote* the conventional filename.

    The test is deliberately made against the source subpath rather than
    against the resolved
    :attr:`~gha_workflow_linter.allow_list_spec.ResolvedSpec.candidates`.
    An omitted filename defaults to the conventional one, so every
    resolved candidate chain ends in it and testing the chain would
    accept any string that happens to parse. Requiring the author to
    have named the file keeps the predicate conservative, which is the
    stated intent of section 5.1.

    Args:
        spec: The resolved coordinate.
        filename: The conventional allow-list filename.

    Returns:
        True when the coordinate carries a subpath whose last segment is
        ``filename``.
    """
    subpath = spec.source.subpath
    if not spec.source.has_subpath or not subpath:
        return False
    return subpath.rsplit("/", 1)[-1] == filename


class AllowListScanner:
    """Find allow-list pins, with exact source anchors, in YAML files.

    Attributes:
        config: Linter configuration, supplying the file-reading and
            YAML-composition behaviour shared with the action-call scan.
        workflow_org: Org owning the workflow being scanned.
        key_patterns: Key-name patterns for the recogniser predicate.
        filename: Conventional allow-list filename.

    Note:
        ``workflow_org`` is not optional in practice. The shorthand
        ``@<sha>`` form, which every internal workflow uses, has no host
        org of its own and takes it from here; an empty or invalid org
        makes those coordinates unparsable, and they are then skipped
        with a debug log like any other unparsable scalar. Callers
        determine the org as described in section 6.3 of the design.
    """

    def __init__(
        self,
        config: Config,
        workflow_org: str,
        *,
        key_patterns: Sequence[str] | None = None,
        filename: str = DEFAULT_FILENAME,
    ) -> None:
        """Initialise the scanner.

        Args:
            config: Linter configuration.
            workflow_org: Org owning the workflow being scanned. It
                supplies the host org when a coordinate omits it.
            key_patterns: Key-name patterns recognised in locations 2
                and 3. Defaults to :data:`DEFAULT_KEY_PATTERNS`.
            filename: Conventional allow-list filename, the other half
                of the recogniser predicate.
        """
        self.config = config
        self.workflow_org = workflow_org
        self.key_patterns = tuple(
            DEFAULT_KEY_PATTERNS if key_patterns is None else key_patterns
        )
        self.filename = filename
        self.logger = logging.getLogger(__name__)
        self._scanner = WorkflowScanner(config)

    def scan_file(self, file_path: Path) -> list[AllowListPin]:
        """Return every allow-list pin in one workflow or action file.

        Args:
            file_path: Path to the file to scan.

        Returns:
            The pins found, in document order. Empty when the file
            cannot be read, is not valid YAML, is empty, or holds no
            recognised coordinate. Never raises for a bad file.
        """
        root = self._scanner.compose_workflow_file(file_path)
        if root is None:
            return []

        # Comments are lexical and absent from the composed tree, so the
        # source is read back for the version comment, the quoting style
        # and any suppression directive.
        try:
            lines = file_path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as error:
            self.logger.warning(f"Error reading file {file_path}: {error}")
            return []

        pins: list[AllowListPin] = []
        for candidate in _collect_candidates(root):
            pin = self._build_pin(candidate, file_path, lines)
            if pin is not None:
                pins.append(pin)

        self.logger.debug(f"Found {len(pins)} allow-list pins in {file_path}")
        return pins

    def scan_files(
        self, paths: Iterable[Path]
    ) -> dict[Path, list[AllowListPin]]:
        """Scan several files, keeping only those that hold pins.

        Args:
            paths: Files to scan.

        Returns:
            Mapping of file path to its pins, in scan order. Files
            without pins are omitted, matching the convention of
            :meth:`~gha_workflow_linter.scanner.WorkflowScanner.scan_directory`.
        """
        results: dict[Path, list[AllowListPin]] = {}
        for path in paths:
            pins = self.scan_file(path)
            if pins:
                results[path] = pins
        return results

    def _resolve_candidate(self, candidate: _Candidate) -> ResolvedSpec | None:
        """Apply the skip rules and the recogniser to one candidate.

        Args:
            candidate: A scalar offered by the structural walk.

        Returns:
            The resolved coordinate, or ``None`` when the scalar is not
            a pin. Every rejection is logged at debug level and none
            produces a finding (design sections 5.2 and 5.4).
        """
        text = str(candidate.node.value)
        key = ".".join(candidate.key_path)

        if _EXPRESSION_MARKER in text:
            self.logger.debug(
                f"Skipping {key}: value is a GitHub expression, not a pin"
            )
            return None

        try:
            spec = resolve_spec(text, workflow_org=self.workflow_org)
        except SpecError as error:
            self.logger.debug(f"Skipping {key}: not a config spec ({error})")
            return None

        if candidate.anchored:
            return spec
        if _names_conventional_filename(spec, self.filename):
            return spec
        if _matches_key_pattern(candidate.key_name, self.key_patterns):
            return spec

        self.logger.debug(
            f"Skipping {key}: parses as a spec but names neither "
            f"'{self.filename}' nor a recognised key"
        )
        return None

    def _lexical_context(
        self,
        node: yaml.nodes.ScalarNode,
        in_scalar_comment: str,
        lines: Sequence[str],
    ) -> _Lexical:
        """Recover the source-level facts around a candidate scalar.

        Args:
            node: The candidate scalar node.
            in_scalar_comment: Comment found inside the scalar, ``""``
                when it has none.
            lines: The file's lines, without line endings.

        Returns:
            The quoting, fixability and trailing comments of the pin.
            The in-scalar comment is listed first when present, because
            it is the one the action itself sees; a YAML comment on the
            same line follows it. A multi-line scalar contributes no
            YAML comment, since its end mark is on another line.
        """
        start = node.start_mark
        raw_line = lines[start.line] if start.line < len(lines) else ""
        multiline = start.line != node.end_mark.line

        yaml_comment = (
            None if multiline else _yaml_comment(raw_line, node.end_mark.column)
        )
        comments = tuple(
            comment
            for comment in (in_scalar_comment or None, yaml_comment)
            if comment is not None
        )
        if in_scalar_comment:
            position = CommentPosition.IN_SCALAR
        elif yaml_comment is not None:
            position = CommentPosition.YAML
        else:
            position = CommentPosition.NONE

        return _Lexical(
            raw_line=raw_line,
            quote_style=_quote_style(raw_line, start.column),
            auto_fixable=not multiline,
            comments=comments,
            position=position,
        )

    def _find_suppression(
        self, lexical: _Lexical, line_index: int, lines: Sequence[str]
    ) -> Suppression | None:
        """Resolve the suppression in force for one pin.

        Either comment position may carry the inline directive, so each
        is offered in turn, most authoritative first. The preceding-line
        form is checked on every attempt, which is harmless: the first
        call already returns it when no inline directive exists.

        Args:
            lexical: The pin's recovered source facts.
            line_index: 0-based index of the pinned line.
            lines: The file's lines, without line endings.

        Returns:
            The effective suppression, or ``None`` when neither form
            declares a directive.
        """
        preceding = _preceding_comment_line(lines, line_index)
        comments: tuple[str | None, ...] = lexical.comments or (None,)
        for comment in comments:
            suppression = find_suppression(
                comment=comment, preceding_line=preceding
            )
            if suppression is not None:
                return suppression
        return None

    def _build_pin(
        self,
        candidate: _Candidate,
        file_path: Path,
        lines: Sequence[str],
    ) -> AllowListPin | None:
        """Turn a recognised candidate into a fully anchored pin.

        Args:
            candidate: A scalar offered by the structural walk.
            file_path: File the scalar was found in.
            lines: The file's lines, without line endings.

        Returns:
            The pin, or ``None`` when the candidate is not one.
        """
        spec = self._resolve_candidate(candidate)
        if spec is None:
            return None

        node = candidate.node
        raw_value, in_scalar_comment = split_comment(str(node.value))
        lexical = self._lexical_context(node, in_scalar_comment, lines)
        suppression = self._find_suppression(
            lexical, node.start_mark.line, lines
        )
        effective = lexical.comments[0] if lexical.comments else None

        return AllowListPin(
            file_path=file_path,
            line_number=node.start_mark.line + 1,
            column=node.start_mark.column,
            key_path=candidate.key_path,
            raw_line=lexical.raw_line,
            raw_value=raw_value,
            quote_style=lexical.quote_style,
            version_comment=parse_trailing_comment(effective).version,
            comment_position=lexical.position,
            directives=(
                suppression.directives
                if suppression is not None
                else frozenset()
            ),
            suppressed_by=(
                suppression.source if suppression is not None else None
            ),
            suppression_reason=(
                suppression.reason if suppression is not None else None
            ),
            spec=spec,
            auto_fixable=lexical.auto_fixable,
        )
