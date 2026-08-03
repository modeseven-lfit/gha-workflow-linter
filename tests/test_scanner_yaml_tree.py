# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for the scanner's composed YAML node tree.

``WorkflowScanner.compose_workflow_file`` exposes PyYAML's node tree so
consumers can map document structure back onto source positions. These
tests pin the guarantees that API makes -- source marks, the failure
contract -- and, just as importantly, document two things it does *not*
guarantee: comments survive, and a bare ``on:`` key stays a string.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml

from gha_workflow_linter.models import Config
from gha_workflow_linter.scanner import WorkflowScanner

# Line numbers in the assertions below are 0-based indices into this
# string, matching PyYAML's ``Mark.line``. The comments name each index
# so the fixture and the assertions cannot drift apart silently.
WORKFLOW = """\
---
name: Test Workflow

on:
  push:

jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      # Pin the action to a commit SHA
      - uses: actions/checkout@v5  # v5.0.0
"""
LINE_NAME = 1
LINE_ON = 3
LINE_PUSH = 4
LINE_JOBS = 6
LINE_RUNS_ON = 8
LINE_USES = 11


@pytest.fixture
def scanner() -> WorkflowScanner:
    """Return a scanner backed by the default configuration."""
    return WorkflowScanner(Config())


@pytest.fixture
def workflow_file(tmp_path: Path) -> Path:
    """Write ``WORKFLOW`` to a workflow file and return its path."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    path = workflows / "test.yaml"
    path.write_text(WORKFLOW, encoding="utf-8")
    return path


def mapping_pairs(
    node: yaml.nodes.Node,
) -> list[tuple[yaml.nodes.ScalarNode, yaml.nodes.Node]]:
    """
    Return the ``(key, value)`` node pairs of a composed mapping.

    Args:
        node: A node expected to be a ``MappingNode``.

    Returns:
        The mapping's pairs, in document order.
    """
    assert isinstance(node, yaml.nodes.MappingNode)
    pairs: list[tuple[yaml.nodes.ScalarNode, yaml.nodes.Node]] = []
    for key_node, value_node in node.value:
        assert isinstance(key_node, yaml.nodes.ScalarNode)
        assert isinstance(value_node, yaml.nodes.Node)
        pairs.append((key_node, value_node))
    return pairs


def key_nodes(node: yaml.nodes.Node) -> dict[str, yaml.nodes.ScalarNode]:
    """
    Return a composed mapping's key nodes, keyed by their raw text.

    Args:
        node: A node expected to be a ``MappingNode``.

    Returns:
        Mapping of raw key text to the key's scalar node.
    """
    return {str(key.value): key for key, _ in mapping_pairs(node)}


def value_nodes(node: yaml.nodes.Node) -> dict[str, yaml.nodes.Node]:
    """
    Return a composed mapping's value nodes, keyed by raw key text.

    Args:
        node: A node expected to be a ``MappingNode``.

    Returns:
        Mapping of raw key text to the key's value node.
    """
    return {str(key.value): value for key, value in mapping_pairs(node)}


class TestComposeWorkflowFile:
    """Test the composed node tree and its source marks."""

    def test_returns_root_mapping_node(
        self, scanner: WorkflowScanner, workflow_file: Path
    ) -> None:
        """A valid workflow composes to a mapping node."""
        root = scanner.compose_workflow_file(workflow_file)

        assert isinstance(root, yaml.nodes.MappingNode)
        assert list(key_nodes(root)) == ["name", "on", "jobs"]

    def test_scalar_nodes_carry_source_marks(
        self, scanner: WorkflowScanner, workflow_file: Path
    ) -> None:
        """Key and value nodes carry 0-based line and column marks."""
        root = scanner.compose_workflow_file(workflow_file)
        assert root is not None
        keys = key_nodes(root)

        assert keys["name"].start_mark.line == LINE_NAME
        assert keys["name"].start_mark.column == 0
        assert keys["on"].start_mark.line == LINE_ON
        assert keys["jobs"].start_mark.line == LINE_JOBS

    def test_value_nodes_carry_source_marks(
        self, scanner: WorkflowScanner, workflow_file: Path
    ) -> None:
        """Marks are available for values, not only for keys."""
        root = scanner.compose_workflow_file(workflow_file)
        assert root is not None

        name_value = value_nodes(root)["name"]
        assert isinstance(name_value, yaml.nodes.ScalarNode)
        assert name_value.value == "Test Workflow"
        assert name_value.start_mark.line == LINE_NAME
        # "name: " is six characters, so the value starts at column 6.
        assert name_value.start_mark.column == 6

    def test_marks_reach_nested_nodes(
        self, scanner: WorkflowScanner, workflow_file: Path
    ) -> None:
        """Marks survive into deeply nested mappings."""
        root = scanner.compose_workflow_file(workflow_file)
        assert root is not None

        build = value_nodes(value_nodes(root)["jobs"])["build"]
        runs_on = key_nodes(build)["runs-on"]

        assert runs_on.start_mark.line == LINE_RUNS_ON

    def test_marks_reach_sequence_items(
        self, scanner: WorkflowScanner, workflow_file: Path
    ) -> None:
        """Sequence entries carry marks too, not just mapping keys."""
        root = scanner.compose_workflow_file(workflow_file)
        assert root is not None

        build = value_nodes(value_nodes(root)["jobs"])["build"]
        steps = value_nodes(build)["steps"]
        assert isinstance(steps, yaml.nodes.SequenceNode)
        first_step = steps.value[0]
        assert isinstance(first_step, yaml.nodes.MappingNode)

        assert key_nodes(first_step)["uses"].start_mark.line == LINE_USES

    def test_end_marks_are_present(
        self, scanner: WorkflowScanner, workflow_file: Path
    ) -> None:
        """Nodes expose an end mark as well as a start mark."""
        root = scanner.compose_workflow_file(workflow_file)
        assert root is not None
        name_key = key_nodes(root)["name"]

        assert name_key.end_mark.line == LINE_NAME
        assert name_key.end_mark.column == len("name")


class TestComposeWorkflowFileFailureModes:
    """Test that composition never raises and returns None instead."""

    def test_invalid_yaml_returns_none(
        self,
        scanner: WorkflowScanner,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Malformed YAML yields None and a warning, not an exception."""
        path = tmp_path / "broken.yaml"
        path.write_text("name: Test\non: [push\njobs: {\n", encoding="utf-8")

        with caplog.at_level(logging.WARNING):
            assert scanner.compose_workflow_file(path) is None

        assert "Invalid YAML" in caplog.text

    def test_missing_file_returns_none(
        self,
        scanner: WorkflowScanner,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A non-existent path yields None and a warning."""
        path = tmp_path / "does-not-exist.yaml"

        with caplog.at_level(logging.WARNING):
            assert scanner.compose_workflow_file(path) is None

        assert "Error reading file" in caplog.text

    def test_unreadable_path_returns_none(
        self, scanner: WorkflowScanner, tmp_path: Path
    ) -> None:
        """A directory in place of a file yields None, not an OSError."""
        directory = tmp_path / "workflows"
        directory.mkdir()

        assert scanner.compose_workflow_file(directory) is None

    def test_empty_file_returns_none(
        self, scanner: WorkflowScanner, tmp_path: Path
    ) -> None:
        """An empty document composes to None, same as a failure.

        This is PyYAML's behaviour, not a decision of the scanner: there
        is no node to return. Callers that need to distinguish "empty"
        from "unparsable" must inspect the file themselves.
        """
        path = tmp_path / "empty.yaml"
        path.write_text("", encoding="utf-8")

        assert scanner.compose_workflow_file(path) is None

    def test_comment_only_file_returns_none(
        self, scanner: WorkflowScanner, tmp_path: Path
    ) -> None:
        """A file holding only comments is an empty document."""
        path = tmp_path / "comments.yaml"
        path.write_text("# just a comment\n", encoding="utf-8")

        assert scanner.compose_workflow_file(path) is None


class TestComposeWorkflowFileGotchas:
    """Document what the node tree deliberately does not carry."""

    def test_bare_on_key_resolves_to_yaml_11_boolean(
        self, scanner: WorkflowScanner, workflow_file: Path
    ) -> None:
        """A bare ``on:`` key is a YAML 1.1 boolean, not the string "on".

        ``SafeLoader`` implements YAML 1.1 resolution, where ``on`` is one
        of the boolean spellings. In the composed tree the key node keeps
        its raw text -- ``"on"`` -- but carries the *bool* tag, and any
        consumer that later constructs Python objects (``yaml.safe_load``)
        sees the key ``True``. A tree walker matching workflow triggers
        must therefore accept both ``"on"`` and ``True``.
        """
        root = scanner.compose_workflow_file(workflow_file)
        assert root is not None
        on_key = key_nodes(root)["on"]

        # In the node tree the key is still the raw text "on" ...
        assert on_key.value == "on"
        # ... but the resolver has already tagged it as a boolean.
        assert on_key.tag == "tag:yaml.org,2002:bool"

        # The trigger mapping underneath is unaffected and still marked.
        triggers = value_nodes(root)["on"]
        assert key_nodes(triggers)["push"].start_mark.line == LINE_PUSH

        # Confirm the consequence rather than assuming it: constructing
        # the same document produces the key True, not "on".
        loaded = yaml.safe_load(WORKFLOW)
        assert isinstance(loaded, dict)
        assert True in loaded
        assert "on" not in loaded
        assert list(loaded) == ["name", True, "jobs"]

    def test_other_keys_keep_the_string_tag(
        self, scanner: WorkflowScanner, workflow_file: Path
    ) -> None:
        """Only YAML 1.1 boolean spellings are retagged."""
        root = scanner.compose_workflow_file(workflow_file)
        assert root is not None
        keys = key_nodes(root)

        assert keys["name"].tag == "tag:yaml.org,2002:str"
        assert keys["jobs"].tag == "tag:yaml.org,2002:str"

    def test_comments_are_absent_from_the_node_tree(
        self, scanner: WorkflowScanner, workflow_file: Path
    ) -> None:
        """Comments are lexical and do not survive composition.

        The fixture carries both a standalone comment and a trailing
        ``# v5.0.0`` version pin. PyYAML drops both while scanning, so no
        node anywhere in the tree mentions them. Recovering a version-pin
        comment requires reading the source line, not the node tree.
        """
        root = scanner.compose_workflow_file(workflow_file)
        assert root is not None

        assert "# Pin the action to a commit SHA" in WORKFLOW
        assert "# v5.0.0" in WORKFLOW

        scalars = [
            str(node.value)
            for node in walk(root)
            if isinstance(node, yaml.nodes.ScalarNode)
        ]
        assert scalars
        assert not any("#" in value for value in scalars)

    def test_uses_scalar_excludes_its_trailing_comment(
        self, scanner: WorkflowScanner, workflow_file: Path
    ) -> None:
        """The ``uses:`` value stops before its trailing comment."""
        root = scanner.compose_workflow_file(workflow_file)
        assert root is not None

        uses_values = [
            str(node.value)
            for node in walk(root)
            if isinstance(node, yaml.nodes.ScalarNode)
            and str(node.value).startswith("actions/checkout")
        ]

        assert uses_values == ["actions/checkout@v5"]


def walk(node: yaml.nodes.Node) -> list[yaml.nodes.Node]:
    """
    Return ``node`` and every node beneath it, depth first.

    Args:
        node: Root of the subtree to walk.

    Returns:
        The subtree's nodes, starting with ``node`` itself.
    """
    nodes: list[yaml.nodes.Node] = [node]
    if isinstance(node, yaml.nodes.MappingNode):
        for key_node, value_node in mapping_pairs(node):
            nodes.extend(walk(key_node))
            nodes.extend(walk(value_node))
    elif isinstance(node, yaml.nodes.SequenceNode):
        for child in node.value:
            assert isinstance(child, yaml.nodes.Node)
            nodes.extend(walk(child))
    return nodes


class TestComposeSharesTheSyntaxGate:
    """Test that the refactored validity gate still behaves."""

    def test_parse_workflow_file_still_rejects_invalid_yaml(
        self, scanner: WorkflowScanner, tmp_path: Path
    ) -> None:
        """The gate in parse_workflow_file survives the shared parse."""
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        path = workflows / "broken.yaml"
        path.write_text(
            "name: Test\non: [push\n  - uses: actions/checkout@v5\n",
            encoding="utf-8",
        )

        assert scanner.parse_workflow_file(path) == {}
        assert scanner.compose_workflow_file(path) is None

    def test_parse_workflow_file_still_accepts_valid_yaml(
        self, scanner: WorkflowScanner, workflow_file: Path
    ) -> None:
        """Valid workflows still yield their action calls."""
        calls = scanner.parse_workflow_file(workflow_file)

        assert [call.reference for call in calls.values()] == ["v5"]

    def test_is_valid_yaml_agrees_with_compose(
        self, scanner: WorkflowScanner
    ) -> None:
        """An empty document is valid even though it composes to None."""
        path = Path("empty.yaml")

        assert scanner._is_valid_yaml("", path) is True
        assert scanner._compose("", path).node is None
        assert scanner._is_valid_yaml("a: [b\n", path) is False
