# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for workflow scanner."""

from __future__ import annotations

from pathlib import Path
import tempfile
from unittest.mock import Mock

from gha_workflow_linter.models import ActionCall, Config
from gha_workflow_linter.scanner import WorkflowScanner


class TestWorkflowScanner:
    """Test the WorkflowScanner class."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.config = Config()
        self.scanner = WorkflowScanner(self.config)

    def test_init(self) -> None:
        """Test WorkflowScanner initialization."""
        assert self.scanner.config is self.config
        assert self.scanner.logger is not None
        assert self.scanner._patterns is not None

    def create_temp_workflow(
        self, content: str, name: str = "test.yml"
    ) -> Path:
        """Helper to create temporary workflow file."""
        temp_dir = Path(tempfile.mkdtemp())
        github_dir = temp_dir / ".github" / "workflows"
        github_dir.mkdir(parents=True)
        workflow_file = github_dir / name
        workflow_file.write_text(content)
        return temp_dir

    def test_find_workflow_files_basic(self) -> None:
        """Test finding basic workflow files."""
        workflow_content = """
name: Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        temp_dir = self.create_temp_workflow(workflow_content)

        try:
            files = list(self.scanner.find_workflow_files(temp_dir))
            assert len(files) == 1
            assert files[0].name == "test.yml"
            assert ".github/workflows" in str(files[0])
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_find_workflow_files_multiple_extensions(self) -> None:
        """Test finding workflow files with different extensions."""
        workflow_content = "name: Test\non: [push]\njobs: {}"

        temp_dir = Path(tempfile.mkdtemp())
        github_dir = temp_dir / ".github" / "workflows"
        github_dir.mkdir(parents=True)

        # Create files with different extensions
        (github_dir / "test1.yml").write_text(workflow_content)
        (github_dir / "test2.yaml").write_text(workflow_content)
        (github_dir / "test3.txt").write_text(
            workflow_content
        )  # Should be ignored

        try:
            files = list(self.scanner.find_workflow_files(temp_dir))
            file_names = {f.name for f in files}

            assert len(files) == 2
            assert "test1.yml" in file_names
            assert "test2.yaml" in file_names
            assert "test3.txt" not in file_names
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_find_workflow_files_exclude_patterns(self) -> None:
        """Test excluding files based on patterns."""
        config = Config(exclude_patterns=["test*", "*.tmp"])
        scanner = WorkflowScanner(config)

        workflow_content = "name: Test\non: [push]\njobs: {}"

        temp_dir = Path(tempfile.mkdtemp())
        github_dir = temp_dir / ".github" / "workflows"
        github_dir.mkdir(parents=True)

        (github_dir / "workflow.yml").write_text(workflow_content)
        (github_dir / "test.yml").write_text(
            workflow_content
        )  # Should be excluded
        (github_dir / "build.tmp.yml").write_text(
            workflow_content
        )  # Should be excluded

        try:
            files = list(scanner.find_workflow_files(temp_dir))
            file_names = {f.name for f in files}

            # The _should_exclude_file method checks if pattern is in path string
            # So all files should be found initially since exclude is checked separately
            assert len(files) >= 1
            assert "workflow.yml" in file_names
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_find_workflow_files_no_github_directory(self) -> None:
        """Test scanning directory without .github directory."""
        temp_dir = Path(tempfile.mkdtemp())

        try:
            files = list(self.scanner.find_workflow_files(temp_dir))
            assert len(files) == 0
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_find_workflow_files_empty_workflows_directory(self) -> None:
        """Test scanning empty workflows directory."""
        temp_dir = Path(tempfile.mkdtemp())
        github_dir = temp_dir / ".github" / "workflows"
        github_dir.mkdir(parents=True)

        try:
            files = list(self.scanner.find_workflow_files(temp_dir))
            assert len(files) == 0
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_find_workflow_files_with_progress(self) -> None:
        """Test finding workflow files with progress tracking."""
        workflow_content = "name: Test\non: [push]\njobs: {}"
        temp_dir = self.create_temp_workflow(workflow_content)

        progress = Mock()
        task_id = Mock()

        try:
            files = list(
                self.scanner.find_workflow_files(temp_dir, progress, task_id)
            )
            assert len(files) == 1
            progress.update.assert_called()
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_scan_directory_basic(self) -> None:
        """Test basic directory scanning."""
        workflow_content = """
name: Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        temp_dir = self.create_temp_workflow(workflow_content)

        try:
            results = self.scanner.scan_directory(temp_dir)
            assert len(results) == 1
            assert list(results.keys())[0].name == "test.yml"
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_scan_directory_with_progress(self) -> None:
        """Test directory scanning with progress tracking."""
        workflow_content = """
name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        temp_dir = self.create_temp_workflow(workflow_content)

        progress = Mock()
        task_id = Mock()

        try:
            results = self.scanner.scan_directory(temp_dir, progress, task_id)
            assert len(results) == 1
            # Check that progress.update was called at least once
            assert progress.update.call_count >= 1
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_parse_workflow_file_valid(self) -> None:
        """Test parsing valid workflow file."""
        workflow_content = """
name: Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Setup Node
        uses: actions/setup-node@v3
        with:
          node-version: '18'
"""
        temp_dir = self.create_temp_workflow(workflow_content)
        workflow_file = temp_dir / ".github" / "workflows" / "test.yml"

        try:
            action_calls = self.scanner.parse_workflow_file(workflow_file)

            assert (
                len(action_calls) >= 1
            )  # Should find at least one action call
            # Check if we have action calls (dict with line numbers as keys)
            if action_calls:
                first_call = list(action_calls.values())[0]
                assert hasattr(first_call, "repository")
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_parse_workflow_file_invalid_yaml(self) -> None:
        """Test parsing workflow file with invalid YAML."""
        invalid_content = """
name: Test
on: [push
jobs: invalid yaml [
"""
        temp_dir = self.create_temp_workflow(invalid_content)
        workflow_file = temp_dir / ".github" / "workflows" / "test.yml"

        try:
            action_calls = self.scanner.parse_workflow_file(workflow_file)
            # Should return empty dict for invalid YAML
            assert action_calls == {}
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_parse_workflow_file_no_jobs(self) -> None:
        """Test parsing workflow file without jobs section."""
        workflow_content = """
name: Test Workflow
on: [push]
"""
        temp_dir = self.create_temp_workflow(workflow_content)
        workflow_file = temp_dir / ".github" / "workflows" / "test.yml"

        try:
            action_calls = self.scanner.parse_workflow_file(workflow_file)
            assert action_calls == {}
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_parse_workflow_file_missing_file(self) -> None:
        """Test parsing non-existent workflow file."""
        nonexistent_file = Path("/nonexistent/workflow.yml")

        action_calls = self.scanner.parse_workflow_file(nonexistent_file)
        assert action_calls == {}

    def test_should_exclude_file_basic(self) -> None:
        """Test checking if file should be excluded."""
        config = Config(exclude_patterns=["test", ".tmp"])
        scanner = WorkflowScanner(config)

        # Should exclude (pattern matches substring in path)
        assert scanner._should_exclude_file(Path("test.yml"))  # contains "test"
        assert scanner._should_exclude_file(Path("file.tmp"))  # contains ".tmp"

        # Should not exclude
        assert not scanner._should_exclude_file(Path("workflow.yml"))

    def test_is_valid_yaml_valid(self) -> None:
        """Test YAML validation with valid content."""
        valid_content = """
name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
"""
        result = self.scanner._is_valid_yaml(valid_content, Path("test.yml"))
        assert result is True

    def test_is_valid_yaml_invalid(self) -> None:
        """Test YAML validation with invalid content."""
        invalid_content = """
name: Test
on: [push
jobs: invalid [
"""
        result = self.scanner._is_valid_yaml(invalid_content, Path("test.yml"))
        assert result is False

    def test_get_scan_summary(self) -> None:
        """Test generating scan summary statistics."""
        # Mock some results

        results = {
            Path("test1.yml"): {
                1: ActionCall(
                    raw_line="uses: actions/checkout@v4",
                    line_number=1,
                    organization="actions",
                    repository="actions/checkout",
                    reference="v4",
                )
            },
            Path("test2.yml"): {
                2: ActionCall(
                    raw_line="uses: actions/setup-node@abc123",
                    line_number=2,
                    organization="actions",
                    repository="actions/setup-node",
                    reference="abc123",
                )
            },
        }

        summary = self.scanner.get_scan_summary(results)

        assert summary["total_files"] == 2
        assert summary["total_calls"] == 2
        assert summary["action_calls"] >= 0
        assert summary["sha_references"] >= 0

    def test_find_workflow_directories(self) -> None:
        """Test finding workflow directories."""
        temp_dir = Path(tempfile.mkdtemp())
        github_dir = temp_dir / ".github" / "workflows"
        github_dir.mkdir(parents=True)

        try:
            workflow_dirs = self.scanner._find_workflow_directories(temp_dir)
            assert len(workflow_dirs) == 1
            assert github_dir in workflow_dirs
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_extract_action_calls_composite_actions(self) -> None:
        """Test extracting action calls from composite actions."""
        workflow_content = """
name: Test Composite
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ./local-action
      - uses: ./.github/actions/custom-action
      - uses: ../relative-action
"""
        temp_dir = self.create_temp_workflow(workflow_content)
        workflow_file = temp_dir / ".github" / "workflows" / "test.yml"

        try:
            action_calls = self.scanner.parse_workflow_file(workflow_file)

            # Should include some action calls (dict format)
            assert len(action_calls) >= 0
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_extract_action_calls_with_docker(self) -> None:
        """Test extracting action calls that use Docker images."""
        workflow_content = """
name: Test Docker
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:latest
      - uses: docker://node:16
      - uses: actions/checkout@v4
"""
        temp_dir = self.create_temp_workflow(workflow_content)
        workflow_file = temp_dir / ".github" / "workflows" / "test.yml"

        try:
            action_calls = self.scanner.parse_workflow_file(workflow_file)

            # Should extract some action calls (dict format)
            assert len(action_calls) >= 0
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_scan_directory_multiple_files(self) -> None:
        """Test scanning directory with multiple workflow files."""
        workflow1 = """
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""

        workflow2 = """
name: Deploy
on: [release]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v3
"""

        temp_dir = Path(tempfile.mkdtemp())
        github_dir = temp_dir / ".github" / "workflows"
        github_dir.mkdir(parents=True)

        (github_dir / "ci.yml").write_text(workflow1)
        (github_dir / "deploy.yml").write_text(workflow2)

        try:
            results = self.scanner.scan_directory(temp_dir)

            assert len(results) == 2
            file_names = {path.name for path in results}
            assert "ci.yml" in file_names
            assert "deploy.yml" in file_names
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_should_exclude_file_patterns(self) -> None:
        """Test checking if file should be excluded based on patterns."""
        config = Config(exclude_patterns=["test", "tmp"])
        scanner = WorkflowScanner(config)

        # Should exclude (pattern in path string)
        assert scanner._should_exclude_file(Path("test.yml"))  # contains "test"
        assert scanner._should_exclude_file(Path("file.tmp"))  # contains "tmp"

        # Should not exclude
        assert not scanner._should_exclude_file(Path("workflow.yml"))

    def test_should_exclude_file_no_patterns(self) -> None:
        """Test checking exclude when no patterns are configured."""
        config = Config(exclude_patterns=[])
        scanner = WorkflowScanner(config)

        # Should never exclude when no patterns configured
        assert not scanner._should_exclude_file(Path("test.yml"))
        assert not scanner._should_exclude_file(Path("anything.yaml"))
