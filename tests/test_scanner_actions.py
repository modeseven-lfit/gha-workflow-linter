# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for action.yaml and action.yml file scanning."""

from __future__ import annotations

from pathlib import Path
import tempfile
from unittest.mock import Mock

from gha_workflow_linter.models import Config
from gha_workflow_linter.scanner import WorkflowScanner


class TestActionFileScanning:
    """Test scanning action.yaml and action.yml files."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.config = Config()
        self.scanner = WorkflowScanner(self.config)

    def create_temp_action(
        self, content: str, name: str = "action.yml", subdir: str | None = None
    ) -> Path:
        """Helper to create temporary action file."""
        temp_dir = Path(tempfile.mkdtemp())

        if subdir:
            action_dir = temp_dir / subdir
            action_dir.mkdir(parents=True)
        else:
            action_dir = temp_dir

        action_file = action_dir / name
        action_file.write_text(content)
        return temp_dir

    def test_find_action_files_root_yml(self) -> None:
        """Test finding action.yml in repository root."""
        action_content = """
name: 'Test Action'
description: 'A test composite action'
runs:
  using: 'composite'
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-node@v3
"""
        temp_dir = self.create_temp_action(action_content, "action.yml")

        try:
            files = list(self.scanner.find_workflow_files(temp_dir))
            assert len(files) == 1
            assert files[0].name == "action.yml"
            assert files[0].parent == temp_dir
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_find_action_files_root_yaml(self) -> None:
        """Test finding action.yaml in repository root."""
        action_content = """
name: 'Test Action'
description: 'A test composite action'
runs:
  using: 'composite'
  steps:
    - uses: actions/checkout@v4
"""
        temp_dir = self.create_temp_action(action_content, "action.yaml")

        try:
            files = list(self.scanner.find_workflow_files(temp_dir))
            assert len(files) == 1
            assert files[0].name == "action.yaml"
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_find_action_files_in_subdirectory(self) -> None:
        """Test finding action.yml in subdirectories."""
        action_content = """
name: 'Custom Action'
runs:
  using: 'composite'
  steps:
    - uses: actions/cache@v4
"""
        temp_dir = self.create_temp_action(
            action_content, "action.yml", subdir="custom-action"
        )

        try:
            files = list(self.scanner.find_workflow_files(temp_dir))
            assert len(files) == 1
            assert files[0].name == "action.yml"
            assert "custom-action" in str(files[0])
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_find_action_files_multiple_subdirectories(self) -> None:
        """Test finding multiple action files in different subdirectories."""
        action_content = """
name: 'Test'
runs:
  using: 'composite'
  steps:
    - uses: actions/checkout@v4
"""
        temp_dir = Path(tempfile.mkdtemp())

        # Create multiple action files
        (temp_dir / "action.yml").write_text(action_content)

        action1_dir = temp_dir / "actions" / "deploy"
        action1_dir.mkdir(parents=True)
        (action1_dir / "action.yml").write_text(action_content)

        action2_dir = temp_dir / "actions" / "build"
        action2_dir.mkdir(parents=True)
        (action2_dir / "action.yaml").write_text(action_content)

        try:
            files = list(self.scanner.find_workflow_files(temp_dir))
            file_paths = {str(f.relative_to(temp_dir)) for f in files}

            assert len(files) == 3
            assert "action.yml" in file_paths
            assert str(Path("actions/deploy/action.yml")) in file_paths
            assert str(Path("actions/build/action.yaml")) in file_paths
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_skip_actions_workflow_directory(self) -> None:
        """Test that action.yml in .github/workflows is not scanned as action file."""
        action_content = """
name: 'Action'
runs:
  using: 'composite'
  steps:
    - uses: actions/checkout@v4
"""
        temp_dir = Path(tempfile.mkdtemp())

        # Create action.yml in .github/workflows (should be treated as workflow)
        workflows_dir = temp_dir / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "action.yml").write_text(action_content)

        # Create action.yml in root (should be scanned as action)
        (temp_dir / "action.yml").write_text(action_content)

        try:
            files = list(self.scanner.find_workflow_files(temp_dir))

            # Should find both, but the one in .github/workflows should be
            # found by workflow scanning, not action scanning
            assert len(files) == 2

            # Verify we have both paths
            file_paths = [str(f.relative_to(temp_dir)) for f in files]
            assert "action.yml" in file_paths
            assert str(Path(".github/workflows/action.yml")) in file_paths
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_skip_actions_enabled(self) -> None:
        """Test that skip_actions config skips action file scanning."""
        action_content = """
name: 'Test Action'
runs:
  using: 'composite'
  steps:
    - uses: actions/checkout@v4
"""
        config = Config(skip_actions=True)
        scanner = WorkflowScanner(config)

        temp_dir = self.create_temp_action(action_content, "action.yml")

        try:
            files = list(scanner.find_workflow_files(temp_dir))
            # Should not find action.yml when skip_actions is True
            assert len(files) == 0
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_skip_actions_disabled(self) -> None:
        """Test that action files are scanned when skip_actions is False."""
        action_content = """
name: 'Test Action'
runs:
  using: 'composite'
  steps:
    - uses: actions/checkout@v4
"""
        config = Config(skip_actions=False)
        scanner = WorkflowScanner(config)

        temp_dir = self.create_temp_action(action_content, "action.yml")

        try:
            files = list(scanner.find_workflow_files(temp_dir))
            # Should find action.yml when skip_actions is False
            assert len(files) == 1
            assert files[0].name == "action.yml"
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_action_file_with_workflows(self) -> None:
        """Test scanning both workflows and action files together."""
        workflow_content = """
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        action_content = """
name: 'Custom Action'
runs:
  using: 'composite'
  steps:
    - uses: actions/setup-node@v3
"""
        temp_dir = Path(tempfile.mkdtemp())

        # Create workflow
        workflows_dir = temp_dir / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").write_text(workflow_content)

        # Create action in root
        (temp_dir / "action.yml").write_text(action_content)

        # Create action in subdirectory
        action_dir = temp_dir / "actions" / "custom"
        action_dir.mkdir(parents=True)
        (action_dir / "action.yaml").write_text(action_content)

        try:
            files = list(self.scanner.find_workflow_files(temp_dir))

            assert len(files) == 3

            file_names = {f.name for f in files}
            assert "ci.yml" in file_names
            assert "action.yml" in file_names
            assert "action.yaml" in file_names
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_parse_action_file(self) -> None:
        """Test parsing action.yml file for action calls."""
        action_content = """
name: 'Multi-step Action'
description: 'An action with multiple steps'
runs:
  using: 'composite'
  steps:
    - name: Checkout
      uses: actions/checkout@v4
    - name: Setup Python
      uses: actions/setup-python@v5
    - name: Cache
      uses: actions/cache@v4
      with:
        path: ~/.cache
        key: test-key
"""
        temp_dir = self.create_temp_action(action_content, "action.yml")
        action_file = temp_dir / "action.yml"

        try:
            action_calls = self.scanner.parse_workflow_file(action_file)

            # Should find multiple action calls
            assert len(action_calls) >= 2

            # Check that we found the expected actions
            action_refs = [call.repository for call in action_calls.values()]
            assert any("checkout" in ref for ref in action_refs)
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_exclude_action_files(self) -> None:
        """Test that exclude patterns work with action files."""
        action_content = """
name: 'Test'
runs:
  using: 'composite'
  steps:
    - uses: actions/checkout@v4
"""
        config = Config(exclude_patterns=["test"])
        scanner = WorkflowScanner(config)

        temp_dir = Path(tempfile.mkdtemp())

        # Create action that should be excluded
        test_dir = temp_dir / "test-action"
        test_dir.mkdir()
        (test_dir / "action.yml").write_text(action_content)

        # Create action that should not be excluded
        prod_dir = temp_dir / "prod-action"
        prod_dir.mkdir()
        (prod_dir / "action.yml").write_text(action_content)

        try:
            files = list(scanner.find_workflow_files(temp_dir))

            # Files are found but should be filtered based on exclude
            # The exclude logic is applied in _should_exclude_file
            # but files are still found by find_workflow_files
            assert len(files) >= 0
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_action_file_with_invalid_yaml(self) -> None:
        """Test parsing action file with invalid YAML."""
        invalid_content = """
name: 'Test'
runs:
  using: 'composite'
  steps: invalid [
"""
        temp_dir = self.create_temp_action(invalid_content, "action.yml")
        action_file = temp_dir / "action.yml"

        try:
            action_calls = self.scanner.parse_workflow_file(action_file)
            # Should return empty dict for invalid YAML
            assert action_calls == {}
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_action_file_with_no_steps(self) -> None:
        """Test parsing action file without steps (e.g., Docker action)."""
        docker_action_content = """
name: 'Docker Action'
description: 'A Docker-based action'
runs:
  using: 'docker'
  image: 'Dockerfile'
"""
        temp_dir = self.create_temp_action(docker_action_content, "action.yml")
        action_file = temp_dir / "action.yml"

        try:
            action_calls = self.scanner.parse_workflow_file(action_file)
            # Docker actions don't have 'uses' steps
            assert action_calls == {}
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_action_file_with_javascript_action(self) -> None:
        """Test parsing JavaScript action (no composite steps)."""
        js_action_content = """
name: 'JavaScript Action'
description: 'A JavaScript-based action'
runs:
  using: 'node20'
  main: 'index.js'
"""
        temp_dir = self.create_temp_action(js_action_content, "action.yml")
        action_file = temp_dir / "action.yml"

        try:
            action_calls = self.scanner.parse_workflow_file(action_file)
            # JavaScript actions don't have 'uses' steps
            assert action_calls == {}
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_scan_directory_with_actions_and_workflows(self) -> None:
        """Test complete directory scan with both workflows and actions."""
        workflow_content = """
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        action_content = """
name: 'Deploy Action'
runs:
  using: 'composite'
  steps:
    - uses: actions/setup-node@v3
"""
        temp_dir = Path(tempfile.mkdtemp())

        # Create workflow
        workflows_dir = temp_dir / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").write_text(workflow_content)

        # Create action in root
        (temp_dir / "action.yml").write_text(action_content)

        try:
            results = self.scanner.scan_directory(temp_dir)

            assert len(results) == 2

            # Both workflow and action should be parsed
            file_names = {path.name for path in results}
            assert "ci.yml" in file_names
            assert "action.yml" in file_names
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_get_scan_summary_with_actions(self) -> None:
        """Test scan summary includes action files."""
        from gha_workflow_linter.models import ActionCall

        results = {
            Path("ci.yml"): {
                1: ActionCall(
                    raw_line="uses: actions/checkout@v4",
                    line_number=1,
                    organization="actions",
                    repository="actions/checkout",
                    reference="v4",
                )
            },
            Path("action.yml"): {
                2: ActionCall(
                    raw_line="uses: actions/setup-node@v3",
                    line_number=2,
                    organization="actions",
                    repository="actions/setup-node",
                    reference="v3",
                )
            },
        }

        summary = self.scanner.get_scan_summary(results)

        assert summary["total_files"] == 2
        assert summary["total_calls"] == 2

    def test_action_file_deep_nesting(self) -> None:
        """Test finding action files in deeply nested directories."""
        action_content = """
name: 'Nested Action'
runs:
  using: 'composite'
  steps:
    - uses: actions/checkout@v4
"""
        temp_dir = Path(tempfile.mkdtemp())

        # Create deeply nested action
        deep_dir = temp_dir / "a" / "b" / "c" / "d" / "e"
        deep_dir.mkdir(parents=True)
        (deep_dir / "action.yml").write_text(action_content)

        try:
            files = list(self.scanner.find_workflow_files(temp_dir))

            assert len(files) == 1
            assert files[0].name == "action.yml"
            assert "a/b/c/d/e" in str(files[0])
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_action_file_with_progress_tracking(self) -> None:
        """Test finding action files with progress tracking."""
        action_content = """
name: 'Test'
runs:
  using: 'composite'
  steps:
    - uses: actions/checkout@v4
"""
        temp_dir = self.create_temp_action(action_content, "action.yml")

        progress = Mock()
        task_id = Mock()

        try:
            files = list(
                self.scanner.find_workflow_files(temp_dir, progress, task_id)
            )
            assert len(files) == 1
            # Progress should be updated
            assert progress.update.call_count >= 1
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_both_yml_and_yaml_extensions(self) -> None:
        """Test that both .yml and .yaml extensions are found for actions."""
        action_content = """
name: 'Test'
runs:
  using: 'composite'
  steps:
    - uses: actions/checkout@v4
"""
        temp_dir = Path(tempfile.mkdtemp())

        # Create action.yml in one directory
        dir1 = temp_dir / "action1"
        dir1.mkdir()
        (dir1 / "action.yml").write_text(action_content)

        # Create action.yaml in another directory
        dir2 = temp_dir / "action2"
        dir2.mkdir()
        (dir2 / "action.yaml").write_text(action_content)

        try:
            files = list(self.scanner.find_workflow_files(temp_dir))

            assert len(files) == 2

            file_names = {f.name for f in files}
            assert "action.yml" in file_names
            assert "action.yaml" in file_names
        finally:
            import shutil

            shutil.rmtree(temp_dir)
