# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for skip_actions configuration and CLI option."""

from __future__ import annotations

from pathlib import Path
import tempfile

from gha_workflow_linter.config import ConfigManager
from gha_workflow_linter.models import CLIOptions, Config


class TestSkipActionsConfig:
    """Test skip_actions configuration option."""

    def test_default_skip_actions_false(self) -> None:
        """Test that skip_actions defaults to False."""
        config = Config()
        assert config.skip_actions is False

    def test_skip_actions_true(self) -> None:
        """Test setting skip_actions to True."""
        config = Config(skip_actions=True)
        assert config.skip_actions is True

    def test_skip_actions_false_explicit(self) -> None:
        """Test explicitly setting skip_actions to False."""
        config = Config(skip_actions=False)
        assert config.skip_actions is False

    def test_skip_actions_in_config_file(self) -> None:
        """Test loading skip_actions from config file."""
        config_content = """
log_level: INFO
parallel_workers: 4
scan_extensions:
  - ".yml"
  - ".yaml"
skip_actions: true
"""
        temp_dir = Path(tempfile.mkdtemp())
        config_file = temp_dir / "config.yaml"
        config_file.write_text(config_content)

        try:
            config_manager = ConfigManager()
            config = config_manager.load_config(config_file)

            assert config.skip_actions is True
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_skip_actions_false_in_config_file(self) -> None:
        """Test loading skip_actions=false from config file."""
        config_content = """
log_level: INFO
skip_actions: false
"""
        temp_dir = Path(tempfile.mkdtemp())
        config_file = temp_dir / "config.yaml"
        config_file.write_text(config_content)

        try:
            config_manager = ConfigManager()
            config = config_manager.load_config(config_file)

            assert config.skip_actions is False
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_skip_actions_in_saved_config(self) -> None:
        """Test that skip_actions is included in saved config."""
        config_manager = ConfigManager()
        temp_dir = Path(tempfile.mkdtemp())
        config_file = temp_dir / "config.yaml"

        try:
            saved_path = config_manager.save_default_config(config_file)

            # Read the saved config
            content = saved_path.read_text()

            # Should contain skip_actions setting
            assert "skip_actions:" in content
            assert "Skip scanning action.yaml/action.yml files" in content
        finally:
            import shutil

            shutil.rmtree(temp_dir)


class TestSkipActionsCLI:
    """Test skip_actions CLI option."""

    def test_cli_options_default_skip_actions(self) -> None:
        """Test that CLIOptions defaults skip_actions to False."""
        cli_options = CLIOptions(path=Path.cwd())
        assert cli_options.skip_actions is False

    def test_cli_options_skip_actions_true(self) -> None:
        """Test setting skip_actions to True in CLIOptions."""
        cli_options = CLIOptions(path=Path.cwd(), skip_actions=True)
        assert cli_options.skip_actions is True

    def test_cli_options_skip_actions_false(self) -> None:
        """Test explicitly setting skip_actions to False in CLIOptions."""
        cli_options = CLIOptions(path=Path.cwd(), skip_actions=False)
        assert cli_options.skip_actions is False


class TestSkipActionsIntegration:
    """Test skip_actions integration with scanner."""

    def create_test_structure(self) -> Path:
        """Create a test directory structure with workflows and actions."""
        temp_dir = Path(tempfile.mkdtemp())

        # Create workflow
        workflows_dir = temp_dir / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        workflow_content = """
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        (workflows_dir / "ci.yml").write_text(workflow_content)

        # Create action in root
        action_content = """
name: 'Test Action'
runs:
  using: 'composite'
  steps:
    - uses: actions/setup-node@v3
"""
        (temp_dir / "action.yml").write_text(action_content)

        # Create action in subdirectory
        action_dir = temp_dir / "custom-action"
        action_dir.mkdir()
        (action_dir / "action.yml").write_text(action_content)

        return temp_dir

    def test_scan_with_skip_actions_false(self) -> None:
        """Test scanning finds both workflows and actions when skip_actions=False."""
        from gha_workflow_linter.scanner import WorkflowScanner

        temp_dir = self.create_test_structure()

        try:
            config = Config(skip_actions=False)
            scanner = WorkflowScanner(config)

            files = list(scanner.find_workflow_files(temp_dir))

            # Should find workflow + 2 actions = 3 files
            assert len(files) == 3

            file_names = {f.name for f in files}
            assert "ci.yml" in file_names
            assert "action.yml" in file_names
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_scan_with_skip_actions_true(self) -> None:
        """Test scanning skips actions when skip_actions=True."""
        from gha_workflow_linter.scanner import WorkflowScanner

        temp_dir = self.create_test_structure()

        try:
            config = Config(skip_actions=True)
            scanner = WorkflowScanner(config)

            files = list(scanner.find_workflow_files(temp_dir))

            # Should find only workflow, no actions
            assert len(files) == 1
            assert files[0].name == "ci.yml"
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_scan_directory_with_skip_actions_false(self) -> None:
        """Test full directory scan with skip_actions=False."""
        from gha_workflow_linter.scanner import WorkflowScanner

        temp_dir = self.create_test_structure()

        try:
            config = Config(skip_actions=False)
            scanner = WorkflowScanner(config)

            results = scanner.scan_directory(temp_dir)

            # Should include workflows and actions
            assert len(results) == 3

            file_names = {path.name for path in results}
            assert "ci.yml" in file_names
            assert "action.yml" in file_names
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_scan_directory_with_skip_actions_true(self) -> None:
        """Test full directory scan with skip_actions=True."""
        from gha_workflow_linter.scanner import WorkflowScanner

        temp_dir = self.create_test_structure()

        try:
            config = Config(skip_actions=True)
            scanner = WorkflowScanner(config)

            results = scanner.scan_directory(temp_dir)

            # Should include only workflows, not actions
            assert len(results) == 1

            file_names = {path.name for path in results}
            assert "ci.yml" in file_names
            assert "action.yml" not in file_names
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_only_actions_with_skip_actions_true(self) -> None:
        """Test repository with only actions (no workflows) when skip_actions=True."""
        from gha_workflow_linter.scanner import WorkflowScanner

        temp_dir = Path(tempfile.mkdtemp())

        # Only create actions, no workflows
        action_content = """
name: 'Test'
runs:
  using: 'composite'
  steps:
    - uses: actions/checkout@v4
"""
        (temp_dir / "action.yml").write_text(action_content)

        try:
            config = Config(skip_actions=True)
            scanner = WorkflowScanner(config)

            files = list(scanner.find_workflow_files(temp_dir))

            # Should find nothing when skip_actions=True
            assert len(files) == 0
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_only_actions_with_skip_actions_false(self) -> None:
        """Test repository with only actions (no workflows) when skip_actions=False."""
        from gha_workflow_linter.scanner import WorkflowScanner

        temp_dir = Path(tempfile.mkdtemp())

        # Only create actions, no workflows
        action_content = """
name: 'Test'
runs:
  using: 'composite'
  steps:
    - uses: actions/checkout@v4
"""
        (temp_dir / "action.yml").write_text(action_content)

        try:
            config = Config(skip_actions=False)
            scanner = WorkflowScanner(config)

            files = list(scanner.find_workflow_files(temp_dir))

            # Should find the action
            assert len(files) == 1
            assert files[0].name == "action.yml"
        finally:
            import shutil

            shutil.rmtree(temp_dir)


class TestSkipActionsLogging:
    """Test logging output with skip_actions option."""

    def test_log_message_when_scanning_actions(self) -> None:
        """Test that log message includes 'actions' when scanning them."""
        import logging
        from unittest.mock import MagicMock

        from gha_workflow_linter.scanner import WorkflowScanner

        config = Config(skip_actions=False)
        scanner = WorkflowScanner(config)

        # Mock the logger
        scanner.logger = MagicMock(spec=logging.Logger)

        temp_dir = Path(tempfile.mkdtemp())

        try:
            list(scanner.find_workflow_files(temp_dir))

            # Check that info was called with message about actions
            info_calls = [
                str(call) for call in scanner.logger.info.call_args_list
            ]
            assert any("actions" in call.lower() for call in info_calls)
        finally:
            import shutil

            shutil.rmtree(temp_dir)

    def test_log_message_summary_includes_actions(self) -> None:
        """Test that summary log includes 'action files'."""
        import logging
        from unittest.mock import MagicMock

        from gha_workflow_linter.scanner import WorkflowScanner

        temp_dir = Path(tempfile.mkdtemp())

        # Create an action file
        action_content = """
name: 'Test'
runs:
  using: 'composite'
  steps:
    - uses: actions/checkout@v4
"""
        (temp_dir / "action.yml").write_text(action_content)

        try:
            config = Config(skip_actions=False)
            scanner = WorkflowScanner(config)

            # Mock the logger
            scanner.logger = MagicMock(spec=logging.Logger)

            list(scanner.find_workflow_files(temp_dir))

            # Check that the summary includes the right terminology
            info_calls = [
                str(call) for call in scanner.logger.info.call_args_list
            ]
            summary_calls = [
                call for call in info_calls if "found" in call.lower()
            ]

            assert len(summary_calls) > 0
        finally:
            import shutil

            shutil.rmtree(temp_dir)
