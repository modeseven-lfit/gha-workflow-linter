# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Workflow scanner for finding and parsing GitHub Actions workflows."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from rich.progress import Progress, TaskID

    from .models import ActionCall, Config

    pass

import yaml

from .patterns import ActionCallPatterns


class WorkflowScanner:
    """Scanner for GitHub Actions workflow files."""

    def __init__(self, config: Config) -> None:
        """
        Initialize the workflow scanner.

        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._patterns = ActionCallPatterns()

    def find_workflow_files(
        self,
        root_path: Path,
        progress: Progress | None = None,
        task_id: TaskID | None = None,
    ) -> Iterator[Path]:
        """
        Find all GitHub workflow files and action definition files in directory tree.

        Args:
            root_path: Root directory to scan
            progress: Optional progress bar
            task_id: Optional task ID for progress updates

        Yields:
            Path objects for workflow files and action definition files
        """
        self.logger.info(f"Scanning for workflows and actions in: {root_path}")

        # Look for .github/workflows directories
        workflow_dirs = self._find_workflow_directories(root_path)

        total_files = 0
        for workflow_dir in workflow_dirs:
            if not workflow_dir.exists() or not workflow_dir.is_dir():
                continue

            for ext in self.config.scan_extensions:
                pattern = f"*{ext}"
                workflow_files = list(workflow_dir.glob(pattern))

                for workflow_file in workflow_files:
                    if self._should_exclude_file(workflow_file):
                        self.logger.debug(f"Excluding file: {workflow_file}")
                        continue

                    total_files += 1
                    if progress and task_id:
                        progress.update(
                            task_id,
                            description=f"Scanning {workflow_file.name}...",
                        )

                    self.logger.debug(f"Found workflow file: {workflow_file}")
                    yield workflow_file

        # Look for action.yaml/action.yml files (unless skip_actions is enabled)
        if not self.config.skip_actions:
            action_files = self._find_action_files(root_path)
            for action_file in action_files:
                if self._should_exclude_file(action_file):
                    self.logger.debug(f"Excluding file: {action_file}")
                    continue

                total_files += 1
                if progress and task_id:
                    progress.update(
                        task_id,
                        description=f"Scanning {action_file.name}...",
                    )

                self.logger.debug(f"Found action file: {action_file}")
                yield action_file

        self.logger.info(f"Found {total_files} workflow and action files")

    def _find_workflow_directories(self, root_path: Path) -> set[Path]:
        """
        Find all .github/workflows directories in the tree.

        Args:
            root_path: Root directory to scan

        Returns:
            Set of workflow directory paths
        """
        workflow_dirs = set()

        # Direct .github/workflows in root
        direct_workflows = root_path / ".github" / "workflows"
        if direct_workflows.exists():
            workflow_dirs.add(direct_workflows)

        # Search for .github/workflows directories recursively
        try:
            for github_dir in root_path.rglob(".github"):
                if github_dir.is_dir():
                    workflows_dir = github_dir / "workflows"
                    if workflows_dir.exists() and workflows_dir.is_dir():
                        workflow_dirs.add(workflows_dir)
        except (PermissionError, OSError) as e:
            self.logger.warning(f"Error scanning directory {root_path}: {e}")

        return workflow_dirs

    def _find_action_files(self, root_path: Path) -> Iterator[Path]:
        """
        Find all action.yaml and action.yml files in directory tree.

        Args:
            root_path: Root directory to scan

        Yields:
            Path objects for action definition files
        """
        self.logger.debug(f"Scanning for action definition files in: {root_path}")

        # Search for action.yaml and action.yml files recursively
        try:
            for ext in self.config.scan_extensions:
                # Look for action.yaml or action.yml (depending on extension)
                action_name = f"action{ext}"

                # Find recursively (rglob includes root directory)
                for action_file in root_path.rglob(action_name):
                    if action_file.is_file():
                        # Skip if it's in .github/workflows (those are workflow files, not actions)
                        if ".github/workflows" not in str(action_file):
                            self.logger.debug(f"Found action file: {action_file}")
                            yield action_file

        except (PermissionError, OSError) as e:
            self.logger.warning(f"Error scanning for action files in {root_path}: {e}")

    def _should_exclude_file(self, file_path: Path) -> bool:
        """
        Check if file should be excluded based on patterns.

        Args:
            file_path: File path to check

        Returns:
            True if file should be excluded
        """
        if not self.config.exclude_patterns:
            return False

        file_str = str(file_path)
        for pattern in self.config.exclude_patterns:
            if pattern in file_str:
                return True

        return False

    def parse_workflow_file(self, file_path: Path) -> dict[int, ActionCall]:
        """
        Parse a workflow file and extract action calls.

        Args:
            file_path: Path to the workflow file

        Returns:
            Dictionary mapping line numbers to ActionCall objects
        """
        self.logger.debug(f"Parsing workflow file: {file_path}")

        try:
            content = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            return {}

        # Validate YAML syntax
        if not self._is_valid_yaml(content, file_path):
            return {}

        # Extract action calls using regex patterns
        action_calls = self._patterns.extract_action_calls(content)

        self.logger.debug(
            f"Found {len(action_calls)} action calls in {file_path}"
        )

        return action_calls

    def _is_valid_yaml(self, content: str, file_path: Path) -> bool:
        """
        Validate YAML syntax of workflow file.

        Args:
            content: File content
            file_path: Path to file (for logging)

        Returns:
            True if valid YAML, False otherwise
        """
        try:
            yaml.safe_load(content)
            return True
        except yaml.YAMLError as e:
            self.logger.warning(f"Invalid YAML in {file_path}: {e}")
            return False

    def scan_directory(
        self,
        root_path: Path,
        progress: Progress | None = None,
        task_id: TaskID | None = None,
    ) -> dict[Path, dict[int, ActionCall]]:
        """
        Scan directory for workflows and parse all action calls.

        Args:
            root_path: Root directory to scan
            progress: Optional progress bar
            task_id: Optional task ID for progress updates

        Returns:
            Dictionary mapping file paths to their action calls
        """

        results: dict[Path, dict[int, ActionCall]] = {}

        for workflow_file in self.find_workflow_files(
            root_path, progress, task_id
        ):
            try:
                action_calls = self.parse_workflow_file(workflow_file)
                if action_calls:
                    results[workflow_file] = action_calls
            except Exception as e:
                self.logger.error(
                    f"Error processing workflow file {workflow_file}: {e}"
                )
                continue

        total_calls = sum(len(calls) for calls in results.values())
        self.logger.info(
            f"Scan complete: {len(results)} files, {total_calls} action/workflow calls"
        )

        return results

    def get_scan_summary(
        self, results: dict[Path, dict[int, ActionCall]]
    ) -> dict[str, int]:
        """
        Generate summary statistics for scan results.

        Args:
            results: Scan results from scan_directory

        Returns:
            Dictionary with summary statistics
        """
        total_files = len(results)
        total_calls = sum(len(calls) for calls in results.values())

        # Count by call type
        action_calls = 0
        workflow_calls = 0

        # Count by reference type
        sha_refs = 0
        tag_refs = 0
        branch_refs = 0

        for file_calls in results.values():
            for action_call in file_calls.values():
                if action_call.call_type.value == "action":
                    action_calls += 1
                elif action_call.call_type.value == "workflow":
                    workflow_calls += 1

                if action_call.reference_type.value == "commit_sha":
                    sha_refs += 1
                elif action_call.reference_type.value == "tag":
                    tag_refs += 1
                elif action_call.reference_type.value == "branch":
                    branch_refs += 1

        return {
            "total_files": total_files,
            "total_calls": total_calls,
            "action_calls": action_calls,
            "workflow_calls": workflow_calls,
            "sha_references": sha_refs,
            "tag_references": tag_refs,
            "branch_references": branch_refs,
        }
