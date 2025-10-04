# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Pytest configuration and shared fixtures for gha-workflow-linter tests."""

from collections.abc import Generator
from pathlib import Path
import tempfile

import pytest

from gha_workflow_linter.models import (
    Config,
    GitConfig,
    LogLevel,
    NetworkConfig,
)


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_workflow_content() -> str:
    """Sample GitHub workflow content for testing."""
    return """---
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

name: Test Workflow

on: [push, pull_request]

permissions: {}

jobs:
  test:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - name: Checkout code
        uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0

      - name: Setup Python
        uses: actions/setup-python@v5.0.0
        with:
          python-version: '3.11'

      - name: Harden Runner
        uses: step-security/harden-runner@f4a75cfd619ee5ce8d5b864b0d183aff3c69b55a # v2.13.1

      - name: Use reusable workflow
        uses: lfit/releng-reusable-workflows/.github/workflows/test.yaml@main
"""


@pytest.fixture
def invalid_workflow_content() -> str:
    """Sample workflow with invalid action calls."""
    return """---
name: Invalid Workflow

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: nonexistent/action@v1.0.0
      - uses: actions/checkout@invalid-ref-12345
      - uses: invalid-org-name_/repo@v1
      - uses: actions/setup-python@nonexistent-branch
"""


@pytest.fixture
def workflow_with_syntax_errors() -> str:
    """Sample workflow with YAML syntax errors."""
    return """---
name: Syntax Error Workflow
on: [push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        invalid_yaml: {unclosed
"""


@pytest.fixture
def test_config() -> Config:
    """Test configuration with reduced timeouts and workers."""
    return Config(
        log_level=LogLevel.DEBUG,
        parallel_workers=2,
        scan_extensions=[".yml", ".yaml"],
        exclude_patterns=["**/node_modules/**", "**/test/**"],
        require_pinned_sha=True,
        git=GitConfig(timeout_seconds=10, use_ssh_agent=True),
        network=NetworkConfig(
            timeout_seconds=10,
            max_retries=2,
            retry_delay_seconds=0.1,
            rate_limit_delay_seconds=0.05,
        ),
    )


@pytest.fixture
def workflow_directory_structure(temp_dir: Path) -> dict[str, Path]:
    """Create a temporary directory structure with workflow files."""
    # Create main project structure
    project_dir = temp_dir / "test-project"
    project_dir.mkdir()

    # Create .github/workflows directory
    workflows_dir = project_dir / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)

    # Create some workflow files
    workflow_files = {
        "main.yml": workflows_dir / "main.yml",
        "test.yaml": workflows_dir / "test.yaml",
        "invalid.yml": workflows_dir / "invalid.yml",
    }

    # Create nested project with workflows
    nested_dir = project_dir / "subproject"
    nested_workflows_dir = nested_dir / ".github" / "workflows"
    nested_workflows_dir.mkdir(parents=True)

    workflow_files["nested.yml"] = nested_workflows_dir / "nested.yml"

    # Create some non-workflow files that should be ignored
    (workflows_dir / "README.md").touch()
    (workflows_dir / "config.json").touch()

    return {
        "project_dir": project_dir,
        "workflows_dir": workflows_dir,
        "nested_workflows_dir": nested_workflows_dir,
        **workflow_files,
    }


@pytest.fixture
def mock_git_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock git commands for testing without network calls."""
    import subprocess

    def mock_run(
        *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        """Mock subprocess.run for git commands."""
        cmd = args[0] if args else kwargs.get("args", [])
        if not isinstance(cmd, list):
            cmd = []

        if not isinstance(cmd, list) or len(cmd) < 2 or cmd[0] != "git":
            # Pass through non-git commands
            return subprocess.CompletedProcess(
                args=cmd, returncode=1, stdout=b"", stderr=b"Not a git command"
            )

        git_cmd = cmd[1] if len(cmd) > 1 else ""

        if git_cmd == "ls-remote":
            # Mock successful repository checks for known good repos
            if "actions/checkout" in " ".join(cmd):
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=0,
                    stdout=b"abc123\trefs/heads/main\n",
                    stderr=b"",
                )
            elif "nonexistent/action" in " ".join(cmd):
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=128,
                    stdout=b"",
                    stderr=b"Repository not found",
                )
            else:
                # Default to success for other repos in tests
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=0,
                    stdout=b"def456\trefs/heads/main\n",
                    stderr=b"",
                )

        # Default to success for other git commands
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=b"", stderr=b""
        )

    monkeypatch.setattr(subprocess, "run", mock_run)


@pytest.fixture
def sample_config_file_content() -> str:
    """Sample configuration file content."""
    return """# gha-workflow-linter configuration file
# SPDX-License-Identifier: Apache-2.0

log_level: INFO
parallel_workers: 4

scan_extensions:
  - ".yml"
  - ".yaml"

exclude_patterns:
  - "**/node_modules/**"
  - "**/vendor/**"

git:
  timeout_seconds: 30
  use_ssh_agent: true

network:
  timeout_seconds: 30
  max_retries: 3
  retry_delay_seconds: 1.0
  rate_limit_delay_seconds: 0.1
"""


@pytest.fixture(autouse=True)
def setup_logging() -> None:
    """Setup test logging configuration."""
    import logging

    logging.getLogger("gha_workflow_linter").setLevel(logging.DEBUG)


# Markers for test categorization
pytest_markers = [
    "unit: marks tests as unit tests (deselect with '-m \"not unit\"')",
    "integration: marks tests as integration tests",
    "slow: marks tests as slow running tests",
    "network: marks tests that require network access",
]


def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest with custom markers."""
    for marker in pytest_markers:
        config.addinivalue_line("markers", marker)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Modify test collection to add markers based on test names."""
    for item in items:
        # Add unit marker to test files starting with test_
        if item.fspath.basename.startswith("test_"):
            item.add_marker(pytest.mark.unit)

        # Add integration marker to integration test files
        if "integration" in item.fspath.basename:
            item.add_marker(pytest.mark.integration)

        # Add slow marker to tests with "slow" in name
        if "slow" in item.name.lower():
            item.add_marker(pytest.mark.slow)

        # Add network marker to tests that use real network calls
        if "network" in item.name.lower() or "real" in item.name.lower():
            item.add_marker(pytest.mark.network)
