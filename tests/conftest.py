# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Pytest configuration and shared fixtures for gha-workflow-linter tests."""

from collections.abc import Generator
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any

import httpx
import pytest

from gha_workflow_linter import github_auth
from gha_workflow_linter.models import (
    Config,
    GitConfig,
    LogLevel,
    NetworkConfig,
)

_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from console output.

    Rich colours its output when it believes it is writing to a terminal,
    and its highlighter puts the escape sequences *inside* values rather
    than around them: ``1.3.0`` is emitted as
    ``\\x1b[1;36m1.3\\x1b[0m.\\x1b[1;36m0\\x1b[0m``, and a number in a
    sentence is styled the same way. An assertion against raw output
    therefore tests the styling as much as the text, and passes or fails
    depending on whether the run happens to have a terminal -- green
    locally, red on CI, or the reverse once a version string changes
    shape. Strip the sequences first so the assertion tests the text.

    Args:
        text: Console output, possibly containing escape sequences.

    Returns:
        The same text with escape sequences removed.
    """
    return _ANSI_ESCAPE_PATTERN.sub("", text)


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

        # cmd is a list by now, so no further isinstance check is needed.
        if len(cmd) < 2 or cmd[0] != "git":
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


@pytest.fixture(autouse=True)
def isolate_github_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop the suite from picking up the developer's GitHub credentials.

    ``get_github_token_with_fallback`` reads ``GITHUB_TOKEN`` and then
    shells out to ``gh auth token``. Whichever answers, the token decides
    which *backend* the tool selects: with one,
    ``_configure_validation_backend`` chooses the GraphQL API and
    pre-flights it; without one, it falls back to Git validation.

    So the suite silently took different code paths on a developer
    machine than on CI, and a green run in one place was not evidence
    about the other. Clearing both sources makes every test start from
    the unauthenticated state CI sees. A test that wants a token passes
    one explicitly, which this does not touch.

    Args:
        monkeypatch: Used to clear the environment and the CLI fallback.
    """
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(
        github_auth, "_get_token_from_gh_cli", lambda: None, raising=True
    )


#: Git subcommands that contact a remote. Anything else -- ``rev-parse``,
#: ``config``, a local ``init`` -- is left alone, so tests may still use
#: git as a local tool.
_NETWORKED_GIT_SUBCOMMANDS = frozenset({"ls-remote", "clone", "fetch", "push"})

#: Domains reserved by RFC 2606 and RFC 6761 as guaranteed not to
#: resolve, plus loopback. A request to one of these cannot reach a real
#: service, so tests that deliberately provoke a connection failure --
#: ``nonexistent-domain-for-testing.invalid`` and friends -- are offline
#: by construction and must not be refused.
_UNREACHABLE_SUFFIXES = (".invalid", ".test", ".example", ".localhost")
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})


def _is_offline_host(host: str) -> bool:
    """Whether a hostname is guaranteed not to reach a real service.

    Args:
        host: Hostname from the request URL.

    Returns:
        ``True`` when the name is reserved or loopback.
    """
    host = host.lower()
    return host in _LOOPBACK_HOSTS or host.endswith(_UNREACHABLE_SUFFIXES)


class NetworkAccessError(RuntimeError):
    """A test reached the network without declaring that it would."""


@pytest.fixture(autouse=True)
def forbid_network(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail any unmarked test that reaches the network.

    The suite has twice been slowed and destabilised by tests quietly
    depending on github.com -- once for 115 seconds against a 120 second
    timeout. Both times the dependency was invisible until measured,
    because a networked test looks exactly like a fast one when the
    network happens to be quick.

    This makes the dependency loud instead. Both routes out are covered:
    httpx for the API clients, and ``subprocess`` for the git binary,
    which no socket-level guard would catch because the traffic belongs
    to a child process.

    The guard sits on httpx's *real* transports rather than on
    ``Client.send``, so a test that installs a ``MockTransport`` is
    unaffected: its requests never reach a transport that would have
    gone anywhere. Requests to reserved or loopback names are allowed
    for the same reason.

    Tests that genuinely need a live answer declare ``@pytest.mark.network``
    and are exempt, which is what makes that marker mean something.

    Args:
        request: Used to read the test's markers.
        monkeypatch: Used to install and remove the guards.

    Raises:
        NetworkAccessError: When an unmarked test attempts a request.
    """
    if request.node.get_closest_marker("network"):
        return

    def refuse(target: str) -> NetworkAccessError:
        return NetworkAccessError(
            f"{request.node.name} attempted to reach {target}. Tests must "
            f"not depend on the network: stub the call, or declare the "
            f"dependency with @pytest.mark.network if a live answer is "
            f"genuinely required."
        )

    real_handle = httpx.HTTPTransport.handle_request
    real_ahandle = httpx.AsyncHTTPTransport.handle_async_request
    real_run = subprocess.run

    def guarded_handle(self: Any, req: Any) -> Any:
        if _is_offline_host(req.url.host):
            return real_handle(self, req)
        raise refuse(str(req.url))

    async def guarded_ahandle(self: Any, req: Any) -> Any:
        if _is_offline_host(req.url.host):
            return await real_ahandle(self, req)
        raise refuse(str(req.url))

    def guarded_run(*args: Any, **kwargs: Any) -> Any:
        cmd = args[0] if args else kwargs.get("args", [])
        if (
            isinstance(cmd, (list, tuple))
            and len(cmd) > 1
            and cmd[0] == "git"
            and cmd[1] in _NETWORKED_GIT_SUBCOMMANDS
        ):
            raise refuse(f"git {cmd[1]}")
        return real_run(*args, **kwargs)

    monkeypatch.setattr(
        httpx.HTTPTransport, "handle_request", guarded_handle, raising=True
    )
    monkeypatch.setattr(
        httpx.AsyncHTTPTransport,
        "handle_async_request",
        guarded_ahandle,
        raising=True,
    )
    monkeypatch.setattr(subprocess, "run", guarded_run, raising=True)


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
    """Mark every test as a unit test unless its file says otherwise.

    ``slow`` and ``network`` were previously guessed from the test's
    name. A name is not evidence about what a test does: the most
    network-dependent test in the suite was called
    ``test_cli_flags_are_accepted`` and matched neither pattern, so the
    heuristic missed precisely the case it existed for while implying
    the tests were categorised. Both are now declared with a decorator,
    and ``network`` is enforced by :func:`forbid_network`.

    Args:
        items: Collected tests, marked in place.
    """
    for item in items:
        if item.fspath.basename.startswith("test_"):
            item.add_marker(pytest.mark.unit)

        if "integration" in item.fspath.basename:
            item.add_marker(pytest.mark.integration)
