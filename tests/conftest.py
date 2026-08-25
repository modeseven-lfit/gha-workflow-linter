# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Pytest configuration and shared fixtures for gha-workflow-linter tests."""

from collections.abc import Generator, Mapping, Sequence
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
from typing import Any

import httpx
import pytest

from gha_workflow_linter import auto_fix, github_api, github_auth
from gha_workflow_linter.models import (
    Config,
    GitConfig,
    LogLevel,
    NetworkConfig,
)

_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


#: Lets a test run pytest in-process, so the suite can check what its
#: own fixtures do to a *failing* test rather than only to passing ones.
pytest_plugins = ["pytester"]


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


#: A well-formed commit SHA the git double answers every lookup with.
#: Forty hex characters, because the validator rejects anything else as
#: malformed before it gets as far as comparing.
SHA_ANSWERING_EVERY_LOOKUP = "a" * 40


@pytest.fixture
def mock_git_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer git commands locally, so validation needs no network.

    The reply honours the caller's text mode. ``git_validator`` runs
    ``subprocess.run(..., text=True)`` and hands the output to a parser
    annotated ``str``, so returning bytes made it raise ``TypeError`` --
    which validation catches and reports as an invalid reference. Tests
    accepting a non-zero exit then stayed green while exercising the
    error path rather than the backend they meant to test.

    Args:
        monkeypatch: Used to replace ``subprocess.run``.
    """

    def reply(
        cmd: list[str],
        returncode: int,
        stdout: str,
        stderr: str,
        *,
        text: bool,
    ) -> subprocess.CompletedProcess[Any]:
        """Build a result in whichever form the caller asked for.

        Args:
            cmd: The command being answered.
            returncode: Exit status to report.
            stdout: Standard output, as text.
            stderr: Standard error, as text.
            text: Whether the caller asked for decoded output.

        Returns:
            The completed process.
        """
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=returncode,
            stdout=stdout if text else stdout.encode(),
            stderr=stderr if text else stderr.encode(),
        )

    def mock_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        """Stand in for ``subprocess.run`` on git commands.

        Args:
            args: Positional arguments as ``subprocess.run`` takes them.
            kwargs: Keyword arguments, read for the text mode.

        Returns:
            A completed process answering the command locally.
        """
        cmd = args[0] if args else kwargs.get("args", [])
        text = bool(kwargs.get("text") or kwargs.get("universal_newlines"))
        if not isinstance(cmd, list):
            cmd = []

        if len(cmd) < 2 or cmd[0] != "git":
            return reply(cmd, 1, "", "Not a git command", text=text)

        if cmd[1] != "ls-remote":
            return reply(cmd, 0, "", "", text=text)

        joined = " ".join(cmd)
        if "nonexistent/action" in joined:
            return reply(cmd, 128, "", "Repository not found", text=text)

        # Echo back whatever reference was asked about, so a lookup
        # resolves rather than merely succeeding: the validator matches
        # the ref it requested against the output, and a fixed
        # ``refs/heads/main`` answers a different question from the one
        # asked about a tag or a SHA.
        requested = cmd[-1] if len(cmd) > 2 else "HEAD"
        sha = SHA_ANSWERING_EVERY_LOOKUP
        lines = f"{sha}\trefs/heads/main\n{sha}\t{requested}\n"
        return reply(cmd, 0, lines, "", text=text)

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


#: The genuine startup refresh, captured before it is stubbed, so a test
#: that exercises it can ask for the real one back.
REAL_UPDATE_RATE_LIMIT_INFO = (
    github_api.GitHubGraphQLClient._update_rate_limit_info
)


@pytest.fixture
def unreachable_git(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make networked git commands fail as an unreachable host would.

    For tests about how the linter *handles* a network failure. They
    previously produced one by naming repositories that do not exist,
    which needed a working connection to establish -- so a test named
    for DNS resolution failing was, in fact, resolving DNS successfully.
    The git backend builds ``https://github.com/...`` directly and
    ignores the configured base URL, so pointing the configuration at a
    reserved domain did not reach the git path at all.

    Only the commands that would have contacted a remote fail. A local
    ``git --version`` or ``git remote get-url`` still runs, so setup a
    test does before reaching the call it cares about is unaffected.

    Args:
        monkeypatch: Used to replace ``subprocess.run``.
    """
    _install_failing_git(
        monkeypatch,
        "fatal: unable to access 'https://github.com/': "
        "Could not resolve host: github.com",
    )


@pytest.fixture
def recorded_git_environments(
    monkeypatch: pytest.MonkeyPatch,
) -> list[Mapping[str, str] | None]:
    """Fail networked git as :func:`unreachable_git` does, and record it.

    For asserting how git was invoked rather than what came back. The
    failure keeps the run moving without a network.

    Args:
        monkeypatch: Used to replace ``subprocess.run``.

    Returns:
        The environment each remote invocation was given.
    """
    return _install_failing_git(
        monkeypatch,
        "fatal: unable to access 'https://github.com/': "
        "Could not resolve host: github.com",
    )


@pytest.fixture
def http_refusing_git(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make networked git commands fail as a refused HTTP request does.

    The remote answered here -- with a refusal -- so the answer is worth
    reporting. The message opens with ``unable to access``, which git
    writes ahead of *any* HTTP failure, including a lost connection;
    matching that prefix would call this reachable remote unreachable
    and discard the finding. This fixture is what keeps the classifier
    reading the reason rather than the prefix.

    Args:
        monkeypatch: Used to replace ``subprocess.run``.
    """
    _install_failing_git(
        monkeypatch,
        "fatal: unable to access "
        "'https://github.com/nonexistent/action.git/': "
        "The requested URL returned error: 404",
    )


@pytest.fixture
def timing_out_git(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make networked git commands time out rather than fail outright.

    A timeout reaches the linter as an exception rather than a non-zero
    exit, and is handled by a different branch. Sharing one double
    between the two would let the timeout test pass while that branch
    was broken, since it would only ever see the connection failure.

    Args:
        monkeypatch: Used to replace ``subprocess.run``.
    """
    real_run = subprocess.run

    def timing_out(*args: Any, **kwargs: Any) -> Any:
        """Time out a networked git command, pass anything else through.

        Args:
            args: Positional arguments as ``subprocess.run`` takes them.
            kwargs: Keyword arguments, passed through.

        Returns:
            The real result for a local command.

        Raises:
            subprocess.TimeoutExpired: For a command reaching a remote.
        """
        cmd = args[0] if args else kwargs.get("args", [])
        if _is_networked_git(cmd):
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=1)
        return real_run(*args, **kwargs)

    monkeypatch.setattr(subprocess, "run", timing_out)


def _is_networked_git(cmd: object) -> bool:
    """Whether a command is a git invocation that reaches a remote.

    Defers to the guard's own classifier, including how it renders each
    token: ``subprocess`` accepts lists and tuples of ``str``, ``bytes``
    or path-like arguments, and rendering those with ``str()`` turns
    ``b"--version"`` into ``"b'--version'"`` -- which reads as neither a
    known local subcommand nor an option, so a local command would be
    failed as though it had reached out.

    Args:
        cmd: The command as ``subprocess`` received it.

    Returns:
        ``True`` when it would contact a remote.
    """
    if not isinstance(cmd, (list, tuple)) or len(cmd) < 2:
        return False
    if not _is_git(cmd[0]):
        return False
    return _reaches_a_remote(["git", *(_token_text(t) for t in cmd[1:])])


@pytest.fixture
def unrunnable_git(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make networked git commands fail before they start.

    An absent or unexecutable ``git`` raises out of ``subprocess.run``
    rather than returning an exit status, so it reaches the linter as
    neither a refusal nor a timeout and lands in each helper's last
    resort. The remote was never asked, which is the same state of
    knowledge as a connection that never opened.

    Args:
        monkeypatch: Used to replace ``subprocess.run``.
    """
    real_run = subprocess.run

    def unrunnable(*args: Any, **kwargs: Any) -> Any:
        """Refuse to start a networked git command, pass anything else on.

        Args:
            args: Positional arguments as ``subprocess.run`` takes them.
            kwargs: Keyword arguments, passed through.

        Returns:
            The real result for a local command.

        Raises:
            FileNotFoundError: For a command reaching a remote.
        """
        cmd = args[0] if args else kwargs.get("args", [])
        if _is_networked_git(cmd):
            raise FileNotFoundError(2, "No such file or directory: 'git'")
        return real_run(*args, **kwargs)

    monkeypatch.setattr(subprocess, "run", unrunnable)


@pytest.fixture
def signal_killed_git(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make networked git commands die the way a killed process does.

    An out-of-memory kill or a cancelled CI job ends git part way
    through: POSIX reports a negative status, and there is no message,
    because the process never got to write one. That silence is not the
    remote answering, but it is indistinguishable from it unless the
    status is read.

    Args:
        monkeypatch: Used to replace ``subprocess.run``.
    """
    _install_failing_git(monkeypatch, "", returncode=-9)


def _install_failing_git(
    monkeypatch: pytest.MonkeyPatch, message: str, returncode: int = 128
) -> list[Mapping[str, str] | None]:
    """Replace ``subprocess.run`` so networked git fails with ``message``.

    Args:
        monkeypatch: Used to install the replacement.
        message: The standard-error text to report.
        returncode: Status to report. A negative value is how POSIX
            reports termination by a signal.

    Returns:
        The environment each remote invocation was given, appended to as
        the run proceeds. Only the commands that reach a remote are
        recorded, since those are the ones whose output gets read.
    """
    real_run = subprocess.run
    environments: list[Mapping[str, str] | None] = []

    def failing_run(
        *args: Any, **kwargs: Any
    ) -> subprocess.CompletedProcess[Any]:
        """Fail a networked git command, pass anything else through.

        Args:
            args: Positional arguments as ``subprocess.run`` takes them.
            kwargs: Keyword arguments, read for the text mode.

        Returns:
            A failed process for git, or the real result otherwise.
        """
        cmd = args[0] if args else kwargs.get("args", [])
        if not _is_networked_git(cmd):
            return real_run(*args, **kwargs)

        environments.append(kwargs.get("env"))
        text = bool(kwargs.get("text") or kwargs.get("universal_newlines"))
        stdout: Any = "" if text else b""
        stderr: Any = message if text else message.encode()
        if kwargs.get("check"):
            # ``subprocess.run`` raises on a non-zero exit when asked to,
            # and callers rely on that: a double that returns the failure
            # instead leaves them parsing empty output as a valid answer,
            # which reads as "no such reference" rather than "could not
            # ask".
            raise subprocess.CalledProcessError(
                returncode=returncode, cmd=cmd, output=stdout, stderr=stderr
            )
        return subprocess.CompletedProcess(
            args=cmd, returncode=returncode, stdout=stdout, stderr=stderr
        )

    monkeypatch.setattr(subprocess, "run", failing_run)
    return environments


@pytest.fixture
def no_rate_limit_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer the pre-flight rate-limit query without asking GitHub.

    ``_configure_validation_backend`` probes ``/rate_limit`` once, before
    dispatching, whenever a token selects the API backend. A test about
    token handling reaches GitHub for that reason alone, which is
    incidental to what it asserts.

    Reports "not throttled", the ordinary case. A test about throttling
    stubs this itself with the answer it needs.

    Args:
        monkeypatch: Used to replace the probe.
    """
    monkeypatch.setattr(
        github_api.GitHubGraphQLClient,
        "check_rate_limit",
        lambda _self: False,
    )


@pytest.fixture
def no_repository_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer the fixer's redirect probe without asking GitHub.

    Before resolving a reference the auto-fixer sends an HTTP ``HEAD``
    to ``https://github.com/<owner>/<repo>`` to notice a renamed
    repository. It is a third route out, distinct from the GraphQL API
    and from ``git ls-remote``, so stubbing those leaves it open -- and
    it is incidental to most tests that happen to run the fixer.

    Args:
        monkeypatch: Used to replace the probe.
    """

    async def no_redirect(_self: object, _repo_key: str) -> None:
        """Report that the repository has not moved.

        Args:
            _self: The fixer, unused.
            _repo_key: The repository asked about, unused.

        Returns:
            ``None``, meaning no redirect.
        """
        return None

    monkeypatch.setattr(
        auto_fix.AutoFixer, "_detect_repository_redirect", no_redirect
    )


@pytest.fixture
def real_client_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restore the startup refresh for a test that is about it.

    ``quiet_client_startup`` stubs the refresh for the whole suite, so a
    test of the refresh itself would otherwise assert against the stub.
    Requested per test rather than overridden per module: an override
    covers every test in the file, and seven of them opened a client for
    unrelated reasons and reached GitHub as a result.

    A test asking for this must supply its own HTTP double, or the guard
    will refuse the request it makes.

    Args:
        monkeypatch: Used to put the genuine method back.
    """
    monkeypatch.setattr(
        github_api.GitHubGraphQLClient,
        "_update_rate_limit_info",
        REAL_UPDATE_RATE_LIMIT_INFO,
    )


@pytest.fixture(autouse=True)
def quiet_client_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop entering the API client from fetching a rate-limit budget.

    ``GitHubGraphQLClient.__aenter__`` refreshes its budget from
    ``/rate_limit`` before doing anything else, so every test that opens
    a client reaches GitHub whether or not it is about the API. That is
    incidental startup work rather than the subject of those tests, and
    it went unnoticed because ``_update_rate_limit_info`` catches
    ``Exception`` and carries on -- so the request happened, failed
    silently, and the test passed.

    Neutralised here rather than in ninety-two individual tests. Nothing
    is lost: the pre-flight query, which is a different call and one
    callers actually depend on, is exercised directly in
    ``test_rate_limit_preflight.py`` with its own doubles.

    Args:
        monkeypatch: Used to replace the refresh for the test's duration.
    """

    async def no_refresh(_self: object) -> None:
        """Skip the startup refresh.

        Args:
            _self: The client, unused.
        """
        return None

    monkeypatch.setattr(
        github_api.GitHubGraphQLClient,
        "_update_rate_limit_info",
        no_refresh,
        raising=True,
    )


#: Git subcommands that always reach a remote. A deny list alone leaks,
#: so this is paired with the allowlist below rather than used on its
#: own.
_NETWORKED_GIT_SUBCOMMANDS = frozenset(
    {"clone", "fetch", "ls-remote", "pull", "push"}
)

#: Subcommands whose networking depends on what they are asked to do,
#: paired with the actions established as local. Anything else is
#: refused, for the same reason the top-level list works this way:
#: ``git remote show`` queries the remote, and ``git submodule foreach``
#: will run whatever it is handed. The linter uses ``remote get-url``,
#: which is why these are not simply refused outright.
_LOCAL_GIT_ACTIONS = {
    "remote": frozenset(
        {"add", "get-url", "remove", "rename", "rm", "set-url"}
    ),
    "submodule": frozenset(
        {"absorbgitdirs", "deinit", "init", "set-branch", "set-url", "status"}
    ),
}

#: Subcommands that are local unless asked to reach a remote, which they
#: name with a flag rather than a subcommand.
_NETWORKED_GIT_FLAGS = {"archive": "--remote"}

#: Actions that are local only while a flag is absent. ``git remote add
#: -f`` fetches from the remote it has just been given, so classifying
#: on the action name alone lets it through.
_LOCAL_GIT_ACTIONS_UNLESS = {
    ("remote", "add"): frozenset({"-f", "--fetch"}),
}

#: Everything else is refused. Working from what is known to be local,
#: rather than from a list of networked commands, means an unfamiliar
#: subcommand is refused until someone establishes it is safe -- a deny
#: list would admit every subcommand nobody thought of. The
#: application's own surface is four commands wide, so this costs
#: nothing in practice.
_LOCAL_GIT_SUBCOMMANDS = frozenset(
    {
        "add",
        "apply",
        "branch",
        "cat-file",
        "check-ignore",
        "checkout",
        "commit",
        "config",
        "diff",
        "for-each-ref",
        "hash-object",
        "init",
        "log",
        "ls-files",
        "ls-tree",
        "merge-base",
        "reset",
        "restore",
        "rev-list",
        "rev-parse",
        "show",
        "show-ref",
        "stash",
        "status",
        "switch",
        "symbolic-ref",
        "tag",
        "update-ref",
        "worktree",
    }
)

#: Git's global options that consume the token after them. The
#: subcommand is not reliably the second token: ``git -C repo fetch`` is
#: ordinary usage, and reading ``cmd[1]`` would find ``-C`` and let the
#: fetch through.
_GIT_GLOBAL_OPTIONS_WITH_VALUE = frozenset(
    {
        "-C",
        "-c",
        "--git-dir",
        "--work-tree",
        "--namespace",
        "--exec-path",
        "--super-prefix",
        "--config-env",
    }
)


def _git_subcommand(command: Sequence[str]) -> tuple[str | None, list[str]]:
    """Find the subcommand in a git invocation, past any global options.

    Args:
        command: The full argument vector, beginning with ``git``.

    Returns:
        The subcommand and the arguments following it, or ``None`` and
        an empty list when the invocation carries no subcommand.
    """
    tokens = list(command[1:])
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith("-"):
            return token, tokens[index + 1 :]
        # ``--git-dir=x`` carries its value; ``--git-dir x`` does not.
        index += 2 if token in _GIT_GLOBAL_OPTIONS_WITH_VALUE else 1
    return None, []


#: Shell control operators that separate one command from the next. A
#: shell string is not one invocation: ``echo ready && git fetch`` runs
#: two, and tokenising the whole line finds ``echo`` at the front.
_SHELL_SEPARATORS = re.compile(r"&&|\|\||;|\||\n|&")

#: Constructs whose expansion this cannot predict. A string carrying one
#: *and* mentioning git is not classifiable, so it is refused rather than
#: guessed at.
_SHELL_SUBSTITUTION = re.compile(r"\$\(|`|\$\{")


def _shell_command_vectors(text: str) -> list[list[str]] | None:
    """Split a shell command line into the invocations it runs.

    Args:
        text: The command line as handed to ``shell=True``.

    Returns:
        One argument vector per invocation, or ``None`` when the line
        cannot be classified and must be refused outright.
    """
    if _SHELL_SUBSTITUTION.search(text):
        # Expansion could produce anything, including a git command
        # assembled at run time.
        return None
    vectors: list[list[str]] = []
    for part in _SHELL_SEPARATORS.split(text):
        try:
            vectors.append(shlex.split(part))
        except ValueError:
            # Unbalanced quoting: not parseable, so not classifiable.
            return None
    return vectors


def _token_text(token: object) -> str:
    """Render one command token as the text the OS would see.

    ``subprocess`` accepts ``str``, ``bytes`` and path-like arguments
    interchangeably, so a guard that reaches for ``str()`` mangles two
    of the three: ``str(b"git")`` is ``"b'git'"``, which matches nothing
    and lets a perfectly ordinary ``[b"git", b"fetch"]`` through.

    Args:
        token: One element of a command vector.

    Returns:
        The token as text, or an empty string when it is neither a
        string, bytes, nor path-like.
    """
    if isinstance(token, bytes):
        return token.decode("utf-8", "replace")
    if isinstance(token, (str, os.PathLike)):
        return str(token)
    return ""


def _is_git(executable: object) -> bool:
    """Whether a command's first token invokes git.

    Compares the basename, because a resolved path is an ordinary way to
    call it: ``subprocess.run([shutil.which("git"), "fetch"])`` passes
    ``/usr/bin/git``, which matching the literal ``git`` would let
    straight through.

    Args:
        executable: The command's first token, of any type accepted by
            ``subprocess`` -- ``str``, ``bytes`` or path-like.

    Returns:
        ``True`` when the token names the git binary.
    """
    return os.path.basename(_token_text(executable)) in {"git", "git.exe"}


def _compound_action_reaches_a_remote(
    subcommand: str, rest: Sequence[str]
) -> bool:
    """Whether a ``remote``/``submodule`` invocation contacts a remote.

    Args:
        subcommand: The compound subcommand.
        rest: The arguments following it.

    Returns:
        ``True`` when the action is not established as local.
    """
    action = next((t for t in rest if not t.startswith("-")), None)
    if action is None:
        # ``git remote`` on its own lists configured names.
        return False
    if action not in _LOCAL_GIT_ACTIONS[subcommand]:
        return True
    reaching = _LOCAL_GIT_ACTIONS_UNLESS.get((subcommand, action), frozenset())
    return any(token in reaching for token in rest)


def _reaches_a_remote(command: Sequence[str]) -> bool:
    """Whether a git invocation would contact a remote.

    Args:
        command: The full argument vector, beginning with ``git``.

    Returns:
        ``True`` when the command is not established as local.
    """
    subcommand, rest = _git_subcommand(command)
    if subcommand is None:
        # Options only, as in ``git --version``.
        return False
    if subcommand in _NETWORKED_GIT_SUBCOMMANDS:
        return True
    if subcommand in _NETWORKED_GIT_FLAGS:
        flag = _NETWORKED_GIT_FLAGS[subcommand]
        return any(token.startswith(flag) for token in rest)
    if subcommand in _LOCAL_GIT_ACTIONS:
        return _compound_action_reaches_a_remote(subcommand, rest)
    return subcommand not in _LOCAL_GIT_SUBCOMMANDS


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


#: The unpatched transports, captured before any guard is installed, so
#: an exempt test can prove the guard stood aside without performing any
#: I/O to do it.
REAL_HTTP_TRANSPORT = httpx.HTTPTransport.handle_request
REAL_ASYNC_HTTP_TRANSPORT = httpx.AsyncHTTPTransport.handle_async_request
REAL_SUBPROCESS_RUN = subprocess.run


class NetworkAccessError(BaseException):
    """A test reached the network without declaring that it would.

    Deliberately not an :class:`Exception`. The application catches
    broadly and by design -- git validation turns a failed lookup into
    an invalid-reference finding, the rate-limit refresh carries on
    after any failure, and the auto-fixer swallows a failed resolution.
    Each is reasonable on its own, and each absorbs a guard raised as an
    ``Exception``: the request is refused, the test records the refusal
    as an ordinary result, and it passes. That is worse than no guard,
    because it looks like one.

    Inheriting from ``BaseException`` puts it past those handlers, so a
    test that reaches for the network fails for having reached. The one
    ``except BaseException`` in the source removes a temporary file and
    re-raises, so nothing absorbs it there either.
    """


@pytest.fixture(autouse=True)
def forbid_network(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Generator[None, None, None]:
    """Fail any unmarked test that reaches the network.

    The suite has repeatedly been slowed and destabilised by tests
    quietly depending on github.com -- once for 115 seconds against a
    120 second timeout. The dependency is invisible until measured,
    because a networked test looks exactly like a fast one whenever the
    network happens to be quick.

    Refusing the request is only half of it. Raising
    :class:`NetworkAccessError` from ``BaseException`` carries it past
    the application's direct ``except Exception`` handlers, but not past
    ``asyncio.gather(..., return_exceptions=True)``, which *returns*
    such objects as results: the git validator turns one into a
    ``NETWORK_ERROR`` finding, and the fixer skips it. Five gather sites
    sit on exactly the routes this guards.

    So violations are recorded as well as raised, and the test fails at
    teardown for having attempted one however its exception was
    disposed of. That holds regardless of what the application catches,
    which is what makes the guarantee worth stating.

    Both routes out are covered: httpx for the API clients, and
    ``subprocess`` for the git binary, whose traffic belongs to a child
    process and which no socket-level guard would see.

    The guard sits on httpx's *real* transports rather than on
    ``Client.send``, so a test that installs a ``MockTransport`` is
    unaffected: its requests never reach a transport that would have
    gone anywhere. A request to a reserved or loopback name is answered
    with the connection error it would have produced, rather than being
    allowed out: reaching for a name that resolves to nothing is still a
    network operation, and httpx would honour a proxy on the way.

    Git is refused by *allowlist*. A list of networked subcommands leaks
    -- ``pull``, ``remote update``, ``submodule update`` and ``archive
    --remote`` all reach a remote -- so anything not established as
    local is refused instead.

    Tests that genuinely need a live answer declare ``@pytest.mark.network``
    and are exempt, which is what makes that marker mean something. A
    test that provokes the guard deliberately declares
    ``@pytest.mark.expects_network_refusal``, so its own violations do
    not fail it at teardown.

    Args:
        request: Used to read the test's markers.
        monkeypatch: Used to install and remove the guards.

    Yields:
        Nothing; the guards are active for the test's duration.

    Raises:
        NetworkAccessError: When an unmarked test attempts a request.
    """
    if request.node.get_closest_marker("network"):
        yield
        return

    attempted: list[str] = []
    # Attached to the node so a test can assert the attempt was seen even
    # when nothing propagated -- which is the case this records for.
    request.node.network_attempts = attempted

    def refuse(target: str) -> NetworkAccessError:
        attempted.append(target)
        return NetworkAccessError(
            f"{request.node.name} attempted to reach {target}. Tests must "
            f"not depend on the network: stub the call, or declare the "
            f"dependency with @pytest.mark.network if a live answer is "
            f"genuinely required."
        )

    real_run = subprocess.run

    def offline_failure(req: Any) -> httpx.ConnectError:
        """Build the error a reserved name would have produced.

        Synthesised rather than delegated to the real transport. A
        reserved name resolves to nothing, but reaching for it is still
        a network operation: httpx honours proxy environment variables
        by default, so the request can leave for a real proxy, and
        without one it still issues a DNS query. Both make the suite
        depend on its surroundings, and a proxy can answer where the
        test expects a refusal.

        Args:
            req: The request that would have gone out.

        Returns:
            The connection error to raise in its place.
        """
        return httpx.ConnectError(
            f"[Errno 8] nodename nor servname provided: {req.url.host}",
            request=req,
        )

    def guarded_handle(_self: Any, req: Any) -> Any:
        if _is_offline_host(req.url.host):
            raise offline_failure(req)
        raise refuse(str(req.url))

    async def guarded_ahandle(_self: Any, req: Any) -> Any:
        if _is_offline_host(req.url.host):
            raise offline_failure(req)
        raise refuse(str(req.url))

    def reaches_a_remote(cmd: Any) -> str | None:
        """Describe the networked git invocation in a command, if any.

        Args:
            cmd: The command as ``subprocess`` received it.

        Returns:
            A short description to refuse with, or ``None`` when the
            command reaches nothing.
        """
        if isinstance(cmd, (str, bytes)):
            text = (
                cmd.decode("utf-8", "replace")
                if isinstance(cmd, bytes)
                else cmd
            )
            vectors = _shell_command_vectors(text)
            if vectors is None:
                return text[:60] if "git" in text else None
        elif isinstance(cmd, (list, tuple)):
            vectors = [[_token_text(token) for token in cmd]]
        else:
            return None

        for vector in vectors:
            if (
                len(vector) > 1
                and _is_git(vector[0])
                and _reaches_a_remote(["git", *vector[1:]])
            ):
                return " ".join(vector[:3])
        return None

    def guarded_run(*args: Any, **kwargs: Any) -> Any:
        cmd = args[0] if args else kwargs.get("args", [])
        reaching = reaches_a_remote(cmd)
        if reaching is not None:
            raise refuse(reaching)
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

    yield

    if attempted and not request.node.get_closest_marker(
        "expects_network_refusal"
    ):
        pytest.fail(
            f"{request.node.name} attempted to reach the network "
            f"{len(attempted)} time(s): "
            f"{', '.join(sorted(set(attempted)))}. Stub the call, or "
            f"declare the dependency with @pytest.mark.network if a live "
            f"answer is genuinely required. This is reported at teardown "
            f"because the refusal may have been caught and discarded -- "
            f"asyncio.gather returns it as a result, and the application "
            f"handles failures broadly -- so the attempt is recorded as "
            f"well as raised.",
            pytrace=False,
        )


# Markers for test categorization
pytest_markers = [
    "unit: marks tests as unit tests (deselect with '-m \"not unit\"')",
    "integration: marks tests as integration tests",
    "slow: marks tests as slow running tests",
    "network: marks tests that require network access",
    "expects_network_refusal: marks tests that provoke the network "
    "guard deliberately, so their own violations must not fail them",
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
