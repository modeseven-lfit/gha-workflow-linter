# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The suite's own guard against reaching the network.

Two separate incidents came from tests quietly depending on github.com:
one test grew to 115 seconds against a 120 second timeout and blocked
committing, and a set of validator tests passed only because a
developer's credentials happened to select a different backend from the
one CI used. Neither was visible until the suite was instrumented,
because a networked test looks exactly like a fast one whenever the
network happens to be quick.

``forbid_network`` in ``conftest`` makes that failure mode loud. These
tests hold it to its contract, because a guard nothing exercises is a
guard that quietly stops working: each case below fails if the
corresponding branch is removed.

The guard is active while these tests run, so they can provoke it
directly rather than simulating it.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import httpx
import pytest

from gha_workflow_linter.git_refs import _parse_ls_remote_lines
from tests.conftest import (
    REAL_ASYNC_HTTP_TRANSPORT,
    REAL_HTTP_TRANSPORT,
    REAL_SUBPROCESS_RUN,
    NetworkAccessError,
    _reaches_a_remote,
)


class TestOutwardRequestsAreRefused:
    """The two routes out of the process, both covered."""

    def test_a_live_http_request_is_refused(self) -> None:
        """The API clients' route, and the one that cost the most time."""
        with pytest.raises(NetworkAccessError, match="api.github.com"):
            httpx.get("https://api.github.com/rate_limit", timeout=5.0)

    @pytest.mark.asyncio
    async def test_a_live_async_request_is_refused(self) -> None:
        """The async transport is a separate object and a separate patch.

        Every client in the linter is asynchronous, so this is the path
        that actually matters -- yet only the synchronous guard was
        asserted, leaving the async one able to break silently. The
        existing API tests would not have noticed: they absorb the
        refusal through the application's own broad handlers.
        """
        async with httpx.AsyncClient() as client:
            with pytest.raises(NetworkAccessError, match="api.github.com"):
                await client.get(
                    "https://api.github.com/rate_limit", timeout=5.0
                )

    @pytest.mark.parametrize(
        "command",
        [
            "git fetch origin",
            "git ls-remote https://github.com/actions/checkout",
            "echo ready && git fetch origin",
            "echo ready; git fetch origin",
            "true || git pull",
            "echo one | git fetch origin",
            "echo one\ngit fetch origin",
            "git fetch origin &",
            "echo $(git fetch origin)",
            "echo `git fetch origin`",
            'git fetch "unbalanced',
        ],
        ids=[
            "plain",
            "ls-remote",
            "and",
            "semicolon",
            "or",
            "pipe",
            "newline",
            "background",
            "substitution",
            "backticks",
            "unparsable",
        ],
    )
    def test_a_shell_command_string_is_refused(self, command: str) -> None:
        """``shell=True`` takes one string, not an argument vector.

        Tokenising the line is not enough on its own: a shell string is
        not one invocation, and ``echo ready && git fetch`` puts ``echo``
        at the front of the vector while still running the fetch. The
        line is split on control operators and every segment classified.

        The last three are not classifiable at all -- expansion could
        assemble a command at run time, and unbalanced quoting cannot be
        parsed -- so they are refused rather than guessed at, on the
        principle that an unreadable git invocation is not evidence of a
        local one.

        Args:
            command: The shell command line under test.
        """
        with pytest.raises(NetworkAccessError):
            subprocess.run(
                command, shell=True, capture_output=True, check=False
            )

    @pytest.mark.parametrize(
        "command",
        ["git --version", "echo hello && git --version", "echo $(date)"],
        ids=["plain", "compound", "substitution-without-git"],
    )
    def test_a_local_shell_command_string_is_allowed(
        self, command: str
    ) -> None:
        """The inverse: shell strings are classified, not banned.

        Including a substitution that has nothing to do with git, since
        refusing every unparsable line regardless of content would make
        the shell unusable to prove a point about network access.

        Args:
            command: The shell command line under test.
        """
        result = subprocess.run(
            command, shell=True, capture_output=True, check=False
        )

        assert result.returncode == 0

    @pytest.mark.parametrize(
        "command",
        [
            ["git", "ls-remote", "https://github.com/actions/checkout"],
            ["git", "pull", "origin", "main"],
            ["git", "remote", "update"],
            ["git", "remote", "show", "origin"],
            ["git", "remote", "prune", "origin"],
            ["git", "submodule", "update", "--init"],
            ["git", "submodule", "foreach", "git fetch"],
            ["git", "remote", "add", "-f", "origin", "https://example.com/x"],
            ["git", "remote", "add", "--fetch", "o", "https://example.com/x"],
            ["git", "archive", "--remote=ssh://host/x", "HEAD"],
            ["git", "clone", "https://github.com/actions/checkout"],
        ],
        ids=[
            "ls-remote",
            "pull",
            "remote-update",
            "remote-show",
            "remote-prune",
            "submodule-update",
            "submodule-foreach",
            "remote-add-f",
            "remote-add-fetch",
            "archive",
            "clone",
        ],
    )
    def test_a_networked_git_command_is_refused(
        self, command: list[str]
    ) -> None:
        """The git binary's route, refused by allowlist rather than deny.

        A socket-level guard would miss all of these: the traffic
        belongs to a child process, so nothing in this interpreter opens
        a connection. A deny list would miss most of them too --
        ``pull``, ``remote update``, ``submodule update`` and ``archive
        --remote`` all reach a remote without naming themselves as
        network commands.

        Args:
            command: The invocation under test.
        """
        with pytest.raises(NetworkAccessError):
            subprocess.run(command, capture_output=True, check=False)

    def test_an_unfamiliar_subcommand_is_refused(self) -> None:
        """The point of the allowlist: unknown means refused, not allowed.

        A deny list admits every subcommand nobody thought of. This is
        the property that makes the guard hold as git grows.
        """
        with pytest.raises(NetworkAccessError):
            subprocess.run(
                ["git", "some-future-subcommand"],
                capture_output=True,
                check=False,
            )

    def test_an_unfamiliar_action_is_refused_too(self) -> None:
        """The same default has to reach inside the compound commands.

        ``remote`` and ``submodule`` are local or not depending on the
        action, so listing the *networked* ones there would reintroduce
        the deny list one level down -- and it leaks the same way, since
        ``remote show`` queries the remote without saying so.
        """
        with pytest.raises(NetworkAccessError):
            subprocess.run(
                ["git", "remote", "some-future-action"],
                capture_output=True,
                check=False,
            )

    def test_a_resolved_path_to_git_is_still_git(self) -> None:
        """Matching the literal ``git`` is not enough to recognise it.

        ``subprocess.run([shutil.which("git"), ...])`` is an ordinary
        way to call a binary, and passes an absolute path. A guard
        comparing the whole token lets it through while believing it
        covers the subprocess route.
        """
        git = shutil.which("git")
        assert git is not None, "git is required to run this suite"

        with pytest.raises(NetworkAccessError):
            subprocess.run(
                [git, "fetch", "origin"], capture_output=True, check=False
            )

    def test_a_path_object_is_recognised_too(self) -> None:
        """``subprocess`` accepts path-like arguments, so the guard must."""
        git = shutil.which("git")
        assert git is not None, "git is required to run this suite"

        with pytest.raises(NetworkAccessError):
            subprocess.run(
                [Path(git), "ls-remote", "https://example.com/x"],
                capture_output=True,
                check=False,
            )

    def test_a_bytes_vector_is_recognised_too(self) -> None:
        """``subprocess`` accepts bytes arguments, so the guard must.

        Rendering a token with ``str()`` turns ``b"git"`` into
        ``"b'git'"``, which matches nothing -- so a guard that claims to
        handle bytes can still let an ordinary bytes invocation through
        while its own helper looks correct in isolation.
        """
        with pytest.raises(NetworkAccessError):
            subprocess.run(
                [b"git", b"fetch", b"origin"],
                capture_output=True,
                check=False,
            )

    @pytest.mark.parametrize(
        "prefix",
        [
            ["-C", "/tmp"],
            ["-c", "user.name=nobody"],
            ["--git-dir", "/tmp/.git"],
            ["--no-pager"],
            ["--git-dir=/tmp/.git"],
        ],
        ids=["-C", "-c", "--git-dir", "--no-pager", "--git-dir="],
    )
    def test_global_options_do_not_smuggle_it_past(
        self, prefix: list[str]
    ) -> None:
        """The subcommand is not reliably the second token.

        ``git -C repo fetch`` is ordinary usage, and a guard reading
        ``cmd[1]`` finds ``-C`` and lets the fetch through. Both forms of
        value-carrying option are covered, since ``--git-dir=x`` consumes
        no following token while ``--git-dir x`` does.

        Args:
            prefix: Global options placed before the subcommand.
        """
        with pytest.raises(NetworkAccessError):
            subprocess.run(
                ["git", *prefix, "fetch", "origin"],
                capture_output=True,
                check=False,
            )

    def test_the_refusal_names_the_test_and_the_remedy(self) -> None:
        """A guard that fires without explaining itself wastes the reader.

        The message has to say which test reached out, where, and what
        to do about it, or the next person meets an assertion with no
        route forward.
        """
        with pytest.raises(NetworkAccessError) as caught:
            httpx.get("https://github.com", timeout=5.0)

        message = str(caught.value)
        assert "test_the_refusal_names_the_test_and_the_remedy" in message
        assert "github.com" in message
        assert "@pytest.mark.network" in message


class TestTheGitDoubleHonoursTextMode:
    """The double must answer in the form its caller asked for.

    ``git_refs`` runs ``subprocess.run(..., text=True)`` and hands
    ``result.stdout`` to ``_parse_ls_remote_lines(stdout: str)``. A
    double returning bytes there produces a ``TypeError`` deep in
    parsing, which validation catches and reports as an invalid
    reference -- so a test accepting a non-zero exit stays green while
    exercising the error path instead of the backend it names.
    """

    def test_text_mode_returns_str(self, mock_git_commands: None) -> None:
        """Args:
        mock_git_commands: The double under test.
        """
        result = subprocess.run(
            ["git", "ls-remote", "--tags", "https://example.com/x"],
            capture_output=True,
            text=True,
            check=False,
        )

        assert isinstance(result.stdout, str)
        assert isinstance(result.stderr, str)

    def test_binary_mode_still_returns_bytes(
        self, mock_git_commands: None
    ) -> None:
        """The inverse: honouring the flag means both directions.

        Args:
            mock_git_commands: The double under test.
        """
        result = subprocess.run(
            ["git", "ls-remote", "https://example.com/x"],
            capture_output=True,
            check=False,
        )

        assert isinstance(result.stdout, bytes)

    def test_the_output_parses_as_real_output_would(
        self, mock_git_commands: None
    ) -> None:
        """Shape matters as much as type, or parsing yields nothing.

        Args:
            mock_git_commands: The double under test.
        """
        result = subprocess.run(
            ["git", "ls-remote", "--tags", "https://example.com/x", "v4"],
            capture_output=True,
            text=True,
            check=False,
        )

        pairs = _parse_ls_remote_lines(result.stdout)
        assert pairs, "the double produced nothing a parser could use"
        assert all(len(sha) == 40 for sha, _ in pairs)


class TestLegitimateTrafficIsUnaffected:
    """The inverses. A guard that blocks everything is unusable."""

    def test_a_mock_transport_is_untouched(self) -> None:
        """Most of the suite stubs httpx this way and must keep working.

        The guard sits on the real transports rather than on
        ``Client.send``, so a request answered by a ``MockTransport``
        never reaches anything that would have gone out. Guarding
        ``send`` instead broke 20 correctly-written tests.
        """
        transport = httpx.MockTransport(
            lambda _request: httpx.Response(200, json={"ok": True})
        )
        with httpx.Client(transport=transport) as client:
            response = client.get("https://api.github.com/rate_limit")

        assert response.json() == {"ok": True}

    def test_a_reserved_host_is_allowed(self) -> None:
        """Names RFC 2606 reserves answer with the failure under test.

        Tests that deliberately provoke a connection failure point at
        ``.invalid`` and assert on the resulting error. They get it --
        but synthesised, not fetched: reaching for a name that resolves
        to nothing is still a network operation, and httpx would honour
        a proxy on the way, which could answer where the test expects a
        refusal.
        """
        with pytest.raises(httpx.ConnectError):
            httpx.get("https://nonexistent-domain.invalid/x", timeout=5.0)

    def test_a_local_git_command_is_allowed(self) -> None:
        """Git is still usable as a local tool.

        Only the subcommands that contact a remote are refused, so a
        test may still create or inspect a repository on disk.
        """
        result = subprocess.run(
            ["git", "--version"], capture_output=True, check=False
        )

        assert result.returncode == 0

    def test_a_local_command_behind_global_options_is_allowed(self) -> None:
        """The inverse of the smuggling case.

        Parsing past global options must not turn into refusing every
        invocation that carries one.
        """
        result = subprocess.run(
            ["git", "-C", "/tmp", "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            check=False,
        )

        # Whatever /tmp is, the guard let the command run and answer.
        assert result.returncode in (0, 128)

    @pytest.mark.parametrize(
        "command",
        [
            ["git", "remote", "get-url", "origin"],
            ["git", "remote"],
            ["git", "remote", "add", "origin", "https://example.com/x"],
            ["git", "submodule", "status"],
        ],
        ids=[
            "remote-get-url",
            "remote-list",
            "remote-add",
            "submodule-status",
        ],
    )
    def test_a_local_action_is_allowed(self, command: list[str]) -> None:
        """The compound commands must stay usable in their local forms.

        The linter itself runs ``git remote get-url`` to determine an
        organisation, so refusing these outright breaks six tests --
        which is how the balance here was established rather than
        guessed.

        Asserted through the classifier rather than by running them.
        ``git remote add`` would otherwise write a remote into whatever
        repository the suite happens to run in, and a test that mutates
        the checkout to prove a point about classification is a poor
        trade.

        Args:
            command: The invocation under test.
        """
        assert _reaches_a_remote(command) is False

    def test_a_non_git_command_is_allowed(self) -> None:
        """The guard inspects the command rather than blocking subprocess."""
        result = subprocess.run(
            ["echo", "hello"], capture_output=True, check=False
        )

        assert result.stdout.strip() == b"hello"


@pytest.mark.network
class TestTheMarkerExempts:
    """The escape hatch, without which the guard could not be adopted.

    A test that genuinely needs a live answer declares it. That is what
    gives ``@pytest.mark.network`` meaning: before this guard existed the
    marker was applied by guessing from the test's name, and so missed
    the most network-dependent test in the suite.

    Proving the exemption must not itself reach the network. These tests
    are exempt, so anything they send really would go out -- and since
    marked tests are not deselected, that would put the dependency back
    into the default suite by way of the guard's own tests. Both cases
    therefore assert that the guard *stood aside*, which is the whole
    claim, without exercising what it stood aside from.
    """

    def test_the_http_guards_are_not_installed(self) -> None:
        """Both transports are left as they were found.

        Identity against the references captured before any patching,
        so this needs no request at all -- not even to a name that
        resolves to nothing, which still costs a DNS query and can meet
        a proxy on the way.
        """
        assert httpx.HTTPTransport.handle_request is REAL_HTTP_TRANSPORT
        assert (
            httpx.AsyncHTTPTransport.handle_async_request
            is REAL_ASYNC_HTTP_TRANSPORT
        )

    def test_a_marked_test_may_run_networked_git(self) -> None:
        """The subprocess route runs rather than being refused.

        Pointed at a local path that is not a repository, so git fails
        without leaving the machine. An unmarked test would not get this
        far: the guard refuses ``ls-remote`` before it runs, whatever it
        is pointed at.
        """
        assert subprocess.run is REAL_SUBPROCESS_RUN

        result = subprocess.run(
            ["git", "ls-remote", "/nonexistent/not-a-repository.git"],
            capture_output=True,
            check=False,
            timeout=30,
        )

        assert result.returncode != 0
