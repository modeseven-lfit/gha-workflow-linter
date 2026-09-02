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

import asyncio
from pathlib import Path
import shutil
import subprocess

import httpx
import pytest

from gha_workflow_linter.git_refs import _parse_ls_remote_lines
from gha_workflow_linter.github_api import GitHubGraphQLClient
from gha_workflow_linter.models import GitHubAPIConfig
from tests.conftest import (
    REAL_ASYNC_HTTP_TRANSPORT,
    REAL_HTTP_TRANSPORT,
    REAL_SUBPROCESS_RUN,
    REAL_UPDATE_RATE_LIMIT_INFO,
    NetworkAccessError,
    _reaches_a_remote,
)

#: The checkout root, so a generated session can import this suite's
#: conftest rather than a copy of it.
REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.expects_network_refusal
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
        url = "https://github.com"
        with pytest.raises(NetworkAccessError) as caught:
            httpx.get(url, timeout=5.0)

        message = str(caught.value)
        assert "test_the_refusal_names_the_test_and_the_remedy" in message
        # Anchored past the delimiter, not merely up to it. The guard
        # refuses with str(req.url), so the exact target is available to
        # assert on -- but "github.com", "https://github.com" and even
        # "https://github.com." are all prefixes of a message naming
        # https://github.com.evil.example, so none of them pins what was
        # actually reached. Including the following word does.
        assert f"attempted to reach {url}. Tests" in message
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


@pytest.mark.expects_network_refusal
class TestTheGuardCannotBeSwallowed:
    """The application catches broadly; the guard must outlive that.

    Git validation turns a failed lookup into an invalid-reference
    finding, the rate-limit refresh carries on after any failure, and
    the auto-fixer swallows a failed resolution. Each is reasonable, and
    each absorbed a guard raised as an ``Exception``: the request was
    refused, the test recorded the refusal as an ordinary result, and it
    passed.

    That is worse than no guard, because it looks like one. Ninety-two
    tests were reaching for the network on that basis.
    """

    def test_it_is_not_an_exception(self) -> None:
        """``except Exception`` must not be able to name it."""
        assert issubclass(NetworkAccessError, BaseException)
        assert not issubclass(NetworkAccessError, Exception)

    def test_a_broad_handler_does_not_absorb_it(self) -> None:
        """Written as the application writes it, to show it passes through."""
        absorbed = False
        try:
            try:
                httpx.get("https://api.github.com/rate_limit", timeout=5.0)
            except Exception:  # noqa: BLE001 - mimics the application
                absorbed = True
        except NetworkAccessError:
            pass

        assert absorbed is False

    def test_the_application_itself_does_not_absorb_it(self) -> None:
        """The handler that hid it longest, exercised directly.

        ``_update_rate_limit_info`` catches ``Exception`` and carries
        on, which is why opening a client reached GitHub in fifty-nine
        tests without any of them failing. Driving the real method is
        what shows the guard now survives it.
        """
        client = GitHubGraphQLClient(GitHubAPIConfig(token=None))
        http = httpx.AsyncClient()
        client._http_client = http

        try:
            with pytest.raises(NetworkAccessError):
                asyncio.run(REAL_UPDATE_RATE_LIMIT_INFO(client))
        finally:
            asyncio.run(http.aclose())

    def test_gathering_it_as_a_result_does_not_hide_it(
        self, request: pytest.FixtureRequest
    ) -> None:
        """The hole ``BaseException`` alone does not close.

        ``asyncio.gather(..., return_exceptions=True)`` does not
        propagate: it *returns* the exception as a result, whatever its
        base class. The git validator then turns one into a
        ``NETWORK_ERROR`` finding and the fixer skips it, so five gather
        sites on exactly the guarded routes could still absorb a
        refusal. Ten tests were passing that way.

        Recording the attempt is what closes it. This provokes a
        refusal, discards it exactly as ``gather`` would, and then
        asserts the guard *noticed* -- which is what fails the test at
        teardown for any case not marked as provoking one deliberately.

        Args:
            request: Used to read what the guard recorded.
        """

        url = "https://api.github.com/rate_limit"

        async def attempt() -> object:
            """Reach for the network and let gather capture the refusal.

            Returns:
                Whatever gather returns, exception or otherwise.
            """

            async def one() -> None:
                async with httpx.AsyncClient() as client:
                    await client.get(url)

            results = await asyncio.gather(one(), return_exceptions=True)
            return results[0]

        captured = asyncio.run(attempt())

        # Returned rather than raised, which is the whole problem.
        assert isinstance(captured, NetworkAccessError)
        # Recorded regardless, which is the answer to it. Membership of
        # the exact URL rather than a host substring: the guard records
        # str(req.url), so nothing is lost by being precise, and a
        # substring test would accept a target that merely contained the
        # host somewhere.
        assert url in request.node.network_attempts


class TestTheTeardownCheckActuallyFails:
    """The recording is only useful if it fails the test that triggered it.

    Every other test of this mechanism runs inside a class marked
    ``expects_network_refusal``, which by design bypasses the teardown
    failure -- so none of them would notice if that branch were deleted.
    This runs pytest on a test that is *not* exempt, and checks the
    report.
    """

    def test_a_swallowed_attempt_fails_the_test(
        self, pytester: pytest.Pytester
    ) -> None:
        """Swallowing the refusal must not save the test.

        The inner test catches ``BaseException`` and passes its own
        assertions, exactly as ``asyncio.gather`` and the application's
        handlers do. It must still be reported as failing.

        Args:
            pytester: Runs a generated test file in a fresh session.
        """
        pytester.makeconftest(
            f"import sys; sys.path.insert(0, {str(REPOSITORY_ROOT)!r})\n"
            "from tests.conftest import *  # noqa: F401,F403\n"
        )
        pytester.makepyfile(
            """
            import httpx

            def test_swallows_the_refusal():
                try:
                    httpx.get("https://api.github.com/rate_limit")
                except BaseException:
                    pass
                assert True
            """
        )

        result = pytester.runpytest("-p", "no:randomly", "--no-cov")

        result.assert_outcomes(passed=1, errors=1)
        result.stdout.fnmatch_lines(["*attempted to reach the network*"])

    def test_a_test_that_stays_offline_is_untouched(
        self, pytester: pytest.Pytester
    ) -> None:
        """The inverse: the teardown must not fail an innocent test.

        Args:
            pytester: Runs a generated test file in a fresh session.
        """
        pytester.makeconftest(
            f"import sys; sys.path.insert(0, {str(REPOSITORY_ROOT)!r})\n"
            "from tests.conftest import *  # noqa: F401,F403\n"
        )
        pytester.makepyfile(
            """
            def test_touches_nothing():
                assert True
            """
        )

        result = pytester.runpytest("-p", "no:randomly", "--no-cov")

        result.assert_outcomes(passed=1, errors=0)


class TestTheFailureDoublesClassifyLikeTheGuard:
    """The failure doubles must recognise a command as the guard does.

    ``unreachable_git`` and ``timing_out_git`` decide what to fail by
    the same question the guard asks, so a second classifier written
    beside them would drift from everything the first one learned --
    global options, compound actions, resolved paths, argument types.
    These hold the two together at the cases most easily got wrong.
    """

    def test_a_local_bytes_command_still_runs(
        self, unreachable_git: None
    ) -> None:
        """Rendering a token with ``str()`` would fail this one.

        ``str(b"--version")`` is ``"b'--version'"``, which reads as
        neither a local subcommand nor an option, so a local command
        would be failed as though it had reached out.

        Args:
            unreachable_git: The double under test.
        """
        result = subprocess.run(
            [b"git", b"--version"], capture_output=True, check=False
        )

        assert result.returncode == 0

    def test_a_tuple_vector_is_recognised(self, unreachable_git: None) -> None:
        """``subprocess`` accepts tuples, so the double must fail them too.

        Args:
            unreachable_git: The double under test.
        """
        result = subprocess.run(
            ("git", "ls-remote", "https://example.com/x"),
            capture_output=True,
            check=False,
        )

        assert result.returncode == 128
        assert b"Could not resolve host" in result.stderr

    def test_the_timeout_double_agrees(self, timing_out_git: None) -> None:
        """Both doubles share the classifier, so both must behave alike.

        Args:
            timing_out_git: The double under test.
        """
        assert (
            subprocess.run(
                [b"git", b"--version"], capture_output=True, check=False
            ).returncode
            == 0
        )

        with pytest.raises(subprocess.TimeoutExpired):
            subprocess.run(
                ("git", "fetch", "origin"), capture_output=True, check=False
            )


@pytest.mark.expects_network_refusal
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
