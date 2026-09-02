# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""
End-to-end test for network error handling in the full linter pipeline.

This test verifies that when network issues occur during validation,
the linter properly reports the network problem instead of incorrectly
marking valid GitHub Actions as invalid.
"""

import ast
import asyncio
from collections.abc import Callable, Generator, Mapping
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Final, NoReturn
from unittest.mock import Mock, patch

import httpx
import pytest

from gha_workflow_linter import action_call_git, git_refs, git_subpath
from gha_workflow_linter.action_call_check import _abort_if_unreachable
from gha_workflow_linter.action_call_git import GitValidationClient
from gha_workflow_linter.cli import _handle_validation_aborted, run_linter
from gha_workflow_linter.exceptions import (
    GitUnreachableError,
    GitUnusableError,
    ValidationAbortedError,
)
from gha_workflow_linter.git_refs import AnnotatedTagPeel, is_transport_failure
from gha_workflow_linter.models import (
    CacheConfig,
    CLIOptions,
    Config,
    GitConfig,
    GitHubAPIConfig,
    ValidationResult,
)

#: The unpatched client class, captured at import. ``_install_api_responder``
#: may run several times in one test, and taking the "original" from the
#: module each time would capture the previous factory -- which pops the
#: transport it is handed and substitutes its own, so every request would
#: be recorded against the first responder.
_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _install_api_responder(
    monkeypatch: pytest.MonkeyPatch,
    responder: Callable[[httpx.Request], httpx.Response],
) -> list[str]:
    """Route every ``httpx.AsyncClient`` through a mock transport.

    Returns the list the transport records into, so a test can assert
    the backend was *reached* rather than merely that the run failed --
    the failure mode these tests had was passing without issuing the
    request they name.

    Args:
        monkeypatch: Used to replace the client class.
        responder: Handler answering each request.

    Returns:
        The URLs asked for, appended to as the run proceeds.
    """
    asked: list[str] = []

    def recording(request: httpx.Request) -> httpx.Response:
        """Record the request, then hand it to the responder.

        Args:
            request: The outgoing request.

        Returns:
            Whatever the responder answers.
        """
        asked.append(str(request.url))
        return responder(request)

    def factory(**kwargs: Any) -> httpx.AsyncClient:
        """Build a client whose transport answers locally.

        Any transport the caller asked for is replaced rather than
        added to, since the point is that nothing leaves.

        Args:
            kwargs: Arguments the caller passed.

        Returns:
            The client.
        """
        kwargs.pop("transport", None)
        return _REAL_ASYNC_CLIENT(
            transport=httpx.MockTransport(recording), **kwargs
        )

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return asked


#: Real git standard error, paired with whether it means the remote was
#: never reached. Both directions are listed together because the risk
#: runs both ways: too narrow a reading blames the workflow for a broken
#: network, and too broad a one discards genuine findings, which passes
#: workflows that are actually wrong.
STDERR_CLASSIFICATION: Final = [
    pytest.param(
        "fatal: unable to access 'https://github.com/a/b.git/': "
        "The requested URL returned error: 404",
        False,
        id="http-404",
    ),
    pytest.param(
        "fatal: unable to access 'https://github.com/a/b.git/': "
        "The requested URL returned error: 403",
        False,
        id="http-403",
    ),
    pytest.param(
        "fatal: could not read Username for 'https://github.com': "
        "terminal prompts disabled",
        False,
        id="auth-prompt-disabled",
    ),
    pytest.param(
        "fatal: repository 'https://github.com/a/b.git/' not found",
        False,
        id="repository-not-found",
    ),
    pytest.param(
        "ERROR: Repository not found.\n"
        "fatal: Could not read from remote repository.",
        False,
        id="ssh-repository-not-found",
    ),
    pytest.param(
        "git@github.com: Permission denied (publickey).\n"
        "fatal: Could not read from remote repository.",
        False,
        id="ssh-permission-denied",
    ),
    pytest.param(
        "fatal: unable to access "
        "'https://github.com/acme/kex_exchange_identification.git/': "
        "The requested URL returned error: 404",
        False,
        id="http-404-for-a-repository-named-after-a-marker",
    ),
    pytest.param(
        "fatal: unable to access 'https://github.com/a/b.git/': "
        "Could not resolve host: github.com",
        True,
        id="dns-failure",
    ),
    pytest.param(
        "fatal: unable to access 'https://127.0.0.1:9/': "
        "Failed to connect to 127.0.0.1 port 9",
        True,
        id="connection-refused",
    ),
    pytest.param(
        "ssh: connect to host github.com port 22: Connection refused",
        True,
        id="ssh-refused",
    ),
    pytest.param(
        "fatal: unable to access 'https://github.com/a/b.git/': "
        "GnuTLS recv error (-110): The TLS connection was "
        "non-properly terminated.",
        True,
        id="tls-connection-dropped",
    ),
    pytest.param(
        "fatal: unable to access 'https://github.com/a/b.git/': "
        "OpenSSL SSL_read: Connection was reset, errno 10054",
        True,
        id="tls-reset",
    ),
    pytest.param(
        "fatal: unable to access 'https://github.com/a/b.git/': "
        "Empty reply from server",
        True,
        id="empty-reply",
    ),
    pytest.param(
        "kex_exchange_identification: Connection closed by remote host\n"
        "Connection closed by 140.82.121.4 port 22",
        True,
        id="ssh-handshake-dropped",
    ),
    pytest.param(
        "fatal: unable to access 'https://github.com/a/b.git/': "
        "CONNECT tunnel failed, response 502",
        True,
        id="proxy-tunnel-failed",
    ),
    pytest.param(
        "fatal: unable to access 'https://github.com/a/b.git/': "
        "SSL certificate problem: unable to get local issuer certificate",
        True,
        id="tls-certificate-rejected",
    ),
    pytest.param(
        "fatal: unable to access 'https://github.com/a/b.git/': "
        "Recv failure: Operation timed out",
        True,
        id="receive-failed",
    ),
    pytest.param(
        "Host key verification failed.\n"
        "fatal: Could not read from remote repository.",
        True,
        id="ssh-host-key-rejected",
    ),
    pytest.param(
        "fatal: unable to access 'https://github.com/a/b.git/': "
        "The requested URL returned error: 500",
        True,
        id="http-500",
    ),
    pytest.param(
        "fatal: unable to access 'https://github.com/a/b.git/': "
        "The requested URL returned error: 503",
        True,
        id="http-503",
    ),
    pytest.param(
        "fatal: unable to access 'https://github.com/a/b.git/': "
        "The requested URL returned error: 429",
        True,
        id="http-429",
    ),
    pytest.param(
        "fatal: unable to access 'https://github.com/a/b.git/': "
        "The requested URL returned error: 408",
        True,
        id="http-408",
    ),
    pytest.param(
        "fatal: unable to access 'https://github.com/a/b.git/': "
        "The requested URL returned error: 407",
        True,
        id="http-407-proxy-auth",
    ),
    pytest.param(
        "error: cannot run ssh: No such file or directory\n"
        "fatal: unable to fork",
        True,
        id="ssh-binary-missing",
    ),
    pytest.param(
        "fatal: Unable to find remote helper for 'https'",
        True,
        id="transport-helper-missing",
    ),
    pytest.param(
        "git: 'remote-https' is not a git command. See 'git --help'.",
        True,
        id="transport-helper-not-installed",
    ),
]


@pytest.mark.parametrize(("stderr", "unreachable"), STDERR_CLASSIFICATION)
def test_git_stderr_says_whether_the_remote_answered(
    stderr: str, unreachable: bool
) -> None:
    """``git ls-remote`` exits 128 either way, so the message decides.

    The refusals here are the ones that look most like a network fault:
    git introduces every HTTP failure, 404 included, with ``unable to
    access``, so a classifier reading that prefix rather than the reason
    behind it would call each of them unreachable and drop the finding.
    The SSH refusals are here for the mirror-image reason -- ``Could not
    read from remote repository`` reads like a transport fault and is
    not one, so nothing may match it.

    The transport cases deliberately range wider than DNS and refused
    connections, since the point of reading the reason rather than
    listing it is that proxies, TLS and dropped handshakes need no entry
    of their own. A status that arrives is not automatically an answer:
    a 5xx or a 429 is GitHub declining to serve the request, which says
    no more about the repository than a severed connection does.

    One case here is about neither: a repository whose *name* is a
    transport fragment. The fragments are matched against the whole
    message, URL included, so a 404 for it must still be a finding.

    Args:
        stderr: Standard error git wrote.
        unreachable: Whether the remote was never reached.
    """
    assert is_transport_failure(stderr) is unreachable


def _run_and_read(
    config: Config, path: Path, capsys: pytest.CaptureFixture[str]
) -> tuple[int, dict[str, Any]]:
    """Run the linter in JSON mode and read what it reported.

    The exit code alone cannot tell a failure to ask from an answer
    worth acting on -- both are ``1`` -- which is how these tests passed
    for years without exercising the condition they name. The document
    distinguishes them: a request the API refused or the transport could
    not complete reports no validation errors, while a request that was
    answered reports whatever the answer implies, per action.

    Args:
        config: Resolved configuration.
        path: Repository to scan.
        capsys: Captures the emitted document.

    Returns:
        The exit code and the parsed document.
    """
    exit_code = run_linter(
        config, CLIOptions(path=path, output_format="json", quiet=True)
    )
    out = capsys.readouterr().out
    document: dict[str, Any] = json.loads(out) if out.strip() else {}
    return exit_code, document


class TestTheGitBackendDistinguishesAnUnreachableHost:
    """A lost connection is not a finding about the workflow.

    ``git ls-remote`` exits ``128`` for a missing repository and for an
    unreachable host alike, so the Git backend reported both as
    ``INVALID_REPOSITORY``: a broken network was presented to the user
    as a broken workflow. That is the pre-commit.ci incident this file
    is named for, fixed on the API backend long ago and only now on this
    one.

    The distinction is read from git's message, since the exit status
    does not carry it. Both directions are asserted, because a guard
    that called *everything* unreachable would satisfy the first half
    while making the linter useless.
    """

    def test_an_unreachable_host_is_a_network_error(
        self, unreachable_git: None
    ) -> None:
        """The case that used to blame the workflow.

        Args:
            unreachable_git: Fails the lookup as a lost connection does.
        """
        client = GitValidationClient(Config().git)

        results = asyncio.run(
            client.validate_repositories_batch(["actions/checkout"])
        )

        assert results["actions/checkout"] is ValidationResult.NETWORK_ERROR

    def test_a_missing_repository_is_still_a_finding(
        self, mock_git_commands: None
    ) -> None:
        """The inverse: a remote that answered "no" told us something.

        Args:
            mock_git_commands: Answers git locally, reporting the
                fixture's known-missing repository as not found.
        """
        client = GitValidationClient(Config().git)

        results = asyncio.run(
            client.validate_repositories_batch(["nonexistent/action"])
        )

        assert (
            results["nonexistent/action"] is ValidationResult.INVALID_REPOSITORY
        )

    def test_references_are_not_blamed_either(
        self, unreachable_git: None
    ) -> None:
        """The same fault sat on the reference path, one layer down.

        Every leaf validator turned any failure into
        ``INVALID_REFERENCE``, so an unreachable host reported each
        action's version as wrong.

        Args:
            unreachable_git: Fails the lookup as a lost connection does.
        """
        client = GitValidationClient(Config().git)

        results = asyncio.run(
            client.validate_references_batch([("actions/checkout", "v4")])
        )

        assert (
            results[("actions/checkout", "v4")]
            is ValidationResult.NETWORK_ERROR
        )

    def test_commit_shas_are_not_blamed_either(
        self, unreachable_git: None
    ) -> None:
        """A pinned SHA takes its own path to the same wrong answer.

        References are grouped by kind and validated by different
        helpers, so covering tags proves nothing about SHAs -- and a
        SHA-pinned workflow is the recommended shape, hence the common
        one.

        Args:
            unreachable_git: Fails the lookup as a lost connection does.
        """
        client = GitValidationClient(Config().git)
        sha = "a" * 40

        results = asyncio.run(
            client.validate_references_batch([("actions/checkout", sha)])
        )

        assert (
            results[("actions/checkout", sha)] is ValidationResult.NETWORK_ERROR
        )

    def test_a_lookup_that_times_out_is_a_network_error(
        self, timing_out_git: None
    ) -> None:
        """A timeout arrives as an exception, down its own branch.

        Nothing was heard from the remote, so nothing is known about the
        repository -- yet the timeout branch reported a plain failure,
        which the layers above read as a definitive "no".

        Args:
            timing_out_git: Times the lookup out instead of failing it.
        """
        client = GitValidationClient(Config().git)

        results = asyncio.run(
            client.validate_repositories_batch(["actions/checkout"])
        )

        assert results["actions/checkout"] is ValidationResult.NETWORK_ERROR

    def test_references_time_out_without_blame_too(
        self, timing_out_git: None
    ) -> None:
        """The reference path has its own timeout branches, per kind.

        Args:
            timing_out_git: Times the lookup out instead of failing it.
        """
        client = GitValidationClient(Config().git)

        results = asyncio.run(
            client.validate_references_batch([("actions/checkout", "v4")])
        )

        assert (
            results[("actions/checkout", "v4")]
            is ValidationResult.NETWORK_ERROR
        )

    def test_a_refused_http_request_is_still_a_finding(
        self, http_refusing_git: None
    ) -> None:
        """The remote answered, so its answer stands.

        Git prefixes every HTTP failure with ``unable to access``,
        whether the server refused the request or was never reached.
        Reading that prefix as a transport fault would turn each real
        finding into a silent network error -- the linter would pass
        everything, which is worse than the fault being fixed here.

        Args:
            http_refusing_git: Answers the lookup with HTTP 404.
        """
        client = GitValidationClient(Config().git)

        results = asyncio.run(
            client.validate_repositories_batch(["nonexistent/action"])
        )

        assert (
            results["nonexistent/action"] is ValidationResult.INVALID_REPOSITORY
        )

    def test_a_lookup_that_never_ran_is_a_network_error(
        self, unrunnable_git: None
    ) -> None:
        """An absent git leaves the remote just as unheard from.

        This arrives as neither a refusal nor a timeout, so it lands in
        each helper's last resort -- which reported it as a plain
        failure, and the layers above read that as the remote saying no.
        The tool would have named the user's actions as the reason it
        could not run itself.

        Args:
            unrunnable_git: Fails the lookup before the command starts.
        """
        client = GitValidationClient(Config().git)

        results = asyncio.run(
            client.validate_repositories_batch(["actions/checkout"])
        )

        assert results["actions/checkout"] is ValidationResult.NETWORK_ERROR

    def test_references_are_not_blamed_when_git_will_not_run(
        self, unrunnable_git: None
    ) -> None:
        """The reference path kept its own copy of that mistake.

        Its fallback recorded the attempt as having reached the remote,
        so every reference was filled in as invalid.

        Args:
            unrunnable_git: Fails the lookup before the command starts.
        """
        client = GitValidationClient(Config().git)

        results = asyncio.run(
            client.validate_references_batch([("actions/checkout", "v4")])
        )

        assert (
            results[("actions/checkout", "v4")]
            is ValidationResult.NETWORK_ERROR
        )

    def test_an_unresolved_unknown_ref_is_not_a_finding(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A ref of no known kind takes two lookups, and either can fail.

        Enumerating branches and tags can reach the remote while the
        SHA lookup behind it does not. That second lookup had its own
        fallback, nested inside the first, which caught the unreachable
        error before the outer one could re-raise it -- so the ref came
        back invalid on the strength of a question never answered.

        Args:
            monkeypatch: Used to answer the enumeration and fail the
                lookup behind it.
        """

        def nothing(_url: str, _config: Any) -> set[str]:
            """Enumerate successfully, finding no refs.

            Args:
                _url: The remote being asked.
                _config: Git configuration.

            Returns:
                No refs, so the SHA lookup is reached.
            """
            return set()

        def unreachable(
            _url: str, _shas: list[str], _config: Any
        ) -> dict[str, ValidationResult]:
            """Lose the connection on the SHA lookup.

            Args:
                _url: The remote being asked.
                _shas: The SHAs asked about.
                _config: Git configuration.

            Raises:
                GitUnreachableError: Always.
            """
            raise GitUnreachableError("connection lost")

        monkeypatch.setattr(action_call_git, "_get_remote_branches", nothing)
        monkeypatch.setattr(action_call_git, "_get_remote_tags", nothing)
        monkeypatch.setattr(
            action_call_git, "_validate_commit_shas_git", unreachable
        )

        with pytest.raises(GitUnreachableError):
            action_call_git._validate_unknown_refs_git(
                "https://github.com/actions/checkout.git",
                ["mystery"],
                GitConfig(),
            )

    def test_a_killed_git_is_a_network_error(
        self, signal_killed_git: None
    ) -> None:
        """Silence from a killed process is not an answer.

        A git ended by the out-of-memory killer, or by a cancelled CI
        job, writes no message at all -- so there is nothing for the
        classifier to read, and an empty message read as the remote
        answering no. Only the negative status distinguishes it.

        Args:
            signal_killed_git: Kills the lookup part way through.
        """
        client = GitValidationClient(Config().git)

        results = asyncio.run(
            client.validate_repositories_batch(["actions/checkout"])
        )

        assert results["actions/checkout"] is ValidationResult.NETWORK_ERROR

    def test_references_survive_a_killed_git_too(
        self, signal_killed_git: None
    ) -> None:
        """The reference helpers read the status through a different door.

        They run git with ``check=True``, so the status arrives on a
        ``CalledProcessError`` rather than on a completed process.

        Args:
            signal_killed_git: Kills the lookup part way through.
        """
        client = GitValidationClient(Config().git)

        results = asyncio.run(
            client.validate_references_batch([("actions/checkout", "v4")])
        )

        assert (
            results[("actions/checkout", "v4")]
            is ValidationResult.NETWORK_ERROR
        )


class TestARetryDoesNotOverwriteAnAnswer:
    """The SSH fallback fills gaps; it does not revise what HTTPS proved.

    References are validated over HTTPS and, if that attempt cannot
    finish, again over SSH. Both attempts wrote into the same results,
    so a partial success followed by a retry lost the part that had
    worked -- and on a machine with no SSH key the retry answers
    ``INVALID_REFERENCE`` for everything. A branch lookup interrupted by
    a slow network was enough to report every SHA in the workflow as
    wrong, which is this file's subject arriving by a different route.
    """

    def test_a_proven_reference_survives_a_failed_retry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """HTTPS proves the SHA, its branch lookup dies, SSH refuses all.

        Args:
            monkeypatch: Used to answer each leaf validator per URL.
        """
        sha = "a" * 40

        def shas(
            url: str, _shas: list[str], _config: Any
        ) -> tuple[dict[str, ValidationResult], dict[str, Any]]:
            """Find the SHA over HTTPS, deny it over SSH.

            Args:
                url: The remote being tried.
                _shas: The SHAs asked about.
                _config: Git configuration.

            Returns:
                The verdict for each SHA, and no peels.
            """
            if url.startswith("https://"):
                return {sha: ValidationResult.VALID}, {}
            return {sha: ValidationResult.INVALID_REFERENCE}, {}

        def branches(
            url: str, refs: list[str], _config: Any
        ) -> dict[str, ValidationResult]:
            """Lose the connection over HTTPS, deny the branch over SSH.

            Args:
                url: The remote being tried.
                refs: The branches asked about.
                _config: Git configuration.

            Returns:
                The verdict for each branch, over SSH.

            Raises:
                GitUnreachableError: For the HTTPS attempt.
            """
            if url.startswith("https://"):
                raise GitUnreachableError("connection lost")
            return dict.fromkeys(refs, ValidationResult.INVALID_REFERENCE)

        monkeypatch.setattr(
            action_call_git, "_validate_commit_shas_with_peels", shas
        )
        monkeypatch.setattr(action_call_git, "_validate_branches_git", branches)

        results, _ = action_call_git._validate_repository_references(
            "actions/checkout", [sha, "main"], GitConfig()
        )

        assert results[sha] is ValidationResult.VALID

    def test_a_later_success_still_outranks_an_earlier_denial(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Keeping the first answer must not mean keeping the worse one.

        Existence is not symmetric: a remote that finds a reference has
        settled the question, while one that does not may simply be
        seeing less of the repository. So the guard above is written to
        refuse *denials*, not to refuse second answers outright.

        Args:
            monkeypatch: Used to answer each leaf validator per URL.
        """
        sha = "b" * 40

        def shas(
            url: str, _shas: list[str], _config: Any
        ) -> tuple[dict[str, ValidationResult], dict[str, Any]]:
            """Deny the SHA over HTTPS, find it over SSH.

            Args:
                url: The remote being tried.
                _shas: The SHAs asked about.
                _config: Git configuration.

            Returns:
                The verdict for each SHA, and no peels.
            """
            if url.startswith("https://"):
                return {sha: ValidationResult.INVALID_REFERENCE}, {}
            return {sha: ValidationResult.VALID}, {}

        def branches(
            url: str, refs: list[str], _config: Any
        ) -> dict[str, ValidationResult]:
            """Lose the connection over HTTPS so the retry happens.

            Args:
                url: The remote being tried.
                refs: The branches asked about.
                _config: Git configuration.

            Returns:
                The verdict for each branch, over SSH.

            Raises:
                GitUnreachableError: For the HTTPS attempt.
            """
            if url.startswith("https://"):
                raise GitUnreachableError("connection lost")
            return dict.fromkeys(refs, ValidationResult.VALID)

        monkeypatch.setattr(
            action_call_git, "_validate_commit_shas_with_peels", shas
        )
        monkeypatch.setattr(action_call_git, "_validate_branches_git", branches)

        results, _ = action_call_git._validate_repository_references(
            "actions/checkout", [sha, "main"], GitConfig()
        )

        assert results[sha] is ValidationResult.VALID

    def test_a_retry_may_not_swap_one_positive_verdict_for_another(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An annotated-tag finding is a finding, and must not be erased.

        ``ANNOTATED_TAG_SHA`` and ``VALID`` are both answers, but they
        disagree about whether the workflow is correct: the first says
        the SHA names a tag object GitHub Actions cannot check out. A
        retry that replaced it with ``VALID`` would pass a workflow that
        is wrong, and take the peel naming the commit to use instead
        away with it -- the false-pass direction, and the one worth
        guarding hardest.

        Args:
            monkeypatch: Used to answer each leaf validator per URL.
        """
        sha = "c" * 40
        peel = AnnotatedTagPeel(tag="v4.1.1", commit_sha="d" * 40)

        def shas(
            url: str, _shas: list[str], _config: Any
        ) -> tuple[dict[str, ValidationResult], dict[str, AnnotatedTagPeel]]:
            """Report a tag object over HTTPS, a plain commit over SSH.

            Args:
                url: The remote being tried.
                _shas: The SHAs asked about.
                _config: Git configuration.

            Returns:
                The verdict for each SHA, and the peel behind it.
            """
            if url.startswith("https://"):
                return {sha: ValidationResult.ANNOTATED_TAG_SHA}, {sha: peel}
            return {sha: ValidationResult.VALID}, {}

        def branches(
            url: str, refs: list[str], _config: Any
        ) -> dict[str, ValidationResult]:
            """Lose the connection over HTTPS so the retry happens.

            Args:
                url: The remote being tried.
                refs: The branches asked about.
                _config: Git configuration.

            Returns:
                The verdict for each branch, over SSH.

            Raises:
                GitUnreachableError: For the HTTPS attempt.
            """
            if url.startswith("https://"):
                raise GitUnreachableError("connection lost")
            return dict.fromkeys(refs, ValidationResult.VALID)

        monkeypatch.setattr(
            action_call_git, "_validate_commit_shas_with_peels", shas
        )
        monkeypatch.setattr(action_call_git, "_validate_branches_git", branches)

        results, peels = action_call_git._validate_repository_references(
            "actions/checkout", [sha, "main"], GitConfig()
        )

        assert results[sha] is ValidationResult.ANNOTATED_TAG_SHA
        assert peels[sha] == peel


#: One reference of each kind, plus the repository lookup. Each takes a
#: different helper to a different subprocess call site, and a lookup
#: asking for several kinds at once stops at the first that fails --
#: so covering them together would leave most of the sites untouched.
REMOTE_LOOKUPS: Final = [
    pytest.param(None, id="repository"),
    pytest.param("main", id="branch"),
    pytest.param("v4.1.1", id="tag"),
    pytest.param("a" * 40, id="commit-sha"),
]


def _look_up(reference: str | None) -> None:
    """Ask the Git backend one question of the given kind.

    Args:
        reference: The reference to look up, or ``None`` to look up the
            repository itself.
    """
    client = GitValidationClient(Config().git)
    if reference is None:
        asyncio.run(client.validate_repositories_batch(["actions/checkout"]))
        return
    asyncio.run(
        client.validate_references_batch([("actions/checkout", reference)])
    )


def _is_subprocess_run(node: ast.Call) -> bool:
    """Whether a call node is ``subprocess.run(...)``.

    Args:
        node: The call to inspect.

    Returns:
        ``True`` for a call to ``run`` on the ``subprocess`` module.
    """
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "run"
        and isinstance(func.value, ast.Name)
        and func.value.id == "subprocess"
    )


class TestAnUnreachableRemoteReadsAsANetworkProblem:
    """Reporting it correctly includes telling the user what it was.

    The Git backend raises a ``GitError`` subclass rather than a
    ``NetworkError``, because the helpers that produce it are caught by
    type. The CLI chose its advice by type too, so a lost connection on
    this backend fell through to "Validation could not be completed" --
    accurate, but it withholds the one thing the user can act on, and
    the API backend says plainly that the network is at fault.
    """

    def test_the_git_backend_gets_the_network_guidance(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Args:
        capsys: Captures what the CLI prints.
        """
        aborted = ValidationAbortedError(
            message="Validation aborted",
            reason="could not reach the remote",
            original_error=GitUnreachableError(
                "Git ls-remote could not reach github.com"
            ),
        )

        assert _handle_validation_aborted(aborted) == 1

        printed = capsys.readouterr().out
        assert "Network connectivity" in printed
        assert "could not be completed" not in printed

    def test_an_unusable_git_is_not_blamed_on_the_network(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Its sibling is just as inconclusive, and needs other advice.

        A missing ``git``, or one killed part way through, leaves the
        remote just as unheard from -- which is why the layers below
        treat the two alike. The user's next step is not the same,
        though, and sending someone with no ``git`` to check their DNS
        would send them looking in the wrong place.

        Args:
            capsys: Captures what the CLI prints.
        """
        aborted = ValidationAbortedError(
            message="Validation aborted",
            reason="git could not be run",
            original_error=GitUnusableError("No such file or directory"),
        )

        assert _handle_validation_aborted(aborted) == 1

        printed = capsys.readouterr().out
        assert "git could not be run" in printed
        assert "Network connectivity" not in printed
        assert "could not be completed" not in printed

    def test_the_cause_survives_the_batch(
        self, unrunnable_git: None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """End to end, since the batch is where the cause was lost.

        Results are ``ValidationResult`` values, which have no room for
        a reason, so the abort raised from them invented a fresh error
        and the two causes became indistinguishable by the time the CLI
        chose its advice.

        Args:
            unrunnable_git: Fails the lookup before the command starts.
            capsys: Captures what the CLI prints.
        """
        client = GitValidationClient(Config().git)

        asyncio.run(client.validate_repositories_batch(["actions/checkout"]))

        cause = client.inconclusive_cause
        assert isinstance(cause, GitUnusableError)

        with pytest.raises(GitUnusableError) as raised:
            _abort_if_unreachable(
                {"actions/checkout": ValidationResult.NETWORK_ERROR}, cause
            )

        assert (
            _handle_validation_aborted(
                ValidationAbortedError(
                    message="Validation aborted",
                    reason="git could not be run",
                    original_error=raised.value,
                )
            )
            == 1
        )
        assert "git could not be run" in capsys.readouterr().out


class TestRemoteGitCommandsPinTheLocale:
    """The classifier reads English, so git must be made to write it.

    Every distinction this module draws comes from git's own words --
    ``unable to access``, ``Could not resolve host``, ``The requested
    URL returned error``. git translates all of them according to the
    environment. Under a translated locale the classifier recognises
    nothing, so every failure looks like the remote answering and the
    old behaviour returns in full: a broken network reported as broken
    workflows, for exactly the developers whose environment is not
    English.

    Nothing in the classifier can detect this, which is why the
    guarantee is asserted here at the point of invocation instead.
    """

    @pytest.mark.parametrize("reference", REMOTE_LOOKUPS)
    def test_every_remote_command_runs_in_the_c_locale(
        self,
        reference: str | None,
        recorded_git_environments: list[Mapping[str, str] | None],
    ) -> None:
        """Args:
        reference: The kind of lookup to make.
        recorded_git_environments: The environment each remote
            invocation was given.
        """
        _look_up(reference)

        assert recorded_git_environments, "no remote command was recorded"
        for env in recorded_git_environments:
            assert env is not None
            assert env["LC_ALL"] == "C"
            # gettext consults this ahead of the locale.
            assert "LANGUAGE" not in env

    @pytest.mark.parametrize("reference", REMOTE_LOOKUPS)
    def test_the_rest_of_the_environment_still_reaches_git(
        self,
        reference: str | None,
        recorded_git_environments: list[Mapping[str, str] | None],
    ) -> None:
        """Pinning the locale must not amount to clearing the environment.

        git needs ``PATH`` to find its own subcommands, and credential
        helpers and the SSH agent are reached the same way, so replacing
        the environment outright would break authentication while every
        test that fakes the network still passed.

        Args:
            reference: The kind of lookup to make.
            recorded_git_environments: The environment each remote
                invocation was given.
        """
        _look_up(reference)

        assert recorded_git_environments
        for env in recorded_git_environments:
            assert env is not None
            assert env.get("PATH") == os.environ.get("PATH")

    def test_no_call_site_is_left_out(self) -> None:
        """The guarantee is about every command, not the reachable ones.

        The tests above cover the four helpers a lookup can take, but
        not every call site is reachable that way: the clone used for
        subpath validation needs a repository that already validated,
        and a helper added later would be reachable by neither. Reading
        the modules instead makes the claim hold by construction.
        """
        for module in (git_refs, git_subpath, action_call_git):
            source = Path(str(module.__file__)).read_text(encoding="utf-8")
            for node in ast.walk(ast.parse(source)):
                if not isinstance(node, ast.Call) or not _is_subprocess_run(
                    node
                ):
                    continue
                given = {keyword.arg for keyword in node.keywords}
                assert "env" in given, (
                    f"{module.__name__}:{node.lineno} runs a command "
                    "without pinning the environment"
                )


class TestEndToEndNetworkError:
    """End-to-end tests for network error handling."""

    @pytest.fixture
    def sample_repo_with_workflows(self) -> Generator[Path, None, None]:
        """Create a temporary directory with sample GitHub workflows."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            workflows_dir = temp_path / ".github" / "workflows"
            workflows_dir.mkdir(parents=True)

            # Create a workflow with unique actions to avoid cache hits
            workflow_content = """
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: unique-test-org/unique-checkout-action@abc123def456
      - uses: another-unique-org/setup-test@def789ghi012
        with:
          version: '1.0'
"""
            workflow_file = workflows_dir / "ci.yaml"
            workflow_file.write_text(workflow_content)

            yield temp_path

    @pytest.fixture
    def config_without_token(self) -> Config:
        """Configuration without GitHub token (simulates pre-commit.ci environment)."""
        import tempfile

        from gha_workflow_linter.models import CacheConfig

        # Use a temporary cache location to avoid interference
        temp_cache_dir = Path(tempfile.mkdtemp()) / "test_cache"
        return Config(
            github_api=GitHubAPIConfig(
                token=None,
                base_url="https://nonexistent-domain-for-testing.invalid",
                graphql_url="https://nonexistent-domain-for-testing.invalid/graphql",
            ),
            cache=CacheConfig(enabled=True, cache_dir=temp_cache_dir),
        )

    @pytest.fixture
    def config_with_real_github_api(self) -> Config:
        """Configuration for successful validation tests that can hit real GitHub API."""
        import tempfile

        from gha_workflow_linter.models import CacheConfig

        # Use a temporary cache location to avoid interference
        temp_cache_dir = Path(tempfile.mkdtemp()) / "test_cache"
        return Config(
            github_api=GitHubAPIConfig(
                token=None,
                base_url="https://api.github.com",
                graphql_url="https://api.github.com/graphql",
            ),
            cache=CacheConfig(enabled=True, cache_dir=temp_cache_dir),
        )

    def test_dns_resolution_failure_exits_with_error_code_1(
        self,
        sample_repo_with_workflows: Path,
        config_without_token: Config,
        no_repository_redirect: None,
        unreachable_git: None,
    ) -> None:
        """Test that DNS resolution failures result in exit code 1.

        The exit code is all this asserts.
        :class:`TestTheGitBackendDistinguishesAnUnreachableHost` covers
        the other half of the original claim -- that such a failure is
        *not* reported as a validation error -- against the client
        directly, where the result of each lookup is visible.
        """
        options = CLIOptions(path=sample_repo_with_workflows)

        exit_code = run_linter(config_without_token, options)

        # Should exit with error code 1 due to network issues
        assert exit_code == 1

    def test_network_timeout_exits_with_error_code_1(
        self,
        sample_repo_with_workflows: Path,
        config_without_token: Config,
        no_repository_redirect: None,
        timing_out_git: None,
    ) -> None:
        """Test that network timeouts result in exit code 1."""
        options = CLIOptions(path=sample_repo_with_workflows)

        # The timeout comes from timing_out_git, not from the reserved
        # domain in the configuration: the Git backend builds
        # github.com URLs directly and never reads base_url.
        exit_code = run_linter(config_without_token, options)
        assert exit_code == 1

    @pytest.fixture
    def config_using_the_api(self) -> Config:
        """Configuration that actually selects the GitHub API backend.

        Without a token the backend resolves to Git, so a test named for
        an API response never issues one -- it exercises ``git
        ls-remote`` instead and passes for a different reason entirely.
        Both the method and the token are set explicitly rather than
        left to resolution.

        Returns:
            A configuration pinned to the API backend.
        """
        from gha_workflow_linter.models import CacheConfig, ValidationMethod

        return Config(
            validation_method=ValidationMethod.GITHUB_API,
            github_api=GitHubAPIConfig(token="test-token-not-a-credential"),
            cache=CacheConfig(
                enabled=False,
                cache_dir=Path(tempfile.mkdtemp()) / "test_cache",
            ),
        )

    def test_github_api_401_exits_with_error_code_1(
        self,
        sample_repo_with_workflows: Path,
        config_using_the_api: Config,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """An authentication failure must not read as a workflow defect.

        Both halves of the name are asserted: the run fails, *and* it
        reports no findings about the workflows. The second is the point
        -- a rejected credential says nothing about the actions being
        checked, and reporting them as invalid is the defect this file
        exists for.

        Args:
            sample_repo_with_workflows: Repository to scan.
            config_using_the_api: Configuration selecting the API.
            monkeypatch: Used to install the HTTP double.
            capsys: Captures the emitted document.
        """
        asked = _install_api_responder(
            monkeypatch,
            lambda request: httpx.Response(
                401, json={"message": "Bad credentials"}
            ),
        )

        exit_code, document = _run_and_read(
            config_using_the_api, sample_repo_with_workflows, capsys
        )

        assert exit_code == 1
        assert asked, "the API backend was never reached"
        assert document["errors"] == [], (
            "a rejected credential was reported as findings about the workflows"
        )

    def test_github_api_rate_limit_exits_with_error_code_1(
        self,
        sample_repo_with_workflows: Path,
        config_using_the_api: Config,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A throttled API must not read as a workflow defect either.

        Distinct from the 401 case only in the status returned, which is
        the point: both must reach the same outcome by the path their
        names describe.

        Args:
            sample_repo_with_workflows: Repository to scan.
            config_using_the_api: Configuration selecting the API.
            monkeypatch: Used to install the HTTP double.
            capsys: Captures the emitted document.
        """
        asked = _install_api_responder(
            monkeypatch,
            lambda request: httpx.Response(
                403,
                headers={"x-ratelimit-remaining": "0"},
                json={"message": "API rate limit exceeded"},
            ),
        )

        exit_code, document = _run_and_read(
            config_using_the_api, sample_repo_with_workflows, capsys
        )

        assert exit_code == 1
        assert asked, "the API backend was never reached"
        assert document["errors"] == [], (
            "a throttled API was reported as findings about the workflows"
        )

    def test_an_answered_request_does_report_findings(
        self,
        sample_repo_with_workflows: Path,
        config_using_the_api: Config,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The inverse, without which the two above assert nothing.

        Every run in this file exits ``1``, so "no findings" only means
        something if a run that *did* reach the API and got an answer
        reports some. This one gets a well-formed but empty answer,
        which is a real statement about the actions rather than a
        failure to ask.

        Args:
            sample_repo_with_workflows: Repository to scan.
            config_using_the_api: Configuration selecting the API.
            monkeypatch: Used to install the HTTP double.
            capsys: Captures the emitted document.
        """
        asked = _install_api_responder(
            monkeypatch,
            lambda request: httpx.Response(200, json={"data": {}}),
        )

        exit_code, document = _run_and_read(
            config_using_the_api, sample_repo_with_workflows, capsys
        )

        assert exit_code == 1
        assert asked, "the API backend was never reached"
        assert document["errors"], (
            "an answered request reported nothing, so the assertions on "
            "the failure cases distinguish nothing"
        )

    @pytest.mark.skip(reason="Skipping to avoid GitHub API rate limits in CI")
    def test_successful_validation_when_network_works(
        self,
        sample_repo_with_workflows: Path,
        config_with_real_github_api: Config,
    ) -> None:
        """
        Test that successful network responses allow validation to proceed.

        This ensures our error handling doesn't break normal operation.
        Uses real GitHub API (may hit rate limits but tests realistic scenario).
        """
        options = CLIOptions(path=sample_repo_with_workflows)

        # No mocking - let it hit real GitHub API for successful validation test
        exit_code = run_linter(config_with_real_github_api, options)

        # Should not fail with network error exit code
        assert exit_code != 1, "Should not fail with network error exit code"

    def test_error_messages_distinguish_network_from_validation_issues(
        self,
        sample_repo_with_workflows: Path,
        config_without_token: Config,
        no_repository_redirect: None,
        unreachable_git: None,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """End to end, which is where the incident was actually seen.

        The exit code is unchanged at ``1`` -- a run that could not
        check anything has not passed -- so it is the document that
        carries the distinction: no findings are named against the
        workflow, because none were established.

        Args:
            sample_repo_with_workflows: Repository to scan.
            config_without_token: Configuration selecting the Git
                backend, as a tokenless environment does.
            no_repository_redirect: Keeps the fixer's probe local.
            unreachable_git: Supplies the lost connection.
            capsys: Captures the emitted document.
        """
        exit_code, document = _run_and_read(
            config_without_token, sample_repo_with_workflows, capsys
        )

        assert exit_code == 1
        assert document["errors"] == [], (
            "a lost connection was reported as findings about the workflow"
        )

    def test_no_false_validation_errors_on_network_failure(
        self, sample_repo_with_workflows: Path, config_without_token: Config
    ) -> None:
        """
        Critical test: Ensure network failures do NOT create ValidationError objects.

        This was the core bug - network issues were being reported as action validation failures.
        """
        options = CLIOptions(path=sample_repo_with_workflows)

        # Mock the validator to capture what would have been returned
        def capture_validation_errors(*_args: Any, **_kwargs: Any) -> NoReturn:
            # This should raise ValidationAbortedError, not return ValidationError objects
            raise ValidationAbortedError(
                "Unable to validate GitHub Actions due to API/network issues",
                reason="DNS resolution failed",
                original_error=Exception("Network error"),
            )

        with patch(
            "gha_workflow_linter.action_call_check.ActionCallValidator.validate_action_calls"
        ) as mock_validate:
            mock_validate.side_effect = capture_validation_errors

            exit_code = run_linter(config_without_token, options)

            # Should exit with error due to network issues
            assert exit_code == 1

            # Verify that validate_action_calls was called (meaning we reached validation)
            assert mock_validate.called

            # The key assertion: no ValidationError objects should be created for network issues
            # The old behavior would have created ValidationError objects marking actions as invalid

    def test_precommit_ci_scenario_reproduction(
        self,
        sample_repo_with_workflows: Path,
        unreachable_git: None,
    ) -> None:
        """
        Exact reproduction of the pre-commit.ci scenario that failed.

        This test verifies the fix for the specific error reported in the GitHub issue.
        """
        # Use configuration similar to pre-commit.ci (no GitHub token).
        # The cache is disabled deliberately: these repository names are
        # stable, so a persistent cache can answer from a previous run
        # and let the assertion pass without the simulated outage being
        # reached at all. That is how this test passed locally while
        # failing on every Python version in CI, whose cache was cold.
        config = Config(
            github_api=GitHubAPIConfig(
                token=None,  # No token available
                base_url="https://api.github.com",
                graphql_url="https://api.github.com/graphql",
            ),
            cache=CacheConfig(
                enabled=False,
                cache_dir=Path(tempfile.mkdtemp()) / "test_cache",
            ),
        )
        options = CLIOptions(path=sample_repo_with_workflows)

        # Simulate the exact error from pre-commit.ci logs with comprehensive mocking
        with patch("httpx.AsyncClient") as mock_client_class:
            from unittest.mock import AsyncMock

            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            mock_client.post.side_effect = httpx.RequestError(
                "[Errno -3] Temporary failure in name resolution",
                request=Mock(),
            )

            # Before fix: This would output "❌ Invalid action call" for valid actions
            # After fix: This should clearly indicate a network connectivity issue
            exit_code = run_linter(config, options)

            # Should fail with network error (exit code 1)
            assert exit_code == 1

    def test_different_network_error_types_all_handled_consistently(
        self,
        sample_repo_with_workflows: Path,
        config_using_the_api: Config,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Four transport failures must all reach the same outcome.

        Previously none of the four was exercised: the tokenless
        configuration selected the Git backend, so the ``post``
        side-effects went unused and every iteration passed on one
        identical git failure. The loop ran four times and tested one
        thing once.

        Args:
            sample_repo_with_workflows: Repository to scan.
            config_using_the_api: Configuration selecting the API.
            monkeypatch: Used to install each failing transport.
        """
        options = CLIOptions(path=sample_repo_with_workflows)

        network_errors = [
            "[Errno -3] Temporary failure in name resolution",
            "Connection refused",
            "Network is unreachable",
            "Timeout",
        ]

        for message in network_errors:

            def failing(
                request: httpx.Request, reason: str = message
            ) -> httpx.Response:
                """Fail the request as a transport error would.

                Args:
                    request: The outgoing request.
                    reason: The failure to report.

                Raises:
                    httpx.RequestError: Always.
                """
                raise httpx.RequestError(reason, request=request)

            asked = _install_api_responder(monkeypatch, failing)

            exit_code = run_linter(config_using_the_api, options)

            assert exit_code == 1, (
                f"Network error {message} should result in exit code 1"
            )
            assert asked, (
                f"the run never issued a request, so {message} was not "
                f"the reason it failed"
            )

    @pytest.mark.skip(reason="Skipping to avoid GitHub API rate limits in CI")
    def test_validation_continues_after_network_recovery(
        self, sample_repo_with_workflows: Path, config_without_token: Config
    ) -> None:
        """
        Test that the system can recover and continue validation after network issues are resolved.

        This ensures the error handling doesn't permanently disable validation.
        """
        options = CLIOptions(path=sample_repo_with_workflows)

        # First attempt: network failure
        with patch("httpx.AsyncClient") as mock_client_class:
            from unittest.mock import AsyncMock

            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client
            mock_client.post.side_effect = httpx.RequestError(
                "Network error", request=Mock()
            )
            exit_code_1 = run_linter(config_without_token, options)
            assert exit_code_1 == 1

        # Second attempt: network works
        with patch("httpx.AsyncClient") as mock_client_class:
            from unittest.mock import AsyncMock

            mock_client = AsyncMock()
            mock_client_class.return_value = mock_client

            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_response.json.return_value = {
                "data": {
                    "rateLimit": {
                        "remaining": 5000,
                        "resetAt": "2024-01-01T00:00:00Z",
                    }
                }
            }
            mock_client.post.return_value = mock_response

            # Should not fail with network error
            exit_code_2 = run_linter(config_without_token, options)

            # Should attempt validation (may succeed or fail based on API responses)
            assert exit_code_2 != 1, (
                "Should not fail with network error exit code"
            )
            assert mock_client.post.called
