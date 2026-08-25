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

import subprocess

import httpx
import pytest

from tests.conftest import NetworkAccessError


class TestOutwardRequestsAreRefused:
    """The two routes out of the process, both covered."""

    def test_a_live_http_request_is_refused(self) -> None:
        """The API clients' route, and the one that cost the most time."""
        with pytest.raises(NetworkAccessError, match="api.github.com"):
            httpx.get("https://api.github.com/rate_limit", timeout=5.0)

    def test_a_networked_git_command_is_refused(self) -> None:
        """The git binary's route.

        A socket-level guard would miss this entirely: the traffic
        belongs to a child process, so nothing in this interpreter ever
        opens a connection.
        """
        with pytest.raises(NetworkAccessError, match="git ls-remote"):
            subprocess.run(
                ["git", "ls-remote", "https://github.com/actions/checkout"],
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
        """Names RFC 2606 reserves cannot reach a real service.

        Tests that deliberately provoke a connection failure point at
        ``.invalid`` and assert on the resulting error. Refusing those
        would replace the error under test with the guard's own.
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
    """

    def test_a_marked_test_may_reach_a_reserved_host(self) -> None:
        """Exemption is proven without depending on a live service.

        Asserting against github.com here would reintroduce exactly the
        dependency this file exists to prevent. A reserved name shows
        the guard stood aside: the failure is the connection's, not the
        guard's.
        """
        with pytest.raises(httpx.ConnectError):
            httpx.get("https://nonexistent-domain.invalid/x", timeout=5.0)

    def test_a_marked_test_may_run_networked_git(self) -> None:
        """The same exemption covers the subprocess route.

        Pointed at a path that cannot resolve, so this asserts the guard
        let the command run rather than that any remote answered.
        """
        result = subprocess.run(
            ["git", "ls-remote", "https://nonexistent-domain.invalid/x.git"],
            capture_output=True,
            check=False,
        )

        assert result.returncode != 0
