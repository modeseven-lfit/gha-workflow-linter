# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for latest-release resolution behind allow-list pins.

A harden-runner allow-list pin carries the **commit** SHA of a host
repository, not the SHA of the annotated tag object that names it. The
whole feature turns on that distinction: comparing a pin against the
tag-object SHA would report every correctly-pinned reference as stale.
The first tests here therefore pin the peel, using the real SHAs from
``lfreleng-actions/.github`` at ``v0.12.2``.

Mocking happens at the transport boundaries -- an ``httpx`` mock
transport for the API backend and ``subprocess.run`` for the Git backend
-- so the real query text, the real response parsing and the real error
classification are all exercised, in the style of
``tests/test_annotated_tag_reporting.py``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import re
import subprocess
from typing import TYPE_CHECKING, Any

import httpx
import pytest

from gha_workflow_linter.allow_list_resolver import AllowListResolver
from gha_workflow_linter.cache import ValidationCache
from gha_workflow_linter.latest_release import (
    LatestRelease,
    ReleaseCandidate,
    ReleasePolicy,
    build_latest_releases_query,
    select_latest_release,
)
from gha_workflow_linter.models import (
    CacheConfig,
    Config,
    GitHubAPIConfig,
    ValidationMethod,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

# ---------------------------------------------------------------------------
# Fixture data: real values from lfreleng-actions/.github and actions/checkout
# ---------------------------------------------------------------------------

ORGANIZATION = "lfreleng-actions"
HOST_REPO = f"{ORGANIZATION}/.github"

# v0.12.2 is an annotated tag: the ref names a tag object, whose target is
# the commit an allow-list pin actually carries.
TAG_NAME = "v0.12.2"
TAG_OBJECT_SHA = "8f363565e79650362c3359ee23b6d6fd295866ee"
PEELED_COMMIT_SHA = "bf6642f68d58c1b81bbe993e676d6cc339ac3654"

PREVIOUS_TAG = "v0.12.1"
PREVIOUS_TAG_OBJECT_SHA = "9ed1afae6b1fbe656074fafc4ff80e6af41e140a"
PREVIOUS_COMMIT_SHA = "60d8d71016f31c26775e5ec9380eba4264aa6f9e"

# v0.7.0: far enough back to be outside any plausible cooldown window,
# and the release a seven-day cooldown actually falls back to while the
# whole v0.12.x series is still warming.
COOLDOWN_TAG = "v0.7.0"
COOLDOWN_TAG_OBJECT_SHA = "76aa85c978113dd3d8501ac95b613a54a54e5597"
COOLDOWN_COMMIT_SHA = "d46590dd8f51bdd71494eb9d2afa3bade1457a62"

# actions/checkout uses lightweight tags: the ref names the commit itself.
LIGHTWEIGHT_REPO = "actions/checkout"
LIGHTWEIGHT_TAG = "v7.0.1"
LIGHTWEIGHT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"

MISSING_REPO = f"{ORGANIZATION}/definitely-does-not-exist"

BRANCH_COMMIT_SHA = "0000111122223333444455556666777788889999"

LS_REMOTE_OUTPUT = (
    f"{BRANCH_COMMIT_SHA}\trefs/heads/main\n"
    f"{TAG_OBJECT_SHA}\trefs/tags/{TAG_NAME}\n"
    f"{PEELED_COMMIT_SHA}\trefs/tags/{TAG_NAME}^{{}}\n"
    f"{PREVIOUS_TAG_OBJECT_SHA}\trefs/tags/{PREVIOUS_TAG}\n"
    f"{PREVIOUS_COMMIT_SHA}\trefs/tags/{PREVIOUS_TAG}^{{}}\n"
)

LS_REMOTE_LIGHTWEIGHT_OUTPUT = (
    f"{LIGHTWEIGHT_SHA}\trefs/tags/{LIGHTWEIGHT_TAG}\n"
    f"{LIGHTWEIGHT_SHA}\trefs/tags/v7\n"
)

_RATE_LIMIT_BODY: dict[str, Any] = {
    "resources": {
        "graphql": {"limit": 5000, "remaining": 5000, "reset": 0, "used": 0}
    }
}

_REPO_ALIAS_RE = re.compile(
    r'(repo_\d+): repository\(owner: "([^"]+)", name: "([^"]+)"\)'
)


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


def _iso_days_ago(days: int) -> str:
    """Render an ISO-8601 UTC timestamp a number of days in the past.

    Args:
        days: How many days ago the timestamp should be.

    Returns:
        A ``YYYY-MM-DDTHH:MM:SSZ`` string, as GitHub returns.
    """
    moment = datetime.now(timezone.utc) - timedelta(days=days)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _annotated_ref(name: str, tag_object: str, commit: str) -> dict[str, Any]:
    """Build the GraphQL ref node GitHub returns for an annotated tag.

    Args:
        name: Tag name.
        tag_object: SHA of the tag object the ref names.
        commit: SHA of the commit the tag object targets.

    Returns:
        A ``refs.nodes`` entry with a nested, peelable target.
    """
    return {
        "name": name,
        "target": {"oid": tag_object, "target": {"oid": commit}},
    }


def _lightweight_ref(name: str, commit: str) -> dict[str, Any]:
    """Build the GraphQL ref node GitHub returns for a lightweight tag.

    Args:
        name: Tag name.
        commit: SHA of the commit the ref names directly.

    Returns:
        A ``refs.nodes`` entry with a flat target.
    """
    return {"name": name, "target": {"oid": commit}}


def _release(
    tag: str,
    published_at: str | None = None,
    *,
    is_draft: bool = False,
    is_prerelease: bool = False,
) -> dict[str, Any]:
    """Build a GraphQL release node.

    Args:
        tag: Release tag name.
        published_at: ISO-8601 publication timestamp, or None.
        is_draft: Whether GitHub marks the release as a draft.
        is_prerelease: Whether GitHub marks the release as a prerelease.

    Returns:
        A release payload shaped like GitHub's.
    """
    return {
        "tagName": tag,
        "publishedAt": published_at,
        "isDraft": is_draft,
        "isPrerelease": is_prerelease,
    }


def _repo_payload(
    refs: list[dict[str, Any]],
    releases: list[dict[str, Any]],
    latest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble one repository's slice of a GraphQL response.

    Args:
        refs: Tag ref nodes.
        releases: Release nodes, newest first.
        latest: The ``latestRelease`` payload, or None.

    Returns:
        The per-repository response fragment.
    """
    return {
        "latestRelease": latest,
        "releases": {"nodes": releases},
        "refs": {"nodes": refs},
    }


_HOST_REFS = [
    _annotated_ref(TAG_NAME, TAG_OBJECT_SHA, PEELED_COMMIT_SHA),
    _annotated_ref(PREVIOUS_TAG, PREVIOUS_TAG_OBJECT_SHA, PREVIOUS_COMMIT_SHA),
]


def _host_payload(
    latest_published: str | None = None,
    previous_published: str | None = None,
) -> dict[str, Any]:
    """Build the standard two-release payload for the host repository.

    Args:
        latest_published: Publication timestamp for ``v0.12.2``.
        previous_published: Publication timestamp for ``v0.12.1``.

    Returns:
        The per-repository response fragment for ``<org>/.github``.
    """
    latest = _release(TAG_NAME, latest_published)
    return _repo_payload(
        refs=_HOST_REFS,
        releases=[latest, _release(PREVIOUS_TAG, previous_published)],
        latest=latest,
    )


_LIGHTWEIGHT_PAYLOAD = _repo_payload(
    refs=[
        _lightweight_ref(LIGHTWEIGHT_TAG, LIGHTWEIGHT_SHA),
        _lightweight_ref("v7", LIGHTWEIGHT_SHA),
    ],
    releases=[_release(LIGHTWEIGHT_TAG)],
    latest=_release(LIGHTWEIGHT_TAG),
)


def _three_release_payload() -> dict[str, Any]:
    """Build the payload behind the live cooldown defect.

    Reproduces ``lfreleng-actions/.github`` as it stood on 2026-08-04:
    the v0.12.x series published within the last week, and v0.7.0 the
    newest release old enough to clear a seven-day cooldown.

    Returns:
        The per-repository response fragment.
    """
    latest = _release(TAG_NAME, _iso_days_ago(6))
    return _repo_payload(
        refs=[
            *_HOST_REFS,
            _annotated_ref(
                COOLDOWN_TAG, COOLDOWN_TAG_OBJECT_SHA, COOLDOWN_COMMIT_SHA
            ),
        ],
        releases=[
            latest,
            _release(PREVIOUS_TAG, _iso_days_ago(5)),
            _release(COOLDOWN_TAG, _iso_days_ago(11)),
        ],
        latest=latest,
    )


# ---------------------------------------------------------------------------
# Transport doubles
# ---------------------------------------------------------------------------


def _graphql_body(
    query: str, repos: Mapping[str, dict[str, Any] | None]
) -> dict[str, Any]:
    """Answer a batched release query from a repository fixture map.

    Repositories absent from ``repos`` are reported the way GitHub does:
    a null alias plus a NOT_FOUND error alongside the data.

    Args:
        query: The generated GraphQL document.
        repos: Mapping of ``owner/repo`` to its response fragment.

    Returns:
        A response body shaped like GitHub's.
    """
    data: dict[str, Any] = {}
    errors: list[dict[str, Any]] = []

    for alias, owner, name in _REPO_ALIAS_RE.findall(query):
        repo_key = f"{owner}/{name}"
        payload = repos.get(repo_key)
        data[alias] = payload
        if payload is None:
            errors.append(
                {
                    "type": "NOT_FOUND",
                    "message": (
                        "Could not resolve to a Repository with the name "
                        f"'{repo_key}'."
                    ),
                }
            )

    body: dict[str, Any] = {"data": data}
    if errors:
        body["errors"] = errors

    return body


def _graphql_responder(
    repos: Mapping[str, dict[str, Any] | None], queries: list[str]
) -> Callable[[httpx.Request], httpx.Response]:
    """Build a mock transport handler serving the fixture repositories.

    Args:
        repos: Mapping of ``owner/repo`` to its response fragment.
        queries: List every GraphQL document is appended to, so tests can
            assert how many requests a resolution actually cost.

    Returns:
        A handler suitable for ``httpx.MockTransport``.
    """

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/rate_limit"):
            return httpx.Response(200, json=_RATE_LIMIT_BODY)
        query = str(json.loads(request.content.decode())["query"])
        queries.append(query)
        return httpx.Response(200, json=_graphql_body(query, repos))

    return respond


def _install_http(
    monkeypatch: pytest.MonkeyPatch,
    responder: Callable[[httpx.Request], httpx.Response],
) -> None:
    """Route every ``httpx.AsyncClient`` through a mock transport.

    Args:
        monkeypatch: pytest monkeypatch fixture
        responder: Handler answering each request.
    """
    original = httpx.AsyncClient

    def factory(**kwargs: Any) -> httpx.AsyncClient:
        return original(transport=httpx.MockTransport(responder), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


class FakeCompleted:
    """Minimal stand-in for ``subprocess.CompletedProcess``."""

    def __init__(self, stdout: str) -> None:
        self.stdout = stdout
        self.returncode = 0
        self.stderr = ""


def _install_ls_remote(
    monkeypatch: pytest.MonkeyPatch,
    outputs: Mapping[str, str],
    calls: list[str],
) -> None:
    """Stub ``subprocess.run`` with canned ``git ls-remote`` output.

    Args:
        monkeypatch: pytest monkeypatch fixture
        outputs: Mapping of repository key to raw ls-remote stdout. A key
            that is absent makes the fake ``git`` fail, as it does for a
            repository that does not exist.
        calls: List every invoked URL is appended to, so tests can assert
            how many remote reads a resolution actually cost.
    """

    def fake_run(cmd: list[str], **_kwargs: Any) -> FakeCompleted:
        url = cmd[-1]
        calls.append(url)
        for repo_key, stdout in outputs.items():
            if url.endswith(f"/{repo_key}.git"):
                return FakeCompleted(stdout)
        raise subprocess.CalledProcessError(128, cmd, stderr="not found")

    monkeypatch.setattr(subprocess, "run", fake_run)


# ---------------------------------------------------------------------------
# Resolver construction
# ---------------------------------------------------------------------------


def _config(
    method: ValidationMethod,
    cache_dir: Path | None = None,
    **overrides: Any,
) -> Config:
    """Build a configuration for the requested backend.

    Args:
        method: Validation method the resolver should use.
        cache_dir: Directory for an enabled cache, or None to disable it.
        **overrides: Additional ``Config`` field values.

    Returns:
        A configuration carrying a dummy token, so token discovery never
        shells out to the GitHub CLI during a test.
    """
    cache = (
        CacheConfig(enabled=True, cache_dir=cache_dir)
        if cache_dir is not None
        else CacheConfig(enabled=False)
    )
    return Config(
        validation_method=method,
        cache=cache,
        github_api=GitHubAPIConfig(token="test-token"),
        **overrides,
    )


def _resolver(config: Config) -> AllowListResolver:
    """Build a resolver over a fresh cache for the given configuration.

    Args:
        config: The configuration to resolve with.

    Returns:
        An ``AllowListResolver``.
    """
    return AllowListResolver(config, ValidationCache(config.cache))


def _api_resolver(
    monkeypatch: pytest.MonkeyPatch,
    repos: Mapping[str, dict[str, Any] | None],
    queries: list[str] | None = None,
    cache_dir: Path | None = None,
    **overrides: Any,
) -> AllowListResolver:
    """Build an API-backed resolver wired to fixture repositories.

    Args:
        monkeypatch: pytest monkeypatch fixture
        repos: Mapping of ``owner/repo`` to its response fragment.
        queries: Optional list collecting the issued GraphQL documents.
        cache_dir: Directory for an enabled cache, or None to disable it.
        **overrides: Additional ``Config`` field values.

    Returns:
        A resolver whose HTTP traffic is served from ``repos``.
    """
    _install_http(
        monkeypatch,
        _graphql_responder(repos, queries if queries is not None else []),
    )
    return _resolver(
        _config(ValidationMethod.GITHUB_API, cache_dir, **overrides)
    )


def _git_resolver(
    monkeypatch: pytest.MonkeyPatch,
    outputs: Mapping[str, str],
    calls: list[str] | None = None,
    cache_dir: Path | None = None,
    **overrides: Any,
) -> AllowListResolver:
    """Build a Git-backed resolver wired to canned ls-remote output.

    Args:
        monkeypatch: pytest monkeypatch fixture
        outputs: Mapping of repository key to raw ls-remote stdout.
        calls: Optional list collecting the invoked remote URLs.
        cache_dir: Directory for an enabled cache, or None to disable it.
        **overrides: Additional ``Config`` field values.

    Returns:
        A resolver whose remote reads are served from ``outputs``.
    """
    _install_ls_remote(monkeypatch, outputs, calls if calls is not None else [])
    return _resolver(_config(ValidationMethod.GIT, cache_dir, **overrides))


# ---------------------------------------------------------------------------
# The core correctness property: annotated tags peel to the commit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_backend_peels_annotated_tag_to_the_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The API backend reports the commit, never the tag object."""
    resolver = _api_resolver(monkeypatch, {HOST_REPO: _host_payload()})

    release = (await resolver.resolve([HOST_REPO]))[HOST_REPO]

    assert release == LatestRelease(tag=TAG_NAME, commit_sha=PEELED_COMMIT_SHA)
    assert release is not None
    assert release.commit_sha != TAG_OBJECT_SHA


@pytest.mark.asyncio
async def test_git_backend_peels_annotated_tag_to_the_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Git backend reports the commit, never the tag object."""
    resolver = _git_resolver(monkeypatch, {HOST_REPO: LS_REMOTE_OUTPUT})

    release = (await resolver.resolve([HOST_REPO]))[HOST_REPO]

    assert release == LatestRelease(tag=TAG_NAME, commit_sha=PEELED_COMMIT_SHA)
    assert release is not None
    assert release.commit_sha != TAG_OBJECT_SHA


@pytest.mark.asyncio
async def test_backends_agree_on_the_shared_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both backends resolve the same fixture to the same tag and commit."""
    api = _api_resolver(monkeypatch, {HOST_REPO: _host_payload()})
    via_api = (await api.resolve([HOST_REPO]))[HOST_REPO]

    monkeypatch.undo()
    git = _git_resolver(monkeypatch, {HOST_REPO: LS_REMOTE_OUTPUT})
    via_git = (await git.resolve([HOST_REPO]))[HOST_REPO]

    assert via_api is not None
    assert via_git is not None
    assert (via_api.tag, via_api.commit_sha) == (
        via_git.tag,
        via_git.commit_sha,
    )


@pytest.mark.asyncio
async def test_lightweight_tag_resolves_to_its_single_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lightweight tag has one SHA, and both backends return it."""
    api = _api_resolver(monkeypatch, {LIGHTWEIGHT_REPO: _LIGHTWEIGHT_PAYLOAD})
    via_api = (await api.resolve([LIGHTWEIGHT_REPO]))[LIGHTWEIGHT_REPO]

    monkeypatch.undo()
    git = _git_resolver(
        monkeypatch, {LIGHTWEIGHT_REPO: LS_REMOTE_LIGHTWEIGHT_OUTPUT}
    )
    via_git = (await git.resolve([LIGHTWEIGHT_REPO]))[LIGHTWEIGHT_REPO]

    expected = LatestRelease(tag=LIGHTWEIGHT_TAG, commit_sha=LIGHTWEIGHT_SHA)
    assert via_api == expected
    assert via_git == expected


def test_query_never_selects_tag_name_on_a_tag_object() -> None:
    """``tagName`` exists on ``Release`` only; ``Tag`` exposes ``name``.

    Selecting ``tagName`` inside a ``... on Tag`` fragment makes the whole
    query fail at run time, and a mocked response would not notice. Guard
    the generated document instead.
    """
    query, aliases = build_latest_releases_query([HOST_REPO])

    assert aliases == {"repo_0": HOST_REPO}
    assert "... on Tag { target { oid } }" in query
    assert "on Tag { tagName" not in query
    assert "latestRelease { tagName" in query


def test_query_skips_repository_keys_that_cannot_name_a_repository() -> None:
    """Unusable keys are dropped rather than interpolated into the query."""
    query, aliases = build_latest_releases_query(
        ["not-a-repo-key", 'evil"/x', HOST_REPO]
    )

    assert aliases == {"repo_2": HOST_REPO}
    assert "evil" not in query


# ---------------------------------------------------------------------------
# Draft and prerelease filtering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_draft_release_is_never_selected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A draft release is skipped even when its tag ref already exists."""
    draft_tag = "v0.12.3"
    draft_sha = "aaaa1111bbbb2222cccc3333dddd4444eeee5555"
    payload = _repo_payload(
        refs=[
            _annotated_ref(draft_tag, "f" * 40, draft_sha),
            *_HOST_REFS,
        ],
        releases=[
            _release(draft_tag, is_draft=True),
            _release(TAG_NAME, _iso_days_ago(10)),
        ],
        latest=_release(TAG_NAME, _iso_days_ago(10)),
    )
    resolver = _api_resolver(monkeypatch, {HOST_REPO: payload})

    release = (await resolver.resolve([HOST_REPO]))[HOST_REPO]

    assert release is not None
    assert release.tag == TAG_NAME
    assert release.commit_sha == PEELED_COMMIT_SHA


@pytest.mark.asyncio
async def test_prerelease_is_excluded_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without ``allow_prerelease`` a prerelease loses to the last stable."""
    resolver = _api_resolver(monkeypatch, {HOST_REPO: _prerelease_payload()})

    release = (await resolver.resolve([HOST_REPO]))[HOST_REPO]

    assert release is not None
    assert release.tag == PREVIOUS_TAG
    assert release.commit_sha == PREVIOUS_COMMIT_SHA


@pytest.mark.asyncio
async def test_prerelease_is_selected_when_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With ``allow_prerelease`` the newer prerelease wins."""
    resolver = _api_resolver(
        monkeypatch, {HOST_REPO: _prerelease_payload()}, allow_prerelease=True
    )

    release = (await resolver.resolve([HOST_REPO]))[HOST_REPO]

    assert release is not None
    assert release.tag == TAG_NAME
    assert release.commit_sha == PEELED_COMMIT_SHA


def _prerelease_payload() -> dict[str, Any]:
    """Build a payload whose newest release is marked as a prerelease.

    Returns:
        A per-repository fragment where ``v0.12.2`` is a prerelease and
        ``v0.12.1`` is the newest stable release.
    """
    return _repo_payload(
        refs=_HOST_REFS,
        releases=[
            _release(TAG_NAME, _iso_days_ago(1), is_prerelease=True),
            _release(PREVIOUS_TAG, _iso_days_ago(20)),
        ],
        latest=_release(PREVIOUS_TAG, _iso_days_ago(20)),
    )


# ---------------------------------------------------------------------------
# Cooldown
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cooldown_falls_back_to_an_older_warm_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A release still inside the cooldown yields to an older eligible one."""
    payload = _host_payload(_iso_days_ago(1), _iso_days_ago(30))
    resolver = _api_resolver(monkeypatch, {HOST_REPO: payload}, cooldown_days=7)

    release = (await resolver.resolve([HOST_REPO]))[HOST_REPO]

    assert release is not None
    assert release.tag == PREVIOUS_TAG
    assert release.commit_sha == PREVIOUS_COMMIT_SHA


@pytest.mark.asyncio
async def test_cooldown_excluding_everything_resolves_to_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When no release is warm enough the repository has no answer."""
    payload = _host_payload(_iso_days_ago(1), _iso_days_ago(2))
    resolver = _api_resolver(
        monkeypatch, {HOST_REPO: payload}, cooldown_days=30
    )

    assert (await resolver.resolve([HOST_REPO]))[HOST_REPO] is None


@pytest.mark.asyncio
async def test_git_backend_declines_under_an_active_cooldown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``git ls-remote`` exposes no dates, so a cooldown cannot be honoured.

    Rather than guess at a release's age the Git backend reports nothing,
    matching ``action_call_versions._get_latest_version_via_git``.
    """
    calls: list[str] = []
    resolver = _git_resolver(
        monkeypatch, {HOST_REPO: LS_REMOTE_OUTPUT}, calls, cooldown_days=7
    )

    assert (await resolver.resolve([HOST_REPO]))[HOST_REPO] is None
    assert calls == []


@pytest.mark.asyncio
async def test_git_backend_resolves_when_no_cooldown_applies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same Git fixture resolves cleanly once the cooldown is off."""
    resolver = _git_resolver(
        monkeypatch, {HOST_REPO: LS_REMOTE_OUTPUT}, cooldown_days=0
    )

    release = (await resolver.resolve([HOST_REPO]))[HOST_REPO]

    assert release is not None
    assert release.tag == TAG_NAME


def test_undated_candidates_are_skipped_while_a_cooldown_is_active() -> None:
    """The selection helper itself refuses to guess at an unknown age."""
    candidates = [
        ReleaseCandidate(tag=TAG_NAME, commit_sha=PEELED_COMMIT_SHA),
        ReleaseCandidate(tag=PREVIOUS_TAG, commit_sha=PREVIOUS_COMMIT_SHA),
    ]

    assert (
        select_latest_release(candidates, ReleasePolicy(cooldown_days=1))
        is None
    )
    assert select_latest_release(candidates, ReleasePolicy()) == LatestRelease(
        tag=TAG_NAME, commit_sha=PEELED_COMMIT_SHA
    )


# ---------------------------------------------------------------------------
# The commit-to-tag map: where a pinned commit sits relative to the target
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_cooldown_target_still_places_the_newer_commits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cooldown-shifted target must not hide the releases above it.

    The target is v0.7.0 because v0.12.x is still warming, but a pin at
    v0.12.2 is ahead rather than stale, and only the map can say so.
    """
    resolver = _api_resolver(
        monkeypatch, {HOST_REPO: _three_release_payload()}, cooldown_days=7
    )

    release = (await resolver.resolve([HOST_REPO]))[HOST_REPO]

    assert release is not None
    assert release.tag == COOLDOWN_TAG
    assert release.commit_sha == COOLDOWN_COMMIT_SHA
    assert release.tag_for_commit(PEELED_COMMIT_SHA) == TAG_NAME
    assert release.tag_for_commit(PREVIOUS_COMMIT_SHA) == PREVIOUS_TAG
    assert release.tag_for_commit(COOLDOWN_COMMIT_SHA) == COOLDOWN_TAG


@pytest.mark.asyncio
async def test_the_newest_release_wins_when_no_cooldown_applies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same fixture without a cooldown behaves exactly as before."""
    resolver = _api_resolver(
        monkeypatch, {HOST_REPO: _three_release_payload()}, cooldown_days=0
    )

    release = (await resolver.resolve([HOST_REPO]))[HOST_REPO]

    assert release is not None
    assert release.tag == TAG_NAME
    assert release.commit_sha == PEELED_COMMIT_SHA
    assert release.tag_for_commit(COOLDOWN_COMMIT_SHA) == COOLDOWN_TAG


@pytest.mark.asyncio
async def test_the_map_ignores_a_commit_no_release_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An annotated tag object is not the commit of any release."""
    resolver = _api_resolver(monkeypatch, {HOST_REPO: _host_payload()})

    release = (await resolver.resolve([HOST_REPO]))[HOST_REPO]

    assert release is not None
    assert release.tag_for_commit(TAG_OBJECT_SHA) is None
    assert release.tag_for_commit(BRANCH_COMMIT_SHA) is None


@pytest.mark.asyncio
async def test_the_map_prefers_the_most_specific_tag_for_a_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``v7`` and ``v7.0.1`` name one commit; the specific tag wins."""
    resolver = _api_resolver(
        monkeypatch, {LIGHTWEIGHT_REPO: _LIGHTWEIGHT_PAYLOAD}
    )

    release = (await resolver.resolve([LIGHTWEIGHT_REPO]))[LIGHTWEIGHT_REPO]

    assert release is not None
    assert release.tag_for_commit(LIGHTWEIGHT_SHA) == LIGHTWEIGHT_TAG


@pytest.mark.asyncio
async def test_commit_lookup_is_case_insensitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hexadecimal case is not a difference in commit identity."""
    resolver = _api_resolver(monkeypatch, {HOST_REPO: _host_payload()})

    release = (await resolver.resolve([HOST_REPO]))[HOST_REPO]

    assert release is not None
    assert release.tag_for_commit(PEELED_COMMIT_SHA.upper()) == TAG_NAME


@pytest.mark.asyncio
async def test_a_cooldown_run_bypasses_the_cache(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A cached ``(tag, sha)`` pair cannot answer a cooldown run.

    The cache persists no commit map, so serving a cooldown-shifted
    target from it would lose the ability to tell a pin that is behind
    the target from one that is ahead of it -- and reporting the latter
    as stale recommends a downgrade. Nothing is written back either, so
    a later run without a cooldown cannot read a shifted target.
    """
    queries: list[str] = []
    resolver = _api_resolver(
        monkeypatch,
        {HOST_REPO: _three_release_payload()},
        queries,
        tmp_path,
        cooldown_days=7,
    )
    resolver.cache.put_latest_version(
        HOST_REPO, COOLDOWN_TAG, COOLDOWN_COMMIT_SHA
    )

    release = (await resolver.resolve([HOST_REPO]))[HOST_REPO]

    assert resolver.cache_usable is False
    assert len(queries) == 1
    assert release is not None
    assert release.tag == COOLDOWN_TAG
    assert release.tag_for_commit(PEELED_COMMIT_SHA) == TAG_NAME


@pytest.mark.asyncio
async def test_a_cached_release_carries_no_commit_map(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The documented degradation of a cache hit, stated explicitly.

    Without a cooldown the target *is* the newest release, so nothing can
    be ahead of it and the missing map costs nothing.
    """
    config = _config(ValidationMethod.GITHUB_API, tmp_path, cooldown_days=0)
    resolver = _resolver(config)
    resolver.cache.put_latest_version(HOST_REPO, TAG_NAME, PEELED_COMMIT_SHA)

    def _explode() -> Any:
        raise AssertionError("the API client must not be constructed")

    monkeypatch.setattr(resolver, "_make_github_client", _explode)

    release = (await resolver.resolve([HOST_REPO]))[HOST_REPO]

    assert resolver.cache_usable is True
    assert release is not None
    assert release.commit_sha == PEELED_COMMIT_SHA
    assert release.tag_for_commit(PEELED_COMMIT_SHA) is None


# ---------------------------------------------------------------------------
# Cost: one lookup per distinct host repository, zero on a cache hit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_many_pins_on_one_host_cost_a_single_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Twenty pins naming one host repository resolve it exactly once."""
    queries: list[str] = []
    resolver = _api_resolver(monkeypatch, {HOST_REPO: _host_payload()}, queries)

    results = await resolver.resolve([HOST_REPO] * 20)

    assert list(results) == [HOST_REPO]
    assert len(queries) == 1


@pytest.mark.asyncio
async def test_git_backend_also_resolves_a_shared_host_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """De-duplication happens before the backend, so Git benefits too."""
    calls: list[str] = []
    resolver = _git_resolver(monkeypatch, {HOST_REPO: LS_REMOTE_OUTPUT}, calls)

    results = await resolver.resolve([HOST_REPO] * 20)

    assert list(results) == [HOST_REPO]
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_a_cache_hit_costs_zero_api_calls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A cached host repository never reaches the API client at all."""
    config = _config(ValidationMethod.GITHUB_API, tmp_path)
    resolver = _resolver(config)
    resolver.cache.put_latest_version(HOST_REPO, TAG_NAME, PEELED_COMMIT_SHA)

    def _explode() -> Any:
        raise AssertionError("the API client must not be constructed")

    monkeypatch.setattr(resolver, "_make_github_client", _explode)

    assert (await resolver.resolve([HOST_REPO]))[HOST_REPO] == LatestRelease(
        tag=TAG_NAME, commit_sha=PEELED_COMMIT_SHA
    )


@pytest.mark.asyncio
async def test_a_resolved_release_is_cached_for_the_next_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The second run within the TTL issues no query at all."""
    queries: list[str] = []
    first = _api_resolver(
        monkeypatch, {HOST_REPO: _host_payload()}, queries, tmp_path
    )
    assert (await first.resolve([HOST_REPO]))[HOST_REPO] is not None
    assert len(queries) == 1

    second = _resolver(_config(ValidationMethod.GITHUB_API, tmp_path))
    release = (await second.resolve([HOST_REPO]))[HOST_REPO]

    assert release == LatestRelease(tag=TAG_NAME, commit_sha=PEELED_COMMIT_SHA)
    assert len(queries) == 1


@pytest.mark.asyncio
async def test_an_unresolved_repository_is_not_cached(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A transient failure must not be remembered as "no release"."""
    resolver = _api_resolver(monkeypatch, {}, None, tmp_path)

    assert (await resolver.resolve([HOST_REPO]))[HOST_REPO] is None
    assert resolver.cache.get_latest_version(HOST_REPO) is None


# ---------------------------------------------------------------------------
# Failure modes: every one resolves to None instead of raising
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_repository_resolves_to_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A NOT_FOUND alias yields None without disturbing its neighbours."""
    resolver = _api_resolver(monkeypatch, {HOST_REPO: _host_payload()})

    results = await resolver.resolve([HOST_REPO, MISSING_REPO])

    assert results[MISSING_REPO] is None
    assert results[HOST_REPO] is not None


@pytest.mark.asyncio
async def test_repository_without_releases_or_tags_resolves_to_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nothing to compare against is a None, not an error."""
    payload = _repo_payload(refs=[], releases=[])
    resolver = _api_resolver(monkeypatch, {HOST_REPO: payload})

    assert (await resolver.resolve([HOST_REPO]))[HOST_REPO] is None


@pytest.mark.asyncio
async def test_repository_with_only_unparsable_tags_resolves_to_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tags that are not clean versions cannot be ranked, so none wins."""
    payload = _repo_payload(
        refs=[_lightweight_ref("nightly", BRANCH_COMMIT_SHA)],
        releases=[],
    )
    resolver = _api_resolver(monkeypatch, {HOST_REPO: payload})

    assert (await resolver.resolve([HOST_REPO]))[HOST_REPO] is None


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (401, "Bad credentials"),
        (403, "API rate limit exceeded"),
        (500, "Server Error"),
    ],
)
@pytest.mark.asyncio
async def test_api_error_statuses_resolve_to_none(
    monkeypatch: pytest.MonkeyPatch, status: int, body: str
) -> None:
    """Auth, rate-limit and server failures all degrade to None."""

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/rate_limit"):
            return httpx.Response(200, json=_RATE_LIMIT_BODY)
        return httpx.Response(status, text=body)

    _install_http(monkeypatch, respond)
    resolver = _resolver(_config(ValidationMethod.GITHUB_API))

    assert (await resolver.resolve([HOST_REPO]))[HOST_REPO] is None


@pytest.mark.asyncio
async def test_network_failure_resolves_to_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unreachable API is a None, not a traceback."""

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/rate_limit"):
            return httpx.Response(200, json=_RATE_LIMIT_BODY)
        raise httpx.ConnectError("connection refused", request=request)

    _install_http(monkeypatch, respond)
    resolver = _resolver(_config(ValidationMethod.GITHUB_API))

    assert (await resolver.resolve([HOST_REPO]))[HOST_REPO] is None


@pytest.mark.asyncio
async def test_malformed_api_response_resolves_to_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A response that is not the expected shape yields None."""

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/rate_limit"):
            return httpx.Response(200, json=_RATE_LIMIT_BODY)
        return httpx.Response(200, json={"data": {"repo_0": "not-an-object"}})

    _install_http(monkeypatch, respond)
    resolver = _resolver(_config(ValidationMethod.GITHUB_API))

    assert (await resolver.resolve([HOST_REPO]))[HOST_REPO] is None


@pytest.mark.asyncio
async def test_api_client_construction_failure_resolves_to_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even a failure before the first request degrades to None."""
    resolver = _resolver(_config(ValidationMethod.GITHUB_API))

    def _explode() -> Any:
        raise RuntimeError("no token available")

    monkeypatch.setattr(resolver, "_make_github_client", _explode)

    assert (await resolver.resolve([HOST_REPO]))[HOST_REPO] is None


@pytest.mark.asyncio
async def test_git_remote_failure_resolves_to_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failing ``git ls-remote`` yields None for that repository only."""
    resolver = _git_resolver(monkeypatch, {HOST_REPO: LS_REMOTE_OUTPUT})

    results = await resolver.resolve([HOST_REPO, MISSING_REPO])

    assert results[MISSING_REPO] is None
    assert results[HOST_REPO] is not None


@pytest.mark.asyncio
async def test_git_remote_without_tags_resolves_to_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A repository advertising no tags has no latest release."""
    resolver = _git_resolver(
        monkeypatch, {HOST_REPO: f"{BRANCH_COMMIT_SHA}\trefs/heads/main\n"}
    )

    assert (await resolver.resolve([HOST_REPO]))[HOST_REPO] is None


@pytest.mark.asyncio
async def test_empty_and_blank_repository_keys_are_ignored() -> None:
    """No usable key means no work and no backend call."""
    resolver = _resolver(_config(ValidationMethod.GITHUB_API))

    assert await resolver.resolve([]) == {}
    assert await resolver.resolve(["", ""]) == {}
