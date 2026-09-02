# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""A cached release must never walk a pin backwards.

Both caches serve an entry for the whole of its TTL, and both record the
newest release *as of the moment the entry was written*. Nothing about
that is wrong until something else advances a pin inside the window --
Dependabot, Renovate, a human, or an earlier repository of a sweep. The
cached answer is then older than the file, and an updater that treats
"differs from the target" as "needs updating" rewrites the pin backwards
and reports it as a successful update.

These tests drive the real update paths with a real, pre-seeded cache,
because the hazard lives in the join between the cache and the updater
and neither half shows it alone.

Every test has an inverse: a guard that refuses every rewrite would
satisfy the positive cases while making the tool useless, so each is
paired with a case that must still be applied.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any
from unittest import mock

import pytest

from gha_workflow_linter.action_call_fix import AutoFixer
from gha_workflow_linter.allow_list_check import AllowListChecker
from gha_workflow_linter.allow_list_resolver import AllowListResolver
from gha_workflow_linter.cache import ValidationCache
from gha_workflow_linter.latest_release import LatestRelease
from gha_workflow_linter.models import (
    ActionCall,
    AllowListFindingKind,
    CacheConfig,
    Config,
    GitHubAPIConfig,
    ReferenceType,
    ValidationError,
    ValidationMethod,
    ValidationResult,
)
from gha_workflow_linter.utils import pinned_version
from gha_workflow_linter.version_utils import _is_downgrade

if TYPE_CHECKING:
    from pathlib import Path

#: Distinct, well-formed commit SHAs standing in for three releases of
#: one action. Only their identity matters, never their content.
SHA_V4 = "a" * 40
SHA_V5 = "b" * 40
SHA_MOVED = "d" * 40

#: A reference that resolves to nothing at all.
BROKEN_SHA = "0" * 40

#: The same, for the allow-list host repository.
HOST = "lfreleng-actions/.github"
SHA_HOST_V10 = "1" * 40
SHA_HOST_V11 = "2" * 40
SHA_HOST_V12 = "3" * 40


class TestIsDowngrade:
    """The shared direction predicate."""

    def test_a_lower_target_is_a_downgrade(self) -> None:
        assert _is_downgrade("v5.0.0", "v4.2.2") is True

    def test_a_higher_target_is_not(self) -> None:
        assert _is_downgrade("v4.2.2", "v5.0.0") is False

    def test_the_same_version_is_not(self) -> None:
        """A moved tag is re-pinned at the same version, and must be."""
        assert _is_downgrade("v5.0.0", "v5.0.0") is False

    def test_an_unparsable_tag_establishes_no_direction(self) -> None:
        """Refusing on an unreadable tag would block ordinary rewrites."""
        assert _is_downgrade("release-2026-01", "v4.2.2") is False
        assert _is_downgrade("v4.2.2", "nightly") is False


class TestPinnedVersion:
    """Which version an action call is taken to be pinned at."""

    @staticmethod
    def _call(reference: str, comment: str | None) -> ActionCall:
        return ActionCall(
            organization="actions",
            repository="checkout",
            reference=reference,
            reference_type=(
                ReferenceType.COMMIT_SHA
                if len(reference) == 40
                else ReferenceType.TAG
            ),
            comment=comment,
            raw_line=f"      - uses: actions/checkout@{reference}",
            line_number=7,
        )

    def test_a_version_reference_outranks_the_comment(self) -> None:
        """The reference is what the workflow actually resolves."""
        call = self._call("v5.0.0", "v1.0.0")

        assert pinned_version(call, "v1.0.0") == "v5.0.0"

    def test_a_sha_pin_falls_back_to_its_comment(self) -> None:
        call = self._call(SHA_V5, "v5.0.0")

        assert pinned_version(call, "v5.0.0") == "v5.0.0"

    def test_a_sha_pin_with_no_version_names_none(self) -> None:
        """Without a version there is no direction to establish."""
        call = self._call(SHA_V5, None)

        assert pinned_version(call, None) is None
        assert pinned_version(call, "renovate: pinned") is None


def _fixer_config(tmp_path: Path) -> Config:
    """Build a config whose cache lives under the test's directory."""
    return Config(
        parallel_workers=2,
        require_pinned_sha=True,
        auto_fix=True,
        update_actions=True,
        fix_test_calls=False,
        validation_method=ValidationMethod.GITHUB_API,
        cache=CacheConfig(enabled=True, cache_dir=tmp_path / "cache"),
        github_api=GitHubAPIConfig(token="test-token"),
    )


def _seed_latest_version(
    config: Config, tag: str, sha: str, repository: str = "actions/checkout"
) -> None:
    """Write a latest-version entry to disk, as a previous run would."""
    cache = ValidationCache(config.cache)
    cache.put_latest_version(repository, tag, sha)
    cache.save()


def _pinned_call(sha: str, comment: str) -> ActionCall:
    """Build the SHA-pinned call a workflow line would produce."""
    raw = f"      - uses: actions/checkout@{sha}  # {comment}"
    return ActionCall(
        organization="actions",
        repository="checkout",
        reference=sha,
        reference_type=ReferenceType.COMMIT_SHA,
        comment=comment,
        raw_line=raw,
        line_number=7,
    )


async def _run_fixer(
    config: Config,
    tmp_path: Path,
    action_call: ActionCall,
    *,
    shas: dict[tuple[str, str], str],
    check_for_updates: bool,
    redirect_to: str | None = None,
    invalid: bool = False,
    salvage: str | None = None,
) -> tuple[dict[Any, Any], dict[str, Any]]:
    """Drive the real fixer, mocking only the network.

    ``_get_latest_versions_batch`` is deliberately *not* mocked: it is
    the function that consults the persistent cache, and the defect
    under test lives in what it hands the update loop. Individual
    reference resolution answers from ``shas`` too, so a reference
    absent from it is genuinely unresolvable rather than accidentally
    reaching the network. The salvage sources answer nothing, leaving
    the default branch as the last resort.

    Args:
        config: Linter configuration.
        tmp_path: Directory holding the workflow file.
        action_call: The single call to consider.
        shas: The reference-to-SHA answers to supply.
        check_for_updates: Whether ``--update-actions`` was requested.
        redirect_to: Repository the action has moved to, if any.
        invalid: Whether the call carries an invalid reference.
        salvage: Reference ``_find_valid_reference`` should offer, if
            any. The remaining salvage sources answer nothing, leaving
            the default branch as the last resort.

    Returns:
        The applied fixes and the outdated-action summary.
    """
    workflow = tmp_path / "ci.yaml"
    workflow.write_text(
        "---\nname: T\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        f"    steps:\n{action_call.raw_line}\n"
    )
    errors = (
        [
            ValidationError(
                file_path=workflow,
                action_call=action_call,
                result=ValidationResult.INVALID_REFERENCE,
                error_message="Invalid reference",
            )
        ]
        if invalid
        else []
    )

    async def one_sha(repo_key: str, ref: str) -> dict[str, str] | None:
        """Answer a single resolution from the same batch answers."""
        sha = shas.get((repo_key, ref))
        return {"sha": sha} if sha else None

    async def no_releases(_repo_keys: list[str]) -> dict[str, tuple[str, str]]:
        """Answer the batch network arm of the latest-version lookup.

        Args:
            _repo_keys: Repositories asked about, unused.

        Returns:
            No releases.
        """
        return {}

    async def no_single_release(_repo_key: str) -> tuple[str, str] | None:
        """Answer the per-repository fallback the batch leaves behind.

        ``_get_latest_versions_batch`` stays real, since the cache
        consultation is what these tests are about, but a repository it
        cannot answer falls through to a single REST lookup as well as
        the GraphQL batch. Stubbing only the batch leaves that open --
        and its refusal was previously absorbed by ``gather``.

        Args:
            _repo_key: Repository asked about, unused.

        Returns:
            No release.
        """
        return None

    with (
        mock.patch.object(AutoFixer, "_get_shas_batch") as batch_shas,
        mock.patch.object(
            AutoFixer,
            "_get_latest_versions_graphql_batch",
            side_effect=no_releases,
        ),
        mock.patch.object(
            AutoFixer,
            "_get_latest_version_single",
            side_effect=no_single_release,
        ),
        mock.patch.object(AutoFixer, "_detect_repository_redirect") as redirect,
        mock.patch.object(
            AutoFixer, "_get_commit_sha_for_reference", side_effect=one_sha
        ),
        mock.patch.object(
            AutoFixer, "_find_valid_reference", return_value=salvage
        ),
        mock.patch.object(
            AutoFixer, "_get_fallback_reference", return_value=None
        ),
        mock.patch.object(AutoFixer, "_get_repository_info", return_value=None),
    ):
        batch_shas.return_value = shas
        redirect.return_value = redirect_to

        async with AutoFixer(config, base_path=tmp_path, quiet=True) as fixer:
            applied, _, outdated = await fixer.fix_validation_errors(
                errors,
                {workflow: {7: action_call}},
                check_for_updates=check_for_updates,
            )

    return applied, outdated


class TestActionCallUpdater:
    """``--update-actions`` against a cache older than the file."""

    @pytest.mark.asyncio
    async def test_a_cached_release_behind_the_pin_is_not_applied(
        self, tmp_path: Path
    ) -> None:
        """The defect: v4 in the cache must not rewrite a v5 pin."""
        config = _fixer_config(tmp_path)
        _seed_latest_version(config, "v4.2.2", SHA_V4)

        applied, _ = await _run_fixer(
            config,
            tmp_path,
            _pinned_call(SHA_V5, "v5.0.0"),
            shas={("actions/checkout", "v5.0.0"): SHA_V5},
            check_for_updates=True,
        )

        assert applied == {}

    @pytest.mark.asyncio
    async def test_a_cached_release_behind_the_pin_is_not_reported_stale(
        self, tmp_path: Path
    ) -> None:
        """Without --update-actions the same pin is merely reported.

        Reporting it as outdated would be the same false statement, one
        step short of acting on it.
        """
        config = _fixer_config(tmp_path)
        config.update_actions = False
        _seed_latest_version(config, "v4.2.2", SHA_V4)

        _, outdated = await _run_fixer(
            config,
            tmp_path,
            _pinned_call(SHA_V5, "v5.0.0"),
            shas={("actions/checkout", "v5.0.0"): SHA_V5},
            check_for_updates=False,
        )

        assert outdated == {}

    @pytest.mark.asyncio
    async def test_a_cached_release_ahead_of_the_pin_is_still_applied(
        self, tmp_path: Path
    ) -> None:
        """The inverse: the guard must not refuse genuine updates."""
        config = _fixer_config(tmp_path)
        _seed_latest_version(config, "v5.0.0", SHA_V5)

        applied, _ = await _run_fixer(
            config,
            tmp_path,
            _pinned_call(SHA_V4, "v4.2.2"),
            shas={("actions/checkout", "v4.2.2"): SHA_V4},
            check_for_updates=True,
        )

        assert SHA_V5 in applied[tmp_path / "ci.yaml"][0]["new_line"]

    @pytest.mark.asyncio
    async def test_a_tag_pin_is_still_resolved_to_the_same_version_sha(
        self, tmp_path: Path
    ) -> None:
        """Equality is not a downgrade, and must not block a rewrite.

        Pinning a floating ``v5.0.0`` to that release's commit changes
        the reference without changing the version. A guard that
        refused everything not strictly newer would silently stop
        ``--update-actions`` doing the one thing it exists for.
        """
        config = _fixer_config(tmp_path)
        _seed_latest_version(config, "v5.0.0", SHA_V5)
        raw = "      - uses: actions/checkout@v5.0.0"
        tag_call = ActionCall(
            organization="actions",
            repository="checkout",
            reference="v5.0.0",
            reference_type=ReferenceType.TAG,
            comment=None,
            raw_line=raw,
            line_number=7,
        )

        applied, _ = await _run_fixer(
            config,
            tmp_path,
            tag_call,
            shas={("actions/checkout", "v5.0.0"): SHA_V5},
            check_for_updates=True,
        )

        assert SHA_V5 in applied[tmp_path / "ci.yaml"][0]["new_line"]

    @pytest.mark.asyncio
    async def test_a_redirect_is_applied_whatever_the_version_numbers(
        self, tmp_path: Path
    ) -> None:
        """Two repositories' version numbers are not comparable.

        An action that has moved starts its new home's numbering
        wherever that project happens to be. Reading a lower number
        there as a downgrade would leave the call pointing at the
        abandoned repository.
        """
        config = _fixer_config(tmp_path)
        _seed_latest_version(config, "v1.0.0", SHA_MOVED, "newowner/checkout")

        applied, _ = await _run_fixer(
            config,
            tmp_path,
            _pinned_call(SHA_V5, "v5.0.0"),
            shas={},
            check_for_updates=True,
            redirect_to="newowner/checkout",
        )

        new_line = applied[tmp_path / "ci.yaml"][0]["new_line"]
        assert "newowner/checkout" in new_line
        assert SHA_MOVED in new_line

    @pytest.mark.asyncio
    async def test_a_pin_with_no_version_is_still_applied(
        self, tmp_path: Path
    ) -> None:
        """No version means no direction, so the rewrite proceeds.

        Refusing here would silently stop updating every pin carrying no
        version comment.
        """
        config = _fixer_config(tmp_path)
        _seed_latest_version(config, "v4.2.2", SHA_V4)

        applied, _ = await _run_fixer(
            config,
            tmp_path,
            _pinned_call(SHA_V5, "pinned by hand"),
            shas={},
            check_for_updates=True,
        )

        assert SHA_V4 in applied[tmp_path / "ci.yaml"][0]["new_line"]


class TestInvalidReferenceRepair:
    """The repair for a broken pin must not smuggle in a downgrade.

    An invalid reference is repaired to the version its comment names
    where that version resolves. It reaches the repository's latest
    release only when it does *not* -- which is as likely to mean a rate
    limit or an outage as a deleted tag, and the latest release may
    itself be a cached answer older than the comment.
    """

    @pytest.mark.asyncio
    async def test_an_older_latest_does_not_repair_a_newer_claim(
        self, tmp_path: Path
    ) -> None:
        """A broken v5 pin is not repaired to a cached v4.

        Repairing it would report a downgrade as a fix, on evidence
        amounting to "v5.0.0 did not answer this time".
        """
        config = _fixer_config(tmp_path)
        config.update_actions = False
        _seed_latest_version(config, "v4.2.2", SHA_V4)

        applied, _ = await _run_fixer(
            config,
            tmp_path,
            _pinned_call(BROKEN_SHA, "v5.0.0"),
            shas={},
            check_for_updates=False,
            invalid=True,
        )

        assert applied == {}

    @pytest.mark.asyncio
    async def test_a_newer_latest_still_repairs_a_broken_pin(
        self, tmp_path: Path
    ) -> None:
        """The inverse: the fallback must still repair what it can.

        Refusing here would leave every unresolvable pin broken, which
        is the problem the fallback exists to solve.
        """
        config = _fixer_config(tmp_path)
        config.update_actions = False
        _seed_latest_version(config, "v5.0.0", SHA_V5)

        applied, _ = await _run_fixer(
            config,
            tmp_path,
            _pinned_call(BROKEN_SHA, "v4.2.2"),
            shas={},
            check_for_updates=False,
            invalid=True,
        )

        assert SHA_V5 in applied[tmp_path / "ci.yaml"][0]["new_line"]

    @pytest.mark.asyncio
    async def test_a_broken_version_reference_does_not_veto_its_own_repair(
        self, tmp_path: Path
    ) -> None:
        """The broken reference is not evidence of where the pin sits.

        A call naming a version tag that does not exist would otherwise
        block every repair to a lower one, leaving it broken for good.
        Only the comment answers here.
        """
        config = _fixer_config(tmp_path)
        config.update_actions = False
        _seed_latest_version(config, "v5.0.0", SHA_V5)
        raw = "      - uses: actions/checkout@v99.0.0"
        broken_tag_call = ActionCall(
            organization="actions",
            repository="checkout",
            reference="v99.0.0",
            reference_type=ReferenceType.TAG,
            comment=None,
            raw_line=raw,
            line_number=7,
        )

        applied, _ = await _run_fixer(
            config,
            tmp_path,
            broken_tag_call,
            shas={},
            check_for_updates=False,
            invalid=True,
        )

        assert SHA_V5 in applied[tmp_path / "ci.yaml"][0]["new_line"]

    @pytest.mark.asyncio
    async def test_a_redirect_repairs_whatever_the_version_numbers(
        self, tmp_path: Path
    ) -> None:
        """A redirected repair compares nothing, as the update path does.

        The comment names a version of the *old* project while the
        latest release belongs to the new one, so the two numbers
        describe different things. Comparing them would reject a new
        home that happens to number lower and leave the call both
        invalid and pointing at an abandoned repository.
        """
        config = _fixer_config(tmp_path)
        config.update_actions = False
        _seed_latest_version(config, "v1.0.0", SHA_MOVED, "newowner/checkout")

        applied, _ = await _run_fixer(
            config,
            tmp_path,
            _pinned_call(BROKEN_SHA, "v5.0.0"),
            shas={},
            check_for_updates=False,
            invalid=True,
            redirect_to="newowner/checkout",
        )

        new_line = applied[tmp_path / "ci.yaml"][0]["new_line"]
        assert "newowner/checkout" in new_line
        assert SHA_MOVED in new_line

    @pytest.mark.asyncio
    async def test_a_salvaged_version_tag_is_guarded_too(
        self, tmp_path: Path
    ) -> None:
        """The last source can name a version, so it is checked as well.

        Salvage searches by prefix, so a broken ``@v4`` finds ``v4.2.2``
        -- a plausible-looking repair that walks a call claiming v5
        backwards, after the cached v4 target was correctly refused one
        step earlier.
        """
        config = _fixer_config(tmp_path)
        config.update_actions = False
        _seed_latest_version(config, "v4.2.2", SHA_V4)

        applied, _ = await _run_fixer(
            config,
            tmp_path,
            _pinned_call(BROKEN_SHA, "v5.0.0"),
            shas={("actions/checkout", "v4.2.2"): SHA_V4},
            check_for_updates=False,
            invalid=True,
            salvage="v4.2.2",
        )

        assert applied == {}

    @pytest.mark.asyncio
    async def test_a_refused_salvage_does_not_fall_back_to_a_branch(
        self, tmp_path: Path
    ) -> None:
        """A refused salvage stops the repair rather than floating it.

        Continuing to the branch fallback would swap a version pin for a
        moving reference, losing the pin as well as the version. The
        call keeps its validation error, so nothing is swallowed.
        """
        config = _fixer_config(tmp_path)
        config.update_actions = False
        _seed_latest_version(config, "v4.2.2", SHA_V4)

        applied, _ = await _run_fixer(
            config,
            tmp_path,
            _pinned_call(BROKEN_SHA, "v5.0.0"),
            shas={
                ("actions/checkout", "v4.2.2"): SHA_V4,
                ("actions/checkout", "main"): SHA_MOVED,
            },
            check_for_updates=False,
            invalid=True,
            salvage="v4.2.2",
        )

        assert SHA_MOVED not in str(applied)

    @pytest.mark.asyncio
    async def test_a_salvaged_branch_is_not_read_as_a_version(
        self, tmp_path: Path
    ) -> None:
        """The inverse: a branch establishes no direction, so it stands.

        Refusing here would leave every broken pin with no version-tag
        salvage unrepaired.
        """
        config = _fixer_config(tmp_path)
        config.update_actions = False

        applied, _ = await _run_fixer(
            config,
            tmp_path,
            _pinned_call(BROKEN_SHA, "v5.0.0"),
            shas={("actions/checkout", "main"): SHA_MOVED},
            check_for_updates=False,
            invalid=True,
            salvage="main",
        )

        assert SHA_MOVED in applied[tmp_path / "ci.yaml"][0]["new_line"]

    @pytest.mark.asyncio
    async def test_a_refused_latest_does_not_fall_back_to_a_branch(
        self, tmp_path: Path
    ) -> None:
        """Refusal carries forward, so a branch cannot slip in after it.

        Salvage consults a cached ``main`` before it looks at tags, so a
        repository with one would replace a pin claiming v5 with a
        floating branch the moment the cached v4 target was refused --
        losing the pin as well as the version.
        """
        config = _fixer_config(tmp_path)
        config.update_actions = False
        _seed_latest_version(config, "v4.2.2", SHA_V4)

        applied, _ = await _run_fixer(
            config,
            tmp_path,
            _pinned_call(BROKEN_SHA, "v5.0.0"),
            shas={("actions/checkout", "main"): SHA_MOVED},
            check_for_updates=False,
            invalid=True,
            salvage="main",
        )

        assert applied == {}

    @pytest.mark.asyncio
    async def test_a_refused_latest_still_accepts_a_newer_salvage(
        self, tmp_path: Path
    ) -> None:
        """The inverse: refusal narrows the repair, it does not end it.

        A salvaged version at least as new as the claim is exactly the
        repair the call needs, and refusing it would abandon a pin that
        could have been fixed correctly.
        """
        config = _fixer_config(tmp_path)
        config.update_actions = False
        _seed_latest_version(config, "v4.2.2", SHA_V4)

        applied, _ = await _run_fixer(
            config,
            tmp_path,
            _pinned_call(BROKEN_SHA, "v5.0.0"),
            shas={("actions/checkout", "v5.1.0"): SHA_V5},
            check_for_updates=False,
            invalid=True,
            salvage="v5.1.0",
        )

        assert SHA_V5 in applied[tmp_path / "ci.yaml"][0]["new_line"]

    @pytest.mark.asyncio
    async def test_a_comment_that_is_not_a_version_vetoes_nothing(
        self, tmp_path: Path
    ) -> None:
        """Only a clean version tag counts as ordering evidence.

        ``_parse_version`` discards a ``-`` suffix, so a date comment
        would read as version 2026 and veto every repair the call could
        possibly need.
        """
        config = _fixer_config(tmp_path)
        config.update_actions = False
        _seed_latest_version(config, "v5.0.0", SHA_V5)

        applied, _ = await _run_fixer(
            config,
            tmp_path,
            _pinned_call(BROKEN_SHA, "2026-08-19"),
            shas={},
            check_for_updates=False,
            invalid=True,
        )

        assert SHA_V5 in applied[tmp_path / "ci.yaml"][0]["new_line"]

    @pytest.mark.asyncio
    async def test_a_resolvable_comment_version_still_wins(
        self, tmp_path: Path
    ) -> None:
        """The comment outranks the latest release when it resolves.

        Pinned here because the guard sits on the step below it: a
        change that stopped consulting the comment would take the
        guarded path for every broken pin.
        """
        config = _fixer_config(tmp_path)
        config.update_actions = False
        _seed_latest_version(config, "v5.0.0", SHA_V5)

        applied, _ = await _run_fixer(
            config,
            tmp_path,
            _pinned_call(BROKEN_SHA, "v4.2.2"),
            shas={("actions/checkout", "v4.2.2"): SHA_V4},
            check_for_updates=False,
            invalid=True,
        )

        assert SHA_V4 in applied[tmp_path / "ci.yaml"][0]["new_line"]


def _workflow_with_host_pin(tmp_path: Path, sha: str, comment: str) -> Path:
    """Write a workflow whose allow-list pin names ``sha``."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    target = workflows / "ci.yaml"
    target.write_text(
        "---\n"
        "name: T\n"
        "on: [push]\n"
        "jobs:\n"
        "  b:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: lfreleng-actions/harden-runner-block-action@abc\n"
        "        with:\n"
        f"          config: '@{sha}'  # {comment}\n"
    )
    return target


def _seed_host_release(
    config: Config, tag: str, sha: str, commit_tags: dict[str, str]
) -> None:
    """Write a host repository's latest release to the on-disk cache."""
    cache = ValidationCache(config.cache)
    cache.put_latest_version(HOST, tag, sha, commit_tags)
    cache.save()


def _live_release() -> LatestRelease:
    """The answer a live resolution would give: v0.12.0 is newest."""
    return LatestRelease(
        tag="v0.12.0",
        commit_sha=SHA_HOST_V12,
        commit_tags={
            SHA_HOST_V12: "v0.12.0",
            SHA_HOST_V11: "v0.11.0",
            SHA_HOST_V10: "v0.10.0",
        },
    )


def _check_with_recorded_resolution(
    config: Config, target: Path, tmp_path: Path
) -> tuple[Any, list[list[str]]]:
    """Run the real checker, recording any live resolution it triggers.

    Only ``_resolve_uncached`` is replaced -- the fail-soft boundary
    around the backends -- so the cache read, the sufficiency test and
    the classification are all the real thing.

    Args:
        config: Linter configuration.
        target: The workflow file to check.
        tmp_path: Repository root.

    Returns:
        The outcome and the repository keys resolved live.
    """
    resolved_live: list[list[str]] = []

    async def _resolve_uncached(
        _self: AllowListResolver, repo_keys: list[str]
    ) -> dict[str, LatestRelease | None]:
        resolved_live.append(list(repo_keys))
        return dict.fromkeys(repo_keys, _live_release())

    with mock.patch.object(
        AllowListResolver, "_resolve_uncached", new=_resolve_uncached
    ):
        outcome = asyncio.run(
            AllowListChecker(config, ValidationCache(config.cache)).check(
                [target], tmp_path
            )
        )

    return outcome, resolved_live


class TestAllowListClassification:
    """``--update-allow-list`` against a cache older than the file."""

    @staticmethod
    def _config(tmp_path: Path) -> Config:
        config = Config(cache=CacheConfig(enabled=True, cache_dir=tmp_path))
        config.allow_list.org = "lfreleng-actions"
        return config

    def test_a_pin_the_cached_target_cannot_place_is_resolved_afresh(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The defect: a v0.12 pin against a v0.11 cache entry.

        v0.12.0 did not exist when the entry was written, so its commit
        is absent from the stored map. Trusting the entry would classify
        a current pin as stale and recommend a downgrade.
        """
        monkeypatch.delenv("GITHUB_REPOSITORY_OWNER", raising=False)
        config = self._config(tmp_path)
        _seed_host_release(
            config,
            "v0.11.0",
            SHA_HOST_V11,
            {SHA_HOST_V11: "v0.11.0", SHA_HOST_V10: "v0.10.0"},
        )
        target = _workflow_with_host_pin(tmp_path, SHA_HOST_V12, "v0.12.0")

        outcome, resolved_live = _check_with_recorded_resolution(
            config, target, tmp_path
        )

        assert resolved_live == [[HOST]]
        assert outcome.findings == []

    def test_a_pin_the_cached_target_can_place_costs_no_lookup(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The inverse: a genuinely stale pin is still answered by cache.

        v0.10.0 is in the stored map, so its position relative to the
        cached target is established without a backend. Re-resolving
        every differing pin would give the same answer at the cost of
        the saving the cache exists for.
        """
        monkeypatch.delenv("GITHUB_REPOSITORY_OWNER", raising=False)
        config = self._config(tmp_path)
        _seed_host_release(
            config,
            "v0.11.0",
            SHA_HOST_V11,
            {SHA_HOST_V11: "v0.11.0", SHA_HOST_V10: "v0.10.0"},
        )
        target = _workflow_with_host_pin(tmp_path, SHA_HOST_V10, "v0.10.0")

        outcome, resolved_live = _check_with_recorded_resolution(
            config, target, tmp_path
        )

        assert resolved_live == []
        assert [f.kind for f in outcome.findings] == [
            AllowListFindingKind.STALE
        ]
        assert outcome.findings[0].target_version == "v0.11.0"


class TestCacheRetainsOrderingData:
    """The commit map must survive a round trip through the cache."""

    def test_the_commit_map_round_trips(self, tmp_path: Path) -> None:
        config = CacheConfig(enabled=True, cache_dir=tmp_path)
        writer = ValidationCache(config)
        writer.put_latest_version(
            HOST, "v0.11.0", SHA_HOST_V11, {SHA_HOST_V10: "v0.10.0"}
        )
        writer.save()

        entry = ValidationCache(config).get_latest_version_entry(HOST)

        assert entry is not None
        assert entry.commit_tags == {SHA_HOST_V10: "v0.10.0"}

    def test_the_map_a_resolution_built_serves_the_next_run(
        self, tmp_path: Path
    ) -> None:
        """A resolution must persist the map, not merely consume one.

        Seeding the entry by hand passes whether or not the resolver
        ever writes the map, so this drives a real resolution first and
        reads the answer back through a second one.
        """
        config = Config(cache=CacheConfig(enabled=True, cache_dir=tmp_path))
        calls: list[list[str]] = []

        async def _resolve_uncached(
            _self: AllowListResolver, repo_keys: list[str]
        ) -> dict[str, LatestRelease | None]:
            calls.append(list(repo_keys))
            return dict.fromkeys(repo_keys, _live_release())

        with mock.patch.object(
            AllowListResolver, "_resolve_uncached", new=_resolve_uncached
        ):
            asyncio.run(
                AllowListResolver(
                    config, ValidationCache(config.cache)
                ).resolve([HOST], {HOST: {SHA_HOST_V12}})
            )
            second = asyncio.run(
                AllowListResolver(
                    config, ValidationCache(config.cache)
                ).resolve([HOST], {HOST: {SHA_HOST_V10}})
            )

        # One live resolution: the second run placed an older pin from
        # the stored map alone.
        assert calls == [[HOST]]
        restored = second[HOST]
        assert restored is not None
        assert restored.tag_for_commit(SHA_HOST_V10) == "v0.10.0"

    def test_an_entry_written_without_a_map_still_loads(
        self, tmp_path: Path
    ) -> None:
        """Older on-disk entries carry no map and must not fail to load."""
        config = CacheConfig(enabled=True, cache_dir=tmp_path)
        writer = ValidationCache(config)
        writer.put_latest_version(HOST, "v0.11.0", SHA_HOST_V11)
        writer.save()

        entry = ValidationCache(config).get_latest_version_entry(HOST)

        assert entry is not None
        assert entry.commit_tags == {}
