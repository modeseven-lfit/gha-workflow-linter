# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for the multi-repository sweep driver in the CLI.

A sweep is orchestration: the work of scanning a repository is already
covered elsewhere, and what remains to be shown is that the driver hands
each repository the right things and survives one of them failing. So
``_run_one_repository`` is replaced with a recorder here -- patched in
``gha_workflow_linter.cli``, which is both where it is defined and where
it is looked up -- and the assertions are about what the driver passed,
in what order, and what it did with the answers.

Three claims carry the feature and are each pinned by name below:

* every discovered repository is visited, sequentially and in sorted
  order, with its own path;
* one :class:`~gha_workflow_linter.cache.ValidationCache` is shared
  across the sweep, so twenty repositories pinning the same host cost
  one latest-release resolution rather than twenty -- the efficiency
  argument for building the mode into the tool at all;
* a repository that raises is recorded and the sweep continues, except
  for :class:`ConfigurationError`, which applies to every repository and
  so is re-raised.

Nothing here touches the network, and every cache is written under
``tmp_path`` rather than the user's cache directory.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from unittest import mock

import pytest
from typer.testing import CliRunner

from gha_workflow_linter import cli, exit_codes
from gha_workflow_linter.allow_list_check import (
    AllowListFinding,
    AllowListOutcome,
)
from gha_workflow_linter.allow_list_scanner import (
    AllowListPin,
    CommentPosition,
    QuoteStyle,
)
from gha_workflow_linter.allow_list_spec import resolve_spec
from gha_workflow_linter.cache import ValidationCache
from gha_workflow_linter.cli import (
    RunOutcome,
    _display_multi_repo_summary,
    _preprocess_args_for_default_command,
    _run_multi_repo,
    _run_repository_in_sweep,
    _sweep_status,
    app,
)
from gha_workflow_linter.exceptions import ConfigurationError
from gha_workflow_linter.models import (
    AllowListFindingKind,
    CacheConfig,
    CLIOptions,
    Config,
    Severity,
)
from tests.conftest import strip_ansi

#: Host repository a pin would name. Any allow-list host would do; what
#: matters is that every repository in the sweep asks about the same one.
HOST_REPOSITORY = "lfreleng-actions/.github"


def make_repository(path: Path) -> Path:
    """Create a directory discovery will recognise as a repository.

    Args:
        path: Directory to create; parents are created as needed.

    Returns:
        The same path, now carrying a ``.git`` directory.
    """
    (path / ".git").mkdir(parents=True)
    return path


def make_container(root: Path, *names: str) -> list[Path]:
    """Create a container directory holding several repositories.

    Args:
        root: Directory to create the repositories under.
        *names: Repository directory names, in creation order.

    Returns:
        The created repository paths, in creation order.
    """
    return [make_repository(root / name) for name in names]


def make_config(tmp_path: Path) -> Config:
    """Build a template configuration with a throwaway cache.

    Args:
        tmp_path: Test-scoped directory to hold the cache file.

    Returns:
        A configuration safe to use without touching the user's cache.
    """
    return Config(cache=CacheConfig(cache_dir=tmp_path / "cache"))


def make_options(container: Path, *, quiet: bool = True) -> CLIOptions:
    """Build the CLI options a sweep is driven with.

    Args:
        container: Path the sweep treats as a container of repositories.
        quiet: Whether to suppress the sweep's console output.

    Returns:
        Options with multi-repository mode enabled.
    """
    return CLIOptions(path=container, multi_repo=True, quiet=quiet)


def write_dependabot_cooldown(repository: Path, days: int) -> None:
    """Give a repository its own Dependabot cooldown policy.

    Args:
        repository: Repository root to write the configuration into.
        days: Value for ``cooldown.default-days``.
    """
    github = repository / ".github"
    github.mkdir(exist_ok=True)
    (github / "dependabot.yml").write_text(
        "version: 2\n"
        "updates:\n"
        "  - package-ecosystem: github-actions\n"
        "    directory: /\n"
        "    cooldown:\n"
        f"      default-days: {days}\n",
        encoding="utf-8",
    )


def make_stale_finding(line: int) -> AllowListFinding:
    """Build one unsuppressed, stale allow-list finding.

    Only the fields the summary consults carry meaning here; the rest
    exist because the dataclasses require them.

    Args:
        line: Line number the pin sits on. Findings are keyed by
            ``(file, line)``, so distinct values keep them distinct.

    Returns:
        A finding that counts towards ``outstanding``.
    """
    pin = AllowListPin(
        file_path=Path(".github/workflows/ci.yaml"),
        line_number=line,
        column=0,
        key_path=("jobs", "b", "steps", "0", "with", "config"),
        raw_line="        config: '@18d9c444'  # v0.1.1",
        raw_value="@18d9c4446bea555d0783e850f6d295f844fe8f67",
        quote_style=QuoteStyle.SINGLE,
        comment_position=CommentPosition.YAML,
        version_comment="v0.1.1",
        directives=frozenset(),
        suppressed_by=None,
        suppression_reason=None,
        spec=resolve_spec(
            "@18d9c4446bea555d0783e850f6d295f844fe8f67",
            workflow_org="lfreleng-actions",
        ),
        auto_fixable=True,
    )
    return AllowListFinding(
        pin=pin,
        kind=AllowListFindingKind.STALE,
        severity=Severity.WARNING,
        message="stale",
        current_sha="18d9c4446bea555d0783e850f6d295f844fe8f67",
        target_sha="bf6642f68d58c1b81bbe993e676d6cc339ac3654",
        target_version="v0.12.2",
        suppressed=False,
    )


def make_allow_list_outcome(
    *, outstanding: int = 0, unresolved: bool = False, fixed: int = 0
) -> AllowListOutcome:
    """Build an allow-list outcome with the given shape.

    Args:
        outstanding: How many unsuppressed findings to leave unfixed.
        unresolved: Whether a host failed to resolve.
        fixed: How many further findings to include and mark as
            rewritten, so partial remediation can be described.

    Returns:
        An outcome the summary can be asked to describe.
    """
    findings = [make_stale_finding(n + 1) for n in range(outstanding + fixed)]
    # Remediation is recorded by line, and the fixed ones are taken from
    # the tail so the outstanding count is the leading slice.
    fixed_lines = frozenset(
        (str(finding.pin.file_path), finding.pin.line_number)
        for finding in findings[outstanding:]
    )
    return AllowListOutcome(
        findings=findings,
        hosts={},
        unresolved={HOST_REPOSITORY: "no releases"} if unresolved else {},
        suppressed_count=0,
        checked=True,
        fixed_lines=fixed_lines,
    )


@dataclasses.dataclass(frozen=True)
class Visit:
    """One call the driver made into a repository's run.

    Attributes:
        config: Configuration that call received.
        options: CLI options that call received.
        cache: Validation cache that call received.
        collect_json: Whether the driver asked for the JSON payload to be
            collected rather than printed.
    """

    config: Config
    options: CLIOptions
    cache: ValidationCache
    collect_json: bool = False


class RecordingRun:
    """Stand-in for ``_run_one_repository`` that records its arguments.

    Attributes:
        visits: Every call made, in the order the driver made them.
    """

    def __init__(
        self, outcomes: dict[str, int | Exception] | None = None
    ) -> None:
        """Record visits and answer with per-repository outcomes.

        Args:
            outcomes: Exit code (or exception to raise) keyed by
                repository directory name. Repositories absent from the
                mapping succeed.
        """
        self.visits: list[Visit] = []
        self._outcomes: dict[str, int | Exception] = outcomes or {}

    def __call__(
        self,
        config: Config,
        options: CLIOptions,
        shared_cache: ValidationCache,
        *,
        collect_json: bool = False,
    ) -> RunOutcome:
        """Record one visit and return its configured outcome.

        Args:
            config: Configuration the driver resolved for this
                repository.
            options: CLI options the driver resolved for this
                repository.
            shared_cache: Cache the driver passed in.
            collect_json: Whether the driver asked for the payload to be
                collected rather than printed.

        Returns:
            The outcome configured for this repository.

        Raises:
            Exception: Whatever was configured for this repository.
        """
        self.visits.append(
            Visit(
                config=config,
                options=options,
                cache=shared_cache,
                collect_json=collect_json,
            )
        )
        outcome = self._outcomes.get(options.path.name, exit_codes.SUCCESS)
        if isinstance(outcome, Exception):
            raise outcome
        return RunOutcome(exit_code=outcome)

    @property
    def visited(self) -> list[Path]:
        """Paths the driver asked for, in visit order.

        Returns:
            The ``path`` of every visit, in order.
        """
        return [visit.options.path for visit in self.visits]


class TestSweepVisits:
    """Which repositories a sweep visits, and with what."""

    def test_visits_every_repository_in_sorted_order(
        self, tmp_path: Path
    ) -> None:
        """All discovered repositories are visited, sorted by path.

        Creation order is deliberately not alphabetical, so a driver
        that echoed the filesystem's order would fail here on at least
        some filesystems.
        """
        make_container(tmp_path, "zeta", "alpha", "middle")
        recorder = RecordingRun()

        with mock.patch.object(cli, "_run_one_repository", recorder):
            exit_code = _run_multi_repo(
                make_config(tmp_path), make_options(tmp_path)
            )

        assert [path.name for path in recorder.visited] == [
            "alpha",
            "middle",
            "zeta",
        ]
        assert exit_code == exit_codes.SUCCESS

    def test_each_visit_receives_its_own_repository_path(
        self, tmp_path: Path
    ) -> None:
        """Each run is rooted at a repository, never at the container.

        Scanning stops at repository boundaries, so a run left pointed
        at the container would find nothing at all.
        """
        repositories = make_container(tmp_path, "one", "two")
        recorder = RecordingRun()

        with mock.patch.object(cli, "_run_one_repository", recorder):
            _run_multi_repo(make_config(tmp_path), make_options(tmp_path))

        assert recorder.visited == sorted(repositories)
        assert tmp_path not in recorder.visited

    def test_no_repositories_found_is_a_notice_not_a_failure(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """An empty container succeeds and says why nothing happened.

        Args:
            tmp_path: Empty container directory.
            capsys: Captures the notice.
        """
        recorder = RecordingRun()

        with mock.patch.object(cli, "_run_one_repository", recorder):
            exit_code = _run_multi_repo(
                make_config(tmp_path), make_options(tmp_path, quiet=False)
            )

        assert exit_code == exit_codes.SUCCESS
        assert recorder.visits == []
        output = " ".join(strip_ansi(capsys.readouterr().out).split())
        assert "No repositories found" in output

    def test_invalid_depth_is_a_runtime_error(self, tmp_path: Path) -> None:
        """A discovery failure ends the sweep rather than propagating."""
        recorder = RecordingRun()

        with (
            mock.patch.object(cli, "_run_one_repository", recorder),
            mock.patch.object(
                cli,
                "find_repositories",
                side_effect=ValueError("depth must not be negative, got -1"),
            ),
        ):
            exit_code = _run_multi_repo(
                make_config(tmp_path), make_options(tmp_path)
            )

        assert exit_code == exit_codes.RUNTIME_ERROR
        assert recorder.visits == []


class TestSharedCache:
    """The one piece of state a sweep deliberately shares."""

    def test_same_cache_instance_reaches_every_repository(
        self, tmp_path: Path
    ) -> None:
        """One cache is built and handed to every repository."""
        make_container(tmp_path, "one", "two", "three")
        recorder = RecordingRun()

        with mock.patch.object(cli, "_run_one_repository", recorder):
            _run_multi_repo(make_config(tmp_path), make_options(tmp_path))

        assert len(recorder.visits) == 3
        first = recorder.visits[0].cache
        assert isinstance(first, ValidationCache)
        assert all(visit.cache is first for visit in recorder.visits)

    def test_host_is_resolved_once_for_the_whole_sweep(
        self, tmp_path: Path
    ) -> None:
        """Three repositories pinning one host cost one resolution.

        This is the efficiency argument for the mode: the second and
        third repositories find the host already cached and never look
        it up. The recorder stands in for the allow-list resolver,
        recording a resolution only on a cache miss.
        """
        make_container(tmp_path, "one", "two", "three")
        resolutions: list[str] = []

        def resolve_once(
            _config: Config,
            options: CLIOptions,
            shared_cache: ValidationCache,
            *,
            collect_json: bool = False,  # noqa: ARG001 - matches the driver
        ) -> RunOutcome:
            """Resolve the host on a cache miss, as a real run would.

            Args:
                _config: Unused; the repository's configuration.
                options: Supplies the repository being visited.
                shared_cache: Cache consulted before resolving.
                collect_json: Unused; accepted to match the driver.

            Returns:
                A successful outcome.
            """
            if shared_cache.get_latest_version(HOST_REPOSITORY) is None:
                resolutions.append(options.path.name)
                shared_cache.put_latest_version(
                    HOST_REPOSITORY, "v1.0.0", "a" * 40
                )
            return RunOutcome(exit_code=exit_codes.SUCCESS)

        with mock.patch.object(cli, "_run_one_repository", resolve_once):
            _run_multi_repo(make_config(tmp_path), make_options(tmp_path))

        assert resolutions == ["one"]


class TestPerRepositoryState:
    """What a sweep deliberately does *not* share."""

    def test_configuration_is_copied_per_repository(
        self, tmp_path: Path
    ) -> None:
        """No repository can see, or corrupt, another's configuration."""
        make_container(tmp_path, "one", "two", "three")
        template = make_config(tmp_path)
        recorder = RecordingRun()

        with mock.patch.object(cli, "_run_one_repository", recorder):
            _run_multi_repo(template, make_options(tmp_path))

        configs = [visit.config for visit in recorder.visits]
        assert all(config is not template for config in configs)
        assert len({id(config) for config in configs}) == len(configs)

    def test_cooldown_is_resolved_from_each_repository(
        self, tmp_path: Path
    ) -> None:
        """Two Dependabot policies stay attached to their repositories.

        Without a per-repository copy the second repository would
        inherit the first one's cooldown, and its action updates would
        be held back (or released) by a policy it never declared.
        """
        repositories = make_container(tmp_path, "slow", "quick")
        for repository, days in zip(repositories, (7, 3), strict=True):
            write_dependabot_cooldown(repository, days)
        recorder = RecordingRun()

        with mock.patch.object(cli, "_run_one_repository", recorder):
            _run_multi_repo(make_config(tmp_path), make_options(tmp_path))

        cooldowns = {
            visit.options.path.name: visit.config.cooldown_days
            for visit in recorder.visits
        }
        assert cooldowns == {"quick": 3, "slow": 7}

    def test_explicit_cooldown_flag_still_wins(self, tmp_path: Path) -> None:
        """``--cooldown`` overrides every repository's Dependabot file."""
        repository = make_repository(tmp_path / "one")
        write_dependabot_cooldown(repository, 7)
        options = CLIOptions(
            path=tmp_path, multi_repo=True, quiet=True, cooldown=2
        )
        recorder = RecordingRun()

        with mock.patch.object(cli, "_run_one_repository", recorder):
            _run_multi_repo(make_config(tmp_path), options)

        assert recorder.visits[0].config.cooldown_days == 2


class TestSweepFailures:
    """What a failing repository costs the rest of the sweep."""

    def test_failure_does_not_stop_later_repositories(
        self, tmp_path: Path
    ) -> None:
        """One unreadable checkout must not cost the others their scan."""
        make_container(tmp_path, "first", "second", "third")
        recorder = RecordingRun({"second": RuntimeError("boom")})

        with mock.patch.object(cli, "_run_one_repository", recorder):
            exit_code = _run_multi_repo(
                make_config(tmp_path), make_options(tmp_path)
            )

        assert [path.name for path in recorder.visited] == [
            "first",
            "second",
            "third",
        ]
        assert exit_code == exit_codes.RUNTIME_ERROR

    def test_failure_is_recorded_on_the_outcome(self, tmp_path: Path) -> None:
        """The failure is described, not merely counted."""
        repository = make_repository(tmp_path / "one")
        recorder = RecordingRun({"one": RuntimeError("boom")})

        with mock.patch.object(cli, "_run_one_repository", recorder):
            outcome = _run_repository_in_sweep(
                make_config(tmp_path),
                make_options(tmp_path),
                ValidationCache(make_config(tmp_path).cache),
                repository,
            )

        assert outcome.error == "boom"
        assert outcome.exit_code == exit_codes.RUNTIME_ERROR

    def test_failure_is_reported_to_the_user(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A silently skipped repository would be worse than a failure.

        Args:
            tmp_path: Container directory.
            capsys: Captures the sweep's output.
        """
        make_container(tmp_path, "one", "two")
        recorder = RecordingRun({"one": RuntimeError("boom")})

        with mock.patch.object(cli, "_run_one_repository", recorder):
            _run_multi_repo(
                make_config(tmp_path), make_options(tmp_path, quiet=False)
            )

        output = " ".join(strip_ansi(capsys.readouterr().out).split())
        assert "failed: boom" in output
        assert "could not be scanned" in output

    def test_configuration_error_stops_the_sweep(self, tmp_path: Path) -> None:
        """A bad setting applies everywhere, so continuing is pointless."""
        make_container(tmp_path, "first", "second")
        recorder = RecordingRun(
            {"first": ConfigurationError("unparsable allow-list spec")}
        )

        with (
            mock.patch.object(cli, "_run_one_repository", recorder),
            pytest.raises(ConfigurationError, match="unparsable"),
        ):
            _run_multi_repo(make_config(tmp_path), make_options(tmp_path))

        assert [path.name for path in recorder.visited] == ["first"]


class TestSweepExitCode:
    """How per-repository results combine into one exit code."""

    @pytest.mark.parametrize(
        ("codes", "expected"),
        [
            pytest.param(
                (exit_codes.SUCCESS, exit_codes.SUCCESS),
                exit_codes.SUCCESS,
                id="all-clean",
            ),
            pytest.param(
                (exit_codes.SUCCESS, exit_codes.DEFECTS_FOUND),
                exit_codes.DEFECTS_FOUND,
                id="defects-beat-success",
            ),
            pytest.param(
                (exit_codes.ALLOW_LIST_STALE, exit_codes.DEFECTS_FOUND),
                exit_codes.ALLOW_LIST_STALE,
                id="stale-beats-defects",
            ),
            pytest.param(
                (exit_codes.ACTIONS_OUTDATED, exit_codes.DEFECTS_FOUND),
                exit_codes.ACTIONS_OUTDATED,
                id="outdated-beats-defects",
            ),
            pytest.param(
                (exit_codes.ALLOW_LIST_STALE, exit_codes.ACTIONS_OUTDATED),
                exit_codes.ALLOW_LIST_STALE,
                id="stale-beats-outdated",
            ),
            pytest.param(
                (exit_codes.ALLOW_LIST_STALE, exit_codes.ALLOW_LIST_UNRESOLVED),
                exit_codes.ALLOW_LIST_UNRESOLVED,
                id="unresolved-wins",
            ),
        ],
    )
    def test_codes_combine_by_precedence(
        self, tmp_path: Path, codes: tuple[int, int], expected: int
    ) -> None:
        """The §8 precedence (4 > 3 > 5 > 1 > 0) holds across a sweep.

        Args:
            tmp_path: Container directory.
            codes: Exit codes the two repositories return.
            expected: The aggregate the sweep must report.
        """
        make_container(tmp_path, "one", "two")
        first, second = codes
        recorder = RecordingRun({"one": first, "two": second})

        with mock.patch.object(cli, "_run_one_repository", recorder):
            exit_code = _run_multi_repo(
                make_config(tmp_path), make_options(tmp_path)
            )

        assert exit_code == expected

    def test_order_does_not_change_the_aggregate(self, tmp_path: Path) -> None:
        """The worst result wins wherever in the sweep it occurred."""
        make_container(tmp_path, "one", "two")
        forwards = RecordingRun(
            {"one": exit_codes.ALLOW_LIST_UNRESOLVED, "two": exit_codes.SUCCESS}
        )
        backwards = RecordingRun(
            {"one": exit_codes.SUCCESS, "two": exit_codes.ALLOW_LIST_UNRESOLVED}
        )

        codes: list[int] = []
        for recorder in (forwards, backwards):
            with mock.patch.object(cli, "_run_one_repository", recorder):
                codes.append(
                    _run_multi_repo(
                        make_config(tmp_path), make_options(tmp_path)
                    )
                )

        assert codes == [
            exit_codes.ALLOW_LIST_UNRESOLVED,
            exit_codes.ALLOW_LIST_UNRESOLVED,
        ]


class TestSweepSummary:
    """The table that closes a sweep."""

    @pytest.mark.parametrize(
        ("outcome", "expected"),
        [
            pytest.param(
                RunOutcome(exit_code=exit_codes.SUCCESS),
                "[green]clean[/green]",
                id="clean",
            ),
            pytest.param(
                RunOutcome(exit_code=exit_codes.DEFECTS_FOUND, files_changed=2),
                "[yellow]updated[/yellow]",
                id="updated",
            ),
            pytest.param(
                RunOutcome(exit_code=exit_codes.ALLOW_LIST_STALE),
                "[yellow]findings[/yellow]",
                id="findings",
            ),
            pytest.param(
                RunOutcome(exit_code=exit_codes.RUNTIME_ERROR, error="boom"),
                "[red]failed[/red]",
                id="failed",
            ),
            pytest.param(
                RunOutcome(exit_code=exit_codes.SUCCESS, error="boom"),
                "[red]failed[/red]",
                id="failure-outranks-a-clean-code",
            ),
            pytest.param(
                RunOutcome(
                    exit_code=exit_codes.SUCCESS,
                    allow_list=make_allow_list_outcome(outstanding=1),
                ),
                "[yellow]findings[/yellow]",
                id="advisory-stale-is-not-clean",
            ),
            pytest.param(
                RunOutcome(
                    exit_code=exit_codes.SUCCESS,
                    allow_list=make_allow_list_outcome(unresolved=True),
                ),
                "[red]unresolved[/red]",
                id="advisory-unresolved-is-not-clean",
            ),
            pytest.param(
                RunOutcome(
                    exit_code=exit_codes.DEFECTS_FOUND,
                    files_changed=1,
                    allow_list=make_allow_list_outcome(unresolved=True),
                ),
                "[red]unresolved[/red]",
                id="unresolved-outranks-work-carried-out",
            ),
            pytest.param(
                RunOutcome(exit_code=exit_codes.SUCCESS, defects=3),
                "[yellow]findings[/yellow]",
                id="defects-without-a-failing-code-are-not-clean",
            ),
            pytest.param(
                RunOutcome(exit_code=exit_codes.SUCCESS, outdated=2),
                "[yellow]findings[/yellow]",
                id="advisory-outdated-actions-are-not-clean",
            ),
            pytest.param(
                RunOutcome(
                    exit_code=exit_codes.DEFECTS_FOUND, write_failures=1
                ),
                "[yellow]findings[/yellow]",
                id="a-rewrite-that-failed-is-not-clean",
            ),
            pytest.param(
                RunOutcome(exit_code=exit_codes.SUCCESS, autofix_error="boom"),
                "[yellow]findings[/yellow]",
                id="an-auto-fix-stage-that-failed-is-not-clean",
            ),
            pytest.param(
                RunOutcome(
                    exit_code=exit_codes.DEFECTS_FOUND,
                    files_changed=2,
                    write_failures=1,
                ),
                "[yellow]findings[/yellow]",
                id="a-partly-written-run-is-not-merely-updated",
            ),
            pytest.param(
                RunOutcome(
                    exit_code=exit_codes.DEFECTS_FOUND,
                    allow_list=make_allow_list_outcome(outstanding=1, fixed=1),
                ),
                "[yellow]findings[/yellow]",
                id="partial-remediation-is-not-merely-updated",
            ),
            pytest.param(
                RunOutcome(
                    exit_code=exit_codes.DEFECTS_FOUND,
                    allow_list=make_allow_list_outcome(fixed=2),
                ),
                "[yellow]updated[/yellow]",
                id="complete-remediation-is-updated",
            ),
            pytest.param(
                RunOutcome(
                    exit_code=exit_codes.DEFECTS_FOUND,
                    files_changed=1,
                    defects=2,
                ),
                "[yellow]findings[/yellow]",
                id="fixed-files-beside-remaining-defects-are-findings",
            ),
        ],
    )
    def test_status_label(self, outcome: RunOutcome, expected: str) -> None:
        """Each outcome shape gets its own label.

        Args:
            outcome: What one repository produced.
            expected: The label the summary must show.
        """
        assert _sweep_status(outcome) == expected

    def test_summary_lists_every_repository(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The closing table accounts for every repository visited.

        Args:
            tmp_path: Supplies repository paths.
            capsys: Captures the table.
        """
        _display_multi_repo_summary(
            [
                (tmp_path / "alpha", RunOutcome(exit_code=exit_codes.SUCCESS)),
                (
                    tmp_path / "beta",
                    RunOutcome(
                        exit_code=exit_codes.RUNTIME_ERROR, error="boom"
                    ),
                ),
            ],
            tmp_path,
        )

        output = " ".join(strip_ansi(capsys.readouterr().out).split())
        assert "alpha" in output
        assert "beta" in output
        assert "clean" in output
        assert "failed" in output
        assert "1 repository(s) could not be scanned" in output


class TestMultiRepoCLI:
    """The flags that reach the driver from the command line."""

    def test_multi_repo_flag_is_honoured(self, tmp_path: Path) -> None:
        """``--multi-repo`` treats PATH as a container, not a checkout.

        An empty container is the one outcome that needs no scanning at
        all, so it exercises the flag end to end without a network or a
        cache.
        """
        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(tmp_path),
                "--multi-repo",
                "--validation-method",
                "git",
            ],
        )

        output = " ".join(strip_ansi(result.stdout).split())
        assert result.exit_code == exit_codes.SUCCESS
        assert "No repositories found" in output
        assert "at depth 1" in output

    def test_short_flag_is_honoured(self, tmp_path: Path) -> None:
        """``-M`` is the same flag."""
        result = CliRunner().invoke(
            app,
            ["lint", str(tmp_path), "-M", "--validation-method", "git"],
        )

        assert result.exit_code == exit_codes.SUCCESS
        assert "No repositories found" in " ".join(
            strip_ansi(result.stdout).split()
        )

    def test_repo_depth_reaches_the_driver(self, tmp_path: Path) -> None:
        """``--repo-depth`` changes how far discovery looks."""
        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(tmp_path),
                "--multi-repo",
                "--repo-depth",
                "3",
                "--validation-method",
                "git",
            ],
        )

        assert result.exit_code == exit_codes.SUCCESS
        assert "at depth 3" in " ".join(strip_ansi(result.stdout).split())

    def test_repo_depth_is_rejected_when_negative(self, tmp_path: Path) -> None:
        """Typer rejects a negative depth before the sweep starts."""
        result = CliRunner().invoke(
            app,
            ["lint", str(tmp_path), "--multi-repo", "--repo-depth", "-1"],
        )

        assert result.exit_code == exit_codes.CLI_USAGE_ERROR

    def test_a_broken_container_dependabot_file_is_not_read(
        self, tmp_path: Path
    ) -> None:
        """The container's own cooldown is never the sweep's business.

        The command layer resolves a cooldown eagerly before dispatching.
        In a sweep that value is discarded in favour of each checkout's
        own, so reading the container's buys nothing -- and an unreadable
        one would abort the command before any per-repository failure
        boundary exists.

        Args:
            tmp_path: Container directory, carrying an unreadable
                Dependabot configuration.
        """
        make_repository(tmp_path / "one")
        github = tmp_path / ".github"
        github.mkdir()
        (github / "dependabot.yml").write_bytes(b"\xff\xfe not utf-8")

        result = CliRunner().invoke(
            app,
            [
                "lint",
                str(tmp_path),
                "--multi-repo",
                "--validation-method",
                "git",
                "--quiet",
            ],
        )

        output = strip_ansi(result.stdout + (result.stderr or ""))
        assert "UnicodeDecodeError" not in output
        assert result.exit_code == exit_codes.SUCCESS

    def test_files_is_refused_before_any_backend_preflight(
        self, tmp_path: Path
    ) -> None:
        """The usage error must not depend on reaching the sweep.

        Backend configuration runs first and makes network calls; when
        rate-limited it exits successfully. An invalid invocation would
        then retire as a success without the error ever being reported.
        Asserting no backend was configured is what pins the ordering.

        Args:
            tmp_path: Container directory.
        """
        make_repository(tmp_path / "one")
        workflow = tmp_path / "one" / "ci.yaml"
        workflow.write_text("name: t\n", encoding="utf-8")

        with mock.patch.object(cli, "_configure_validation_backend") as backend:
            result = CliRunner().invoke(
                app,
                [
                    "lint",
                    str(tmp_path),
                    "--multi-repo",
                    "--files",
                    str(workflow),
                ],
            )

        backend.assert_not_called()
        assert result.exit_code == exit_codes.RUNTIME_ERROR
        assert "--files cannot be combined with --multi-repo" in strip_ansi(
            result.stdout + (result.stderr or "")
        )

    def test_a_single_run_still_resolves_its_cooldown(
        self, tmp_path: Path
    ) -> None:
        """The guard against skipping the resolution for everyone.

        Only a sweep discards the eagerly resolved value. A single run
        depends on it, and nothing else in the suite covers the command
        layer's wiring of it.

        Args:
            tmp_path: The repository being linted.
        """
        make_repository(tmp_path)
        write_dependabot_cooldown(tmp_path, 5)
        seen: list[int] = []

        def capture(config: Config, _options: CLIOptions) -> int:
            """Record the cooldown the command layer resolved.

            Args:
                config: Configuration the command built.
                _options: Unused.

            Returns:
                A successful exit code.
            """
            seen.append(config.cooldown_days)
            return exit_codes.SUCCESS

        with mock.patch.object(cli, "run_linter", capture):
            CliRunner().invoke(
                app,
                [
                    "lint",
                    str(tmp_path),
                    "--validation-method",
                    "git",
                    "--quiet",
                ],
            )

        assert seen == [5]

    def test_a_sweep_defers_the_cooldown_to_each_repository(
        self, tmp_path: Path
    ) -> None:
        """The container's value never reaches the template config.

        Args:
            tmp_path: Container directory, carrying its own cooldown.
        """
        make_repository(tmp_path / "one")
        write_dependabot_cooldown(tmp_path, 5)
        seen: list[int] = []

        def capture(config: Config, _options: CLIOptions) -> int:
            """Record the cooldown the command layer resolved.

            Args:
                config: Configuration the command built.
                _options: Unused.

            Returns:
                A successful exit code.
            """
            seen.append(config.cooldown_days)
            return exit_codes.SUCCESS

        with mock.patch.object(cli, "run_linter", capture):
            CliRunner().invoke(
                app,
                [
                    "lint",
                    str(tmp_path),
                    "--multi-repo",
                    "--validation-method",
                    "git",
                    "--quiet",
                ],
            )

        assert seen == [0]

    def test_repo_depth_survives_the_bare_invocation(self) -> None:
        """``--repo-depth`` consumes its value when ``lint`` is implied.

        The preprocessor scans for the first positional token to decide
        whether a subcommand was given. If ``--repo-depth`` were missing
        from its set of value-taking options, a value that happens to
        spell a subcommand would be mistaken for one and ``lint`` would
        never be injected.
        """
        assert _preprocess_args_for_default_command(
            ["--repo-depth", "2", "src/", "--multi-repo"]
        ) == ["lint", "--repo-depth", "2", "src/", "--multi-repo"]
        assert _preprocess_args_for_default_command(
            ["--repo-depth", "lint", "src/"]
        ) == ["lint", "--repo-depth", "lint", "src/"]


class TestPerRepositoryOrgResolution:
    """Which organisation each checkout resolves shorthand pins against.

    ``GITHUB_REPOSITORY_OWNER`` names the repository a workflow was
    launched for. Under Actions that is a sound answer for a single run
    and a wrong one for every repository of a sweep bar one, so the
    sweep clears it and each checkout falls back to its own remotes.
    """

    def test_the_environment_org_is_cleared_per_repository(
        self, tmp_path: Path
    ) -> None:
        """Every visit is told not to trust the environment.

        Args:
            tmp_path: Container directory.
        """
        make_container(tmp_path, "one", "two")
        recorder = RecordingRun()

        with mock.patch.object(cli, "_run_one_repository", recorder):
            _run_multi_repo(make_config(tmp_path), make_options(tmp_path))

        assert [
            visit.config.allow_list.use_environment_org
            for visit in recorder.visits
        ] == [False, False]

    def test_a_single_run_still_trusts_the_environment(self) -> None:
        """The default is unchanged outside a sweep.

        This is the guard against clearing the flag globally, which
        would break the single-repository case the variable exists for.
        """
        assert Config().allow_list.use_environment_org is True

    def test_the_root_repository_shortcut_keeps_the_environment(
        self, tmp_path: Path
    ) -> None:
        """Pointing --multi-repo at a checkout is a single run.

        The flag is documented as safe to leave in a wrapper script, so
        it must not quietly cost that checkout the environment source.
        Under Actions a checkout often has no useful remote, and
        ``GITHUB_REPOSITORY_OWNER`` describes exactly this repository.

        Args:
            tmp_path: A directory that is itself a repository.
        """
        repository = make_repository(tmp_path / "solo")
        recorder = RecordingRun()

        with mock.patch.object(cli, "_run_one_repository", recorder):
            _run_multi_repo(make_config(tmp_path), make_options(repository))

        assert [visit.options.path for visit in recorder.visits] == [repository]
        assert recorder.visits[0].config.allow_list.use_environment_org is True

    def test_an_explicitly_disabled_environment_stays_disabled(
        self, tmp_path: Path
    ) -> None:
        """The shortcut restores the configured value, not ``True``.

        A configuration that turns the environment source off is
        honoured by an ordinary single-repository run, so adding
        ``--multi-repo`` in a wrapper script must not quietly turn it
        back on.

        Args:
            tmp_path: A directory that is itself a repository.
        """
        repository = make_repository(tmp_path / "solo")
        config = make_config(tmp_path)
        config.allow_list.use_environment_org = False
        recorder = RecordingRun()

        with mock.patch.object(cli, "_run_one_repository", recorder):
            _run_multi_repo(config, make_options(repository))

        assert recorder.visits[0].config.allow_list.use_environment_org is False


class TestSweepRejectsIndividualFiles:
    """``--files`` and ``--multi-repo`` ask for different things.

    The scanner honours an absolute ``--files`` path whatever root it is
    given, so a sweep would scan -- and under ``--update-allow-list``
    rewrite -- the same file once per repository, attributing it to each
    in turn. Refused rather than given an arbitrary meaning.
    """

    def test_the_combination_is_refused(self, tmp_path: Path) -> None:
        """A sweep with named files stops before visiting anything.

        Args:
            tmp_path: Container directory.
        """
        make_container(tmp_path, "one")
        options = make_options(tmp_path).model_copy(
            update={"files": ["/tmp/elsewhere/.github/workflows/ci.yaml"]}
        )
        recorder = RecordingRun()

        with (
            mock.patch.object(cli, "_run_one_repository", recorder),
            pytest.raises(ConfigurationError, match="--files"),
        ):
            _run_multi_repo(make_config(tmp_path), options)

        assert recorder.visits == []

    def test_a_sweep_without_files_still_runs(self, tmp_path: Path) -> None:
        """The guard is specific to ``--files`` being supplied.

        Args:
            tmp_path: Container directory.
        """
        make_container(tmp_path, "one")
        recorder = RecordingRun()

        with mock.patch.object(cli, "_run_one_repository", recorder):
            code = _run_multi_repo(
                make_config(tmp_path), make_options(tmp_path)
            )

        assert code == exit_codes.SUCCESS
        assert len(recorder.visits) == 1


class TestSilentFailures:
    """A failure with nothing to say is still a failure.

    Every consumer of ``RunOutcome.error`` tests it for truth: the
    summary's failure count, the ``failed`` label and the JSON
    document's ``error`` field. An exception carrying no message would
    otherwise be read as no failure at all, and the repository would be
    reported as having mere findings.
    """

    def test_an_empty_message_still_records_a_failure(
        self, tmp_path: Path
    ) -> None:
        """The exception class stands in for the missing message.

        Args:
            tmp_path: Container directory.
        """
        repository = make_repository(tmp_path / "one")
        recorder = RecordingRun({"one": RuntimeError()})

        with mock.patch.object(cli, "_run_one_repository", recorder):
            outcome = _run_repository_in_sweep(
                make_config(tmp_path),
                make_options(tmp_path),
                ValidationCache(make_config(tmp_path).cache),
                repository,
                silent=True,
            )

        assert outcome.error == "RuntimeError"
        assert _sweep_status(outcome) == "[red]failed[/red]"

    def test_a_message_is_preferred_when_there_is_one(
        self, tmp_path: Path
    ) -> None:
        """The fallback must not displace a real description.

        Args:
            tmp_path: Container directory.
        """
        repository = make_repository(tmp_path / "one")
        recorder = RecordingRun({"one": RuntimeError("disk went away")})

        with mock.patch.object(cli, "_run_one_repository", recorder):
            outcome = _run_repository_in_sweep(
                make_config(tmp_path),
                make_options(tmp_path),
                ValidationCache(make_config(tmp_path).cache),
                repository,
                silent=True,
            )

        assert outcome.error == "disk went away"

    def test_a_broken_dependabot_file_costs_only_its_repository(
        self, tmp_path: Path
    ) -> None:
        """Preparation must sit inside the failure boundary.

        Resolving the cooldown reads the repository's own
        ``dependabot.yml``, and a file that is not valid UTF-8 raises
        past the resolver's narrow handling. Outside the boundary that
        would abort the sweep, contradicting the promise that one bad
        checkout costs only itself.

        Args:
            tmp_path: Container directory.
        """
        make_container(tmp_path, "broken", "healthy")
        github = tmp_path / "broken" / ".github"
        github.mkdir()
        (github / "dependabot.yml").write_bytes(b"\xff\xfe not utf-8")
        recorder = RecordingRun()

        with mock.patch.object(cli, "_run_one_repository", recorder):
            code = _run_multi_repo(
                make_config(tmp_path), make_options(tmp_path)
            )

        # The healthy repository was still visited, and the broken one
        # was recorded rather than allowed to stop the sweep.
        assert [visit.options.path.name for visit in recorder.visits] == [
            "healthy"
        ]
        assert code == exit_codes.RUNTIME_ERROR

    def test_the_reason_reaches_the_console_too(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The user sees the same description the outcome carries.

        A fallback that reached only the outcome would leave the live
        line reading ``failed:`` with nothing after it.

        Args:
            tmp_path: Container directory.
            capsys: Captures the live failure line.
        """
        repository = make_repository(tmp_path / "one")
        recorder = RecordingRun({"one": RuntimeError()})

        with mock.patch.object(cli, "_run_one_repository", recorder):
            _run_repository_in_sweep(
                make_config(tmp_path),
                make_options(tmp_path, quiet=False),
                ValidationCache(make_config(tmp_path).cache),
                repository,
                silent=False,
            )

        output = " ".join(strip_ansi(capsys.readouterr().out).split())
        assert "failed: RuntimeError" in output


class TestSweepJsonOutput:
    """``--multi-repo --format json`` must stay machine-readable.

    Printing each repository's payload as it completed would put several
    top-level objects on standard output, which no JSON parser accepts,
    and the sweep's own commentary would sit among them. Every test here
    drives the sweep with ``quiet=False``, so the only thing that can be
    keeping standard output clean is the JSON mode itself.
    """

    @staticmethod
    def json_options(container: Path) -> CLIOptions:
        """Build options for a talkative sweep in JSON mode.

        Args:
            container: Path the sweep treats as a container.

        Returns:
            Options with JSON output and console commentary enabled.
        """
        return CLIOptions(
            path=container,
            multi_repo=True,
            quiet=False,
            output_format="json",
        )

    def test_sweep_emits_one_parseable_document(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Two repositories yield one document, not two.

        Args:
            tmp_path: Container directory.
            capsys: Captures standard output.
        """
        make_container(tmp_path, "alpha", "beta")
        recorder = RecordingRun()

        with mock.patch.object(cli, "_run_one_repository", recorder):
            _run_multi_repo(make_config(tmp_path), self.json_options(tmp_path))

        document = json.loads(capsys.readouterr().out)
        assert [entry["repository"] for entry in document["repositories"]] == [
            "alpha",
            "beta",
        ]
        assert document["summary"]["repositories"] == 2

    def test_each_repository_payload_is_carried_through(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A repository's own results reach the aggregate document.

        Args:
            tmp_path: Container directory.
            capsys: Captures standard output.
        """
        make_container(tmp_path, "alpha")

        def with_payload(
            _config: Config,
            _options: CLIOptions,
            _cache: ValidationCache,
            *,
            collect_json: bool = False,
        ) -> RunOutcome:
            """Answer with a payload, as a collecting run would.

            Args:
                _config: Unused.
                _options: Unused.
                _cache: Unused.
                collect_json: Recorded on the payload, so the test can
                    show the driver asked for collection.

            Returns:
                An outcome carrying a JSON payload.
            """
            return RunOutcome(
                exit_code=exit_codes.SUCCESS,
                json_payload={"collected": collect_json},
            )

        with mock.patch.object(cli, "_run_one_repository", with_payload):
            _run_multi_repo(make_config(tmp_path), self.json_options(tmp_path))

        document = json.loads(capsys.readouterr().out)
        assert document["repositories"][0]["results"] == {"collected": True}

    def test_otherwise_invisible_failures_are_named(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A non-zero code must have something in the document to explain it.

        Neither a failed rewrite nor a failed auto-fix stage produces a
        validation error, so a consumer reading only ``results`` would
        find nothing at all.

        Args:
            tmp_path: Container directory.
            capsys: Captures standard output.
        """
        make_container(tmp_path, "alpha")

        def with_failures(
            _config: Config,
            _options: CLIOptions,
            _cache: ValidationCache,
            *,
            collect_json: bool = False,  # noqa: ARG001 - matches the driver
        ) -> RunOutcome:
            """Answer with a run that failed invisibly.

            Args:
                _config: Unused.
                _options: Unused.
                _cache: Unused.
                collect_json: Unused.

            Returns:
                An outcome carrying both invisible failure kinds.
            """
            return RunOutcome(
                exit_code=exit_codes.DEFECTS_FOUND,
                write_failures=2,
                autofix_error="resolution exploded",
                json_payload={},
            )

        with mock.patch.object(cli, "_run_one_repository", with_failures):
            _run_multi_repo(make_config(tmp_path), self.json_options(tmp_path))

        entry = json.loads(capsys.readouterr().out)["repositories"][0]
        assert entry["write_failures"] == 2
        assert entry["autofix_error"] == "resolution exploded"

    def test_a_failure_is_named_in_the_document(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A repository that could not be scanned is reported as such.

        Args:
            tmp_path: Container directory.
            capsys: Captures standard output.
        """
        make_container(tmp_path, "alpha", "beta")
        recorder = RecordingRun({"beta": RuntimeError("boom")})

        with mock.patch.object(cli, "_run_one_repository", recorder):
            _run_multi_repo(make_config(tmp_path), self.json_options(tmp_path))

        document = json.loads(capsys.readouterr().out)
        errors = {
            entry["repository"]: entry["error"]
            for entry in document["repositories"]
        }
        assert errors == {"alpha": None, "beta": "boom"}
        assert document["summary"]["failed"] == 1

    def test_an_empty_sweep_still_emits_a_document(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Finding nothing is a result, not an absence of output.

        A consumer cannot otherwise tell an empty container from a run
        that crashed before printing.

        Args:
            tmp_path: Empty container directory.
            capsys: Captures standard output.
        """
        code = _run_multi_repo(
            make_config(tmp_path), self.json_options(tmp_path)
        )

        document = json.loads(capsys.readouterr().out)
        assert code == exit_codes.SUCCESS
        assert document["repositories"] == []
        assert document["summary"] == {
            "repositories": 0,
            "failed": 0,
            "exit_code": exit_codes.SUCCESS,
        }

    def test_the_summary_table_is_not_printed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The closing table would corrupt the document.

        Args:
            tmp_path: Container directory.
            capsys: Captures standard output.
        """
        make_container(tmp_path, "alpha")
        recorder = RecordingRun()

        with mock.patch.object(cli, "_run_one_repository", recorder):
            _run_multi_repo(make_config(tmp_path), self.json_options(tmp_path))

        output = capsys.readouterr().out
        assert "Repository Summary" not in output
        assert "Scanning 1 repositories" not in output

    def test_a_real_run_does_not_corrupt_the_document(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Drives the real per-repository run, not a stand-in.

        Every other test in this class replaces ``_run_one_repository``,
        so none of them can see what an actual repository prints. A real
        run opens a Rich progress display and reports "No workflows
        found to validate" on standard output, both of which would sit
        inside the aggregate document.

        Repositories with no workflows are used deliberately: they reach
        that message by the shortest path and need no network.

        Args:
            tmp_path: Container directory.
            capsys: Captures standard output.
        """
        make_container(tmp_path, "one", "two")
        # quiet=False is the point: the sweep must impose its own
        # silence rather than inherit it from the caller.
        options = CLIOptions(
            path=tmp_path,
            multi_repo=True,
            quiet=False,
            output_format="json",
        )

        code = _run_multi_repo(make_config(tmp_path), options)

        document = json.loads(strip_ansi(capsys.readouterr().out))
        assert code == exit_codes.SUCCESS
        assert [entry["repository"] for entry in document["repositories"]] == [
            "one",
            "two",
        ]

    def test_the_sweep_imposes_silence_on_each_repository(
        self, tmp_path: Path
    ) -> None:
        """The effective silence reaches each repository's own options.

        Args:
            tmp_path: Container directory.
        """
        make_container(tmp_path, "one")
        recorder = RecordingRun()

        with mock.patch.object(cli, "_run_one_repository", recorder):
            _run_multi_repo(make_config(tmp_path), self.json_options(tmp_path))

        assert recorder.visits[0].options.quiet is True

    def test_a_talkative_text_sweep_stays_talkative(
        self, tmp_path: Path
    ) -> None:
        """Silence is not imposed when nothing asked for it.

        This is the guard against quieting every sweep, which would cost
        the text mode its per-repository output.

        Args:
            tmp_path: Container directory.
        """
        make_container(tmp_path, "one")
        recorder = RecordingRun()
        options = make_options(tmp_path, quiet=False)

        with mock.patch.object(cli, "_run_one_repository", recorder):
            _run_multi_repo(make_config(tmp_path), options)

        assert recorder.visits[0].options.quiet is False


class TestSweepSummaryLabels:
    """How the closing table names each repository."""

    def test_grouped_repositories_stay_distinguishable(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Two repositories sharing a basename get separate rows.

        ``--repo-depth 2`` supports grouped layouts, where rendering the
        basename alone would print the same label twice and leave a
        finding unattributable.

        Args:
            tmp_path: Container directory.
            capsys: Captures the table.
        """
        _display_multi_repo_summary(
            [
                (
                    tmp_path / "group-a" / "service",
                    RunOutcome(exit_code=exit_codes.SUCCESS),
                ),
                (
                    tmp_path / "group-b" / "service",
                    RunOutcome(exit_code=exit_codes.SUCCESS),
                ),
            ],
            tmp_path,
        )

        output = " ".join(strip_ansi(capsys.readouterr().out).split())
        assert "group-a/service" in output
        assert "group-b/service" in output

    def test_the_root_repository_shortcut_keeps_its_basename(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Relative-to-itself would render as a bare dot.

        Args:
            tmp_path: The repository, which is also the sweep root.
            capsys: Captures the table.
        """
        repository = make_repository(tmp_path / "solo")

        _display_multi_repo_summary(
            [(repository, RunOutcome(exit_code=exit_codes.SUCCESS))],
            repository,
        )

        output = " ".join(strip_ansi(capsys.readouterr().out).split())
        assert "solo" in output

    def test_a_relative_root_repository_still_has_a_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``Path(".")`` has an empty basename.

        A caller may name a repository by a relative path, and a blank
        label would lose the attribution the helper exists to provide.

        Args:
            tmp_path: The repository, entered so ``.`` denotes it.
            monkeypatch: Changes the working directory.
        """
        repository = make_repository(tmp_path / "solo")
        monkeypatch.chdir(repository)

        assert cli._repository_label(Path("."), Path(".")) == "solo"

    def test_a_filesystem_root_checkout_still_has_a_label(self) -> None:
        """The last resort is the path itself, never an empty string."""
        assert cli._repository_label(Path("/"), Path("/")) == "/"

    def test_the_live_heading_also_distinguishes_grouped_repositories(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The heading printed per repository must attribute too.

        The closing table and the live commentary name the same thing,
        so a layout the table can distinguish must not collapse in the
        running output.

        Args:
            tmp_path: Container directory.
            capsys: Captures the headings.
        """
        make_repository(tmp_path / "group-a" / "service")
        make_repository(tmp_path / "group-b" / "service")
        options = make_options(tmp_path, quiet=False).model_copy(
            update={"repo_depth": 2}
        )
        recorder = RecordingRun()

        with mock.patch.object(cli, "_run_one_repository", recorder):
            _run_multi_repo(make_config(tmp_path), options)

        output = " ".join(strip_ansi(capsys.readouterr().out).split())
        # Anchored on the heading marker. The closing table names the
        # same repositories, so an unanchored assertion passes on the
        # table alone and says nothing about the heading.
        assert "\u2500\u2500 group-a/service" in output
        assert "\u2500\u2500 group-b/service" in output


class TestUnreadableRoot:
    """A sweep that examined nothing must not report success.

    ``find_repositories`` raises when the root itself cannot be listed,
    and the driver has to turn that into a runtime error rather than
    taking the empty-container path, which exits zero. Skipping an
    unreadable *descendant* stays right: the rest of the sweep is still
    worth doing.
    """

    def test_an_unreadable_root_is_a_runtime_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Exit code, not a successful empty sweep.

        Args:
            tmp_path: Container directory.
            monkeypatch: Replaces discovery with an unreadable root.
        """
        monkeypatch.setattr(
            cli,
            "find_repositories",
            mock.Mock(side_effect=PermissionError("Permission denied")),
        )

        code = _run_multi_repo(make_config(tmp_path), make_options(tmp_path))

        assert code == exit_codes.RUNTIME_ERROR

    def test_an_empty_container_still_succeeds(self, tmp_path: Path) -> None:
        """The guard against failing every empty sweep.

        Args:
            tmp_path: An empty, readable container.
        """
        code = _run_multi_repo(make_config(tmp_path), make_options(tmp_path))

        assert code == exit_codes.SUCCESS
