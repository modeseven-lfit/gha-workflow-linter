# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Pre-flight reports a rate limit; it does not act on one.

``check_rate_limit_and_exit_if_needed`` used to call ``sys.exit(0)`` on
discovering the GitHub API had throttled the client. The process ended
inside the API client: before the command dispatched, before any output
contract was met, and before the validation that sits after pre-flight
could run. A ``--format json`` run therefore emitted *no document at
all* while exiting successfully, which a consumer cannot tell from a
crash, and an unreadable path went unreported.

These tests pin the three things that replaced it:

* the client returns the status and terminates nothing;
* the run still scans, still emits its document, and marks that document
  ``rate_limited`` so a consumer can tell "checks skipped" from "checks
  found nothing";
* a run that *asked* a question with ``--verify-*`` gets
  :data:`~gha_workflow_linter.exit_codes.RATE_LIMITED` rather than a
  success it did not earn.

Every assertion is paired with its inverse. A guard that reported a rate
limit unconditionally, or that read a failed check as a limit, or that
failed every verifying run, would satisfy the positive cases while being
useless or actively wrong -- so each has a case that must go the other
way.
"""

from __future__ import annotations

import json
from pathlib import Path
import time
from typing import TYPE_CHECKING, Any
from unittest import mock

import pytest
from typer.testing import CliRunner

from gha_workflow_linter import exit_codes
from gha_workflow_linter.cli import (
    RunOutcome,
    _apply_cli_overrides,
    _AutoFixOutcome,
    _configure_validation_backend,
    _determine_exit_code,
    _sweep_status,
    _ValidationOutcome,
    app,
    run_linter,
)
from gha_workflow_linter.github_api import GitHubGraphQLClient
from gha_workflow_linter.models import (
    CacheConfig,
    CLIOptions,
    Config,
    GitHubAPIConfig,
    GitHubRateLimitInfo,
    ValidationMethod,
)
from gha_workflow_linter.validator import ActionCallValidator

if TYPE_CHECKING:
    from collections.abc import Iterator


#: A workflow with one pinned call, so a scan finds something to report
#: and an empty ``errors`` list means "nothing observed" rather than
#: "nothing to observe".
WORKFLOW = """---
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000 # v4.0.0
"""


def _repository(root: Path) -> Path:
    """Write a minimal repository with one workflow.

    The ``.git`` directory is what sweep discovery recognises, so the
    same helper serves both single-repository and sweep tests.

    Args:
        root: Directory to populate.

    Returns:
        The repository root, for passing to ``--path``.
    """
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    (workflows / "ci.yaml").write_text(WORKFLOW)
    (root / ".git").mkdir(exist_ok=True)
    return root


def _config(tmp_path: Path) -> Config:
    """Build a configuration with a private cache.

    A shared cache would let one test's entries decide another's result.

    Args:
        tmp_path: Directory to hold the cache.

    Returns:
        A configuration safe to mutate.
    """
    return Config(
        github_api=GitHubAPIConfig(token=None),
        cache=CacheConfig(enabled=False, cache_dir=tmp_path / "cache"),
    )


def _options(path: Path, **kwargs: Any) -> CLIOptions:
    """Build CLI options rooted at ``path``.

    Args:
        path: Repository or container to scan.
        kwargs: Overrides applied on top.

    Returns:
        The resolved options.
    """
    base: dict[str, Any] = {"path": path, "quiet": True}
    base.update(kwargs)
    return CLIOptions(**base)


@pytest.fixture
def rate_limit_response() -> Iterator[Any]:
    """Patch ``httpx.Client`` so the pre-flight request is answered here.

    ``check_rate_limit`` imports httpx inside the function and opens a
    client as a context manager, so the double must honour both.

    Yields:
        A callable taking the payload and status code to answer with,
        returning the mock response for further assertions.
    """
    with mock.patch("httpx.Client") as client_class:
        session = client_class.return_value.__enter__.return_value

        def answer(payload: Any, status_code: int = 200) -> mock.Mock:
            """Configure the response the pre-flight request receives.

            Args:
                payload: Decoded JSON body, or an exception to raise.
                status_code: HTTP status to report.

            Returns:
                The configured response mock.
            """
            response = mock.Mock()
            response.status_code = status_code
            if isinstance(payload, Exception):
                session.get.side_effect = payload
            else:
                response.json.return_value = payload
                session.get.return_value = response
            return response

        yield answer


def _limits(remaining: int, core: int | None = None) -> dict[str, Any]:
    """Build a ``/rate_limit`` body reporting ``remaining`` requests.

    The reset is placed in the future, because a budget of one is only a
    limit while the window is still open.

    Args:
        remaining: GraphQL requests the API says are left.
        core: REST requests left, when the case needs to say. Omitted
            entirely by default, so the tests also cover a response that
            does not mention the resource.

    Returns:
        A body shaped like the GitHub REST response.
    """
    reset = int(time.time()) + 3600
    resources: dict[str, Any] = {
        "graphql": {
            "limit": 5000,
            "remaining": remaining,
            "reset": reset,
            "used": 5000 - remaining,
        }
    }
    if core is not None:
        resources["core"] = {
            "limit": 5000,
            "remaining": core,
            "reset": reset,
            "used": 5000 - core,
        }
    return {"resources": resources}


class TestCheckRateLimitReports:
    """The client answers the question; it does not end the process."""

    def test_an_exhausted_budget_is_a_rate_limit(
        self, rate_limit_response: Any
    ) -> None:
        """Zero remaining requests reports ``True``."""
        rate_limit_response(_limits(0))
        client = GitHubGraphQLClient(GitHubAPIConfig(token=None))

        assert client.check_rate_limit() is True

    def test_a_healthy_budget_is_not(self, rate_limit_response: Any) -> None:
        """The inverse: a guard reporting ``True`` always would fail here."""
        rate_limit_response(_limits(5000))
        client = GitHubGraphQLClient(GitHubAPIConfig(token=None))

        assert client.check_rate_limit() is False

    def test_pre_flight_never_terminates_the_process(
        self, rate_limit_response: Any
    ) -> None:
        """The defect itself: discovering a limit must not exit.

        Written as an explicit ``SystemExit`` guard rather than relying on
        the return value, because the original code exited *instead of*
        returning and would pass no assertion about its result.
        """
        rate_limit_response(_limits(0))
        client = GitHubGraphQLClient(GitHubAPIConfig(token=None))

        # Bound before the attempt rather than only inside it. Proving
        # the handler cannot fall through needs ``pytest.fail`` to
        # resolve as ``NoReturn``, and the type checker runs without the
        # project environment, so pytest is unresolved there and the
        # binding has to hold without it.
        limited: bool | None = None
        try:
            limited = client.check_rate_limit()
        except SystemExit as exit_call:  # pragma: no cover - regression guard
            pytest.fail(
                f"pre-flight exited the process with {exit_call.code} instead "
                f"of reporting the rate limit to its caller"
            )

        assert limited is True

    def test_a_failed_check_is_not_evidence_of_a_limit(
        self, rate_limit_response: Any
    ) -> None:
        """The inverse: not looking is not the same as looking and finding.

        A transport failure here would otherwise skip every check in the
        run, and the async flow reports its own errors later anyway.
        """
        rate_limit_response(RuntimeError("connection reset"))
        client = GitHubGraphQLClient(GitHubAPIConfig(token=None))

        assert client.check_rate_limit() is False

    def test_a_refused_request_is_not_a_limit(
        self, rate_limit_response: Any
    ) -> None:
        """A non-200 answer tells us nothing about the budget."""
        rate_limit_response(_limits(0), status_code=500)
        client = GitHubGraphQLClient(GitHubAPIConfig(token=None))

        assert client.check_rate_limit() is False


class TestBudgetExhaustion:
    """The predicate every rate-limit decision rests on.

    Lives on :class:`GitHubRateLimitInfo` because it asks a question
    about that budget's own state, alongside ``percentage_used``.
    """

    def test_nothing_left_is_exhausted(self) -> None:
        assert GitHubRateLimitInfo(remaining=0).exhausted is True

    def test_a_full_budget_is_not(self) -> None:
        assert GitHubRateLimitInfo(remaining=5000).exhausted is False

    def test_a_single_request_is_exhausted_while_the_window_is_open(
        self,
    ) -> None:
        """Spending it would leave none for the work that follows."""
        budget = GitHubRateLimitInfo(
            remaining=1, reset_at=int(time.time()) + 3600
        )

        assert budget.exhausted is True

    def test_a_stale_window_says_nothing(self) -> None:
        """Past its reset, the figure describes a budget already refilled."""
        budget = GitHubRateLimitInfo(
            remaining=1, reset_at=int(time.time()) - 3600
        )

        assert budget.exhausted is False

    def test_a_stale_window_says_nothing_at_zero_either(self) -> None:
        """The rule cannot depend on how depleted the stale figure is.

        This combination was the one row of the table left untested, and
        the one that diverged: zero remaining short-circuited before the
        window was consulted, so a spent window reporting zero was called
        exhausted while the same window reporting one was called healthy.
        Two figures carrying equally stale information disagreed about
        what that staleness meant.
        """
        stale = int(time.time()) - 3600

        assert (
            GitHubRateLimitInfo(remaining=0, reset_at=stale).exhausted
            is GitHubRateLimitInfo(remaining=1, reset_at=stale).exhausted
            is False
        )

    def test_an_open_window_is_exhausted_at_zero_and_at_one(self) -> None:
        """The inverse: a live window still reports both as exhausted.

        Without this, a guard that answered ``False`` unconditionally
        would satisfy the staleness cases while disabling the check.
        """
        live = int(time.time()) + 3600

        assert (
            GitHubRateLimitInfo(remaining=0, reset_at=live).exhausted
            is GitHubRateLimitInfo(remaining=1, reset_at=live).exhausted
            is True
        )

    def test_an_unreported_reset_is_not_a_passed_window(self) -> None:
        """A reset of zero means the API said nothing about the window.

        Reading it as "already passed" would turn a spent budget into a
        healthy one, which is the wrong direction for an answer that
        decides whether any API work runs.
        """
        assert GitHubRateLimitInfo(remaining=0, reset_at=0).exhausted is True

    def test_an_unreported_budget_defaults_to_healthy(self) -> None:
        """The defaults must describe ignorance, not exhaustion.

        ``check_rate_limit`` builds one of these per resource straight
        from the API response, so a resource the response omits arrives
        here as defaults. Reading those as spent would stop the tool
        working against any instance that does not report them.
        """
        assert GitHubRateLimitInfo().exhausted is False


class TestBothBudgets:
    """GraphQL and REST are counted separately and spent separately.

    Validation goes through GraphQL, but the auto-fixer and the reference
    resolver reach ``api.github.com/repos`` directly. Reading only the
    GraphQL budget therefore answered a question the run had not asked.
    """

    def test_an_exhausted_rest_budget_is_a_rate_limit(
        self, rate_limit_response: Any
    ) -> None:
        """The fixer cannot work, so the run must not claim it looked.

        A throttled REST call is swallowed, no latest version is found,
        and nothing is reported as outdated -- so ``--verify-actions``
        exited ``0`` having checked nothing. That is the defect this
        whole change exists to prevent, arriving through the other
        budget.
        """
        rate_limit_response(_limits(5000, core=0))
        client = GitHubGraphQLClient(GitHubAPIConfig(token=None))

        assert client.check_rate_limit() is True

    def test_a_healthy_rest_budget_is_not(
        self, rate_limit_response: Any
    ) -> None:
        """The inverse: reporting a limit on every response is no use."""
        rate_limit_response(_limits(5000, core=5000))
        client = GitHubGraphQLClient(GitHubAPIConfig(token=None))

        assert client.check_rate_limit() is False

    def test_an_exhausted_graphql_budget_still_counts(
        self, rate_limit_response: Any
    ) -> None:
        """Neither budget masks the other."""
        rate_limit_response(_limits(0, core=5000))
        client = GitHubGraphQLClient(GitHubAPIConfig(token=None))

        assert client.check_rate_limit() is True

    def test_an_unreported_budget_is_not_exhaustion(
        self, rate_limit_response: Any
    ) -> None:
        """Silence about a resource says nothing about it.

        A response omitting ``core`` -- an older or self-hosted instance,
        say -- must not read as zero remaining, or the tool would refuse
        to do anything at all against it.
        """
        rate_limit_response(_limits(5000))
        client = GitHubGraphQLClient(GitHubAPIConfig(token=None))

        assert client.check_rate_limit() is False


class TestStatusReachesTheCommand:
    """Pre-flight's answer has to travel, or nothing can act on it."""

    def test_a_rate_limited_backend_is_reported_upwards(
        self, tmp_path: Path
    ) -> None:
        config = _config(tmp_path)
        config.validation_method = ValidationMethod.GITHUB_API

        with mock.patch.object(
            GitHubGraphQLClient, "check_rate_limit", return_value=True
        ):
            limited = _configure_validation_backend(
                config, _options(tmp_path), None, None
            )

        assert limited is True

    def test_a_healthy_backend_is_not(self, tmp_path: Path) -> None:
        """The inverse: the common case must not claim a limit."""
        config = _config(tmp_path)
        config.validation_method = ValidationMethod.GITHUB_API

        with mock.patch.object(
            GitHubGraphQLClient, "check_rate_limit", return_value=False
        ):
            limited = _configure_validation_backend(
                config, _options(tmp_path), None, None
            )

        assert limited is False

    def test_the_git_backend_is_never_pre_flighted(
        self, tmp_path: Path
    ) -> None:
        """Git validation makes no API request, so it has no budget."""
        config = _config(tmp_path)
        config.validation_method = ValidationMethod.GIT

        with mock.patch.object(
            GitHubGraphQLClient, "check_rate_limit"
        ) as check:
            limited = _configure_validation_backend(
                config, _options(tmp_path), None, None
            )

        assert limited is False
        check.assert_not_called()


def _exit_code(
    options: CLIOptions,
    *,
    rate_limited: bool,
    config: Config | None = None,
    autofix: _AutoFixOutcome | None = None,
) -> int:
    """Decide the exit code for an otherwise clean run.

    The CLI options are translated onto the configuration with the real
    ``_apply_cli_overrides``, because that translation is part of what is
    under test: ``--verify-allow-list`` reaches the decision as
    ``config.allow_list.verify``, and a configuration file can set the
    same value with no flag at all.

    Args:
        options: Resolved CLI options.
        rate_limited: Whether pre-flight found the API throttled.
        config: Configuration to start from, for cases a flag cannot
            express.
        autofix: Outcome of the auto-fix stage, when the case needs one.

    Returns:
        The code the run would exit with.
    """
    resolved = config or Config()
    _apply_cli_overrides(resolved, options, None)
    return _determine_exit_code(
        options,
        _ValidationOutcome({}, [], ActionCallValidator(Config()), 0),
        autofix
        or _AutoFixOutcome(
            {}, {"actions_moved": 0, "calls_updated": 0}, {}, [], None
        ),
        resolved,
        None,
        rate_limited=rate_limited,
    )


class TestRateLimitedExitCode:
    """Who asked a question decides whether silence is an answer."""

    def test_an_advisory_run_still_succeeds(self, tmp_path: Path) -> None:
        """The inverse, and the important one.

        A throttle at GitHub must not break every build in the estate.
        A guard returning ``RATE_LIMITED`` unconditionally fails here.
        """
        code = _exit_code(_options(tmp_path), rate_limited=True)

        assert code == exit_codes.SUCCESS

    @pytest.mark.parametrize("flag", ["verify_actions", "verify_allow_list"])
    def test_a_verifying_run_reports_that_it_could_not_look(
        self, tmp_path: Path, flag: str
    ) -> None:
        """ "Could not look" is not an answer to "is this current?".

        Args:
            tmp_path: Repository root.
            flag: The ``--verify-*`` option under test.
        """
        code = _exit_code(_options(tmp_path, **{flag: True}), rate_limited=True)

        assert code == exit_codes.RATE_LIMITED

    @pytest.mark.parametrize(
        "setting",
        ["update_actions", "allow_list.verify", "allow_list.update"],
    )
    def test_a_configured_demand_counts_as_much_as_a_flag(
        self, tmp_path: Path, setting: str
    ) -> None:
        """A configuration file may ask without any CLI flag being passed.

        ``_apply_cli_overrides`` deliberately lets a configured ``True``
        stand when the flag is absent, so ``config`` holds the effective
        value and reading ``options`` alone would let a configured
        verifying run report a success it never earned. Updating counts
        too: a rate-limited run performs no rewrites, and this function
        already refuses to call an update that did nothing a success.

        Args:
            tmp_path: Repository root.
            setting: Dotted path of the configuration flag under test.
        """
        config = Config()
        target: Any = config
        *parents, leaf = setting.split(".")
        for parent in parents:
            target = getattr(target, parent)
        setattr(target, leaf, True)

        assert (
            _exit_code(_options(tmp_path), rate_limited=True, config=config)
            == exit_codes.RATE_LIMITED
        )

    def test_a_run_that_demanded_nothing_is_unaffected(
        self, tmp_path: Path
    ) -> None:
        """The inverse: the default configuration asks the API nothing.

        Args:
            tmp_path: Repository root.
        """
        assert (
            _exit_code(_options(tmp_path), rate_limited=True)
            == exit_codes.SUCCESS
        )

    @pytest.mark.parametrize(
        ("disabled", "setting"),
        [
            ("allow_list.enabled", "allow_list.verify"),
            ("allow_list.enabled", "allow_list.update"),
            ("auto_fix", "update_actions"),
        ],
    )
    def test_a_demand_whose_stage_is_off_asks_nothing(
        self, tmp_path: Path, disabled: str, setting: str
    ) -> None:
        """A throttle must not fail work that would not have run anyway.

        ``--no-allow-list --verify-allow-list`` succeeds when the API is
        healthy, because the stage that would have found something never
        runs. Rate limiting must not turn that inert combination into a
        failure: nothing was skipped that would otherwise have happened.

        Args:
            tmp_path: Repository root.
            disabled: Dotted path of the stage switch to turn off.
            setting: Dotted path of the demand it would have answered.
        """
        config = Config()
        for path, value in ((setting, True), (disabled, False)):
            target: Any = config
            *parents, leaf = path.split(".")
            for parent in parents:
                target = getattr(target, parent)
            setattr(target, leaf, value)

        assert (
            _exit_code(_options(tmp_path), rate_limited=True, config=config)
            == exit_codes.SUCCESS
        )

    def test_verifying_actions_needs_the_fixer_too(
        self, tmp_path: Path
    ) -> None:
        """``--verify-actions`` is answered by the fixer's detection.

        With auto-fix off nothing detects an outdated call, so the flag
        can produce no finding and asks the API nothing.

        Args:
            tmp_path: Repository root.
        """
        config = Config()
        config.auto_fix = False

        assert (
            _exit_code(
                _options(tmp_path, verify_actions=True),
                rate_limited=True,
                config=config,
            )
            == exit_codes.SUCCESS
        )

    @pytest.mark.parametrize("flag", ["verify_actions", "verify_allow_list"])
    def test_a_verifying_run_that_did_look_is_unaffected(
        self, tmp_path: Path, flag: str
    ) -> None:
        """The inverse: enforcement still passes when the checks ran.

        Args:
            tmp_path: Repository root.
            flag: The ``--verify-*`` option under test.
        """
        code = _exit_code(
            _options(tmp_path, **{flag: True}), rate_limited=False
        )

        assert code == exit_codes.SUCCESS

    def test_it_outranks_the_findings_of_a_run_that_did_look(
        self, tmp_path: Path
    ) -> None:
        """A rate-limited run must not report a finding as its reason.

        The code is appended rather than returned early, so the
        precedence table stays the single authority. This shows the
        table is what decides, not the order the conditions are tested
        in.

        Args:
            tmp_path: Repository root.
        """
        options = _options(tmp_path, verify_actions=True)
        code = _exit_code(
            options,
            rate_limited=True,
            autofix=_AutoFixOutcome(
                {},
                {"actions_moved": 0, "calls_updated": 0},
                {},
                [Path(".github/workflows/ci.yaml")],
                None,
            ),
        )

        assert code == exit_codes.RATE_LIMITED


class TestOutputContract:
    """The document is owed whatever the API said."""

    def test_a_rate_limited_run_still_emits_a_document(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The defect verbatim: this used to print nothing at all.

        Args:
            tmp_path: Repository root.
            capsys: Captures standard output.
        """
        options = _options(_repository(tmp_path), output_format="json")

        code = run_linter(_config(tmp_path), options, rate_limited=True)

        document = json.loads(capsys.readouterr().out)
        assert code == exit_codes.SUCCESS
        assert document["rate_limited"] is True

    def test_a_normal_run_says_so_explicitly(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        no_repository_redirect: None,
    ) -> None:
        """The inverse, and the reason the key is never omitted.

        A consumer inferring this from absence could not tell a
        rate-limited document from one produced by an older version.

        Args:
            tmp_path: Repository root.
            capsys: Captures standard output.
        """
        options = _options(_repository(tmp_path), output_format="json")

        with mock.patch.object(
            ActionCallValidator, "validate_action_calls", return_value=[]
        ):
            run_linter(_config(tmp_path), options)

        document = json.loads(capsys.readouterr().out)
        assert document["rate_limited"] is False

    def test_the_marker_is_what_separates_the_two_documents(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        no_repository_redirect: None,
    ) -> None:
        """Both runs report zero errors; only the marker distinguishes them.

        This is the acceptance criterion stated as an assertion: without
        the key the two documents are byte-identical, so "checks skipped"
        and "checks found nothing" are indistinguishable.

        Args:
            tmp_path: Repository root.
            capsys: Captures standard output.
        """
        options = _options(_repository(tmp_path), output_format="json")

        run_linter(_config(tmp_path), options, rate_limited=True)
        skipped = json.loads(capsys.readouterr().out)

        with mock.patch.object(
            ActionCallValidator, "validate_action_calls", return_value=[]
        ):
            run_linter(_config(tmp_path), options)
        clean = json.loads(capsys.readouterr().out)

        assert skipped["errors"] == clean["errors"] == []
        assert skipped["rate_limited"] != clean["rate_limited"]

    def test_a_verifying_run_reports_six_and_a_document(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The exit code changes; the obligation to report does not.

        Args:
            tmp_path: Repository root.
            capsys: Captures standard output.
        """
        options = _options(
            _repository(tmp_path), output_format="json", verify_actions=True
        )

        code = run_linter(_config(tmp_path), options, rate_limited=True)

        document = json.loads(capsys.readouterr().out)
        assert code == exit_codes.RATE_LIMITED
        assert document["rate_limited"] is True

    def test_the_scan_still_runs(self, tmp_path: Path) -> None:
        """Validation after pre-flight must still report its failures.

        An unreadable path exited ``0`` before, because the process was
        gone before the scanner ran. Reordering pre-flight would not have
        fixed this; not exiting does.

        Args:
            tmp_path: Repository root.
        """
        options = _options(_repository(tmp_path), output_format="json")

        with mock.patch(
            "gha_workflow_linter.cli.WorkflowScanner.scan_directory",
            side_effect=PermissionError("Permission denied"),
        ):
            code = run_linter(_config(tmp_path), options, rate_limited=True)

        assert code == exit_codes.RUNTIME_ERROR

    def test_a_repository_with_no_action_calls_still_reports(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Finding no calls is a clean result a rate-limited run cannot claim.

        The scan short-circuits on an empty result, which is right for a
        run that looked. A rate-limited one has to reach its document and
        its exit-code decision regardless, so the check for it comes
        first.

        Args:
            tmp_path: Repository root.
            capsys: Captures standard output.
        """
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yaml").write_text(
            "---\nname: CI\non: [push]\njobs:\n  a:\n"
            "    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
        )
        options = _options(tmp_path, output_format="json", verify_actions=True)

        code = run_linter(_config(tmp_path), options, rate_limited=True)

        document = json.loads(capsys.readouterr().out)
        assert code == exit_codes.RATE_LIMITED
        assert document["rate_limited"] is True


class TestSkippedApiStages:
    """ "Skipping checks" has to mean not making the requests.

    Auto-fix resolves versions through the API and the allow-list check
    resolves hosts through it. Left running against an API pre-flight has
    already found throttled, they would issue exactly the requests the
    skip promised to avoid, and would turn a throttle into rewrite
    failures and unresolved hosts -- findings about an estate the run
    never managed to examine.
    """

    def test_the_fixer_does_not_run(self, tmp_path: Path) -> None:
        """Auto-fix is on by default, so this is the common case.

        Args:
            tmp_path: Repository root.
        """
        options = _options(_repository(tmp_path), output_format="json")

        with mock.patch("gha_workflow_linter.cli._run_auto_fix_stage") as stage:
            run_linter(_config(tmp_path), options, rate_limited=True)

        stage.assert_not_called()

    def test_the_allow_list_check_does_not_run(self, tmp_path: Path) -> None:
        """Enabled by default too, and it resolves hosts over GraphQL.

        Args:
            tmp_path: Repository root.
        """
        options = _options(_repository(tmp_path), output_format="json")

        with mock.patch(
            "gha_workflow_linter.cli._run_allow_list_stage"
        ) as stage:
            run_linter(_config(tmp_path), options, rate_limited=True)

        stage.assert_not_called()

    def test_both_run_when_the_api_is_available(self, tmp_path: Path) -> None:
        """The inverse: skipping everything always would be no tool at all.

        Args:
            tmp_path: Repository root.
        """
        options = _options(_repository(tmp_path), output_format="json")

        with (
            mock.patch.object(
                ActionCallValidator, "validate_action_calls", return_value=[]
            ),
            mock.patch(
                "gha_workflow_linter.cli._run_auto_fix_stage"
            ) as autofix,
            mock.patch(
                "gha_workflow_linter.cli._run_allow_list_stage"
            ) as allow_list,
        ):
            autofix.return_value = _AutoFixOutcome(
                {}, {"actions_moved": 0, "calls_updated": 0}, {}
            )
            allow_list.return_value = None
            run_linter(_config(tmp_path), options)

        autofix.assert_called_once()
        allow_list.assert_called_once()


class TestSweepOutputContract:
    """A sweep owes the same document, and says so once for the estate."""

    def test_the_sweep_document_is_marked(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A weekly sweep must tell a clean estate from an unexamined one.

        Args:
            tmp_path: Container directory.
            capsys: Captures standard output.
        """
        _repository(tmp_path / "alpha")
        options = _options(tmp_path, output_format="json", multi_repo=True)

        code = run_linter(_config(tmp_path), options, rate_limited=True)

        document = json.loads(capsys.readouterr().out)
        assert code == exit_codes.SUCCESS
        assert document["summary"]["rate_limited"] is True
        assert document["repositories"][0]["results"]["rate_limited"] is True

    def test_an_unexamined_empty_sweep_is_still_marked(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A sweep with no repositories has no payload to carry the fact.

        Hoisting the marker into ``summary`` is what makes this case
        expressible at all.

        Args:
            tmp_path: Empty container directory.
            capsys: Captures standard output.
        """
        options = _options(tmp_path, output_format="json", multi_repo=True)

        run_linter(_config(tmp_path), options, rate_limited=True)

        document = json.loads(capsys.readouterr().out)
        assert document["repositories"] == []
        assert document["summary"]["rate_limited"] is True

    def test_an_unexamined_empty_sweep_answers_a_demand(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Finding no repositories is a clean result it did not establish.

        The empty sweep has no per-repository outcomes to aggregate, so
        its code comes from the run's own state instead. Without that it
        would report success while the equivalent single repository --
        one with no action calls -- reports ``RATE_LIMITED``.

        Args:
            tmp_path: Empty container directory.
            capsys: Captures standard output.
        """
        options = _options(
            tmp_path,
            output_format="json",
            multi_repo=True,
            verify_actions=True,
        )

        code = run_linter(_config(tmp_path), options, rate_limited=True)

        document = json.loads(capsys.readouterr().out)
        assert code == exit_codes.RATE_LIMITED
        # The document must never disagree with the process status.
        assert document["summary"]["exit_code"] == code

    def test_an_empty_sweep_that_demanded_nothing_succeeds(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The inverse: an advisory sweep is still allowed to find nothing.

        Args:
            tmp_path: Empty container directory.
            capsys: Captures standard output.
        """
        options = _options(tmp_path, output_format="json", multi_repo=True)

        code = run_linter(_config(tmp_path), options, rate_limited=True)

        document = json.loads(capsys.readouterr().out)
        assert code == exit_codes.SUCCESS
        assert document["summary"]["exit_code"] == code

    def test_a_healthy_sweep_says_so(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        no_repository_redirect: None,
    ) -> None:
        """The inverse: an ordinary sweep must not claim it was throttled.

        Args:
            tmp_path: Container directory.
            capsys: Captures standard output.
        """
        _repository(tmp_path / "alpha")
        options = _options(tmp_path, output_format="json", multi_repo=True)

        with mock.patch.object(
            ActionCallValidator, "validate_action_calls", return_value=[]
        ):
            run_linter(_config(tmp_path), options)

        document = json.loads(capsys.readouterr().out)
        assert document["summary"]["rate_limited"] is False
        assert document["repositories"][0]["results"]["rate_limited"] is False


class TestTextOutput:
    """The reader is owed the same distinction the JSON consumer gets."""

    def test_it_does_not_claim_the_calls_are_valid(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The text-mode twin of the byte-identical JSON document.

        Zero validation errors renders as "All action calls are valid",
        which a run that checked none of them never established.

        Args:
            tmp_path: Repository root.
            capsys: Captures standard output.
        """
        options = _options(_repository(tmp_path), quiet=False)

        run_linter(_config(tmp_path), options, rate_limited=True)

        output = capsys.readouterr().out
        assert "All action calls are valid" not in output
        assert "rate-limited" in output.lower()

    def test_a_healthy_run_still_reports_success(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        no_repository_redirect: None,
    ) -> None:
        """The inverse: a clean run must still say so.

        Args:
            tmp_path: Repository root.
            capsys: Captures standard output.
        """
        options = _options(_repository(tmp_path), quiet=False)

        with mock.patch.object(
            ActionCallValidator, "validate_action_calls", return_value=[]
        ):
            run_linter(_config(tmp_path), options)

        assert "All action calls are valid" in capsys.readouterr().out


class TestSweepStatusLabel:
    """A row of zeros must not read as a row of findings, or as clean."""

    def test_a_rate_limited_repository_has_its_own_label(self) -> None:
        """``findings`` would tell the reader the opposite of the truth.

        The counts are empty because nothing was checked, not because
        nothing was wrong -- the same argument that gives ``unresolved``
        its own label.
        """
        status = _sweep_status(
            RunOutcome(exit_code=exit_codes.RATE_LIMITED, rate_limited=True)
        )

        assert "rate-limited" in status
        assert "findings" not in status

    def test_an_advisory_rate_limited_repository_is_not_clean(self) -> None:
        """The label cannot be read off the exit code.

        An advisory run reports ``SUCCESS`` by design, so deriving the
        label from the code marked every throttled repository of an
        advisory sweep ``clean`` -- the sweep-wide version of claiming
        all action calls are valid.
        """
        status = _sweep_status(
            RunOutcome(exit_code=exit_codes.SUCCESS, rate_limited=True)
        )

        assert "rate-limited" in status
        assert "clean" not in status

    def test_an_ordinary_finding_is_unaffected(self) -> None:
        """The inverse: a real finding still reads as one."""
        status = _sweep_status(
            RunOutcome(exit_code=exit_codes.DEFECTS_FOUND, defects=1)
        )

        assert "findings" in status

    def test_a_clean_repository_is_still_clean(self) -> None:
        """The inverse: labelling everything rate-limited would be useless."""
        status = _sweep_status(RunOutcome(exit_code=exit_codes.SUCCESS))

        assert "clean" in status


class TestAdvisorySweepSummary:
    """The sweep table is the only signal a sweep's reader gets.

    Per-repository output is silenced during a sweep, so a wrong label
    here is not merely untidy: it is the whole report.
    """

    def test_an_advisory_throttled_sweep_is_not_reported_clean(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Exit code ``0`` is correct; "clean" is not.

        Args:
            tmp_path: Container directory.
            capsys: Captures standard output.
        """
        _repository(tmp_path / "alpha")
        options = _options(tmp_path, multi_repo=True, quiet=False)

        code = run_linter(_config(tmp_path), options, rate_limited=True)

        output = capsys.readouterr().out
        assert code == exit_codes.SUCCESS
        assert "rate-limited" in output
        assert "clean" not in output

    def test_a_repository_with_no_calls_is_not_reported_clean_either(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Defence in depth for the status of a call-free repository.

        A throttled run reaches its outcome before the empty-scan short
        circuit, so this repository takes the ordinary path and the
        status is right for that reason alone. The short circuit still
        records the rate-limit state on its own outcome, and this holds
        the pair together: with the ordering regressed *and* that state
        dropped, the sweep displays a repository it never examined as
        ``clean``. Either one alone is survivable, which is the point of
        keeping both.

        Args:
            tmp_path: Container directory.
            capsys: Captures standard output.
        """
        repository = tmp_path / "alpha"
        workflows = repository / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yaml").write_text(
            "---\nname: CI\non: [push]\njobs:\n  a:\n"
            "    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
        )
        (repository / ".git").mkdir()
        options = _options(tmp_path, multi_repo=True, quiet=False)

        run_linter(_config(tmp_path), options, rate_limited=True)

        output = capsys.readouterr().out
        assert "rate-limited" in output
        assert "clean" not in output


class TestCommandHandoff:
    """The two halves must be joined, not merely each correct.

    Every other test here drives ``_configure_validation_backend`` or
    ``run_linter`` directly. Both could be right while the one line
    joining them dropped the status, and the defect would return in the
    only place a user meets it. These tests cross that boundary by
    invoking the real command.
    """

    def _invoke(self, repository: Path, *extra: str) -> Any:
        """Run the ``lint`` command against a throttled API.

        Args:
            repository: Repository to scan.
            extra: Further command-line arguments.

        Returns:
            The runner's result.
        """
        with mock.patch.object(
            GitHubGraphQLClient, "check_rate_limit", return_value=True
        ):
            return CliRunner().invoke(
                app,
                [
                    "lint",
                    str(repository),
                    "--format",
                    "json",
                    # Forces the GitHub API backend, which is the only
                    # one that pre-flights, and supplies the token that
                    # selection needs without reaching a keyring.
                    "--validation-method",
                    "github-api",
                    "--github-token",
                    "x" * 40,
                    "--no-cache",
                    *extra,
                ],
            )

    def test_the_command_carries_the_status_into_the_run(
        self, tmp_path: Path
    ) -> None:
        """Dropping the keyword would pass every other test in this file.

        Args:
            tmp_path: Repository root.
        """
        result = self._invoke(_repository(tmp_path))

        document = json.loads(result.stdout)
        assert result.exit_code == exit_codes.SUCCESS
        assert document["rate_limited"] is True

    def test_a_verifying_command_exits_six(self, tmp_path: Path) -> None:
        """The exit code has to survive the same handoff.

        Args:
            tmp_path: Repository root.
        """
        result = self._invoke(_repository(tmp_path), "--verify-actions")

        document = json.loads(result.stdout)
        assert result.exit_code == exit_codes.RATE_LIMITED
        assert document["rate_limited"] is True

    def test_a_healthy_command_reports_nothing_of_the_kind(
        self, tmp_path: Path
    ) -> None:
        """The inverse: an unthrottled command must not claim a limit.

        Args:
            tmp_path: Repository root.
        """
        with (
            mock.patch.object(
                GitHubGraphQLClient, "check_rate_limit", return_value=False
            ),
            mock.patch.object(
                ActionCallValidator, "validate_action_calls", return_value=[]
            ),
        ):
            result = CliRunner().invoke(
                app,
                [
                    "lint",
                    str(_repository(tmp_path)),
                    "--format",
                    "json",
                    "--validation-method",
                    "github-api",
                    # Neither stage is what this asserts, and both reach
                    # the API on a healthy run: the fixer resolves
                    # versions, the allow-list check resolves its host.
                    "--no-auto-fix",
                    "--no-allow-list",
                    "--github-token",
                    "x" * 40,
                    "--no-cache",
                ],
            )

        assert json.loads(result.stdout)["rate_limited"] is False
