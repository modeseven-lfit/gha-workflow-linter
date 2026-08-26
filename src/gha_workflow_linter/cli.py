# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Command-line interface for gha-workflow-linter."""

# aislop-ignore-file complexity/file-too-large -- The Typer entry points and
# their orchestration helpers are addressed by module-symbol name in ~165
# test mock-patch sites (mock.patch("gha_workflow_linter.cli.<symbol>") for
# ConfigManager, WorkflowScanner, ActionCallValidator, ValidationCache,
# console, Progress and the run_linter/output helpers). Splitting this module
# would relocate those symbols and break every patch site, a disproportionate
# change for a style-level size warning. Long/complex functions here have been
# decomposed into helpers instead.

from __future__ import annotations

import asyncio
from collections import defaultdict
import dataclasses
from dataclasses import dataclass, field
import json
import logging
from pathlib import Path
import textwrap
from typing import Any

from rich.logging import RichHandler
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.table import Table
import typer

from . import __version__, exit_codes
from .allow_list_check import AllowListChecker, AllowListOutcome
from .allow_list_fix import AppliedFix
from .allow_list_fix import apply_fixes as apply_allow_list_fixes
from .allow_list_report import (
    build_json as build_allow_list_json,
)
from .allow_list_report import (
    render_text as render_allow_list,
)
from .auto_fix import AutoFixer
from .cache import CachePrimeReport, ValidationCache
from .config import ConfigManager
from .console import console, err_console
from .dependabot import resolve_cooldown
from .exceptions import (
    AuthenticationError,
    ConfigurationError,
    GitHubAPIError,
    GitUnreachableError,
    GitUnusableError,
    NetworkError,
    RateLimitError,
    TemporaryAPIError,
    ValidationAbortedError,
)
from .github_auth import get_github_token_with_fallback
from .models import (
    ActionCall,
    CLIOptions,
    Config,
    LogLevel,
    ValidationError,
    ValidationMethod,
    ValidationResult,
)
from .multi_repo import find_repositories, is_repository
from .scanner import WorkflowScanner
from .system_utils import get_default_workers
from .utils import has_test_comment
from .validator import ActionCallValidator


def _get_relative_path(file_path: Path, base_path: Path) -> Path:
    """
    Safely compute relative path from base_path to file_path.

    Args:
        file_path: The file path to make relative
        base_path: The base path to compute relative to

    Returns:
        Relative path if possible, otherwise the original file_path
    """
    try:
        return file_path.relative_to(base_path)
    except ValueError:
        # If relative path can't be computed, use the original path
        return file_path


def _resolve_cooldown_days(
    explicit: int | None,
    scan_path: Path,
    quiet: bool,
    output_format: str,
) -> int:
    """Resolve the action-update cooldown window in days.

    Precedence:
        1. An explicit ``--cooldown`` CLI value.
        2. The repository's Dependabot ``cooldown.default-days`` setting.
        3. ``0`` (cooldown disabled; original behaviour).

    When the value is sourced from the Dependabot configuration a single
    informational line is emitted (unless suppressed by quiet/JSON mode).

    Args:
        explicit: The value passed via ``--cooldown`` (``None`` if unset).
        scan_path: Path being linted; used to locate the Dependabot config.
        quiet: Whether quiet mode is active.
        output_format: The selected output format (``text`` or ``json``).

    Returns:
        The resolved cooldown window in days.
    """
    if explicit is not None:
        return explicit

    cooldown = resolve_cooldown(scan_path)
    if cooldown is None:
        return 0

    if not quiet and output_format != "json":
        # ``markup=False`` keeps the literal square brackets visible in the
        # terminal instead of having Rich parse them as style tags. Emoji
        # shortcodes are still rendered because emoji handling is a
        # separate Rich option.
        console.print(
            f"Using cooldown timer/value [{cooldown.days}] from "
            "dependabot configuration :robot_face:",
            markup=False,
        )
    return cooldown.days


def help_callback(ctx: typer.Context, _param: Any, value: bool) -> None:
    """Show help with version information."""
    if not value or ctx.resilient_parsing:
        return
    _print_version()
    console.print()
    console.print(ctx.get_help())
    raise typer.Exit()


def main_app_help_callback(
    ctx: typer.Context, _param: Any, value: bool
) -> None:
    """Show main app help with version information."""
    if not value or ctx.resilient_parsing:
        return
    _print_version()
    console.print()
    console.print(ctx.get_help())
    raise typer.Exit()


def cache_help_callback(ctx: typer.Context, _param: Any, value: bool) -> None:
    """Show cache command help with version information."""
    if not value or ctx.resilient_parsing:
        return
    _print_version()
    console.print()
    console.print(ctx.get_help())
    raise typer.Exit()


def _print_version() -> None:
    """Print version string with consistent formatting."""
    # Keep version output formatting consistent across CLI help and callbacks.
    console.print(f"gha-workflow-linter version {__version__} 🏷️")


def _render_cache_prime_banners(
    prime_report: CachePrimeReport, *, quiet: bool = False
) -> None:
    """Render any user-facing banners surfaced by ``ValidationCache.prime()``.

    Centralizes the banner-printing logic so that any code path that
    primes a cache (the lint flow, the standalone cache subcommand,
    future entry points) renders identical output. Emoji follow the
    project convention (trailing) for consistent terminal spacing.

    Args:
        prime_report: The report returned by
            ``ValidationCache.prime()``. The function silently no-ops
            when this is not a real ``CachePrimeReport`` (test suites
            occasionally mock ``ValidationCache`` entirely, in which
            case the return is a ``Mock``).
        quiet: When True, suppress all output.
    """
    # isinstance guards the runtime case documented above: tests may pass a
    # Mock in place of a real CachePrimeReport. Static types never see that,
    # so basedpyright's "unnecessary" verdict is a false positive here.
    if quiet or not isinstance(prime_report, CachePrimeReport):  # pyright: ignore[reportUnnecessaryIsInstance]
        return
    if prime_report.version_mismatch_purged:
        console.print(
            "[cyan]Cache version mismatch; "
            "purging cache to ensure consistency ♻️[/cyan]"
        )
    if prime_report.suspicious_patterns_purged:
        reasons = ", ".join(prime_report.suspicious_reasons) or "unknown"
        console.print(
            "[yellow]Suspicious cache patterns detected "
            f"({reasons}); purging cache ♻️[/yellow]"
        )


def version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        _print_version()
        raise typer.Exit()


def _preprocess_args_for_default_command(
    args: list[str] | None = None,
) -> list[str]:
    """
    Preprocess CLI arguments to inject 'lint' command if no subcommand is provided.

    This allows the CLI to work like other linters where you can just run:
        gha-workflow-linter /path --verbose
    instead of requiring:
        gha-workflow-linter lint /path --verbose

    Args:
        args: Arguments to preprocess. If None, uses sys.argv[1:]

    Returns:
        Preprocessed argument list
    """
    import sys

    # Use sys.argv when no args provided; otherwise copy to avoid mutation.
    args = sys.argv[1:] if args is None else list(args)

    # Known subcommands
    known_commands = {"lint", "cache"}

    # Options that consume the following token as their value when used
    # in the bare (non ``--name=value``) form. Only used to skip past
    # an option's value when scanning for the first positional; we no
    # longer need to insert ``lint`` between option pairs because we
    # always prepend.
    value_taking_options = {
        "--config",
        "-c",
        "--github-token",
        "--workers",
        "-j",
        "--exclude",
        "-e",
        "--cache-ttl",
        "--cooldown",
        "--validation-method",
        "--log-level",
        "--format",
        "-f",
        "--files",
        "--allow-list-org",
        "--repo-depth",
    }

    # No args at all: behave like the explicit `lint` subcommand.
    if not args:
        args.append("lint")
        return args

    # If --help or --version is the *only* meaningful argument, let it
    # route to the top-level app so the user sees the application banner /
    # help text. When other tokens are present we prepend ``lint`` (below)
    # and let Typer route --help/--version to the lint subcommand, where
    # it remains useful.
    has_eager = any(a in ("--help", "--version") for a in args)
    has_other_tokens = any(a not in ("--help", "--version") for a in args)
    if has_eager and not has_other_tokens:
        return args

    # Detect whether the *first non-option positional token* is a known
    # subcommand. Restricting detection to that position (rather than
    # scanning the entire argv) avoids mis-classifying values of
    # value-taking options — e.g. ``--config lint`` should not be
    # treated as 'subcommand already present', because ``lint`` there
    # is the *value* of ``--config``, not a command.
    i = 0
    first_positional: str | None = None
    while i < len(args):
        arg = args[i]
        if arg.startswith("-"):
            # ``--name=value`` carries its value in the same token, so
            # advance by 1; bare value-taking options consume the next
            # token as the value, so advance by 2.
            if (
                "=" not in arg
                and arg in value_taking_options
                and i + 1 < len(args)
            ):
                i += 2
            else:
                i += 1
            continue
        first_positional = arg
        break

    if first_positional is not None and first_positional in known_commands:
        # The user explicitly invoked a subcommand; leave argv untouched.
        return args

    # Otherwise the user is in "default lint" mode. Prepend ``lint`` so
    # every subsequent option/argument is parsed as a lint-subcommand
    # token. We must not insert ``lint`` *between* an option and its
    # positional path (e.g. ``--config foo.yml src/``) because Click /
    # Typer parse options that appear before the subcommand name as
    # *top-level* options and would error out — ``--verbose`` and
    # ``--config`` are lint-subcommand options, not app-level options.
    return ["lint", *args]


app = typer.Typer(
    name="gha-workflow-linter",
    help="GitHub Actions workflow linter for validating action and workflow calls",
    add_completion=False,
    rich_markup_mode="rich",
)


# Add custom help option to main app
@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    _help: bool = typer.Option(
        False,
        "--help",
        callback=main_app_help_callback,
        is_eager=True,
        help="Show this message and exit",
        expose_value=False,
    ),
    _version: bool = typer.Option(
        False,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
        expose_value=False,
    ),
) -> None:
    """GitHub Actions workflow linter for validating action and workflow calls"""
    # The preprocessing of args happens before this callback is invoked
    # This callback exists primarily for --help and --version handling
    pass


def run() -> None:
    """Main entry point that preprocesses arguments and runs the app."""
    import sys

    # Preprocess arguments to inject 'lint' if needed
    processed_args = _preprocess_args_for_default_command()

    sys.argv[1:] = processed_args

    # Run the app normally (it will read from sys.argv)
    app()


def setup_logging(log_level: LogLevel, quiet: bool = False) -> None:
    """
    Setup logging configuration.

    Args:
        log_level: Logging level
        quiet: Suppress all output except errors
    """
    level = logging.ERROR if quiet else getattr(logging, log_level.value)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Clear existing handlers to avoid duplicates in tests
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add our handler
    # Diagnostics belong on standard error. The JSON output modes write
    # their document to standard output, and a single log record landing
    # there would make it unparsable -- a certainty in a sweep, which
    # logs an error for every repository it survives.
    rich_handler = RichHandler(
        console=err_console,
        show_time=False,
        show_path=False,
        markup=True,
    )
    rich_handler.setLevel(level)
    rich_handler.setFormatter(logging.Formatter("%(message)s"))
    root_logger.addHandler(rich_handler)

    # Set httpx logging to WARNING to suppress verbose HTTP request logs
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("httpcore.connection").setLevel(logging.WARNING)
    logging.getLogger("httpcore.http11").setLevel(logging.WARNING)


def _apply_cli_overrides(
    config: Config, options: CLIOptions, workers: int | None
) -> None:
    """Apply CLI option overrides onto the loaded configuration."""
    logger = logging.getLogger(__name__)

    if workers is not None:
        config.parallel_workers = workers
    else:
        # Auto-detect performance cores if not specified
        config.parallel_workers = get_default_workers()
    if options.exclude is not None:
        config.exclude_patterns = options.exclude
    if not options.parallel:
        config.parallel_workers = 1
    config.require_pinned_sha = options.require_pinned_sha

    # Apply auto-fix overrides (only if explicitly provided)
    if options.auto_fix is not None:
        config.auto_fix = options.auto_fix
    if options.update_actions is not None:
        config.update_actions = options.update_actions
    if options.allow_prerelease is not None:
        config.allow_prerelease = options.allow_prerelease
    if options.two_space_comments is not None:
        config.two_space_comments = options.two_space_comments
    if options.skip_actions is not None:
        config.skip_actions = options.skip_actions
    if options.fix_test_calls is not None:
        config.fix_test_calls = options.fix_test_calls

    # Apply validation method override if specified
    if options.validation_method is not None:
        config.validation_method = options.validation_method

    if options.no_cache:
        config.cache.enabled = False
        logger.debug("Cache disabled via --no-cache")

    if options.cache_ttl is not None:
        config.cache.default_ttl_seconds = options.cache_ttl
        logger.debug(f"Cache TTL overridden to {options.cache_ttl} seconds")

    # Allow-list pin checking. Only --allow-list is tri-state; the rest are
    # opt-in switches that a config file may also enable, so a CLI False
    # must not clobber a configured True.
    if options.allow_list is not None:
        config.allow_list.enabled = options.allow_list
    if options.verify_allow_list:
        config.allow_list.verify = True
    if options.update_allow_list:
        config.allow_list.update = True
    if options.show_suppressed:
        config.allow_list.show_suppressed = True
    if options.allow_list_org is not None:
        config.allow_list.org = options.allow_list_org


def _configure_validation_backend(
    config: Config,
    options: CLIOptions,
    github_token: str | None,
    workers: int | None,
) -> bool:
    """Resolve the GitHub token, select a validation method, and pre-flight it.

    Applies the resolved method/token back onto ``config`` and prints the
    chosen backend (unless quiet/JSON). When the GitHub API backend is
    selected, this also performs the rate-limit pre-flight check.

    Returns:
        ``True`` when the API reported the client is rate-limited. The
        caller decides what that means: pre-flight reports the state and
        terminates nothing, so the command still reaches its output
        contract and the validation that follows this stage still runs.
    """
    logger = logging.getLogger(__name__)

    # Skip GitHub token operations if Git method is explicitly chosen
    effective_token = None
    if config.validation_method != ValidationMethod.GIT:
        # In JSON mode, suppress any human-readable console output from the
        # token fallback (e.g. GitHub CLI messages) so it cannot corrupt the
        # JSON stream.
        json_mode = options.output_format == "json"
        # Resolve GitHub token with CLI fallback
        effective_token = get_github_token_with_fallback(
            explicit_token=github_token or config.github_api.token,
            console=None if json_mode else console,
            quiet=options.quiet or json_mode,
        )
        if effective_token:
            config.github_api.token = effective_token

    # Determine validation method based on token availability and preference
    if not config.validation_method:
        if effective_token:
            config.validation_method = ValidationMethod.GITHUB_API
        else:
            config.validation_method = ValidationMethod.GIT
            if not options.quiet and options.output_format != "json":
                console.print(
                    "[yellow]No GitHub token available, using Git validation method ℹ️[/yellow]"
                )

    # Display validation method being used (suppress for JSON output)
    if not options.quiet and options.output_format != "json":
        if config.validation_method == ValidationMethod.GITHUB_API:
            console.print("[blue]Using validation method: [GraphQL] 🔍[/blue]")
        else:
            console.print("[blue]Using validation method: [Git/SSH] 🔍[/blue]")

        # Display number of parallel workers
        worker_source = "auto-detected" if workers is None else "configured"
        console.print(
            f"[blue]Using {config.parallel_workers} parallel worker(s) "
            f"({worker_source}) ⚙️[/blue]"
        )

    # Only check rate limits if using GitHub API
    if config.validation_method == ValidationMethod.GITHUB_API:
        from .github_api import GitHubGraphQLClient

        github_client = GitHubGraphQLClient(config.github_api)
        if github_client.check_rate_limit():
            return True
        if not effective_token and not options.quiet:
            logger.warning(
                "No GitHub token available; API requests may be rate-limited ⚠️"
            )

    return False


def _resolve_update_actions(
    update_actions: bool | None,
    auto_latest: bool | None,
    *,
    quiet: bool,
) -> bool | None:
    """Combine the canonical flag with its deprecated predecessor.

    ``--auto-latest`` was renamed to ``--update-actions`` once a second
    updatable thing (the allow-list) existed and the old name stopped
    saying which. The old spelling keeps working so scripts and CI
    configurations do not break.

    Args:
        update_actions: Value of ``--update-actions``, or None.
        auto_latest: Value of the deprecated ``--auto-latest``, or None.
        quiet: Suppress the deprecation notice.

    Returns:
        The effective value, or None when neither flag was given.
    """
    if auto_latest is None:
        return update_actions

    if not quiet:
        # stderr, never stdout: --format json must stay machine-readable.
        err_console.print(
            "[yellow]--auto-latest is deprecated; use --update-actions "
            "⚠️[/yellow]"
        )

    if update_actions is not None:
        # Both given: the canonical flag wins, so a script adding the new
        # name to an existing invocation gets what it asked for.
        return update_actions
    return auto_latest


def _reject_conflicting_verbosity(
    *,
    verbose: bool,
    quiet: bool,
    output_format: str,
    multi_repo: bool,
    path: Path | None,
) -> None:
    """Refuse ``--verbose`` with ``--quiet``, in the requested format.

    Checked before anything else, so the refusal predates the command's
    own error handling and has to report itself. In JSON mode that means
    the document, not a Rich message on the stream the document belongs
    to.

    Args:
        verbose: Whether verbose output was asked for.
        quiet: Whether quiet output was asked for.
        output_format: The format the caller asked for.
        multi_repo: Whether a sweep was requested, deciding the shape.
        path: The path the run was pointed at, if given.

    Raises:
        typer.Exit: Always, when both were given.
    """
    if not (verbose and quiet):
        return

    reason = "--verbose and --quiet cannot be used together"
    if output_format == "json":
        _emit_setup_failure(
            f"Configuration error: {reason}",
            output_format=output_format,
            multi_repo=multi_repo,
            path=path or Path.cwd(),
        )
    else:
        console.print(f"[red]Error: {reason}[/red]")
    # Arguably a usage error (code 2), but this has always exited 1 and
    # changing it would break callers; see exit_codes.RUNTIME_ERROR.
    raise typer.Exit(exit_codes.RUNTIME_ERROR)


@app.command()
def lint(
    path: Path | None = typer.Argument(
        None,
        help="Path to scan for workflows (default: current directory)",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
    config_file: Path | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Configuration file path",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    github_token: str | None = typer.Option(
        None,
        "--github-token",
        help="GitHub API token (or set GITHUB_TOKEN environment variable)",
        hide_input=True,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress all output except errors",
    ),
    log_level: LogLevel = typer.Option(
        LogLevel.INFO,
        "--log-level",
        help="Set logging level",
    ),
    output_format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format (text, json)",
    ),
    fail_on_error: bool = typer.Option(
        True,
        "--fail-on-error/--no-fail-on-error",
        help="Exit with error code if validation failures found",
    ),
    parallel: bool = typer.Option(
        True,
        "--parallel/--no-parallel",
        help="Enable parallel processing",
    ),
    workers: int | None = typer.Option(
        None,
        "--workers",
        "-j",
        help="Number of parallel workers (default: auto-detect performance cores)",
        min=1,
        max=32,
    ),
    exclude: list[str] | None = typer.Option(
        None,
        "--exclude",
        "-e",
        help="Patterns to exclude (multiples accepted)",
    ),
    require_pinned_sha: bool = typer.Option(
        True,
        "--require-pinned-sha/--no-require-pinned-sha",
        help="Require action calls to be pinned to commit SHAs (default: enabled)",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Bypass local cache and always validate against remote repositories",
    ),
    cache_ttl: int | None = typer.Option(
        None,
        "--cache-ttl",
        help="Override default cache TTL in seconds",
        min=60,  # minimum 1 minute
    ),
    validation_method: ValidationMethod | None = typer.Option(
        None,
        "--validation-method",
        help="Validation method: github-api or git (auto-detected if not specified)",
    ),
    auto_fix: bool | None = typer.Option(
        None,
        "--auto-fix/--no-auto-fix",
        help="Automatically fix broken/invalid SHA pins, versions, and branches (default: enabled unless overridden in config)",
    ),
    update_actions: bool | None = typer.Option(
        None,
        "--update-actions/--no-update-actions",
        help=(
            "When auto-fixing, update action calls to the latest release "
            "(default: disabled unless overridden in config)"
        ),
    ),
    auto_latest: bool | None = typer.Option(
        None,
        "--auto-latest/--no-auto-latest",
        help=(
            "(deprecated) Former name for --update-actions. Still "
            "honoured; will be removed in a future major release"
        ),
    ),
    allow_prerelease: bool | None = typer.Option(
        None,
        "--allow-prerelease/--no-allow-prerelease",
        help="Allow prerelease versions when finding latest versions (default: disabled unless overridden in config)",
    ),
    two_space_comments: bool | None = typer.Option(
        None,
        "--no-two-space-comments/--two-space-comments",
        help="Use two spaces before inline comments when fixing (default: enabled unless overridden in config)",
    ),
    skip_actions: bool | None = typer.Option(
        None,
        "--skip-actions/--no-skip-actions",
        help="Skip scanning action.yaml/action.yml files (default: disabled unless overridden in config, actions ARE scanned)",
    ),
    fix_test_calls: bool | None = typer.Option(
        None,
        "--fix-test-calls",
        help="Enable auto-fixing action calls with 'test' in comments (default: disabled unless overridden in config, test actions are skipped)",
    ),
    cooldown: int | None = typer.Option(
        None,
        "--cooldown",
        help=(
            "Minimum number of days an action release must have been "
            "available before updating to it. When unset, the value is "
            "read from the repository's .github/dependabot.yml cooldown "
            "setting, falling back to 0 (no cooldown)."
        ),
        min=0,
    ),
    files: list[str] | None = typer.Option(
        None,
        "--files",
        help="Specific files to scan (supports wildcards, can be specified multiple times)",
    ),
    verify_actions: bool = typer.Option(
        False,
        "--verify-actions",
        help=(
            "Treat outdated action calls as errors and exit with status 5. "
            "Without this flag outdated actions are reported but do not "
            "fail the run"
        ),
    ),
    allow_list: bool | None = typer.Option(
        None,
        "--allow-list/--no-allow-list",
        help=(
            "Detect stale harden-runner allow-list pins (default: enabled). "
            "Findings are advisory unless --verify-allow-list is given"
        ),
    ),
    verify_allow_list: bool = typer.Option(
        False,
        "--verify-allow-list",
        help=(
            "Treat stale allow-list pins as errors and exit with status 3 "
            "(or 4 if the latest release cannot be resolved)"
        ),
    ),
    update_allow_list: bool = typer.Option(
        False,
        "--update-allow-list",
        help=(
            "Rewrite stale allow-list pins in place. Pins carrying an "
            "'allow-list-pin-ok' directive are never rewritten"
        ),
    ),
    show_suppressed: bool = typer.Option(
        False,
        "--show-suppressed",
        help=(
            "Report allow-list pins silenced by an 'allow-list-pin-ok' "
            "directive. Never affects the exit code"
        ),
    ),
    allow_list_org: str | None = typer.Option(
        None,
        "--allow-list-org",
        help=(
            "Organisation used to resolve the '@<sha>' allow-list shorthand. "
            "Inferred from GITHUB_REPOSITORY_OWNER, then the 'upstream' git "
            "remote, then 'origin', when not given"
        ),
    ),
    multi_repo: bool = typer.Option(
        False,
        "--multi-repo",
        "-M",
        help=(
            "Treat PATH as a container of git repositories and visit each "
            "in turn, sharing one cache across them"
        ),
    ),
    repo_depth: int = typer.Option(
        1,
        "--repo-depth",
        help=(
            "How many levels below PATH to look for repositories when "
            "--multi-repo is given"
        ),
        min=0,
    ),
    _help: bool = typer.Option(
        False,
        "--help",
        callback=help_callback,
        is_eager=True,
        help="Show this message and exit",
    ),
) -> None:
    """
    Scan GitHub Actions workflows and action definitions for invalid action and workflow calls.

    This tool scans for .github/workflows directories and action.yaml/action.yml files,
    validating that all 'uses' statements reference valid repositories, branches, tags,
    or commit SHAs.

    Validation Methods:
        github-api: Uses GitHub GraphQL API (requires token, faster)
        git: Uses Git operations (no token required, works with SSH keys)

        If --validation-method is not specified, the tool automatically selects:
        - 'github-api' if a GitHub token is available
        - 'git' if no token is found (automatic fallback)

    Cache Options:
        --no-cache: Bypass cache and always validate against remote repositories
        --cache-ttl: Override default cache TTL (7 days) in seconds

    GitHub API Authentication (for github-api method):

        # Using environment variable (recommended)
        export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
        gha-workflow-linter lint

        # Using CLI flag
        gha-workflow-linter lint --github-token ghp_xxxxxxxxxxxxxxxxxxxx

        # Using GitHub CLI (automatic fallback)
        gh auth login
        gha-workflow-linter lint

    Git Authentication (for git method):

        # Uses your existing Git configuration, SSH keys, or ssh-agent
        # No additional setup required if you can already clone GitHub repos

    Examples:

        # Scan current directory (auto-detects validation method)
        gha-workflow-linter lint

        # Force Git validation method
        gha-workflow-linter lint --validation-method git

        # Force GitHub API method
        gha-workflow-linter lint --validation-method github-api

        # Scan specific path with custom workers
        gha-workflow-linter lint /path/to/project --workers 8

        # Use custom config and output JSON
        gha-workflow-linter lint --config config.yaml --format json

        # Verbose output with 8 workers and token
        gha-workflow-linter lint --verbose --workers 8 --github-token ghp_xxx

        # Disable SHA pinning requirement
        gha-workflow-linter lint --no-require-pinned-sha

        # Auto-fix issues without using latest versions
        gha-workflow-linter lint --auto-fix --no-update-actions

        # Auto-fix with two-space comment formatting
        gha-workflow-linter lint --auto-fix --two-space-comments

        # Enable auto-fixing for actions with 'test' in comments (default is to skip them)
        gha-workflow-linter lint --auto-fix --fix-test-calls

        # Only update to releases at least 7 days old (supply-chain cooldown)
        gha-workflow-linter lint --auto-fix --update-actions --cooldown 7

        # Scan only specific files
        gha-workflow-linter lint --files .github/workflows/ci.yml

        # Scan multiple files with wildcards
        gha-workflow-linter lint --files ".github/workflows/*.yml" --files "action.yml"

        # Auto-fix only specific files
        gha-workflow-linter lint --auto-fix --files .github/workflows/release.yml
    """
    _reject_conflicting_verbosity(
        verbose=verbose,
        quiet=quiet,
        output_format=output_format,
        multi_repo=multi_repo,
        path=path,
    )

    # JSON format implies quiet mode (suppress console output)
    if output_format == "json":
        quiet = True

    if verbose:
        log_level = LogLevel.DEBUG

    setup_logging(log_level, quiet)
    logger = logging.getLogger(__name__)

    # Force set logger level to ERROR in quiet mode as safety measure
    # (ensures AutoFixer can detect quiet mode via logger.getEffectiveLevel())
    if quiet:
        logging.getLogger("gha_workflow_linter").setLevel(logging.ERROR)

    # Set default path
    if path is None:
        path = Path.cwd()

    try:
        config_manager = ConfigManager()
        config = config_manager.load_config(config_file)

        # Refused before any backend preflight: that preflight makes
        # network calls and can exit on a rate limit, which would retire
        # an invalid invocation as a success without ever reporting it.
        _reject_files_with_multi_repo(files, multi_repo=multi_repo)

        # Override config with CLI options
        cli_options = CLIOptions(
            path=path,
            config_file=config_file,
            verbose=verbose,
            quiet=quiet,
            output_format=output_format,
            fail_on_error=fail_on_error,
            parallel=parallel,
            exclude=exclude,
            require_pinned_sha=require_pinned_sha,
            no_cache=no_cache,
            cache_ttl=cache_ttl,
            validation_method=validation_method,
            auto_fix=auto_fix,
            update_actions=_resolve_update_actions(
                update_actions, auto_latest, quiet=quiet
            ),
            allow_prerelease=allow_prerelease,
            two_space_comments=two_space_comments,
            skip_actions=skip_actions,
            fix_test_calls=fix_test_calls,
            cooldown=cooldown,
            files=files,
            verify_actions=verify_actions,
            allow_list=allow_list,
            verify_allow_list=verify_allow_list,
            update_allow_list=update_allow_list,
            show_suppressed=show_suppressed,
            allow_list_org=allow_list_org,
            multi_repo=multi_repo,
            repo_depth=repo_depth,
        )

        # Apply CLI overrides to config
        _apply_cli_overrides(config, cli_options, workers)

        # Resolve the action-update cooldown window. Precedence: explicit
        # --cooldown flag, then the repository's Dependabot configuration,
        # then 0 (no cooldown / original behaviour).
        #
        # A sweep skips this. The cooldown belongs to each checkout, and
        # ``_run_repository_in_sweep`` resolves it there from that
        # repository's own configuration, so reading the container's
        # would announce a value that is then discarded -- and an
        # unreadable one would abort the whole command before the
        # per-repository failure boundary exists.
        config.cooldown_days = (
            0
            if multi_repo
            else _resolve_cooldown_days(cooldown, path, quiet, output_format)
        )

        logger.debug(f"Starting gha-workflow-linter {__version__}")

        # Resolve token, select validation method, and pre-flight it
        rate_limited = _configure_validation_backend(
            config, cli_options, github_token, workers
        )

        # Only show scanning path if we're actually going to proceed
        logger.debug(f"Scanning path: {path}")

        exit_code = run_linter(config, cli_options, rate_limited=rate_limited)

    except typer.Exit:
        # Re-raise typer.Exit to avoid catching it as a general exception
        raise
    except ValidationAbortedError as e:
        # These errors should already be handled in run_linter, but catch here as fallback
        logger.error(f"Validation aborted: {e.message}")
        raise typer.Exit(exit_codes.RUNTIME_ERROR) from None
    except (ValueError, ConfigurationError) as e:
        logger.error(f"Configuration error: {e}")
        if verbose:
            logger.exception("Full traceback:")
        # Refused before any scanning, so nothing has been emitted yet
        # and the promised document is still owed.
        _emit_setup_failure(
            f"Configuration error: {e}",
            output_format=output_format,
            multi_repo=multi_repo,
            path=path,
        )
        raise typer.Exit(exit_codes.RUNTIME_ERROR) from None
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if verbose:
            logger.exception("Full traceback:")
        raise typer.Exit(exit_codes.RUNTIME_ERROR) from None

    raise typer.Exit(exit_code)


@app.command()
def cache(
    info: bool = typer.Option(False, "--info", help="Show cache information"),
    cleanup: bool = typer.Option(
        False, "--cleanup", help="Remove expired cache entries"
    ),
    purge: bool = typer.Option(
        False, "--purge", help="Clear all cache entries"
    ),
    config_file: Path | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Configuration file path",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    _help: bool = typer.Option(
        False,
        "--help",
        callback=cache_help_callback,
        is_eager=True,
        help="Show this message and exit",
        expose_value=False,
    ),
) -> None:
    """Manage local validation cache."""
    from .config import ConfigManager

    config_manager = ConfigManager()
    config = config_manager.load_config(config_file)

    cache_instance = ValidationCache(config.cache)
    # Prime the cache so version-mismatch / suspicious-patterns purges
    # are surfaced to the user. Without this, ``cache --info`` could
    # silently empty an incompatible cache file with no explanation.
    _render_cache_prime_banners(cache_instance.prime())

    if purge:
        removed_count = cache_instance.purge()
        console.print(f"[green]Purged {removed_count} cache entries ✅[/green]")
        return

    if cleanup:
        removed_count = cache_instance.cleanup()
        console.print(
            f"[green]Removed {removed_count} expired cache entries ✅[/green]"
        )
        return

    if info:
        cache_info = cache_instance.get_cache_info()

        table = Table(title="Cache Information")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Enabled", str(cache_info["enabled"]))
        table.add_row("Cache File", cache_info["cache_file"])
        table.add_row(
            "File Exists", str(cache_info.get("cache_file_exists", False))
        )
        table.add_row("Total Entries", str(cache_info["entries"]))

        if cache_info["entries"] > 0:
            table.add_row(
                "Expired Entries", str(cache_info.get("expired_entries", 0))
            )
            if cache_info.get("oldest_entry_age"):
                table.add_row(
                    "Oldest Entry Age",
                    f"{cache_info['oldest_entry_age']:.1f} seconds",
                )
            if cache_info.get("newest_entry_age"):
                table.add_row(
                    "Newest Entry Age",
                    f"{cache_info['newest_entry_age']:.1f} seconds",
                )

        table.add_row("Max Cache Size", str(cache_info["max_cache_size"]))
        table.add_row("TTL (seconds)", str(cache_info["ttl_seconds"]))

        console.print(table)

        # Show stats if available
        stats = cache_info["stats"]
        if stats["hits"] > 0 or stats["misses"] > 0:
            console.print()
            stats_table = Table(title="Cache Statistics")
            stats_table.add_column("Metric", style="cyan")
            stats_table.add_column("Value", style="green")

            stats_table.add_row("Cache Hits", str(stats["hits"]))
            stats_table.add_row("Cache Misses", str(stats["misses"]))
            stats_table.add_row(
                "Hit Rate", f"{cache_instance.stats.hit_rate:.1f}%"
            )
            stats_table.add_row("Cache Writes", str(stats["writes"]))
            stats_table.add_row("Purges", str(stats["purges"]))
            stats_table.add_row(
                "Cleanup Removed", str(stats["cleanup_removed"])
            )

            console.print(stats_table)
        return

    # Default: show basic cache info
    cache_info = cache_instance.get_cache_info()
    console.print(f"Cache enabled: {cache_info['enabled']}")
    console.print(f"Cache entries: {cache_info['entries']}")
    console.print(f"Cache file: {cache_info['cache_file']}")


@dataclass(frozen=True)
class _ValidationOutcome:
    """Results of scanning and validating a workflow tree."""

    workflow_calls: dict[Path, dict[int, ActionCall]]
    validation_errors: list[ValidationError]
    validator: ActionCallValidator
    total_calls: int


@dataclass(frozen=True)
class _AutoFixOutcome:
    """Files changed and statistics produced by the auto-fixer.

    Attributes:
        fixed_files: Changes applied, per file.
        redirect_stats: Repository-redirect counters.
        stale_actions_summary: Outdated calls detected but not applied.
        write_failures: Files a rewrite was planned for but could not be
            written.
        stage_error: Why the stage failed outright, or None. Failures
            here are logged and swallowed so validation results still
            reach the reader, which leaves nothing else to show that the
            requested fixing never happened.
    """

    fixed_files: dict[Path, list[dict[str, str]]]
    redirect_stats: dict[str, int]
    stale_actions_summary: dict[str, list[dict[str, Any]]]
    write_failures: list[Path] = field(default_factory=list)
    stage_error: str | None = None


@dataclass(frozen=True)
class _ScanShortCircuit:
    """A scan/validate stage that ended before producing results.

    Carries the reason as well as the code, so a caller aggregating many
    repositories can tell a repository that *failed* from one that merely
    had findings. Collapsing both to an integer made an unreadable
    checkout indistinguishable from a lint result, which is the sharper
    edge of reporting an unusable input as an absence of problems.

    Attributes:
        exit_code: What this stage alone would exit with.
        error: Why the run stopped, or ``None`` when nothing went wrong
            (there was simply nothing to validate).
    """

    exit_code: int
    error: str | None = None


def _handle_validation_aborted(
    e: ValidationAbortedError, *, suppress_console: bool = False
) -> int:
    """Print actionable guidance for an aborted validation.

    Returns the linter exit code (always 1) so callers can return it
    directly. When ``suppress_console`` is set (quiet or JSON output
    modes) only the logger is used, so stdout is not polluted and JSON
    output is not corrupted.
    """
    logger = logging.getLogger(__name__)
    logger.error(f"Validation aborted: {e.message}")

    if suppress_console:
        return 1

    # Provide specific guidance based on the error type
    # The Git backend reports an unreachable remote as a GitError
    # subclass rather than a NetworkError, because the helpers that
    # raise it are caught by type. It is the same condition, though,
    # and the advice below is exactly what it calls for.
    if isinstance(e.original_error, (NetworkError, GitUnreachableError)):
        console.print(
            "\n[yellow]❌ Network connectivity issue detected[/yellow]"
        )
        console.print("[dim]• Check your internet connection")
        console.print("[dim]• Verify DNS resolution is working")
        console.print("[dim]• Try again in a few moments[/dim]")
    elif isinstance(e.original_error, GitUnusableError):
        # Its sibling above, and just as inconclusive, but the network
        # is not what to go and look at.
        console.print("\n[yellow]❌ git could not be run[/yellow]")
        console.print("[dim]• Check that git is installed and on PATH")
        console.print(
            "[dim]• The process may have been killed: check for an "
            "out-of-memory kill or a cancelled job"
        )
        console.print("[dim]• Try again once git can run[/dim]")
    elif isinstance(e.original_error, AuthenticationError):
        console.print("\n[yellow]❌ GitHub API authentication failed[/yellow]")
        from .github_auth import get_github_cli_suggestions

        for suggestion in get_github_cli_suggestions():
            console.print(f"[dim]• {suggestion}")
        console.print("[dim]• Ensure token has 'public_repo' scope[/dim]")
    elif isinstance(e.original_error, RateLimitError):
        console.print("\n[yellow]❌ GitHub API rate limit exceeded[/yellow]")
        console.print("[dim]• Wait for rate limit to reset")
        from .github_auth import get_github_cli_suggestions

        for suggestion in get_github_cli_suggestions():
            console.print(f"[dim]• {suggestion}")
        console.print("[dim]• Try again later[/dim]")
    elif isinstance(e.original_error, (GitHubAPIError, TemporaryAPIError)):
        console.print("\n[yellow]❌ GitHub API error[/yellow]")
        console.print("[dim]• This may be a temporary GitHub service issue")
        console.print("[dim]• Try again in a few minutes")
        console.print(
            "[dim]• Check GitHub status at https://status.github.com/[/dim]"
        )
    else:
        console.print("\n[yellow]❌ Validation could not be completed[/yellow]")
        console.print(f"[dim]• {e.reason}[/dim]")

    console.print(
        "\n[red]Cannot determine if action calls are valid or invalid.[/red]"
    )
    console.print(
        "[red]Validation was not performed due to the above issue.[/red]"
    )
    return 1


def _describe_exception(error: Exception) -> str:
    """Describe a failure, even one carrying no message.

    ``str(RuntimeError())`` is empty, and every consumer of a recorded
    reason tests it for truth, so an empty description reads as no
    failure at all. The class name is a poor description but an honest
    one.

    Args:
        error: The exception to describe.

    Returns:
        The exception's message, or its class name when it has none.
    """
    return str(error) or type(error).__name__


def _emit_setup_failure(
    reason: str, *, output_format: str, multi_repo: bool, path: Path
) -> None:
    """Emit the JSON document for a run that failed before it started.

    A configuration error is refused before any scanning, so the run
    produces no results of its own -- but it has already promised a
    document, and returning without one leaves a ``--format json``
    consumer an empty stream. The shape matches whichever mode was
    requested, so the caller parses the failure with the same code it
    would have used for the results.

    Args:
        reason: Why the run was refused.
        output_format: The format the caller asked for.
        multi_repo: Whether a sweep was requested, which decides the
            document's shape.
        path: The path the run was pointed at.
    """
    if output_format != "json":
        return

    if multi_repo:
        _output_multi_repo_json(
            [], path, exit_code=exit_codes.RUNTIME_ERROR, error=reason
        )
        return

    print(
        json.dumps(
            build_json_results({}, {}, [], path, None, error=reason), indent=2
        )
    )


def _reject_files_with_multi_repo(
    files: list[str] | None, *, multi_repo: bool
) -> None:
    """Refuse ``--files`` combined with ``--multi-repo``.

    ``--files`` names individual paths, and the scanner honours an
    absolute one whatever root it is given. Combined with a sweep it
    would scan -- and under ``--update-allow-list`` rewrite -- the same
    file once per repository, attributing it to each in turn. The two
    options ask for different things, so the combination is refused
    rather than given an arbitrary meaning.

    Called from the command before any backend preflight, since that
    preflight makes network calls and can exit on a rate limit, which
    would retire an invalid invocation as a success. Called again from
    the sweep itself, which a library caller can reach directly.

    Args:
        files: Individual paths the caller named, if any.
        multi_repo: Whether a sweep was requested.

    Raises:
        ConfigurationError: If both were given.
    """
    if multi_repo and files:
        raise ConfigurationError(
            "--files cannot be combined with --multi-repo: --files names "
            "individual paths, which a sweep would scan once per "
            "repository. Run the linter in the repository that owns "
            "those files instead."
        )


def _scan_and_validate(
    config: Config,
    options: CLIOptions,
    scanner: WorkflowScanner,
    shared_cache: ValidationCache,
    *,
    rate_limited: bool = False,
) -> _ScanShortCircuit | _ValidationOutcome:
    """Scan workflows and validate their action calls.

    Returns a :class:`_ScanShortCircuit` when the run stops early (scan
    error, nothing to validate, or aborted validation); otherwise returns
    a :class:`_ValidationOutcome` for downstream processing.
    """
    logger = logging.getLogger(__name__)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        # Progress renders to standard output, which in JSON mode
        # carries the document. run_linter normalises that mode to
        # quiet before anything runs, so this needs no separate test.
        disable=options.quiet,
    ) as progress:
        # Scan for workflows
        scan_task = progress.add_task("Scanning workflows...", total=None)

        try:
            workflow_calls = scanner.scan_directory(
                options.path, progress, scan_task, specific_files=options.files
            )
        except Exception as e:
            reason = _describe_exception(e)
            logger.error(f"Error scanning workflows: {reason}")
            return _ScanShortCircuit(1, f"Error scanning workflows: {reason}")

        if rate_limited:
            # Nothing can be validated, but the scan already succeeded,
            # so the run returns an outcome rather than short-circuiting:
            # the caller still emits its document, still reports what it
            # scanned, and still reaches the exit-code decision. Zero
            # errors here means "none observed", which is why the exit
            # code -- not this outcome -- carries the fact that nothing
            # was checked.
            #
            # This is decided before the empty-scan check below, because
            # that check reports a clean result -- a repository with
            # nothing to validate -- and a run that never looked is not
            # entitled to claim one.
            validator = ActionCallValidator(config, cache=shared_cache)
            return _ValidationOutcome(
                workflow_calls,
                [],
                validator,
                sum(len(calls) for calls in workflow_calls.values()),
            )

        if not workflow_calls:
            if not options.quiet:
                console.print("[yellow]No workflows found to validate[/yellow]")
            # Not a failure: a repository with no workflows is a valid,
            # clean result rather than one that could not be scanned.
            # The caller still owes a document, which it emits from this
            # outcome without running any stage over an empty scan.
            return _ScanShortCircuit(0)

        # Count total calls for progress tracking
        total_calls = sum(len(calls) for calls in workflow_calls.values())

        validate_task = progress.add_task(
            "Validating action calls...", total=total_calls
        )

        try:
            validator = ActionCallValidator(config, cache=shared_cache)
            validation_errors = validator.validate_action_calls(
                workflow_calls, progress, validate_task
            )
        except ValidationAbortedError as e:
            return _ScanShortCircuit(
                _handle_validation_aborted(
                    e,
                    suppress_console=options.quiet
                    or options.output_format == "json",
                ),
                # str(e) rather than e.message: the message is the
                # generic summary and the reason carries the underlying
                # failure, so reporting the message alone would drop the
                # network or authentication detail a reader needs.
                f"Validation aborted: {e}",
            )
        except Exception as e:
            reason = _describe_exception(e)
            logger.error(f"Unexpected error validating action calls: {reason}")
            return _ScanShortCircuit(
                1, f"Unexpected error validating action calls: {reason}"
            )

    return _ValidationOutcome(
        workflow_calls, validation_errors, validator, total_calls
    )


def _run_auto_fix_stage(
    config: Config,
    options: CLIOptions,
    shared_cache: ValidationCache,
    validation: _ValidationOutcome,
) -> _AutoFixOutcome:
    """Run the auto-fixer and report the resulting changes.

    Auto-fix failures are logged and swallowed so the linter can still
    report validation results.
    """
    logger = logging.getLogger(__name__)

    # Derived once and used for every display in this stage. The fixer's
    # live progress, the applied-changes listing and the failure notice
    # all write to standard output, which in JSON mode carries the
    # document -- and a programmatic caller of ``run_linter`` gets none
    # of the command layer's quiet coercion.
    silent = options.quiet or options.output_format == "json"

    fixed_files: dict[Path, list[dict[str, str]]] = {}
    redirect_stats: dict[str, int] = {"actions_moved": 0, "calls_updated": 0}
    stale_actions_summary: dict[str, list[dict[str, Any]]] = {}
    write_failures: list[Path] = []
    stage_error: str | None = None

    # Determine if we should run auto-fix:
    # - If auto_fix is enabled, fix validation errors and check for outdated
    #   versions.
    # - If update_actions is also enabled, update to latest versions.
    should_run_auto_fix = (config.auto_fix or not config.fix_test_calls) and (
        validation.validation_errors or config.auto_fix
    )
    if not should_run_auto_fix:
        return _AutoFixOutcome(
            fixed_files, redirect_stats, stale_actions_summary
        )

    try:

        async def run_auto_fix() -> tuple[
            dict[Path, list[dict[str, str]]],
            dict[str, int],
            dict[str, list[dict[str, Any]]],
            list[Path],
        ]:
            async with AutoFixer(
                config,
                base_path=options.path,
                cache=shared_cache,
                quiet=silent,
            ) as auto_fixer:
                # When auto_fix is enabled, always pass all action calls to
                # check. check_for_updates=True only when update_actions is
                # enabled (update to latest versions); False means: fix
                # validation errors, report outdated versions.
                all_calls = validation.workflow_calls if config.auto_fix else {}
                check_for_updates = config.update_actions
                result = await auto_fixer.fix_validation_errors(
                    validation.validation_errors,
                    all_calls,
                    check_for_updates=check_for_updates,
                )
                # Read inside the context: a rewrite that failed leaves
                # no trace in the returned tuple.
                return (*result, list(auto_fixer.write_failures))

        (
            fixed_files,
            redirect_stats,
            stale_actions_summary,
            write_failures,
        ) = asyncio.run(run_auto_fix())

        if fixed_files and not silent:
            _display_auto_fix_changes(fixed_files, options)

    except Exception as e:
        # Swallowed so validation results still reach the reader, but
        # recorded: with nothing applied, nothing stale and no
        # validation error, an all-empty outcome would otherwise report
        # a successful run that did no fixing at all.
        stage_error = _describe_exception(e)
        logger.warning(f"Auto-fix failed: {stage_error}")
        if not silent:
            console.print(f"[yellow]Auto-fix failed: {stage_error} ⚠️[/yellow]")

    return _AutoFixOutcome(
        fixed_files,
        redirect_stats,
        stale_actions_summary,
        write_failures,
        stage_error,
    )


def _display_auto_fix_changes(
    fixed_files: dict[Path, list[dict[str, str]]],
    options: CLIOptions,
) -> None:
    """Render skipped testing actions and applied fixes to the console."""
    # Separate skipped items from actual fixes
    files_with_fixes: dict[Path, list[dict[str, str]]] = {}
    files_with_skipped: dict[Path, list[dict[str, str]]] = {}

    for file_path, changes in fixed_files.items():
        skipped = [c for c in changes if c.get("skipped") == "true"]
        fixes = [c for c in changes if c.get("skipped") != "true"]
        if fixes:
            files_with_fixes[file_path] = fixes
        if skipped:
            files_with_skipped[file_path] = skipped

    if files_with_skipped:
        _display_skipped_testing_actions(files_with_skipped, options)
    if files_with_fixes:
        _display_applied_fixes(files_with_fixes, options)


def _display_skipped_testing_actions(
    files_with_skipped: dict[Path, list[dict[str, str]]],
    options: CLIOptions,
) -> None:
    """Render the list of testing actions that were skipped."""
    total_skipped = sum(len(v) for v in files_with_skipped.values())
    console.print(
        f"\n[cyan]Skipped {total_skipped} testing action(s) in "
        f"{len(files_with_skipped)} file(s): ⏩[/cyan]"
    )
    for file_path, changes in files_with_skipped.items():
        console.print(
            f"\n[bold]{_get_relative_path(file_path, options.path)} 📄[/bold]"
        )
        for change in changes:
            line = change["old_line"].strip()
            # Remove leading "- " if present
            if line.startswith("- "):
                line = line[2:]
            console.print(f"  ⏩ {line}")


def _display_applied_fixes(
    files_with_fixes: dict[Path, list[dict[str, str]]],
    options: CLIOptions,
) -> None:
    """Render the workflow calls that were rewritten by auto-fix."""
    total_updated = sum(len(changes) for changes in files_with_fixes.values())
    console.print(
        f"\n[yellow]Updated {total_updated} workflow call(s) in "
        f"{len(files_with_fixes)} file(s): 🔧[/yellow]"
    )
    for file_path, changes in files_with_fixes.items():
        console.print(
            f"\n[bold]{_get_relative_path(file_path, options.path)} 📄[/bold]"
        )
        for change in changes:
            console.print(f"[red]  - {change['old_line'].strip()}[/red]")
            console.print(f"[green]  + {change['new_line'].strip()}[/green]")
    console.print()  # Add blank line after changes


def _emit_results(
    options: CLIOptions,
    scanner: WorkflowScanner,
    validation: _ValidationOutcome,
    autofix: _AutoFixOutcome,
    config: Config,
    allow_list: AllowListOutcome | None = None,
    *,
    collect_json: bool = False,
    rate_limited: bool = False,
) -> dict[str, Any] | None:
    """Generate and display the scan/validation results.

    Args:
        options: Resolved CLI options.
        scanner: The scanner that produced the workflow calls.
        validation: Outcome of the scan/validate stage.
        autofix: Outcome of the auto-fix stage.
        config: Resolved configuration.
        allow_list: Outcome of the allow-list stage, when it ran.
        collect_json: Return the JSON payload instead of printing it, so
            a sweep can assemble one document from many repositories.
        rate_limited: Whether the checks were skipped because the API was
            rate-limited, recorded in the JSON document so a consumer can
            tell that from a clean run.

    Returns:
        The JSON payload when ``collect_json`` is set and the output
        format is JSON, so a caller may aggregate it; ``None``
        otherwise.
    """
    scan_summary = scanner.get_scan_summary(validation.workflow_calls)

    # Calculate unique calls for statistics
    unique_calls: set[str] = set()
    for calls in validation.workflow_calls.values():
        for call in calls.values():
            call_key = f"{call.organization}/{call.repository}@{call.reference}"
            unique_calls.add(call_key)

    validation_summary = validation.validator.get_validation_summary(
        validation.validation_errors, validation.total_calls, len(unique_calls)
    )

    if options.output_format == "json":
        if collect_json:
            # The caller is assembling one document from several
            # repositories, so hand back the payload rather than
            # printing a top-level object of our own.
            return build_json_results(
                scan_summary,
                validation_summary,
                validation.validation_errors,
                options.path,
                allow_list,
                rate_limited=rate_limited,
            )
        output_json_results(
            scan_summary,
            validation_summary,
            validation.validation_errors,
            options.path,
            allow_list,
            rate_limited=rate_limited,
        )
        return None

    output_text_results(
        scan_summary,
        validation_summary,
        validation.validation_errors,
        options.path,
        options.quiet,
        autofix.fixed_files,
        autofix.redirect_stats,
        autofix.stale_actions_summary,
        rate_limited=rate_limited,
    )
    if allow_list is not None and not options.quiet:
        # Only suggest remediation when it has not already run.
        render_allow_list(
            allow_list,
            root=options.path,
            show_suppressed=config.allow_list.show_suppressed,
            update_hint=not config.allow_list.update,
        )
    return None


#: Sentinel host key used when the allow-list stage itself fails, rather
#: than a specific host repository failing to resolve. Keeps the failure
#: visible to exit-code determination without inventing a repository name.
STAGE_FAILURE_HOST = "<allow-list check>"


def _run_allow_list_stage(
    config: Config,
    options: CLIOptions,
    shared_cache: ValidationCache,
) -> AllowListOutcome | None:
    """Detect stale harden-runner allow-list pins.

    Allow-list pins are an ``lfreleng-actions`` convention rather than
    GitHub-native syntax, so in the default advisory mode a failure here
    must never break a run that would otherwise have succeeded: the error
    is logged and the check skipped.

    Under ``allow_list.verify`` the opposite holds. The caller asked for
    enforcement, and enforcement that degrades to "pass" when the check
    cannot run is worse than useless, so the failure is reported as an
    unresolved host and becomes exit status ``ALLOW_LIST_UNRESOLVED``.

    Args:
        config: Resolved configuration.
        options: Resolved CLI options.
        shared_cache: Cache shared with validation and auto-fix.

    Returns:
        The outcome, or None when checking is disabled, or when it failed
        while running in advisory mode.
    """
    if not config.allow_list.enabled:
        return None

    logger = logging.getLogger(__name__)
    scanner = WorkflowScanner(config)

    try:
        paths = _allow_list_paths(config, options, scanner)
        checker = AllowListChecker(config, shared_cache)
        outcome = asyncio.run(checker.check(paths, options.path))
        if config.allow_list.update:
            outcome = _apply_allow_list_fixes(outcome, options)
        return outcome
    except ConfigurationError:
        # A bad setting is a usage error, not a transient failure. It
        # must surface in advisory mode too, or a typo in
        # --allow-list-org would silently disable the whole check.
        raise
    except Exception as e:  # noqa: BLE001 - advisory unless enforcing
        logger.warning(f"Allow-list check failed: {_describe_exception(e)}")
        if config.allow_list.update:
            # Updating was explicitly requested, so silently doing none
            # of it -- or part of it, if earlier files were already
            # rewritten -- must not report success. Same reasoning as
            # the action fixer's stage error.
            if not options.quiet:
                console.print(
                    f"[red]Allow-list update could not complete: "
                    f"{_describe_exception(e)} ❌[/red]"
                )
            return AllowListOutcome(
                findings=[],
                hosts={},
                unresolved={STAGE_FAILURE_HOST: _describe_exception(e)},
                suppressed_count=0,
                checked=True,
            )
        if not config.allow_list.verify:
            # Advisory mode: a developer offline on a train must still be
            # able to commit, so the check is skipped entirely.
            return None
        # Enforcement was requested. Reporting "pass" because the check
        # itself broke is worse than useless, so surface the failure as
        # an unresolved host and let the caller exit with
        # ALLOW_LIST_UNRESOLVED.
        if not options.quiet:
            console.print(
                f"[red]Allow-list verification could not run: "
                f"{_describe_exception(e)} ❌[/red]"
            )
        return AllowListOutcome(
            findings=[],
            hosts={},
            unresolved={STAGE_FAILURE_HOST: _describe_exception(e)},
            suppressed_count=0,
            checked=True,
        )


def _apply_allow_list_fixes(
    outcome: AllowListOutcome,
    options: CLIOptions,
) -> AllowListOutcome:
    """Rewrite stale pins and fold the result back into the outcome.

    Only unsuppressed findings are offered to the fixer: a suppression
    that survived detection but lost to remediation would be worse than
    none at all.

    Args:
        outcome: The outcome of the detection pass.
        options: Resolved CLI options, for reporting paths.

    Returns:
        The outcome with ``fixed_lines`` populated.
    """
    logger = logging.getLogger(__name__)
    fixes = apply_allow_list_fixes(outcome.unsuppressed)

    for finding, reason in fixes.skipped:
        logger.debug(
            f"Not rewriting {finding.pin.file_path}:"
            f"{finding.pin.line_number}: {reason}"
        )

    if not fixes.applied:
        return outcome

    if not options.quiet:
        _display_allow_list_fixes(fixes.applied, options)

    return dataclasses.replace(
        outcome,
        fixed_lines=frozenset(
            (str(fix.finding.pin.file_path), fix.line_number)
            for fix in fixes.applied
        ),
    )


def _display_allow_list_fixes(
    applied: list[AppliedFix],
    options: CLIOptions,
) -> None:
    """Report the allow-list pins that remediation rewrote.

    Args:
        applied: The fixes written to disk.
        options: Resolved CLI options, for relative paths.
    """
    console.print("\n[green]Updated allow-list pins ✅[/green]")
    by_file: dict[Path, list[AppliedFix]] = defaultdict(list)
    for fix in applied:
        by_file[fix.finding.pin.file_path].append(fix)

    for file_path in sorted(by_file):
        relative = _get_relative_path(file_path, options.path)
        console.print(f"\n  [bold]{relative}[/bold]")
        for fix in by_file[file_path]:
            pad = " " * len(str(fix.line_number))
            console.print(
                f"    line {fix.line_number}   "
                f"[red]{fix.old_line.strip()}[/red]"
            )
            console.print(
                f"    {pad}        [green]{fix.new_line.strip()}[/green]"
            )

    console.print(
        "\n[yellow]Files have been modified; please review the changes "
        "and commit them ⚠️[/yellow]"
    )


def _allow_list_paths(
    config: Config,
    options: CLIOptions,
    scanner: WorkflowScanner,
) -> list[Path]:
    """Collect the files the allow-list check should read.

    Honours ``--files`` so the check covers the same scope as validation.
    Otherwise it adds ``allow_list.extra_globs`` to the usual discovery:
    example caller workflows live outside ``.github/workflows`` and are
    not found by the standard scan, but they carry pins too.

    Args:
        config: Resolved configuration.
        options: Resolved CLI options.
        scanner: Scanner providing the standard discovery.

    Returns:
        Deduplicated file paths, in discovery order.
    """
    if options.files:
        return list(
            scanner.scan_directory(options.path, specific_files=options.files)
        )

    paths: list[Path] = list(scanner.find_workflow_files(options.path))
    seen = set(paths)
    for pattern in config.allow_list.extra_globs:
        for path in sorted(options.path.glob(pattern)):
            if path.is_file() and path not in seen:
                seen.add(path)
                paths.append(path)
    return paths


def _demanded_an_answer(options: CLIOptions, config: Config) -> bool:
    """Whether the run asked the API to verify or change something.

    An advisory run asked nothing: it wanted whatever the tool could
    tell it, and a throttled API leaves it with less to say rather than
    with a wrong answer. A run that passed a verification or update flag
    did ask, and "could not look" answers neither *is this current?* nor
    *make this current*. Both are already treated that way elsewhere in
    :func:`_determine_exit_code`, where an incomplete allow-list check
    fails a verifying run and an updating one alike.

    The allow-list settings are read from ``config`` rather than
    ``options`` because a configuration file may enable them without any
    CLI flag, and :func:`_apply_cli_overrides` deliberately lets it:
    ``config`` holds the effective value.

    Each demand is gated on the stage that would have answered it. A
    throttle must not fail work that would not have run anyway: with
    ``--no-allow-list`` the allow-list stage never runs, so
    ``--verify-allow-list`` beside it asks nothing of the API and is
    inert whether or not GitHub is throttling. The action-call settings
    depend on the fixer the same way, since it is what detects an
    outdated call and what rewrites one.

    Args:
        options: Resolved CLI options.
        config: Resolved configuration.

    Returns:
        ``True`` when reporting success would claim work the run did not
        do, or an answer it never obtained.
    """
    wanted_from_fixer = options.verify_actions or config.update_actions
    wanted_from_allow_list = (
        config.allow_list.verify or config.allow_list.update
    )
    return (config.auto_fix and wanted_from_fixer) or (
        config.allow_list.enabled and wanted_from_allow_list
    )


def _determine_exit_code(
    options: CLIOptions,
    validation: _ValidationOutcome,
    autofix: _AutoFixOutcome,
    config: Config,
    allow_list: AllowListOutcome | None = None,
    *,
    rate_limited: bool = False,
) -> int:
    """Compute the process exit code from fixes and validation errors.

    This is the single decision point for the process exit status. It is
    deliberately independent of reporting: presentation flags such as
    ``--quiet`` and ``--format json`` must never change the code a given
    repository state produces.

    Args:
        options: Resolved CLI options.
        validation: Outcome of the scan/validate stage.
        autofix: Outcome of the auto-fix stage.
        config: Resolved configuration.
        allow_list: Outcome of the allow-list stage, when it ran.
        rate_limited: Whether the API was rate-limited, so the checks a
            verifying or updating run asked for never ran. An advisory
            run asked no question and still succeeds; a run that did ask
            gets no answer from "could not look".

    Returns:
        A code from :mod:`gha_workflow_linter.exit_codes`.
    """
    codes: list[int] = []

    if rate_limited and _demanded_an_answer(options, config):
        # Appended rather than returned, so the precedence table in
        # exit_codes stays the single authority on which condition wins.
        codes.append(exit_codes.RATE_LIMITED)

    # A rewrite the caller asked for that could not be written is a
    # failure, and one that shows up nowhere else: the planned change is
    # absent from the applied fixes, and under --update-actions the call
    # was never recorded as stale either. Reporting success would tell
    # the caller the work was done.
    if autofix.write_failures:
        codes.append(exit_codes.DEFECTS_FOUND)

    # A stage that failed outright leaves even less behind. It only
    # fails the run when updating was explicitly requested, though:
    # auto-fix runs by default, and a stage that could not reach the
    # network must not stop a developer committing, exactly as the
    # allow-list check degrades in advisory mode. Asking for
    # --update-actions is asking for work to be done, so silently doing
    # none of it is a different matter.
    if autofix.stage_error and config.update_actions:
        codes.append(exit_codes.DEFECTS_FOUND)

    # Files modified on disk are reported as a failure so a CI job or a
    # pre-commit hook notices that the tree changed underneath it.
    if autofix.fixed_files:
        has_actual_fixes = any(
            change.get("skipped") != "true"
            for changes in autofix.fixed_files.values()
            for change in changes
        )
        if has_actual_fixes:
            codes.append(exit_codes.DEFECTS_FOUND)

    # Validation errors (excluding test references, which are advisory by
    # convention) count when the caller has not disabled failure.
    if options.fail_on_error:
        actual_errors = [
            e
            for e in validation.validation_errors
            if not has_test_comment(e.action_call)
        ]
        if actual_errors:
            codes.append(exit_codes.DEFECTS_FOUND)

    # Outdated action calls are a CURRENCY finding: advisory unless the
    # caller opted in with --verify-actions.
    if options.verify_actions and _has_outdated_actions(autofix):
        codes.append(exit_codes.ACTIONS_OUTDATED)

    # Allow-list findings are advisory unless --verify-allow-list is set.
    # An unresolved check outranks a stale one: enforcement that silently
    # degrades to "pass" when the network is down is worse than useless.
    if allow_list is not None:
        if allow_list.fixed_count:
            # Files changed on disk, so the caller must notice, exactly as
            # for the action-call fixer.
            codes.append(exit_codes.DEFECTS_FOUND)
        # An incomplete check fails when enforcement was requested, and
        # equally when updating was: asking for an update and silently
        # getting none of it -- or part of it, if earlier files were
        # already rewritten -- must not report success.
        if allow_list.unresolved and (
            config.allow_list.verify or config.allow_list.update
        ):
            codes.append(exit_codes.ALLOW_LIST_UNRESOLVED)
        elif config.allow_list.verify and allow_list.outstanding:
            # Anything remediation already rewrote is no longer a
            # problem, so only what remains can fail the run.
            codes.append(exit_codes.ALLOW_LIST_STALE)

    return exit_codes.combine(*codes) if codes else exit_codes.SUCCESS


def _has_outdated_actions(autofix: _AutoFixOutcome) -> bool:
    """Report whether any action call has a newer release available.

    Args:
        autofix: Outcome of the auto-fix stage.

    Returns:
        True when at least one outdated (but otherwise valid) action call
        was detected.
    """
    return any(
        items for items in autofix.stale_actions_summary.values() if items
    )


@dataclasses.dataclass(frozen=True)
class RunOutcome:
    """What one repository's run produced.

    Attributes:
        exit_code: The code this repository alone would have exited with.
        allow_list: Outcome of the allow-list stage, when it ran.
        files_changed: How many files a fixer rewrote.
        defects: Validation errors left unrepaired, excluding test
            references and anything the auto-fixer rewrote.
        outdated: Action calls with a newer release available. Advisory
            unless ``--verify-actions``, so the exit code alone cannot
            reveal them.
        write_failures: Files a rewrite was planned for but could not be
            written. Counted separately because such a file appears in
            no other tally.
        autofix_error: Why the auto-fix stage failed outright, or None.
            Recorded for the same reason: a stage that never ran leaves
            nothing else behind.
        error: Description of a failure that stopped the run, or None.
        json_payload: This repository's JSON results, present only when
            the caller asked for them to be collected rather than
            printed.
        rate_limited: Whether the API was throttled, so no check ran.
            Recorded rather than inferred from ``exit_code``: an
            advisory run reports :data:`~gha_workflow_linter.exit_codes.SUCCESS`
            by design, so the code cannot distinguish a repository that
            was examined and found clean from one that was never
            examined at all.
    """

    exit_code: int
    allow_list: AllowListOutcome | None = None
    files_changed: int = 0
    defects: int = 0
    outdated: int = 0
    write_failures: int = 0
    autofix_error: str | None = None
    error: str | None = None
    json_payload: dict[str, Any] | None = None
    rate_limited: bool = False


def run_linter(
    config: Config, options: CLIOptions, *, rate_limited: bool = False
) -> int:
    """
    Run the main linting process.

    Args:
        config: Configuration object
        options: CLI options
        rate_limited: Whether pre-flight found the GitHub API
            rate-limited. The run still scans, still reports, and still
            emits its document; it skips every stage that needs the API,
            and says so in the exit code when the caller asked for one.

    Returns:
        Exit code from :mod:`gha_workflow_linter.exit_codes`.
    """
    # Standard output carries the document in JSON mode, so every
    # presentational thing that would otherwise land there has to go
    # quiet -- cache-prime banners before it, a stale-actions summary
    # after it, allow-list notices around it. Gating each site
    # separately left the ones nobody had thought of, so the mode is
    # normalised once here instead, which is what the command layer
    # already does before calling this. A direct caller gets no such
    # coercion, and a direct caller is who parses the output.
    if options.output_format == "json" and not options.quiet:
        options = options.model_copy(update={"quiet": True})

    if options.multi_repo:
        return _run_multi_repo(config, options, rate_limited=rate_limited)

    shared_cache = ValidationCache(config.cache)
    # Eagerly load the cache and run all startup-time checks so any
    # banners render *before* opening the Rich Progress UI (printing
    # inside the progress block would interleave with the active
    # spinner and corrupt output).
    _render_cache_prime_banners(shared_cache.prime(), quiet=options.quiet)
    return _run_one_repository(
        config, options, shared_cache, rate_limited=rate_limited
    ).exit_code


def _short_circuit_document(
    scanner: WorkflowScanner,
    config: Config,
    shared_cache: ValidationCache,
    outcome: _ScanShortCircuit,
    rate_limited: bool,
) -> dict[str, Any]:
    """Build the JSON document for a run that ended before validating.

    Two situations reach here and a consumer must be able to tell them
    apart. A scan that *failed* has no counts to report and carries its
    reason in ``error``. A scan that succeeded and found nothing to
    check reports real, zero-valued summaries and no error, so its
    document has the same shape as any other clean run.

    Both previously emitted nothing at all, which left the two
    indistinguishable from each other and from a crash.

    Args:
        scanner: The scanner that ran, for its summary shape.
        config: Resolved configuration.
        shared_cache: Cache the validator would have used.
        outcome: What the scan stage returned.
        rate_limited: Whether the API was rate-limited.

    Returns:
        The document, ready to print or collect.
    """
    if outcome.error:
        return build_json_results(
            {},
            {},
            [],
            Path(),
            None,
            rate_limited=rate_limited,
            error=outcome.error,
        )

    validator = ActionCallValidator(config, cache=shared_cache)
    return build_json_results(
        scanner.get_scan_summary({}),
        validator.get_validation_summary([], 0, 0),
        [],
        Path(),
        None,
        rate_limited=rate_limited,
    )


def _run_one_repository(
    config: Config,
    options: CLIOptions,
    shared_cache: ValidationCache,
    *,
    collect_json: bool = False,
    rate_limited: bool = False,
) -> RunOutcome:
    """Scan, validate, fix and report a single repository.

    Args:
        config: Resolved configuration for this repository.
        options: Resolved CLI options, with ``path`` set to it.
        shared_cache: Cache shared with every other stage, and across
            repositories in a multi-repository run.
        collect_json: Return the JSON payload on the outcome instead of
            printing it, so a sweep can assemble one document rather
            than emitting several.
        rate_limited: Whether pre-flight found the API rate-limited. The
            scan still runs -- so an unreadable path is still reported
            rather than passing silently -- and the results still emit;
            every stage that needs the API is skipped.

    Returns:
        What the run produced, for aggregation by the caller.
    """
    scanner = WorkflowScanner(config)

    scan_result = _scan_and_validate(
        config, options, scanner, shared_cache, rate_limited=rate_limited
    )
    if isinstance(scan_result, _ScanShortCircuit):
        payload = None
        if options.output_format == "json":
            # The run promised a document whether or not it got far
            # enough to fill one in. Without this, a failed scan and a
            # repository with nothing to check both emitted an empty
            # stream, which a consumer cannot tell from a crash.
            payload = _short_circuit_document(
                scanner, config, shared_cache, scan_result, rate_limited
            )
            if not collect_json:
                print(json.dumps(payload, indent=2))
        return RunOutcome(
            exit_code=scan_result.exit_code,
            error=scan_result.error,
            json_payload=payload,
            # Recorded even though the ordering in _scan_and_validate
            # means a throttled run reaches its outcome before the
            # empty-scan short circuit, so this is not observable today.
            # An outcome that misdescribes its own run is a trap for the
            # next reader of RunOutcome.rate_limited, and it is what
            # would make a regression in that ordering show up as
            # "clean" rather than as a wrong status.
            rate_limited=rate_limited,
        )
    validation = scan_result

    if rate_limited:
        # Both remaining stages reach the GitHub API: the fixer resolves
        # versions through it, and the allow-list check resolves hosts.
        # Running them against an API that pre-flight has already found
        # throttled would issue exactly the requests "Skipping Checks"
        # promised to avoid, and would turn a throttle into rewrite
        # failures and unresolved hosts -- findings about the estate,
        # from a run that never managed to examine it.
        autofix = _AutoFixOutcome(
            {}, {"actions_moved": 0, "calls_updated": 0}, {}
        )
        allow_list = None
    else:
        autofix = _run_auto_fix_stage(config, options, shared_cache, validation)

        allow_list = _run_allow_list_stage(config, options, shared_cache)

    payload = _emit_results(
        options,
        scanner,
        validation,
        autofix,
        config,
        allow_list,
        collect_json=collect_json,
        rate_limited=rate_limited,
    )

    # Report outdated actions when auto-fix repaired validation errors but
    # version bumps were only detected, not applied. This is presentation
    # only: it must not short-circuit exit-code determination, or a real
    # defect elsewhere in the run would be masked (and the exit code would
    # depend on --quiet, which also gates this block).
    if (
        autofix.stale_actions_summary
        and not config.update_actions
        and not options.quiet
    ):
        _display_stale_actions_from_summary(
            autofix.stale_actions_summary, options
        )

    repaired = _repaired_locations(autofix)

    return RunOutcome(
        exit_code=_determine_exit_code(
            options,
            validation,
            autofix,
            config,
            allow_list,
            rate_limited=rate_limited,
        ),
        allow_list=allow_list,
        files_changed=sum(
            1
            for changes in autofix.fixed_files.values()
            if any(change.get("skipped") != "true" for change in changes)
        ),
        defects=sum(
            1
            for error in validation.validation_errors
            if not has_test_comment(error.action_call)
            and (error.file_path, error.action_call.line_number) not in repaired
        ),
        outdated=sum(
            len(items) for items in autofix.stale_actions_summary.values()
        ),
        write_failures=len(autofix.write_failures),
        autofix_error=autofix.stage_error,
        json_payload=payload,
        rate_limited=rate_limited,
    )


def _repaired_locations(autofix: _AutoFixOutcome) -> set[tuple[Path, int]]:
    """Locate the calls the auto-fixer actually rewrote.

    Used to keep a repaired call out of the outstanding-defect tally: it
    was a validation error when the run began, but it is not one the
    reader still has to deal with, and counting it as both fixed and
    outstanding reads as a contradiction.

    Skipped entries are excluded, since those record a call the fixer
    deliberately left alone.

    Args:
        autofix: Outcome of the auto-fix stage.

    Returns:
        ``(file path, line number)`` pairs that were rewritten on disk.
    """
    repaired: set[tuple[Path, int]] = set()
    for file_path, changes in autofix.fixed_files.items():
        for change in changes:
            if change.get("skipped") == "true":
                continue
            line_number = change.get("line_number")
            if line_number is None:
                continue
            try:
                repaired.add((file_path, int(line_number)))
            except ValueError:  # pragma: no cover - defensive
                continue
    return repaired


def _repository_label(repository: Path, root: Path) -> str:
    """Name a repository for the sweep's output.

    Grouped layouts put more than one ``service`` under a container, so
    the basename alone cannot attribute a finding. The path relative to
    the sweep root can, except when the two are the same -- the
    root-repository shortcut -- where it degrades to ``.``.

    That shortcut takes the basename instead, but of the *resolved*
    path: a caller may name a repository ``Path(".")``, whose basename
    is empty, and a blank label loses the attribution this exists to
    provide. A checkout at the filesystem root has no basename either,
    so the path itself is the last resort.

    Args:
        repository: The repository being described.
        root: The container the sweep was pointed at.

    Returns:
        A non-empty label distinguishing this repository from its
        siblings.
    """
    relative = str(_get_relative_path(repository, root))
    if relative != ".":
        return relative

    try:
        resolved = repository.resolve()
    except OSError:  # pragma: no cover - defensive
        resolved = repository
    return resolved.name or str(resolved)


def _discover_or_report(
    options: CLIOptions, *, json_mode: bool, rate_limited: bool
) -> list[Path] | None:
    """Find the repositories to sweep, reporting a failure as a document.

    Discovery is the one stage that can fail before the sweep has
    anything to report, and it used to return straight to the caller.
    Under ``--format json`` that meant exiting non-zero having printed
    nothing, which a consumer cannot tell from a crash.

    Args:
        options: Resolved CLI options, supplying the path and depth.
        json_mode: Whether the caller owes a JSON document.
        rate_limited: Whether pre-flight found the API rate-limited.

    Returns:
        The repositories found, or ``None`` when discovery failed and
        the reason has been reported.
    """
    logger = logging.getLogger(__name__)

    try:
        return find_repositories(options.path, depth=options.repo_depth)
    except ValueError as error:
        reason = f"Invalid repository depth: {error}"
    except OSError as error:
        # An unreadable root means nothing was examined. Reporting an
        # empty sweep would be indistinguishable from a container with
        # no repositories in it, and would exit successfully.
        reason = f"Cannot read {options.path}: {_describe_exception(error)}"

    logger.error(reason)
    if json_mode:
        _output_multi_repo_json(
            [],
            options.path,
            rate_limited=rate_limited,
            exit_code=exit_codes.RUNTIME_ERROR,
            error=reason,
        )
    return None


def _run_multi_repo(
    config: Config, options: CLIOptions, *, rate_limited: bool = False
) -> int:
    """Visit every repository beneath the given path in turn.

    Repositories are processed sequentially. The intra-repository
    parallelism already saturates the API budget, and one repository at a
    time keeps the progress output legible and attributes a failure to
    the repository that caused it.

    The cache is built once and shared, so twenty repositories pinning
    the same allow-list host cost one latest-release lookup rather than
    twenty -- under the default release policy. A cooldown or prerelease
    eligibility makes a cached answer policy-dependent, so both bypass
    the cache and each repository resolves the host for itself.
    Configuration is copied per repository, because the workflow
    organisation and the Dependabot cooldown are properties of each one.

    In JSON output mode every repository's payload is collected into a
    single document rather than printed as it goes, so standard output
    stays parseable, and the progress commentary is suppressed for the
    same reason.

    Args:
        config: Resolved configuration, used as the template per
            repository.
        options: Resolved CLI options, with ``path`` as the container.

    Returns:
        The most significant exit code across every repository.
    """
    json_mode = options.output_format == "json"

    try:
        _reject_files_with_multi_repo(options.files, multi_repo=True)
    except ConfigurationError as error:
        # The command layer refuses this combination before reaching
        # here, so only a library caller arrives with it -- and it is
        # owed the document just the same.
        _emit_setup_failure(
            f"Configuration error: {error}",
            output_format=options.output_format,
            multi_repo=True,
            path=options.path,
        )
        raise
    # Anything written to standard output would sit alongside the JSON
    # document, so the commentary goes quiet in JSON mode as well.
    silent = options.quiet or json_mode

    repositories = _discover_or_report(
        options, json_mode=json_mode, rate_limited=rate_limited
    )
    if repositories is None:
        return exit_codes.RUNTIME_ERROR

    if not repositories:
        # An empty sweep examined nothing, which is a clean result only
        # if the run had nothing to ask. Rate-limited, it did not even
        # establish that the container was empty of work it could act
        # on, so it answers as a repository with no action calls does.
        empty_code = (
            exit_codes.RATE_LIMITED
            if rate_limited and _demanded_an_answer(options, config)
            else exit_codes.SUCCESS
        )
        if json_mode:
            # An empty sweep still owes the caller a document, or a
            # consumer cannot tell it from a crash.
            _output_multi_repo_json(
                [],
                options.path,
                rate_limited=rate_limited,
                exit_code=empty_code,
            )
        elif not options.quiet:
            console.print(
                f"[yellow]No repositories found under {options.path} "
                f"at depth {options.repo_depth} ⚠️[/yellow]"
            )
        return empty_code

    shared_cache = ValidationCache(config.cache)
    _render_cache_prime_banners(shared_cache.prime(), quiet=silent)

    if not silent:
        console.print(
            f"\n[bold]Scanning {len(repositories)} repositories under "
            f"{options.path}[/bold]\n"
        )

    results: list[tuple[Path, RunOutcome]] = []
    for repository in repositories:
        results.append(
            (
                repository,
                _run_repository_in_sweep(
                    config,
                    options,
                    shared_cache,
                    repository,
                    silent=silent,
                    rate_limited=rate_limited,
                    # Pointing --multi-repo at a checkout visits that one
                    # repository, which is the case
                    # GITHUB_REPOSITORY_OWNER describes correctly, so the
                    # shortcut keeps whatever was configured. A genuine
                    # sweep forces it off regardless.
                    use_environment_org=(
                        config.allow_list.use_environment_org
                        and is_repository(options.path)
                    ),
                    label=_repository_label(repository, options.path),
                ),
            )
        )

    sweep_code = exit_codes.combine(
        *(outcome.exit_code for _, outcome in results)
    )

    if json_mode:
        _output_multi_repo_json(
            results,
            options.path,
            rate_limited=rate_limited,
            exit_code=sweep_code,
        )
    elif not options.quiet:
        _display_multi_repo_summary(results, options.path)

    return sweep_code


def _output_multi_repo_json(
    results: list[tuple[Path, RunOutcome]],
    root: Path,
    *,
    rate_limited: bool = False,
    exit_code: int = exit_codes.SUCCESS,
    error: str | None = None,
) -> None:
    """Emit one JSON document covering the whole sweep.

    Printing each repository's payload as it completed would put several
    top-level objects on standard output, which no JSON parser accepts.
    Wrapping them keeps ``--multi-repo --format json`` machine-readable.

    Args:
        results: Per-repository outcomes, in visit order.
        root: The container the sweep was pointed at, used to label each
            repository relatively.
        rate_limited: Whether pre-flight found the API rate-limited.
            Pre-flight runs once for the whole sweep, so this describes
            every repository in the document, including a sweep that
            found no repositories at all.
        exit_code: The code the process will exit with. Taken from the
            caller rather than recomputed here, so the document cannot
            disagree with the status the sweep actually returns -- an
            empty sweep has no outcomes to aggregate, and its code comes
            from the run's own state instead.
        error: Why the sweep could not run, when it failed before
            examining anything. Distinguishes that from a container that
            genuinely holds no repositories, which is otherwise the same
            empty document.
    """
    document = {
        "error": error,
        "repositories": [
            {
                "repository": _repository_label(repository, root),
                "exit_code": outcome.exit_code,
                "error": outcome.error,
                # Both are otherwise-invisible reasons for a non-zero
                # exit: neither produces a validation error, so a
                # consumer reading only ``results`` would find nothing
                # to explain the code.
                "write_failures": outcome.write_failures,
                "autofix_error": outcome.autofix_error,
                "results": outcome.json_payload,
            }
            for repository, outcome in results
        ],
        "summary": {
            "repositories": len(results),
            "failed": sum(1 for _, o in results if o.error),
            # Hoisted out of the per-repository payloads so a consumer
            # need not open one to learn the sweep looked at nothing, and
            # so an empty sweep -- which has no payloads at all -- can
            # still say so.
            "rate_limited": rate_limited,
            "exit_code": exit_code,
        },
    }

    # Plain print() avoids Rich formatting/ANSI codes in JSON output.
    print(json.dumps(document, indent=2))


def _run_repository_in_sweep(
    config: Config,
    options: CLIOptions,
    shared_cache: ValidationCache,
    repository: Path,
    *,
    silent: bool = False,
    use_environment_org: bool = False,
    label: str | None = None,
    rate_limited: bool = False,
) -> RunOutcome:
    """Run one repository of a sweep, surviving its failure.

    A repository that raises is recorded and the sweep continues: one
    unreadable checkout in twenty must not cost the other nineteen their
    results.

    Args:
        config: Template configuration.
        options: Template CLI options.
        shared_cache: Cache shared across the sweep.
        repository: The repository to visit.
        silent: Suppress this repository's console commentary, either
            because the caller asked for quiet or because a JSON
            document is being assembled on standard output.
        use_environment_org: Whether ``GITHUB_REPOSITORY_OWNER`` may name
            this repository's workflow organisation. False for a genuine
            sweep, where the variable describes one repository at most;
            true for the root-repository shortcut, which is the ordinary
            single-repository case wearing a different flag.
        label: How to name the repository in output. Defaults to its
            basename.

    Returns:
        What that repository produced, or a runtime error outcome.
    """
    logger = logging.getLogger(__name__)

    if not silent:
        console.print(f"[bold cyan]── {label or repository.name}[/bold cyan]")

    # Both the workflow organisation and the cooldown are properties of
    # the repository being scanned, so each gets its own copy rather than
    # inheriting whatever the previous one resolved.
    # Preparation sits inside the failure boundary alongside the run
    # itself. Resolving the cooldown reads this repository's
    # ``dependabot.yml``, and a malformed one raises past the narrow
    # handling in the resolver -- which outside the boundary would abort
    # the whole sweep, contradicting the promise that one bad checkout
    # costs only itself.
    try:
        repo_config = config.model_copy(deep=True)
        # ``silent`` rather than ``options.quiet``: the repository's own
        # run prints progress and messages such as "No workflows found
        # to validate" to standard output, which would sit inside the
        # aggregate JSON document. The command layer coerces quiet for
        # JSON output already, but relying on that leaves the sweep
        # correct only by distance, and a programmatic caller of
        # ``run_linter`` gets no such coercion.
        repo_options = options.model_copy(
            update={"path": repository, "quiet": silent}
        )
        repo_config.cooldown_days = _resolve_cooldown_days(
            options.cooldown, repository, quiet=True, output_format="text"
        )
        # GITHUB_REPOSITORY_OWNER names the repository the workflow was
        # launched for, so across a sweep it would answer identically
        # for every checkout and resolve their shorthand pins against
        # one, possibly foreign, organisation. Each repository resolves
        # from its own remotes instead; an explicit --allow-list-org
        # still outranks both.
        repo_config.allow_list.use_environment_org = use_environment_org

        return _run_one_repository(
            repo_config,
            repo_options,
            shared_cache,
            collect_json=options.output_format == "json",
            rate_limited=rate_limited,
        )
    except ConfigurationError:
        # A bad setting is a usage error and applies to every repository,
        # so there is nothing to be gained by continuing.
        raise
    except Exception as e:  # noqa: BLE001 - one repository must not stop the sweep
        # Computed once so the log, the console and the outcome all
        # describe the failure the same way.
        reason = _describe_exception(e)
        logger.error(f"Failed to scan {repository}: {reason}")
        if not silent:
            console.print(f"[red]  failed: {reason} ❌[/red]")
        return RunOutcome(
            exit_code=exit_codes.RUNTIME_ERROR,
            error=reason,
        )


def _display_multi_repo_summary(
    results: list[tuple[Path, RunOutcome]],
    root: Path,
) -> None:
    """Render the aggregate table closing a sweep.

    Args:
        results: Per-repository outcomes, in visit order.
        root: The container the sweep was pointed at. Rows are labelled
            relative to it, so grouped layouts such as ``group-a/service``
            and ``group-b/service`` stay distinguishable.
    """
    table = Table(title="Repository Summary")
    table.add_column("Repository", style="cyan")
    table.add_column("Pins", justify="right")
    table.add_column("Stale", justify="right")
    table.add_column("Fixed", justify="right")
    table.add_column("Defects", justify="right")
    table.add_column("Status")

    for repository, outcome in results:
        allow_list = outcome.allow_list
        pins = len(allow_list.findings) if allow_list else 0
        # What still needs attention, not what was found: a pin the
        # sweep rewrote is no longer stale, and showing it as both
        # stale and fixed reads as a contradiction.
        stale = len(allow_list.outstanding) if allow_list else 0
        fixed = allow_list.fixed_count if allow_list else 0
        table.add_row(
            _repository_label(repository, root),
            str(pins),
            str(stale),
            str(fixed),
            str(outcome.defects),
            _sweep_status(outcome),
        )

    console.print()
    console.print(table)

    failures = [name for name, o in results if o.error]
    if failures:
        console.print(
            f"\n[red]{len(failures)} repository(s) could not be "
            f"scanned ❌[/red]"
        )


def _sweep_status(outcome: RunOutcome) -> str:
    """Describe one repository's outcome for the summary table.

    ``clean`` is reserved for a repository with nothing outstanding, and
    ``updated`` for one whose outstanding work is *finished*. The exit
    code alone can establish neither: allow-list findings and outdated
    action calls both stay advisory unless ``--verify-*`` asks
    otherwise, and defects survive ``--no-fail-on-error``. Reading the
    code alone produced rows marked ``clean`` beside a non-zero Stale
    column, which is a contradiction in the same row.

    What remains is therefore tested before what was done. A partial
    remediation changes files *and* leaves pins outstanding, and calling
    that ``updated`` would tell the reader the repository needs no
    further attention when it does.

    A repository whose hosts could not be resolved gets its own label
    rather than sharing ``findings``: the check did not complete, so its
    empty counts say nothing, and a row of zeros marked ``findings``
    gives the reader no way to tell the two apart. A rate-limited
    repository gets one for the same reason, and is read from the
    recorded state rather than the exit code, since an advisory run
    reports success however little it managed to check.

    Args:
        outcome: What the repository produced.

    Returns:
        A short, styled status.
    """
    if outcome.error:
        return "[red]failed[/red]"

    # Read from the recorded state rather than the exit code, because an
    # advisory run reports SUCCESS by design: the code cannot tell a
    # repository that was examined and found clean from one that was
    # never examined. Given its own label for the reason ``unresolved``
    # has one -- the checks did not run, so the empty counts beside it
    # say nothing, and ``clean`` or ``findings`` on a row of zeros both
    # tell the reader the opposite of what happened.
    if outcome.rate_limited:
        return "[red]rate-limited[/red]"

    allow_list = outcome.allow_list
    if allow_list and allow_list.unresolved:
        return "[red]unresolved[/red]"

    if (
        (allow_list and allow_list.outstanding)
        or outcome.defects
        or outcome.outdated
        or outcome.write_failures
        or outcome.autofix_error
    ):
        return "[yellow]findings[/yellow]"

    # Nothing outstanding, so any rewriting that happened finished the
    # job. Allow-list rewrites are tracked on their own outcome rather
    # than in the action-call fixer's tally, so both count here.
    if outcome.files_changed or (allow_list and allow_list.fixed_count):
        return "[yellow]updated[/yellow]"

    return (
        "[green]clean[/green]"
        if outcome.exit_code == exit_codes.SUCCESS
        else "[yellow]findings[/yellow]"
    )


def _create_scan_summary_table(
    scan_summary: dict[str, Any],
    validation_summary: dict[str, Any],
    total_fixes: int = 0,
    redirect_stats: dict[str, int] | None = None,
) -> Table:
    """Create the scan summary table.

    This table is always displayed with the same structure regardless of CLI flags.
    """
    table = Table(title="Scan Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right", style="magenta")

    # Core metrics - always displayed
    table.add_row("Workflow files", str(scan_summary["total_files"]))
    table.add_row("Total action calls", str(scan_summary["total_calls"]))
    table.add_row("Action calls", str(scan_summary["action_calls"]))
    table.add_row("Workflow calls", str(scan_summary["workflow_calls"]))
    table.add_row("SHA references", str(scan_summary["sha_references"]))
    table.add_row("Tag references", str(scan_summary["tag_references"]))
    table.add_row("Branch references", str(scan_summary["branch_references"]))

    # Validation efficiency metrics - always displayed when available
    if validation_summary.get("unique_calls_validated", 0) > 0:
        table.add_row(
            "Unique calls validated",
            str(validation_summary["unique_calls_validated"]),
        )
        table.add_row(
            "Duplicate calls avoided",
            str(validation_summary["duplicate_calls_avoided"]),
        )
        efficiency = (
            1
            - validation_summary["unique_calls_validated"]
            / validation_summary["total_calls"]
        ) * 100
        table.add_row("Validation efficiency", f"{efficiency:.1f}%")

    # Update statistics - always displayed when checking for updates
    if total_fixes > 0:
        table.add_row("Action calls updated", str(total_fixes))

    # Redirect statistics - always displayed when redirects are found
    if redirect_stats and redirect_stats.get("actions_moved", 0) > 0:
        table.add_row(
            "Actions moved/relocated", str(redirect_stats["actions_moved"])
        )
        table.add_row(
            "Calls updated (relocated)", str(redirect_stats["calls_updated"])
        )

    return table


def _create_api_stats_table(validation_summary: dict[str, Any]) -> Table | None:
    """Create the API statistics table if there are API calls."""
    if validation_summary.get("api_calls_total", 0) == 0:
        return None

    api_table = Table(title="API Call Statistics")
    api_table.add_column("Metric", style="cyan")
    api_table.add_column("Count", justify="right", style="magenta")

    api_table.add_row(
        "Total API calls", str(validation_summary["api_calls_total"])
    )
    api_table.add_row(
        "GraphQL calls", str(validation_summary["api_calls_graphql"])
    )
    api_table.add_row(
        "REST API calls", str(validation_summary["api_calls_rest"])
    )
    api_table.add_row(
        "Git operations", str(validation_summary["api_calls_git"])
    )
    api_table.add_row("Cache hits", str(validation_summary["cache_hits"]))

    if validation_summary.get("rate_limit_delays", 0) > 0:
        api_table.add_row(
            "Rate limit delays", str(validation_summary["rate_limit_delays"])
        )
    if validation_summary.get("failed_api_calls", 0) > 0:
        api_table.add_row(
            "Failed API calls", str(validation_summary["failed_api_calls"])
        )

    return api_table


def _display_validation_summary(
    validation_summary: dict[str, Any], skip_success: bool = False
) -> None:
    """Display validation results summary."""
    # Calculate actual errors (excluding test references)
    actual_errors = validation_summary["total_errors"] - validation_summary.get(
        "test_references", 0
    )
    test_refs = validation_summary.get("test_references", 0)

    if actual_errors == 0 and test_refs == 0:
        if not skip_success:
            console.print("[green]All action calls are valid! ✅[/green]")
        return

    # Show actual errors
    if actual_errors > 0:
        console.print(f"[red]Found {actual_errors} validation errors ❌[/red]")

        if validation_summary["invalid_repositories"] > 0:
            console.print(
                f"  - {validation_summary['invalid_repositories']} invalid repositories"
            )
        if validation_summary["invalid_references"] > 0:
            console.print(
                f"  - {validation_summary['invalid_references']} invalid references"
            )
        if validation_summary.get("invalid_paths", 0) > 0:
            console.print(
                f"  - {validation_summary['invalid_paths']} invalid "
                f"subdirectory action paths"
            )
        if validation_summary["network_errors"] > 0:
            console.print(
                f"  - {validation_summary['network_errors']} network errors"
            )
        if validation_summary["timeouts"] > 0:
            console.print(f"  - {validation_summary['timeouts']} timeouts")
        if validation_summary["not_pinned_to_sha"] > 0:
            console.print(
                f"  - {validation_summary['not_pinned_to_sha']} actions not pinned to SHA"
            )

    # Show test references as warnings
    if test_refs > 0:
        if actual_errors > 0:
            console.print()  # Add spacing between errors and warnings
        console.print(
            f"[yellow]Found {test_refs} test action references ⚠️[/yellow]"
        )

    # Show deduplication and API efficiency
    if validation_summary.get("duplicate_calls_avoided", 0) > 0:
        console.print(
            f"[dim]Deduplication avoided {validation_summary['duplicate_calls_avoided']} redundant validations[/dim]"
        )

    # Show API efficiency metrics
    if validation_summary.get("api_calls_total", 0) > 0:
        console.print(
            f"[dim]Made {validation_summary['api_calls_total']} API calls "
            f"({validation_summary['api_calls_graphql']} GraphQL, "
            f"{validation_summary['cache_hits']} cache hits)[/dim]"
        )

    if validation_summary.get("rate_limit_delays", 0) > 0:
        console.print(
            f"[yellow]Rate limiting encountered {validation_summary['rate_limit_delays']} times[/yellow]"
        )


def _display_stale_actions_from_summary(
    stale_actions: dict[str, list[dict[str, Any]]],
    _options: CLIOptions,
) -> None:
    """
    Display a report of outdated action calls from a pre-built summary.

    Args:
        stale_actions: Dictionary mapping relative file paths to lists of stale action info
        options: CLI options
    """
    # Already imported at module level via .console singleton.
    if not stale_actions:
        console.print("[green]All action calls are up to date! ✅[/green]\n")
        return

    # Count incorrect (invalid) and outdated actions separately
    incorrect_count = 0
    outdated_count = 0
    incorrect_files = set()
    outdated_files = set()

    for file_path, actions in stale_actions.items():
        for action_info in actions:
            if action_info.get("is_invalid", False):
                incorrect_count += 1
                incorrect_files.add(file_path)
            else:
                outdated_count += 1
                outdated_files.add(file_path)

    # Display separate counts for incorrect and outdated actions
    if incorrect_count > 0:
        console.print(
            f"\n[red]Found {incorrect_count} incorrect action call(s) in {len(incorrect_files)} file(s)[/red]"
        )
    if outdated_count > 0:
        console.print(
            f"[yellow]Found {outdated_count} outdated action call(s) in {len(outdated_files)} file(s)[/yellow]"
        )

    console.print()

    for file_path in sorted(stale_actions.keys()):
        console.print(f"[bold]{file_path} 📄[/bold]")
        for action_info in stale_actions[file_path]:
            current_display = (
                action_info["current_ref"][:12] + "..."
                if len(action_info["current_ref"]) > 40
                else action_info["current_ref"]
            )
            latest_display = (
                action_info["latest_ref"][:12] + "..."
                if len(action_info["latest_ref"]) > 40
                else action_info["latest_ref"]
            )

            # Check if this is an invalid reference (validation error) or just outdated
            is_invalid = action_info.get("is_invalid", False)

            # Show action with redirect indicator if applicable
            action_display = action_info["action"]
            if action_info.get("redirected", False):
                action_display += " [orange3](moved/relocated)[/orange3]"

            # Use different colors and labels based on whether it's invalid or just outdated
            if is_invalid:
                # Invalid reference - entire line in red, correction line in green
                console.print(
                    f"  [red]Line {action_info['line']}:[/red] [red]{action_display}[/red]"
                )
                if action_info["current_comment"]:
                    console.print(
                        f"    [red]Invalid:  @{current_display} # {action_info['current_comment'].lstrip('#').strip()}[/red]"
                    )
                else:
                    console.print(
                        f"    [red]Invalid:  @{current_display}[/red]"
                    )
                console.print(
                    f"    [green]Correct:  @{latest_display} # {action_info['latest_version']}[/green]"
                )
            else:
                # Just outdated - use yellow for line and current ref
                console.print(
                    f"  [yellow]Line {action_info['line']}:[/yellow] {action_display}"
                )
                console.print(
                    f"    [yellow]Current:[/yellow]  @{current_display}", end=""
                )
                if action_info["current_comment"]:
                    console.print(
                        f" [dim]# {action_info['current_comment'].lstrip('#').strip()}[/dim]"
                    )
                else:
                    console.print()
                console.print(
                    f"    [green]Latest:[/green]   @{latest_display} [dim]# {action_info['latest_version']}[/dim]"
                )
        console.print()

    console.print(
        "[cyan]Run with [bold]--auto-fix --update-actions[/bold] to update "
        "these actions 💡[/cyan]\n"
    )


#: Results whose error message carries actionable remediation that the
#: action reference alone does not convey. Messages for other results
#: restate what the reader can already see, so they stay unrendered.
_REMEDIABLE_RESULTS = frozenset({ValidationResult.ANNOTATED_TAG_SHA})


def _print_deduplicated_action_refs(items: list[dict[str, Any]]) -> None:
    """
    Print a list of action references, collapsing duplicates per file.

    Items are dicts with at least ``action_ref`` and ``line`` keys. When the
    same ``action_ref`` appears more than once for a file, a single entry is
    printed annotated with the number of occurrences and the sorted set of
    distinct source line numbers, instead of repeating the same line N times.

    An optional ``message`` key carrying remediation advice (for example the
    peeled commit SHA behind an annotated tag object) is printed beneath the
    reference. Only results whose message tells the reader something the
    reference itself does not are rendered, so the common cases stay terse.
    """
    # Preserve first-seen order while grouping by action_ref. Use a set so
    # that repeated (ref, line) pairs collapse to a single line number, then
    # render in sorted order for stable output.
    grouped: dict[str, set[int]] = {}
    occurrences: dict[str, int] = {}
    messages: dict[str, str] = {}
    for item in items:
        ref = item["action_ref"]
        line = item["line"]
        grouped.setdefault(ref, set()).add(line)
        occurrences[ref] = occurrences.get(ref, 0) + 1
        message = item.get("message")
        if message and item.get("result") in _REMEDIABLE_RESULTS:
            messages.setdefault(ref, message)

    for ref, line_set in grouped.items():
        count = occurrences[ref]
        sorted_lines = sorted(line_set)
        if count == 1:
            console.print(f"   {ref} [dim][line {sorted_lines[0]}][/dim]")
        else:
            line_list = ", ".join(str(n) for n in sorted_lines)
            label = "line" if len(sorted_lines) == 1 else "lines"
            console.print(
                f"   {ref} [dim](x{count})[/dim] "
                f"[dim][{label} {line_list}][/dim]"
            )
        remediation = messages.get(ref)
        if remediation:
            # Wrap explicitly with a hanging indent: letting the console
            # wrap a long single-line message flushes continuations to
            # column 0, which reads as unrelated output.
            for text in textwrap.wrap(
                " ".join(remediation.split()),
                width=72,
                initial_indent="     ",
                subsequent_indent="     ",
            ):
                console.print(f"[yellow]{text}[/yellow]")


def output_text_results(
    scan_summary: dict[str, Any],
    validation_summary: dict[str, Any],
    errors: list[Any],
    scan_path: Path,
    quiet: bool = False,
    fixed_files: dict[Path, list[dict[str, str]]] | None = None,
    redirect_stats: dict[str, int] | None = None,
    stale_actions_summary: dict[str, list[dict[str, Any]]] | None = None,
    *,
    rate_limited: bool = False,
) -> None:
    """
    Output results in human-readable text format.

    Args:
        scan_summary: Scan statistics
        validation_summary: Validation statistics summary
        errors: List of validation errors
        scan_path: Base path for computing relative paths
        quiet: Whether to suppress non-error output
        fixed_files: Dictionary of files that were auto-fixed
        redirect_stats: Statistics about redirected/relocated actions
        stale_actions_summary: Dictionary of stale actions to report
        rate_limited: Whether the API was rate-limited, so no call was
            checked. The reader is told that instead of being told the
            calls are valid, which the run never established.
    """
    if not quiet:
        # Count total action calls fixed
        total_fixes = 0
        if fixed_files:
            for changes in fixed_files.values():
                for change in changes:
                    if change.get("skipped") != "true":
                        total_fixes += 1

        # Display scan summary (with redirect stats if available)
        table = _create_scan_summary_table(
            scan_summary, validation_summary, total_fixes, redirect_stats
        )

        # Display API statistics if available
        api_table = _create_api_stats_table(validation_summary)
        if api_table:
            console.print()  # Add blank line before API table
            console.print(api_table)

        console.print()
        console.print(table)

        # Check if files were modified
        has_actual_fixes = False
        if fixed_files:
            for changes in fixed_files.values():
                for change in changes:
                    if change.get("skipped") != "true":
                        has_actual_fixes = True
                        break
                if has_actual_fixes:
                    break

        # Display validation summary (but skip "all valid" message if files were modified or there are stale actions)
        has_stale_actions = bool(
            stale_actions_summary and any(stale_actions_summary.values())
        )
        _display_validation_summary(
            validation_summary,
            skip_success=(
                has_actual_fixes or has_stale_actions or rate_limited
            ),
        )

        if rate_limited:
            # "All action calls are valid" would be the text-mode twin of
            # the byte-identical JSON document: a run that checked
            # nothing, reporting no problems, read as a clean result.
            console.print(
                "[yellow]GitHub API rate-limited; no action calls were "
                "checked ⚠️[/yellow]"
            )

        # Display modification message after scan summary if files were modified
        if has_actual_fixes:
            console.print(
                "\n[yellow]Files have been modified; please review the changes and commit them ⚠️[/yellow]"
            )

    # Separate errors by type
    if errors:
        # Group errors by file and type
        actual_errors = defaultdict(list)
        test_warnings = defaultdict(list)

        for error in errors:
            relative_path = _get_relative_path(error.file_path, scan_path)

            # Format action reference without 'uses:'
            action_ref = f"{error.action_call.organization}/{error.action_call.repository}@{error.action_call.reference}"
            if error.action_call.comment:
                action_ref += f"  {error.action_call.comment}"

            error_info = {
                "action_ref": action_ref,
                "line": error.action_call.line_number,
                "result": error.result,
                "message": error.error_message,
            }

            # Check if this is a test reference based on comment
            if has_test_comment(error.action_call):
                test_warnings[relative_path].append(error_info)
            else:
                actual_errors[relative_path].append(error_info)

        # Display actual validation errors (deduplicated per file: same
        # action_ref appearing multiple times is collapsed with a count)
        if actual_errors:
            console.print("\n[red]Validation Errors:[/red]")
            for file_path in sorted(actual_errors.keys()):
                console.print(
                    f"Invalid action call in workflow: [bold]{file_path}[/bold] ❌"
                )
                _print_deduplicated_action_refs(actual_errors[file_path])

        # Display test action warnings (deduplicated per file)
        if test_warnings:
            console.print("\n[yellow]Test Action Calls:[/yellow]")
            for file_path in sorted(test_warnings.keys()):
                console.print(
                    f"Test action calls in workflow: [bold]{file_path}[/bold] ⚠️"
                )
                _print_deduplicated_action_refs(test_warnings[file_path])


def build_json_results(
    scan_summary: dict[str, Any],
    validation_summary: dict[str, Any],
    errors: list[Any],
    scan_path: Path,
    allow_list: AllowListOutcome | None = None,
    *,
    rate_limited: bool = False,
    error: str | None = None,
) -> dict[str, Any]:
    """
    Build the JSON results document for one repository.

    Kept separate from printing so a multi-repository sweep can collect
    each repository's payload and emit a single document, rather than
    concatenating several top-level objects onto standard output.

    Args:
        scan_summary: Scan statistics
        validation_summary: Validation statistics
        errors: List of validation errors
        scan_path: Base path for computing relative paths
        allow_list: Allow-list outcome, merged in under an ``allow_list``
            key when the check ran
        rate_limited: Whether the API was rate-limited, so the checks
            never ran
        error: Why the run could not complete, when it could not

    Returns:
        The results as a JSON-serialisable mapping.
    """
    result = {
        # Always present, and stated even when false: a rate-limited run
        # produces the same empty ``errors`` list as a clean one, so a
        # consumer that had to infer this from absence could not tell
        # "checks skipped" from "checks found nothing" -- the very
        # confusion this key exists to prevent.
        "rate_limited": rate_limited,
        # Likewise always present. A run that failed before it could
        # examine anything reports no findings, which is indistinguishable
        # from finding none unless it says why.
        "error": error,
        "scan_summary": scan_summary,
        "validation_summary": validation_summary,
        "errors": [
            {
                "file_path": str(
                    _get_relative_path(error.file_path, scan_path)
                ),
                "line_number": error.action_call.line_number,
                "raw_line": error.action_call.raw_line.strip(),
                "organization": error.action_call.organization,
                "repository": error.action_call.repository,
                "reference": error.action_call.reference,
                "call_type": error.action_call.call_type.value,
                "reference_type": error.action_call.reference_type.value,
                "validation_result": error.result.value,
                "error_message": error.error_message,
            }
            for error in errors
        ],
    }

    if allow_list is not None:
        result.update(build_allow_list_json(allow_list, root=scan_path))

    return result


def output_json_results(
    scan_summary: dict[str, Any],
    validation_summary: dict[str, Any],
    errors: list[Any],
    scan_path: Path,
    allow_list: AllowListOutcome | None = None,
    *,
    rate_limited: bool = False,
) -> None:
    """
    Output results in JSON format.

    Args:
        scan_summary: Scan statistics
        validation_summary: Validation statistics
        errors: List of validation errors
        scan_path: Base path for computing relative paths
        allow_list: Allow-list outcome, merged in under an ``allow_list``
            key when the check ran
        rate_limited: Whether the API was rate-limited, so the checks
            never ran
    """
    result = build_json_results(
        scan_summary,
        validation_summary,
        errors,
        scan_path,
        allow_list,
        rate_limited=rate_limited,
    )

    # Use plain print() to avoid Rich formatting/ANSI codes in JSON output
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    app()
