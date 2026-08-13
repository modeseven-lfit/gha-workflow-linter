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
from dataclasses import dataclass
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

from . import exit_codes
from ._version import __version__
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
    rich_handler = RichHandler(
        console=console,
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
) -> None:
    """Resolve the GitHub token, select a validation method, and pre-flight it.

    Applies the resolved method/token back onto ``config`` and prints the
    chosen backend (unless quiet/JSON). When the GitHub API backend is
    selected, this also performs the rate-limit pre-flight check.
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
        try:
            github_client.check_rate_limit_and_exit_if_needed()
            # If we get here, we're not rate limited
            if not effective_token and not options.quiet:
                logger.warning(
                    "No GitHub token available; API requests may be rate-limited ⚠️"
                )
        except SystemExit:
            # Rate limit check triggered exit, re-raise to exit cleanly
            raise


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
    if verbose and quiet:
        console.print(
            "[red]Error: --verbose and --quiet cannot be used together[/red]"
        )
        # Arguably a usage error (code 2), but this has always exited 1 and
        # changing it would break callers; see exit_codes.RUNTIME_ERROR.
        raise typer.Exit(exit_codes.RUNTIME_ERROR)

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
        )

        # Apply CLI overrides to config
        _apply_cli_overrides(config, cli_options, workers)

        # Resolve the action-update cooldown window. Precedence: explicit
        # --cooldown flag, then the repository's Dependabot configuration,
        # then 0 (no cooldown / original behaviour).
        config.cooldown_days = _resolve_cooldown_days(
            cooldown, path, quiet, output_format
        )

        logger.debug(f"Starting gha-workflow-linter {__version__}")

        # Resolve token, select validation method, and pre-flight it
        _configure_validation_backend(
            config, cli_options, github_token, workers
        )

        # Only show scanning path if we're actually going to proceed
        logger.debug(f"Scanning path: {path}")

        exit_code = run_linter(config, cli_options)

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
    """Files changed and statistics produced by the auto-fixer."""

    fixed_files: dict[Path, list[dict[str, str]]]
    redirect_stats: dict[str, int]
    stale_actions_summary: dict[str, list[dict[str, Any]]]


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
    if isinstance(e.original_error, NetworkError):
        console.print(
            "\n[yellow]❌ Network connectivity issue detected[/yellow]"
        )
        console.print("[dim]• Check your internet connection")
        console.print("[dim]• Verify DNS resolution is working")
        console.print("[dim]• Try again in a few moments[/dim]")
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


def _scan_and_validate(
    config: Config,
    options: CLIOptions,
    scanner: WorkflowScanner,
    shared_cache: ValidationCache,
) -> int | _ValidationOutcome:
    """Scan workflows and validate their action calls.

    Returns an ``int`` exit code when the run short-circuits (scan error,
    nothing to validate, or aborted validation); otherwise returns a
    :class:`_ValidationOutcome` for downstream processing.
    """
    logger = logging.getLogger(__name__)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        disable=options.quiet,
    ) as progress:
        # Scan for workflows
        scan_task = progress.add_task("Scanning workflows...", total=None)

        try:
            workflow_calls = scanner.scan_directory(
                options.path, progress, scan_task, specific_files=options.files
            )
        except Exception as e:
            logger.error(f"Error scanning workflows: {e}")
            return 1

        if not workflow_calls:
            if not options.quiet:
                console.print("[yellow]No workflows found to validate[/yellow]")
            return 0

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
            return _handle_validation_aborted(
                e,
                suppress_console=options.quiet
                or options.output_format == "json",
            )
        except Exception as e:
            logger.error(f"Unexpected error validating action calls: {e}")
            return 1

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

    fixed_files: dict[Path, list[dict[str, str]]] = {}
    redirect_stats: dict[str, int] = {"actions_moved": 0, "calls_updated": 0}
    stale_actions_summary: dict[str, list[dict[str, Any]]] = {}

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
        ]:
            async with AutoFixer(
                config,
                base_path=options.path,
                cache=shared_cache,
            ) as auto_fixer:
                # When auto_fix is enabled, always pass all action calls to
                # check. check_for_updates=True only when update_actions is
                # enabled (update to latest versions); False means: fix
                # validation errors, report outdated versions.
                all_calls = validation.workflow_calls if config.auto_fix else {}
                check_for_updates = config.update_actions
                return await auto_fixer.fix_validation_errors(
                    validation.validation_errors,
                    all_calls,
                    check_for_updates=check_for_updates,
                )

        fixed_files, redirect_stats, stale_actions_summary = asyncio.run(
            run_auto_fix()
        )

        if fixed_files and not options.quiet:
            _display_auto_fix_changes(fixed_files, options)

    except Exception as e:
        logger.warning(f"Auto-fix failed: {e}")
        if not options.quiet:
            console.print(f"[yellow]Auto-fix failed: {e} ⚠️[/yellow]")

    return _AutoFixOutcome(fixed_files, redirect_stats, stale_actions_summary)


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
) -> None:
    """Generate and display the scan/validation results."""
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
        output_json_results(
            scan_summary,
            validation_summary,
            validation.validation_errors,
            options.path,
            allow_list,
        )
    else:
        output_text_results(
            scan_summary,
            validation_summary,
            validation.validation_errors,
            options.path,
            options.quiet,
            autofix.fixed_files,
            autofix.redirect_stats,
            autofix.stale_actions_summary,
        )
        if allow_list is not None and not options.quiet:
            # Only suggest remediation when it has not already run.
            render_allow_list(
                allow_list,
                root=options.path,
                show_suppressed=config.allow_list.show_suppressed,
                update_hint=not config.allow_list.update,
            )


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
        logger.warning(f"Allow-list check failed: {e}")
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
                f"[red]Allow-list verification could not run: {e} ❌[/red]"
            )
        return AllowListOutcome(
            findings=[],
            hosts={},
            unresolved={STAGE_FAILURE_HOST: str(e)},
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


def _determine_exit_code(
    options: CLIOptions,
    validation: _ValidationOutcome,
    autofix: _AutoFixOutcome,
    config: Config,
    allow_list: AllowListOutcome | None = None,
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

    Returns:
        A code from :mod:`gha_workflow_linter.exit_codes`.
    """
    codes: list[int] = []

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
        if config.allow_list.verify:
            if allow_list.unresolved:
                codes.append(exit_codes.ALLOW_LIST_UNRESOLVED)
            elif allow_list.outstanding:
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


def run_linter(config: Config, options: CLIOptions) -> int:
    """
    Run the main linting process.

    Args:
        config: Configuration object
        options: CLI options

    Returns:
        Exit code from :mod:`gha_workflow_linter.exit_codes`.
    """
    scanner = WorkflowScanner(config)

    # Build a single ValidationCache and share it across the validator
    # and (later) the auto-fixer to avoid duplicate disk I/O and
    # competing save() calls.
    shared_cache = ValidationCache(config.cache)

    # Eagerly load the cache and run all startup-time checks so any
    # banners render *before* opening the Rich Progress UI (printing
    # inside the progress block would interleave with the active
    # spinner and corrupt output).
    _render_cache_prime_banners(shared_cache.prime(), quiet=options.quiet)

    scan_result = _scan_and_validate(config, options, scanner, shared_cache)
    if isinstance(scan_result, int):
        return scan_result
    validation = scan_result

    autofix = _run_auto_fix_stage(config, options, shared_cache, validation)

    allow_list = _run_allow_list_stage(config, options, shared_cache)

    _emit_results(options, scanner, validation, autofix, config, allow_list)

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

    return _determine_exit_code(
        options, validation, autofix, config, allow_list
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
            skip_success=(has_actual_fixes or has_stale_actions),
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


def output_json_results(
    scan_summary: dict[str, Any],
    validation_summary: dict[str, Any],
    errors: list[Any],
    scan_path: Path,
    allow_list: AllowListOutcome | None = None,
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
    """
    result = {
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

    # Use plain print() to avoid Rich formatting/ANSI codes in JSON output
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    app()
