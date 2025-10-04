# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""CLI interface for gha-workflow-linter using Typer."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from rich.console import Console
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

from . import __version__
from .cache import ValidationCache
from .config import ConfigManager
from .exceptions import (
    AuthenticationError,
    ConfigurationError,
    GitHubAPIError,
    NetworkError,
    RateLimitError,
    TemporaryAPIError,
    ValidationAbortedError,
)
from .models import CLIOptions, Config, LogLevel
from .scanner import WorkflowScanner
from .validator import ActionCallValidator


def help_callback(ctx: typer.Context, _param: Any, value: bool) -> None:
    """Show help with version information."""
    if not value or ctx.resilient_parsing:
        return
    console.print(f"🏷️ gha-workflow-linter version {__version__}")
    console.print()
    console.print(ctx.get_help())
    raise typer.Exit()


def main_app_help_callback(
    ctx: typer.Context, _param: Any, value: bool
) -> None:
    """Show main app help with version information."""
    if not value or ctx.resilient_parsing:
        return
    console.print(f"🏷️ gha-workflow-linter version {__version__}")
    console.print()
    console.print(ctx.get_help())
    raise typer.Exit()


def cache_help_callback(ctx: typer.Context, _param: Any, value: bool) -> None:
    """Show cache command help with version information."""
    if not value or ctx.resilient_parsing:
        return
    console.print(f"🏷️ gha-workflow-linter version {__version__}")
    console.print()
    console.print(ctx.get_help())
    raise typer.Exit()


console = Console()


def version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        console.print(f"🏷️ gha-workflow-linter version {__version__}")
        raise typer.Exit()


app = typer.Typer(
    name="gha-workflow-linter",
    help="GitHub Actions workflow linter for validating action and workflow calls",
    add_completion=False,
    rich_markup_mode="rich",
)


# Add custom help option to main app
@app.callback(invoke_without_command=True)  # type: ignore[misc]
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
    if ctx.invoked_subcommand is None:
        # Only show help if no subcommand was invoked
        pass


def setup_logging(log_level: LogLevel, quiet: bool = False) -> None:
    """
    Setup logging configuration.

    Args:
        log_level: Logging level
        quiet: Suppress all output except errors
    """
    level = logging.ERROR if quiet else getattr(logging, log_level.value)

    # Get root logger and set its level explicitly
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


@app.command()  # type: ignore[misc]
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
        help="Number of parallel workers (default: 4)",
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
    purge_cache: bool = typer.Option(
        False,
        "--purge-cache",
        help="Clear all cached validation results and exit",
    ),
    cache_ttl: int | None = typer.Option(
        None,
        "--cache-ttl",
        help="Override default cache TTL in seconds",
        min=60,  # minimum 1 minute
    ),
    _help: bool = typer.Option(
        False,
        "--help",
        callback=help_callback,
        is_eager=True,
        help="Show this message and exit",
    ),
    _version: bool = typer.Option(
        False,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
) -> None:
    """
    Scan GitHub Actions workflows for invalid action and workflow calls.

    This tool scans for .github/workflows directories and validates that all
    'uses' statements reference valid repositories, branches, tags, or commit SHAs.

    Cache Options:
        --no-cache: Bypass cache and always validate against remote repositories
        --purge-cache: Clear all cached validation results and exit
        --cache-ttl: Override default cache TTL (7 days) in seconds

    GitHub API Authentication:

        # Using environment variable (recommended)
        export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
        gha-workflow-linter lint

        # Using CLI flag
        gha-workflow-linter lint --github-token ghp_xxxxxxxxxxxxxxxxxxxx

    Examples:

        # Scan current directory
        gha-workflow-linter lint

        # Scan specific path
        gha-workflow-linter lint /path/to/project

        # Use custom config and output JSON
        gha-workflow-linter lint --config config.yaml --format json

        # Verbose output with 8 workers and token
        gha-workflow-linter lint --verbose --workers 8 --github-token ghp_xxx

        # Disable SHA pinning requirement
        gha-workflow-linter lint --no-require-pinned-sha
    """
    # Handle mutually exclusive options
    if verbose and quiet:
        console.print(
            "[red]Error: --verbose and --quiet cannot be used together[/red]"
        )
        raise typer.Exit(1)

    if verbose:
        log_level = LogLevel.DEBUG

    # Setup logging
    setup_logging(log_level, quiet)
    logger = logging.getLogger(__name__)

    # Set default path
    if path is None:
        path = Path.cwd()

    try:
        # Load configuration
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
            require_pinned_sha=require_pinned_sha,
            no_cache=no_cache,
            purge_cache=purge_cache,
            cache_ttl=cache_ttl,
        )

        # Apply GitHub token from CLI if provided
        if github_token:
            config.github_api.token = github_token

        # Apply CLI overrides to config
        if workers is not None:
            config.parallel_workers = workers
        if exclude is not None:
            config.exclude_patterns = exclude
        if not parallel:
            config.parallel_workers = 1
        config.require_pinned_sha = require_pinned_sha

        # Handle cache options
        if no_cache:
            config.cache.enabled = False
            logger.debug("Cache disabled via --no-cache")

        if cache_ttl is not None:
            config.cache.default_ttl_seconds = cache_ttl
            logger.debug(f"Cache TTL overridden to {cache_ttl} seconds")

        # Handle cache purge option
        if purge_cache:
            cache = ValidationCache(config.cache)
            removed_count = cache.purge()
            if not quiet:
                console.print(
                    f"[green]✅ Purged {removed_count} cache entries[/green]"
                )
            raise typer.Exit(0)

        logger.info(f"Starting gha-workflow-linter {__version__}")
        logger.info(f"Scanning path: {path}")

        # Check for GitHub token and show warning if missing
        effective_token = github_token or config.effective_github_token
        if not effective_token and not quiet:
            logger.info("⚠️ No GitHub token; risk of rate-limiting")

        # Run the linting process
        exit_code = run_linter(config, cli_options)

    except typer.Exit:
        # Re-raise typer.Exit to avoid catching it as a general exception
        raise
    except ValidationAbortedError as e:
        # These errors should already be handled in run_linter, but catch here as fallback
        logger.error(f"Validation aborted: {e.message}")
        raise typer.Exit(1) from None
    except (ValueError, ConfigurationError) as e:
        logger.error(f"Configuration error: {e}")
        if verbose:
            logger.exception("Full traceback:")
        raise typer.Exit(1) from None
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if verbose:
            logger.exception("Full traceback:")
        raise typer.Exit(1) from None

    raise typer.Exit(exit_code)


@app.command()  # type: ignore[misc]
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
    # Load configuration
    from .config import ConfigManager

    config_manager = ConfigManager()
    config = config_manager.load_config(config_file)

    cache_instance = ValidationCache(config.cache)

    if purge:
        removed_count = cache_instance.purge()
        console.print(f"[green]✅ Purged {removed_count} cache entries[/green]")
        return

    if cleanup:
        removed_count = cache_instance.cleanup()
        console.print(
            f"[green]✅ Removed {removed_count} expired cache entries[/green]"
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


def run_linter(config: Config, options: CLIOptions) -> int:
    """
    Run the main linting process.

    Args:
        config: Configuration object
        options: CLI options

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    logger = logging.getLogger(__name__)

    # Initialize scanner and validator
    scanner = WorkflowScanner(config)

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
                options.path, progress, scan_task
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

        # Validate action calls
        validate_task = progress.add_task(
            "Validating action calls...", total=total_calls
        )

        try:
            validator = ActionCallValidator(config)
            validation_errors = validator.validate_action_calls(
                workflow_calls, progress, validate_task
            )
        except ValidationAbortedError as e:
            logger.error(f"Validation aborted: {e.message}")

            # Provide specific guidance based on the error type
            if isinstance(e.original_error, NetworkError):
                console.print(
                    "\n[yellow]❌ Network connectivity issue detected[/yellow]"
                )
                console.print("[dim]• Check your internet connection")
                console.print("[dim]• Verify DNS resolution is working")
                console.print("[dim]• Try again in a few moments[/dim]")
            elif isinstance(e.original_error, AuthenticationError):
                console.print(
                    "\n[yellow]❌ GitHub API authentication failed[/yellow]"
                )
                console.print(
                    "[dim]• Set a valid GitHub token: export GITHUB_TOKEN=ghp_xxx"
                )
                console.print("[dim]• Or use: --github-token ghp_xxx")
                console.print(
                    "[dim]• Ensure token has 'public_repo' scope[/dim]"
                )
            elif isinstance(e.original_error, RateLimitError):
                console.print(
                    "\n[yellow]❌ GitHub API rate limit exceeded[/yellow]"
                )
                console.print("[dim]• Wait for rate limit to reset")
                console.print("[dim]• Use a GitHub token to increase limits")
                console.print("[dim]• Try again later[/dim]")
            elif isinstance(
                e.original_error, (GitHubAPIError, TemporaryAPIError)
            ):
                console.print("\n[yellow]❌ GitHub API error[/yellow]")
                console.print(
                    "[dim]• This may be a temporary GitHub service issue"
                )
                console.print("[dim]• Try again in a few minutes")
                console.print(
                    "[dim]• Check GitHub status at https://status.github.com/[/dim]"
                )
            else:
                console.print(
                    "\n[yellow]❌ Validation could not be completed[/yellow]"
                )
                console.print(f"[dim]• {e.reason}[/dim]")

            console.print(
                "\n[red]Cannot determine if action calls are valid or invalid.[/red]"
            )
            console.print(
                "[red]Validation was not performed due to the above issue.[/red]"
            )
            return 1
        except Exception as e:
            logger.error(f"Unexpected error validating action calls: {e}")
            return 1

    # Generate and display results
    scan_summary = scanner.get_scan_summary(workflow_calls)

    # Calculate unique calls for statistics
    unique_calls = set()
    for calls in workflow_calls.values():
        for call in calls.values():
            call_key = f"{call.organization}/{call.repository}@{call.reference}"
            unique_calls.add(call_key)

    validation_summary = validator.get_validation_summary(
        validation_errors, total_calls, len(unique_calls)
    )

    if options.output_format == "json":
        output_json_results(scan_summary, validation_summary, validation_errors)
    else:
        output_text_results(
            scan_summary, validation_summary, validation_errors, options.quiet
        )

    # Determine exit code
    if validation_errors and options.fail_on_error:
        return 1

    return 0


def _create_scan_summary_table(
    scan_summary: dict[str, Any], validation_summary: dict[str, Any]
) -> Table:
    """Create the scan summary table."""
    table = Table(title="Scan Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right", style="magenta")

    table.add_row("Workflow files", str(scan_summary["total_files"]))
    table.add_row("Total action calls", str(scan_summary["total_calls"]))
    table.add_row("Action calls", str(scan_summary["action_calls"]))
    table.add_row("Workflow calls", str(scan_summary["workflow_calls"]))
    table.add_row("SHA references", str(scan_summary["sha_references"]))
    table.add_row("Tag references", str(scan_summary["tag_references"]))
    table.add_row("Branch references", str(scan_summary["branch_references"]))

    # Add validation efficiency metrics
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


def _display_validation_summary(validation_summary: dict[str, Any]) -> None:
    """Display validation results summary."""
    if validation_summary["total_errors"] == 0:
        console.print("[green]✅ All action calls are valid![/green]")
        return

    console.print(
        f"[red]❌ Found {validation_summary['total_errors']} validation errors[/red]"
    )

    if validation_summary["invalid_repositories"] > 0:
        console.print(
            f"  - {validation_summary['invalid_repositories']} invalid repositories"
        )
    if validation_summary["invalid_references"] > 0:
        console.print(
            f"  - {validation_summary['invalid_references']} invalid references"
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


def output_text_results(
    scan_summary: dict[str, Any],
    validation_summary: dict[str, Any],
    errors: list[Any],
    quiet: bool = False,
) -> None:
    """
    Output results in human-readable text format.

    Args:
        scan_summary: Scan statistics
        validation_summary: Validation statistics
        errors: List of validation errors
        quiet: Suppress non-error output
    """
    if not quiet:
        # Display scan summary
        table = _create_scan_summary_table(scan_summary, validation_summary)

        # Display API statistics if available
        api_table = _create_api_stats_table(validation_summary)
        if api_table:
            console.print(api_table)

        console.print(table)
        console.print()

        # Display validation summary
        _display_validation_summary(validation_summary)

    # Always display errors
    if errors:
        console.print("\n[red]Validation Errors:[/red]")
        for error in errors:
            console.print(str(error))


def output_json_results(
    scan_summary: dict[str, Any],
    validation_summary: dict[str, Any],
    errors: list[Any],
) -> None:
    """
    Output results in JSON format.

    Args:
        scan_summary: Scan statistics
        validation_summary: Validation statistics
        errors: List of validation errors
    """
    result = {
        "scan_summary": scan_summary,
        "validation_summary": validation_summary,
        "errors": [
            {
                "file_path": str(error.file_path),
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

    console.print(json.dumps(result, indent=2))


if __name__ == "__main__":
    app()
