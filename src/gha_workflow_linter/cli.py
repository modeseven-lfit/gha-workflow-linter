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
from typer.core import TyperGroup

from . import __version__
from .config import ConfigManager
from .models import CLIOptions, Config, LogLevel
from .scanner import WorkflowScanner
from .validator import ActionCallValidator

def help_callback(ctx: typer.Context, param: Any, value: bool) -> None:
    """Show help with version information."""
    if not value or ctx.resilient_parsing:
        return
    console.print(f"🏷️ gha-workflow-linter version {__version__}")
    console.print()
    console.print(ctx.get_help())
    raise typer.Exit()


app = typer.Typer(
    name="gha-workflow-linter",
    help="GitHub Actions workflow linter for validating action and workflow calls",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()


def version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        console.print(f"🏷️ gha-workflow-linter version {__version__}")
        raise typer.Exit()


def setup_logging(log_level: LogLevel, quiet: bool = False) -> None:
    """
    Setup logging configuration.

    Args:
        log_level: Logging level
        quiet: Suppress all output except errors
    """
    level = logging.ERROR if quiet else getattr(logging, log_level.value)

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                console=console,
                show_time=False,
                show_path=False,
                markup=True,
            )
        ],
    )

    # Set httpx logging to WARNING to suppress verbose HTTP request logs
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("httpcore.connection").setLevel(logging.WARNING)
    logging.getLogger("httpcore.http11").setLevel(logging.WARNING)


@app.command()  # type: ignore[misc]
def main(
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
        "--config", "-c",
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
        "--verbose", "-v",
        help="Enable verbose output",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet", "-q",
        help="Suppress all output except errors",
    ),
    log_level: LogLevel = typer.Option(
        LogLevel.INFO,
        "--log-level",
        help="Set logging level",
    ),
    output_format: str = typer.Option(
        "text",
        "--format", "-f",
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
        "--workers", "-j",
        help="Number of parallel workers (default: 4)",
        min=1,
        max=32,
    ),
    exclude: list[str] | None = typer.Option(
        None,
        "--exclude", "-e",
        help="Patterns to exclude (multiples accepted)",
    ),
    require_pinned_sha: bool = typer.Option(
        True,
        "--require-pinned-sha/--no-require-pinned-sha",
        help="Require action calls to be pinned to commit SHAs (default: enabled)",
    ),
    _help: bool = typer.Option(
        None,
        "--help",
        callback=help_callback,
        is_eager=True,
        help="Show this message and exit",
    ),
    _version: bool | None = typer.Option(
        None,
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

    GitHub API Authentication:

        # Using environment variable (recommended)
        export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
        gha-workflow-linter

        # Using CLI flag
        gha-workflow-linter --github-token ghp_xxxxxxxxxxxxxxxxxxxx

    Examples:

        # Scan current directory
        gha-workflow-linter

        # Scan specific path
        gha-workflow-linter /path/to/project

        # Use custom config and output JSON
        gha-workflow-linter --config config.yaml --format json

        # Verbose output with 8 workers and token
        gha-workflow-linter --verbose --workers 8 --github-token ghp_xxx

        # Disable SHA pinning requirement
        gha-workflow-linter --no-require-pinned-sha
    """
    # Handle mutually exclusive options
    if verbose and quiet:
        console.print("[red]Error: --verbose and --quiet cannot be used together[/red]")
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

        logger.info(f"Starting gha-workflow-linter {__version__}")
        logger.info(f"Scanning path: {path}")

        # Check for GitHub token and show warning if missing
        effective_token = github_token or config.effective_github_token
        if not effective_token and not quiet:
            logger.info("⚠️ No GitHub token; risk of rate-limiting")

        # Run the linting process
        exit_code = run_linter(config, cli_options)

    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if verbose:
            logger.exception("Full traceback:")
        raise typer.Exit(1) from None

    raise typer.Exit(exit_code)


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
            "Validating action calls...",
            total=total_calls
        )

        try:
            validator = ActionCallValidator(config)
            validation_errors = validator.validate_action_calls(
                workflow_calls, progress, validate_task
            )
        except Exception as e:
            logger.error(f"Error validating action calls: {e}")
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
        validation_errors,
        total_calls,
        len(unique_calls)
    )

    if options.output_format == "json":
        output_json_results(
            scan_summary, validation_summary, validation_errors
        )
    else:
        output_text_results(
            scan_summary, validation_summary, validation_errors, options.quiet
        )

    # Determine exit code
    if validation_errors and options.fail_on_error:
        return 1

    return 0


def _create_scan_summary_table(scan_summary: dict[str, Any], validation_summary: dict[str, Any]) -> Table:
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
        table.add_row("Unique calls validated", str(validation_summary["unique_calls_validated"]))
        table.add_row("Duplicate calls avoided", str(validation_summary["duplicate_calls_avoided"]))
        efficiency = (1 - validation_summary["unique_calls_validated"] / validation_summary["total_calls"]) * 100
        table.add_row("Validation efficiency", f"{efficiency:.1f}%")

    return table


def _create_api_stats_table(validation_summary: dict[str, Any]) -> Table | None:
    """Create the API statistics table if there are API calls."""
    if validation_summary.get("api_calls_total", 0) == 0:
        return None

    api_table = Table(title="API Call Statistics")
    api_table.add_column("Metric", style="cyan")
    api_table.add_column("Count", justify="right", style="magenta")

    api_table.add_row("Total API calls", str(validation_summary["api_calls_total"]))
    api_table.add_row("GraphQL calls", str(validation_summary["api_calls_graphql"]))
    api_table.add_row("REST API calls", str(validation_summary["api_calls_rest"]))
    api_table.add_row("Git operations", str(validation_summary["api_calls_git"]))
    api_table.add_row("Cache hits", str(validation_summary["cache_hits"]))

    if validation_summary.get("rate_limit_delays", 0) > 0:
        api_table.add_row("Rate limit delays", str(validation_summary["rate_limit_delays"]))
    if validation_summary.get("failed_api_calls", 0) > 0:
        api_table.add_row("Failed API calls", str(validation_summary["failed_api_calls"]))

    return api_table


def _display_validation_summary(validation_summary: dict[str, Any]) -> None:
    """Display validation results summary."""
    if validation_summary["total_errors"] == 0:
        console.print("[green]✅ All action calls are valid![/green]")
        return

    console.print(f"[red]❌ Found {validation_summary['total_errors']} validation errors[/red]")

    if validation_summary["invalid_repositories"] > 0:
        console.print(f"  - {validation_summary['invalid_repositories']} invalid repositories")
    if validation_summary["invalid_references"] > 0:
        console.print(f"  - {validation_summary['invalid_references']} invalid references")
    if validation_summary["network_errors"] > 0:
        console.print(f"  - {validation_summary['network_errors']} network errors")
    if validation_summary["timeouts"] > 0:
        console.print(f"  - {validation_summary['timeouts']} timeouts")
    if validation_summary["not_pinned_to_sha"] > 0:
        console.print(f"  - {validation_summary['not_pinned_to_sha']} actions not pinned to SHA")

    # Show deduplication and API efficiency
    if validation_summary.get("duplicate_calls_avoided", 0) > 0:
        console.print(f"[dim]Deduplication avoided {validation_summary['duplicate_calls_avoided']} redundant validations[/dim]")

    # Show API efficiency metrics
    if validation_summary.get("api_calls_total", 0) > 0:
        console.print(f"[dim]Made {validation_summary['api_calls_total']} API calls "
                    f"({validation_summary['api_calls_graphql']} GraphQL, "
                    f"{validation_summary['cache_hits']} cache hits)[/dim]")

    if validation_summary.get("rate_limit_delays", 0) > 0:
        console.print(f"[yellow]Rate limiting encountered {validation_summary['rate_limit_delays']} times[/yellow]")


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
        ]
    }

    console.print(json.dumps(result, indent=2))


if __name__ == "__main__":
    app()
