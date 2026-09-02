#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""
Async execution tracer for GHA Workflow Linter.

This script traces async/await patterns to identify where the code is
running serially instead of in parallel. It helps identify bottlenecks
where we're awaiting operations one at a time instead of using
asyncio.gather() or similar parallel patterns.
"""

import argparse
import asyncio
import contextlib
import functools
from pathlib import Path
import sys
import time
from typing import Any

# Add parent directory to path to import the linter
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class AsyncTracer:
    """Traces async function calls to identify serial vs parallel execution."""

    def __init__(self) -> None:
        self.call_stack: list[tuple[str, float]] = []
        self.call_times: dict[str, list[float]] = {}
        self.parallel_opportunities: list[Any] = []
        self.serial_chains: list[list[str]] = []
        self.current_chain: list[str] = []

    def trace_async_call(self, func_name: str, start: bool) -> None:
        """Record an async function call."""
        timestamp = time.perf_counter()

        if start:
            # Starting a new async call
            self.call_stack.append((func_name, timestamp))
            self.current_chain.append(func_name)
        # Ending an async call
        elif self.call_stack:
            name, start_time = self.call_stack.pop()
            elapsed = timestamp - start_time

            if func_name not in self.call_times:
                self.call_times[func_name] = []
            self.call_times[func_name].append(elapsed)

            # Check if this could have been parallel
            if len(self.current_chain) > 1:
                self.serial_chains.append(list(self.current_chain))

            if self.current_chain and self.current_chain[-1] == func_name:
                self.current_chain.pop()

    def wrap_async_function(self, func: Any) -> Any:
        """Wrap an async function to trace its execution."""
        if not asyncio.iscoroutinefunction(func):
            return func

        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            func_name = f"{func.__module__}.{func.__qualname__}"
            self.trace_async_call(func_name, start=True)
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                self.trace_async_call(func_name, start=False)

        return wrapper

    def print_report(self) -> None:
        """Print a report of async execution patterns."""
        print("\n" + "=" * 70)
        print("ASYNC EXECUTION TRACE REPORT")
        print("=" * 70)

        # Sort functions by total time
        func_stats = {}
        for func_name, times in self.call_times.items():
            func_stats[func_name] = {
                "calls": len(times),
                "total_time": sum(times),
                "avg_time": sum(times) / len(times),
                "max_time": max(times),
                "min_time": min(times),
            }

        sorted_funcs = sorted(
            func_stats.items(), key=lambda x: x[1]["total_time"], reverse=True
        )

        print("\n📊 TOP ASYNC FUNCTIONS BY TOTAL TIME:")
        print("-" * 70)
        for func_name, stats in sorted_funcs[:20]:
            # Shorten module path for readability
            short_name = func_name.split(".")[-1]
            module = ".".join(func_name.split(".")[:-1])
            if "gha_workflow_linter" in module:
                module = module.replace("gha_workflow_linter.", "")

            print(f"\n{short_name} ({module})")
            print(f"  Calls:      {stats['calls']}")
            print(f"  Total time: {stats['total_time']:.3f}s")
            print(f"  Avg time:   {stats['avg_time']:.3f}s")
            print(f"  Max time:   {stats['max_time']:.3f}s")

        # Identify potential parallelization opportunities
        print("\n" + "=" * 70)
        print("🔍 SERIAL EXECUTION PATTERNS (Potential Bottlenecks)")
        print("=" * 70)

        # Look for repeated calls to the same function
        for func_name, times in self.call_times.items():
            if len(times) > 1:
                short_name = func_name.split(".")[-1]
                total_time = sum(times)
                if total_time > 1.0:  # Only show if significant time
                    print(f"\n⚠️  {short_name}")
                    print(f"   Called {len(times)} times sequentially")
                    print(f"   Total time: {total_time:.3f}s")
                    print(
                        "   Could potentially run in parallel with asyncio.gather()"
                    )
                    print(
                        f"   Potential speedup: {len(times)}x (if fully parallelizable)"
                    )

        print("\n" + "=" * 70)
        print("💡 RECOMMENDATIONS")
        print("=" * 70)

        print("""
Based on the trace, here are optimization opportunities:

1. 🚀 BATCH API CALLS:
   - Look for functions making multiple similar API calls
   - Use asyncio.gather() to run them concurrently
   - Example: await asyncio.gather(*[validate_repo(r) for r in repos])

2. 🔄 PARALLEL FILE PROCESSING:
   - If scanning/parsing multiple files, process them concurrently
   - Use asyncio.gather() or asyncio.TaskGroup
   - Example: await asyncio.gather(*[parse_file(f) for f in files])

3. 📊 GRAPHQL BATCHING:
   - GraphQL queries are already batched, but ensure they're awaited together
   - Multiple separate batches should use gather() not sequential await
   - Check if batch size is optimal for your workload

4. ⚡ RATE LIMIT AWARE CONCURRENCY:
   - Use asyncio.Semaphore to limit concurrent operations
   - This prevents overwhelming the API while still parallelizing
   - Example: sem = asyncio.Semaphore(10); async with sem: await api_call()

5. 🎯 FOCUS AREAS:
   - Functions called many times with similar args = batch opportunity
   - Long-running functions = prime candidates for parallelization
   - Sequential loops over collections = use gather() or TaskGroup
        """)


def monkey_patch_async_functions() -> AsyncTracer:
    """Monkey-patch async functions in the linter to trace execution."""
    tracer: AsyncTracer = AsyncTracer()

    # Import modules to patch
    from gha_workflow_linter import (
        action_call_check,
        action_call_fix,
        github_api,
    )

    # Patch GitHubGraphQLClient methods
    for attr_name in dir(github_api.GitHubGraphQLClient):
        if attr_name.startswith("_") and not attr_name.startswith("__"):
            attr = getattr(github_api.GitHubGraphQLClient, attr_name)
            if asyncio.iscoroutinefunction(attr):
                setattr(
                    github_api.GitHubGraphQLClient,
                    attr_name,
                    tracer.wrap_async_function(attr),
                )

    # Patch public methods too
    for method in ["validate_repositories_batch", "validate_references_batch"]:
        original = getattr(github_api.GitHubGraphQLClient, method)
        setattr(
            github_api.GitHubGraphQLClient,
            method,
            tracer.wrap_async_function(original),
        )

    # Patch action_call_check methods
    for attr_name in dir(action_call_check.ActionCallValidator):
        if attr_name.startswith("_") or attr_name.startswith("validate"):
            attr = getattr(action_call_check.ActionCallValidator, attr_name)
            if asyncio.iscoroutinefunction(attr):
                setattr(
                    action_call_check.ActionCallValidator,
                    attr_name,
                    tracer.wrap_async_function(attr),
                )

    # Patch AutoFixer methods if action_call_fix module exists
    try:
        for attr_name in dir(action_call_fix.AutoFixer):
            attr = getattr(action_call_fix.AutoFixer, attr_name)
            if asyncio.iscoroutinefunction(attr):
                setattr(
                    action_call_fix.AutoFixer,
                    attr_name,
                    tracer.wrap_async_function(attr),
                )
    except AttributeError:
        # Expected - action_call_fix module may not have all attributes during inspection
        pass

    return tracer


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Trace async execution in GHA Workflow Linter"
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to scan (default: current directory)",
    )
    parser.add_argument(
        "--no-parallel",
        action="store_true",
        help="Run without parallel workers",
    )
    parser.add_argument(
        "--workers", type=int, help="Number of parallel workers"
    )
    parser.add_argument(
        "--clear-cache", action="store_true", help="Clear cache before running"
    )

    args = parser.parse_args()

    print("=" * 70)
    print("Starting async execution tracing...")
    print("=" * 70)
    print("\nThis will run the linter and trace all async function calls.")
    print(
        "The trace report will show where serial execution can be parallelized.\n"
    )

    # Monkey-patch async functions before importing CLI
    tracer = monkey_patch_async_functions()

    # Import CLI after patching
    from gha_workflow_linter.cli import app as cli_app

    # Build CLI arguments
    cli_args = ["gha-workflow-linter", args.path]

    if args.no_parallel:
        cli_args.append("--no-parallel")
    elif args.workers:
        cli_args.extend(["--workers", str(args.workers)])

    if args.clear_cache:
        cli_args.append("--clear-cache")

    # Backup and replace sys.argv
    original_argv = sys.argv
    sys.argv = cli_args

    try:
        start_time = time.perf_counter()

        # Run the linter
        with contextlib.suppress(SystemExit):
            cli_app()

        end_time = time.perf_counter()

        print("\n" + "=" * 70)
        print(f"Execution completed in {end_time - start_time:.3f}s")
        print("=" * 70)

        # Print trace report
        tracer.print_report()

    finally:
        sys.argv = original_argv


if __name__ == "__main__":
    main()
