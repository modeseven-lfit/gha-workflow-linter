# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Auto-fix functionality for GitHub Actions workflow issues."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from contextlib import nullcontext
import logging
from pathlib import Path
import re
from typing import Any

import httpx
from rich.live import Live
from rich.text import Text

from .auto_fix_versions import _VersionResolutionMixin
from .cache import ValidationCache
from .console import console as _shared_console
from .file_edit import replace_lines
from .git_validator import GitValidationClient
from .github_api import GitHubGraphQLClient
from .models import (
    ActionCall,
    Config,
    ReferenceType,
    ValidationError,
    ValidationMethod,
    ValidationResult,
)
from .patterns import ActionCallPatterns
from .utils import has_test_comment


class AutoFixer(_VersionResolutionMixin):
    """Auto-fixes GitHub Actions workflow issues."""

    def __init__(
        self,
        config: Config,
        base_path: Path | None = None,
        cache: ValidationCache | None = None,
    ) -> None:
        """
        Initialize the auto-fixer.

        Args:
            config: Configuration object.
            base_path: Base path for making file paths relative in output.
            cache: Optional pre-built ``ValidationCache`` shared with the
                validator. When ``None`` the auto-fixer builds its own
                cache.
        """
        self.config = config
        self.base_path = base_path or Path.cwd()
        self.logger = logging.getLogger(__name__)
        self._http_client: httpx.AsyncClient | None = None
        self._graphql_client: GitHubGraphQLClient | None = None
        if cache is not None:
            self._cache = cache
        else:
            # Standalone / library use: build our own cache and prime
            # it so version-mismatch / suspicious-patterns purges happen
            # before any read or write. The CLI path passes a pre-primed
            # shared cache via the ``cache=`` argument; in that case we
            # skip priming here to avoid a second pass.
            self._cache = ValidationCache(config.cache)
            self._cache.prime()
        self._git_client: GitValidationClient | None = None

        # Caching for batch operations (session-level cache)
        self._latest_versions_cache: dict[
            str, tuple[str, str, float]
        ] = {}  # {repo: (tag, sha, timestamp)}
        self._cache_ttl = 300  # 5 minutes

        # Redirect tracking
        self._redirects_seen: set[str] = (
            set()
        )  # Track redirects we've already displayed
        self._redirects_found: set[str] = (
            set()
        )  # Track unique redirected actions
        self._redirect_updates: int = (
            0  # Count of action calls updated due to redirects
        )

    async def __aenter__(self) -> AutoFixer:
        """Async context manager entry."""
        # Initialize HTTP client for redirect detection (works for both validation methods)
        # Uses GitHub web URLs (not API) to avoid rate limits
        headers = {
            "User-Agent": "gha-workflow-linter",
        }

        # Add authentication if available (helps with private repos)
        if self.config.effective_github_token:
            headers["Authorization"] = (
                f"token {self.config.effective_github_token}"
            )

        self._http_client = httpx.AsyncClient(
            timeout=self.config.network.timeout_seconds,
            follow_redirects=False,  # Don't follow, we want to detect redirects
            headers=headers,
        )

        # Use the same validation method as the main validation process
        if self.config.validation_method == ValidationMethod.GITHUB_API:
            self._graphql_client = GitHubGraphQLClient(self.config.github_api)
            await self._graphql_client.__aenter__()
        else:
            # Using Git validation method - initialize Git client
            self._git_client = GitValidationClient(self.config.git)

        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        if self._graphql_client:
            await self._graphql_client.__aexit__(exc_type, exc_val, exc_tb)
        if self._http_client:
            await self._http_client.aclose()

        self._cache.save()

    async def fix_validation_errors(
        self,
        errors: list[ValidationError],
        all_action_calls: dict[Path, dict[int, ActionCall]],
        check_for_updates: bool = False,
    ) -> tuple[
        dict[Path, list[dict[str, str]]],
        dict[str, int],
        dict[str, list[dict[str, Any]]],
    ]:
        """
        Fix validation errors in workflow files using efficient batch processing.

        Args:
            errors: List of validation errors to fix
            all_action_calls: Dict of all action calls to check for updates/fixes (required for batch processing)
            check_for_updates: If True, check all actions and update to latest versions (--auto-latest)
                              If False, only fix validation errors and report outdated versions

        Returns:
            Tuple of:
            - Dictionary mapping file paths to lists of change dictionaries
              Each change dict has 'old_line', 'new_line', and 'line_number' keys
              For skipped items, dict will have 'skipped': True
            - Dictionary with redirect statistics: 'actions_moved' and 'calls_updated'
            - Dictionary mapping relative file paths to lists of outdated action info (for reporting)
        """
        if not self.config.auto_fix:
            # Even if auto_fix is disabled, still collect skipped testing items if fix_test_calls is disabled
            if not self.config.fix_test_calls:
                return (
                    self._collect_skipped_testing_items(errors),
                    {"actions_moved": 0, "calls_updated": 0},
                    {},
                )
            return {}, {"actions_moved": 0, "calls_updated": 0}, {}

        fixes_by_file: dict[Path, dict[int, tuple[str, str]]] = {}
        skipped_by_file: dict[Path, dict[int, str]] = {}
        stale_actions_summary: dict[str, list[dict[str, Any]]] = {}

        # Reset redirect tracking for this run
        self._redirects_found.clear()
        self._redirect_updates = 0

        # Create a set of validation error action calls that need fixing
        # These are actions with validation errors that should always be fixed when auto_fix is enabled
        validation_error_calls: set[tuple[Path, int]] = set()
        for error in errors:
            # Determine if this error should trigger a fix
            should_fix = False

            if error.result == ValidationResult.INVALID_REFERENCE:
                # Invalid reference (SHA/tag/branch doesn't exist) - ALWAYS FIX
                should_fix = True
            elif error.result == ValidationResult.INVALID_REPOSITORY:
                # Invalid repository (might be redirected) - ALWAYS TRY TO FIX
                should_fix = True
            elif error.result == ValidationResult.NOT_PINNED_TO_SHA:
                # Not pinned to SHA - FIX ONLY IF require_pinned_sha is enabled
                should_fix = self.config.require_pinned_sha
            elif error.result == ValidationResult.TEST_REFERENCE:
                # Test reference - skip (unless fix_test_calls is enabled, handled below)
                should_fix = False
            elif error.result in [
                ValidationResult.INVALID_SYNTAX,
                ValidationResult.INVALID_PATH,
                ValidationResult.NETWORK_ERROR,
                ValidationResult.TIMEOUT,
            ]:
                # Cannot auto-fix these - skip.
                # INVALID_PATH means the subdirectory subpath itself is bogus;
                # changing the ref will not make a non-existent path appear.
                should_fix = False

            if should_fix:
                # Check if this action should be skipped due to fix_test_calls flag
                if not self.config.fix_test_calls and has_test_comment(
                    error.action_call
                ):
                    # Track as skipped
                    if error.file_path not in skipped_by_file:
                        skipped_by_file[error.file_path] = {}
                    skipped_by_file[error.file_path][
                        error.action_call.line_number
                    ] = error.action_call.raw_line.strip()
                    file_name = error.file_path.name
                    self.logger.debug(
                        f"Skipped testing action {error.action_call.organization}/{error.action_call.repository} in {file_name} (line {error.action_call.line_number})"
                    )
                    continue

                # Track this as a validation error that should be fixed
                validation_error_calls.add(
                    (error.file_path, error.action_call.line_number)
                )

        # Use batch processing for efficient fixes
        # validation_error_calls will be fixed regardless of check_for_updates setting
        # Non-error updates only applied when check_for_updates=True (--auto-latest)
        console = _shared_console
        if check_for_updates:
            self.logger.debug(
                "Checking all action calls for updates (--auto-latest enabled)"
            )
        else:
            self.logger.debug(
                "Checking all action calls (will fix validation errors and report outdated versions)"
            )

        # Use batch processing for performance
        # Check if we should show live updates (not in quiet mode)
        show_live_updates = self.logger.getEffectiveLevel() < logging.ERROR

        # Use Live context only when not in quiet mode, otherwise use nullcontext
        live_context = (
            Live("", console=console, refresh_per_second=4)
            if show_live_updates
            else nullcontext()
        )

        with live_context as live:
            (
                version_fixes,
                version_skipped,
                stale_summary,
            ) = await self._process_action_calls_batch(
                all_action_calls,
                live if show_live_updates else None,
                check_for_updates=check_for_updates,
                validation_error_calls=validation_error_calls,
                validation_errors=errors,
                show_live_updates=show_live_updates,
            )
            # When check_for_updates=False, only validation errors are fixed (stale_summary populated for reporting)
            # When check_for_updates=True, all fixes are applied (validation errors + version updates)
            for file_path, line_fixes in version_fixes.items():
                if file_path not in fixes_by_file:
                    fixes_by_file[file_path] = {}
                fixes_by_file[file_path].update(line_fixes)

            for file_path, skipped_lines in version_skipped.items():
                if file_path not in skipped_by_file:
                    skipped_by_file[file_path] = {}
                skipped_by_file[file_path].update(skipped_lines)

            stale_actions_summary = stale_summary

        # Apply fixes to files
        applied_fixes: dict[Path, list[dict[str, str]]] = {}
        for file_path, line_fixes in fixes_by_file.items():
            try:
                changes = await self._apply_fixes_to_file(file_path, line_fixes)
                applied_fixes[file_path] = changes
            except Exception as e:
                self.logger.error(f"Failed to apply fixes to {file_path}: {e}")

        # Add skipped items to the output
        for file_path, skipped_lines in skipped_by_file.items():
            if file_path not in applied_fixes:
                applied_fixes[file_path] = []
            for line_num, old_line in skipped_lines.items():
                applied_fixes[file_path].append(
                    {
                        "old_line": old_line,
                        "new_line": old_line,
                        "line_number": str(line_num),
                        "skipped": "true",
                    }
                )

        redirect_stats = {
            "actions_moved": len(self._redirects_found),
            "calls_updated": self._redirect_updates,
        }

        return applied_fixes, redirect_stats, stale_actions_summary

    def _collect_skipped_testing_items(
        self, errors: list[ValidationError]
    ) -> dict[Path, list[dict[str, str]]]:
        """
        Collect items that would be skipped due to testing comments.
        Used when auto_fix is disabled but fix_test_calls is disabled (default).

        Args:
            errors: List of validation errors

        Returns:
            Dictionary mapping file paths to lists of skipped items
        """
        skipped_by_file: dict[Path, list[dict[str, str]]] = {}

        for error in errors:
            # Collect actions with test comments
            if has_test_comment(error.action_call):
                if error.file_path not in skipped_by_file:
                    skipped_by_file[error.file_path] = []
                skipped_by_file[error.file_path].append(
                    {
                        "old_line": error.action_call.raw_line.strip(),
                        "new_line": error.action_call.raw_line.strip(),
                        "line_number": str(error.action_call.line_number),
                        "skipped": "true",
                    }
                )

        return skipped_by_file

    async def _process_action_calls_batch(
        self,
        all_action_calls: dict[Path, dict[int, ActionCall]],
        live: Live | None,
        check_for_updates: bool = False,
        validation_error_calls: set[tuple[Path, int]] | None = None,
        validation_errors: list[ValidationError] | None = None,
        show_live_updates: bool = True,
    ) -> tuple[
        dict[Path, dict[int, tuple[str, str]]],
        dict[Path, dict[int, str]],
        dict[str, list[dict[str, Any]]],
    ]:
        """
        Process all action calls in batch for checking updates and fixes.

        This is the high-performance batch processing implementation that:
        1. Deduplicates repos before fetching
        2. Fetches all latest versions in parallel/batch
        3. Handles INVALID_REFERENCE errors by finding valid references
        4. Fetches all SHAs in parallel/batch
        5. Applies fixes using pre-fetched data

        Args:
            all_action_calls: Dictionary mapping file paths to action calls
            live: Rich Live display for progress updates
            check_for_updates: If True, update to latest versions (--auto-latest)
                              If False, only fix validation errors and report outdated versions
            validation_error_calls: Set of (file_path, line_number) tuples for validation errors
                                   that should always be fixed
            validation_errors: List of ValidationError objects to extract error types from

        Returns:
            Tuple of (fixes_by_file, skipped_by_file, outdated_actions_summary)
        """
        fixes_by_file: dict[Path, dict[int, tuple[str, str]]] = {}
        skipped_by_file: dict[Path, dict[int, str]] = {}
        outdated_actions_summary: dict[str, list[dict[str, Any]]] = defaultdict(
            list
        )

        unique_repos: set[str] = set()
        action_call_list: list[tuple[Path, int, ActionCall]] = []

        for file_path, calls in all_action_calls.items():
            for line_num, action_call in calls.items():
                # Skip test actions if fix_test_calls is disabled
                if not self.config.fix_test_calls and has_test_comment(
                    action_call
                ):
                    if file_path not in skipped_by_file:
                        skipped_by_file[file_path] = {}
                    skipped_by_file[file_path][line_num] = (
                        action_call.raw_line.strip()
                    )
                    continue

                action_call_list.append((file_path, line_num, action_call))
                repo_key = (
                    f"{action_call.organization}/{action_call.repository}"
                )
                base_repo_key = self._get_base_repository(repo_key)
                unique_repos.add(base_repo_key)

        if not action_call_list:
            return fixes_by_file, skipped_by_file, {}

        validation_result_map: dict[tuple[Path, int], ValidationResult] = {}
        if validation_errors:
            for error in validation_errors:
                validation_result_map[
                    (error.file_path, error.action_call.line_number)
                ] = error.result

        # Track which action calls have invalid references
        # We'll handle these after fetching latest versions
        invalid_ref_actions: set[tuple[Path, int]] = set()
        if validation_errors:
            for error in validation_errors:
                if error.result == ValidationResult.INVALID_REFERENCE:
                    invalid_ref_actions.add(
                        (error.file_path, error.action_call.line_number)
                    )

        if show_live_updates and live:
            live.update(
                Text(
                    f"  Fetching latest versions for {len(unique_repos)} unique repositories...",
                    style="dim",
                )
            )

        latest_versions = await self._get_latest_versions_batch(
            list(unique_repos)
        )

        refs_to_resolve: list[tuple[str, str]] = []
        redirect_map: dict[str, str] = {}
        redirected_repos: list[str] = []

        semaphore = asyncio.Semaphore(20)  # Limit concurrent HEAD requests

        async def check_redirect_with_limit(
            repo_key: str,
        ) -> tuple[str, str | None]:
            """Check a single repository for redirects with rate limiting."""
            async with semaphore:
                new_repo = await self._detect_repository_redirect(repo_key)
                return repo_key, new_repo

        redirect_results = await asyncio.gather(
            *[check_redirect_with_limit(rk) for rk in unique_repos]
        )

        for repo_key, new_repo in redirect_results:
            if new_repo:
                redirect_map[repo_key] = new_repo
                redirected_repos.append(new_repo)
                # Track unique redirected actions
                self._redirects_found.add(repo_key)

                # Show redirect message
                if repo_key not in self._redirects_seen:
                    self._redirects_seen.add(repo_key)
                    if show_live_updates and live:
                        moved_msg = Text()
                        moved_msg.append("  Action has moved: ", style="dim")
                        moved_msg.append(repo_key, style="orange3")
                        live.update(moved_msg)
                        await asyncio.sleep(0.3)

                        new_location_msg = Text()
                        new_location_msg.append("  New location: ", style="dim")
                        new_location_msg.append(new_repo, style="green")
                        live.update(new_location_msg)
                        await asyncio.sleep(0.3)

        if redirected_repos:
            if show_live_updates and live:
                live.update(
                    Text(
                        f"  Fetching latest versions for {len(redirected_repos)} redirected repositories...",
                        style="dim",
                    )
                )
            redirected_versions = await self._get_latest_versions_batch(
                redirected_repos
            )
            latest_versions.update(redirected_versions)

        # Step 3c: Collect refs that need SHA resolution (use set for O(1) lookup)
        refs_to_resolve_set: set[tuple[str, str]] = set()

        for repo_key in unique_repos:
            effective_repo = redirect_map.get(repo_key, repo_key)

            # Check in latest_versions using effective (possibly redirected) repo
            if effective_repo in latest_versions:
                tag, sha = latest_versions[effective_repo]
                if not sha:  # SHA not available yet, need to resolve
                    refs_to_resolve_set.add((effective_repo, tag))

        # Step 3d: Collect existing version comments that need SHA verification
        # This avoids N individual API calls during the update loop
        for _file_path, _line_num, action_call in action_call_list:
            if (
                action_call.reference_type == ReferenceType.COMMIT_SHA
                and action_call.comment
            ):
                comment_text = action_call.comment.strip().lstrip("#").strip()
                # If the comment looks like a version tag, we'll need to verify it
                if ActionCallPatterns.VERSION_TAG_PATTERN.match(comment_text):
                    repo_key = (
                        f"{action_call.organization}/{action_call.repository}"
                    )
                    base_repo_key = self._get_base_repository(repo_key)
                    effective_repo = redirect_map.get(
                        base_repo_key, base_repo_key
                    )
                    # Add to batch resolution (set automatically handles duplicates)
                    refs_to_resolve_set.add((effective_repo, comment_text))

        # Convert set to list for batch processing
        refs_to_resolve = list(refs_to_resolve_set)

        if refs_to_resolve:
            if show_live_updates and live:
                live.update(
                    Text(
                        f"  Resolving SHAs for {len(refs_to_resolve)} references...",
                        style="dim",
                    )
                )
            sha_map = await self._get_shas_batch(refs_to_resolve)
        else:
            sha_map = {}

        if show_live_updates and live:
            live.update(
                Text(
                    f"  Checking {len(action_call_list)} action calls for updates...",
                    style="dim",
                )
            )

        for file_path, line_num, action_call in action_call_list:
            try:
                repo_key = (
                    f"{action_call.organization}/{action_call.repository}"
                )
                base_repo_key = self._get_base_repository(repo_key)
                original_base_repo = (
                    base_repo_key  # Keep original for comparison
                )

                try:
                    relative_path = (
                        str(file_path.relative_to(self.base_path))
                        if self.base_path
                        else str(file_path)
                    )
                except ValueError:
                    # File is outside base_path (e.g., temp directory in tests)
                    relative_path = str(file_path)

                # Check if repo was redirected
                new_base_repo = redirect_map.get(base_repo_key)
                repo_was_redirected = False
                if new_base_repo:
                    repo_was_redirected = True
                    # Preserve any path component from original
                    if len(repo_key.split("/")) > 2:
                        # Has path component, append it to new base
                        path_component = "/".join(repo_key.split("/")[2:])
                        repo_key = f"{new_base_repo}/{path_component}"
                    else:
                        repo_key = new_base_repo
                    base_repo_key = new_base_repo
                    # Don't increment counter here - wait until we know a change is needed

                # Check if this action has an invalid reference
                has_invalid_ref = (file_path, line_num) in invalid_ref_actions

                if has_invalid_ref:
                    # For invalid references, try to find a valid replacement
                    # Priority: 1) version from comment (if valid), 2) latest version, 3) fallback reference
                    valid_ref: str | None = None
                    valid_sha: str | None = None

                    # First, check if there's a version comment we can use
                    if action_call.comment:
                        comment_text = (
                            action_call.comment.strip().lstrip("#").strip()
                        )
                        if ActionCallPatterns.VERSION_TAG_PATTERN.match(
                            comment_text
                        ):
                            # Try to get SHA for the comment version
                            if (base_repo_key, comment_text) in sha_map:
                                valid_sha = sha_map[
                                    (base_repo_key, comment_text)
                                ]
                                valid_ref = comment_text
                            else:
                                # Fallback to individual fetch
                                sha_info = (
                                    await self._get_commit_sha_for_reference(
                                        base_repo_key, comment_text
                                    )
                                )
                                if sha_info:
                                    valid_sha = sha_info["sha"]
                                    valid_ref = comment_text

                    # If comment version didn't work, try latest version
                    if not valid_ref:
                        effective_lookup_repo = base_repo_key
                        if effective_lookup_repo in latest_versions:
                            target_ref, cached_sha = latest_versions[
                                effective_lookup_repo
                            ]
                            valid_ref = target_ref
                            valid_sha = cached_sha

                            # Get SHA if not cached
                            if not valid_sha:
                                if (
                                    effective_lookup_repo,
                                    target_ref,
                                ) in sha_map:
                                    valid_sha = sha_map[
                                        (effective_lookup_repo, target_ref)
                                    ]
                                else:
                                    sha_info = await self._get_commit_sha_for_reference(
                                        effective_lookup_repo, target_ref
                                    )
                                    valid_sha = (
                                        sha_info["sha"] if sha_info else None
                                    )

                    # If still no valid ref, use fallback logic
                    if not valid_ref:
                        valid_ref = await self._find_valid_reference(
                            base_repo_key, action_call.reference
                        )

                        if not valid_ref:
                            valid_ref = await self._get_fallback_reference(
                                base_repo_key, action_call.reference
                            )

                        if not valid_ref:
                            # Last resort: use default branch
                            repo_info = await self._get_repository_info(
                                base_repo_key
                            )
                            valid_ref = (
                                repo_info.get("default_branch", "main")
                                if repo_info
                                else "main"
                            )

                        if valid_ref and not valid_sha:
                            if (base_repo_key, valid_ref) in sha_map:
                                valid_sha = sha_map[(base_repo_key, valid_ref)]
                            else:
                                sha_info = (
                                    await self._get_commit_sha_for_reference(
                                        base_repo_key, valid_ref
                                    )
                                )
                                valid_sha = (
                                    sha_info["sha"] if sha_info else None
                                )

                    # Now build the fix if we have a valid reference
                    # When require_pinned_sha is False, we can fix with just the ref
                    if valid_ref and (
                        valid_sha or not self.config.require_pinned_sha
                    ):
                        # Determine final_ref based on require_pinned_sha setting
                        if self.config.require_pinned_sha:
                            # valid_sha is guaranteed to be truthy here due to the outer condition
                            assert (
                                valid_sha is not None
                            )  # Type narrowing for mypy
                            final_ref = valid_sha
                        else:
                            # Can use valid_ref directly when pinning not required
                            assert (
                                valid_ref is not None
                            )  # Type narrowing for mypy
                            final_ref = valid_ref

                        # Set version comment to add to the fixed line (if valid_ref is a version tag)
                        replacement_comment: str | None = (
                            valid_ref
                            if ActionCallPatterns.VERSION_TAG_PATTERN.match(
                                valid_ref
                            )
                            else None
                        )

                        fixed_line = self._build_fixed_line(
                            action_call,
                            final_ref,
                            replacement_comment,
                            repo_key if repo_was_redirected else None,
                        )

                        if (
                            fixed_line
                            and fixed_line != action_call.raw_line.strip()
                        ):
                            if file_path not in fixes_by_file:
                                fixes_by_file[file_path] = {}
                            fixes_by_file[file_path][line_num] = (
                                action_call.raw_line.strip(),
                                fixed_line,
                            )
                            file_name = file_path.name
                            if show_live_updates and live:
                                update_msg = f"  Fixed invalid ref: {action_call.organization}/{action_call.repository} in {file_name}"
                                live.update(Text(update_msg, style="dim"))
                            continue
                    # Invalid reference handled - skip latest version check to avoid redundant processing
                    # (latest version was already tried as part of invalid ref resolution)
                    continue

                # Get latest version info (using the effective repo after redirect)
                effective_lookup_repo = (
                    base_repo_key  # Use the potentially redirected repo
                )
                if effective_lookup_repo in latest_versions:
                    target_ref, cached_sha = latest_versions[
                        effective_lookup_repo
                    ]

                    # Get SHA (from cache or batch-fetched)
                    target_sha: str | None = None
                    if cached_sha:
                        target_sha = cached_sha
                    elif (effective_lookup_repo, target_ref) in sha_map:
                        target_sha = sha_map[
                            (effective_lookup_repo, target_ref)
                        ]
                    else:
                        # Fallback to individual fetch (shouldn't happen often)
                        sha_info = await self._get_commit_sha_for_reference(
                            effective_lookup_repo, target_ref
                        )
                        target_sha = sha_info["sha"] if sha_info else None

                    if target_sha:
                        # Check if this is actually a change
                        final_ref = (
                            target_sha
                            if self.config.require_pinned_sha
                            else target_ref
                        )
                        version_comment: str | None = (
                            target_ref
                            if ActionCallPatterns.VERSION_TAG_PATTERN.match(
                                target_ref
                            )
                            else None
                        )

                        # Fix false update bug: Check if anything actually changed
                        existing_comment: str | None = None
                        if action_call.comment:
                            existing_comment = (
                                action_call.comment.strip().lstrip("#").strip()
                            )

                        # Check if current SHA doesn't match the version in its own comment (corrupted reference)
                        has_mismatched_sha = False
                        existing_version_sha: str | None = None
                        if (
                            existing_comment
                            and action_call.reference_type
                            == ReferenceType.COMMIT_SHA
                            and ActionCallPatterns.VERSION_TAG_PATTERN.match(
                                existing_comment
                            )
                        ):
                            # Use pre-fetched SHA from batch resolution (Step 3d)
                            existing_version_sha = sha_map.get(
                                (effective_lookup_repo, existing_comment)
                            )
                            if (
                                existing_version_sha
                                and action_call.reference
                                != existing_version_sha
                            ):
                                # If current SHA doesn't match what the comment claims, it's corrupted/mismatched
                                has_mismatched_sha = True

                        # Check if repository changed (compare new vs original)
                        repo_changed = repo_was_redirected or (
                            base_repo_key != original_base_repo
                        )
                        comment_changed = (
                            (version_comment != existing_comment)
                            if version_comment
                            else False
                        )
                        ref_changed = final_ref != action_call.reference

                        # When has_mismatched_sha is True, we should fix to the CURRENT version
                        # (from the comment), not upgrade to latest version
                        # This takes priority regardless of check_for_updates setting
                        if has_mismatched_sha:
                            # Use the existing comment version instead of latest
                            fix_ref = (
                                existing_version_sha
                                if self.config.require_pinned_sha
                                and existing_version_sha
                                else existing_comment
                            )
                            fix_comment = existing_comment

                            # Only fix if we have a valid reference
                            if fix_ref:
                                fixed_line = self._build_fixed_line(
                                    action_call,
                                    fix_ref,
                                    fix_comment,
                                    repo_key if repo_was_redirected else None,
                                )

                                if (
                                    fixed_line
                                    and fixed_line
                                    != action_call.raw_line.strip()
                                ):
                                    if file_path not in fixes_by_file:
                                        fixes_by_file[file_path] = {}
                                    fixes_by_file[file_path][line_num] = (
                                        action_call.raw_line.strip(),
                                        fixed_line,
                                    )
                                    file_name = file_path.name
                                    if show_live_updates and live:
                                        update_msg = f"  Fixed mismatched SHA: {action_call.organization}/{action_call.repository} in {file_name}"
                                        live.update(
                                            Text(update_msg, style="dim")
                                        )
                        elif ref_changed or comment_changed or repo_changed:
                            fixed_line = self._build_fixed_line(
                                action_call,
                                final_ref,
                                version_comment,
                                repo_key if repo_changed else None,
                            )

                            if (
                                fixed_line
                                and fixed_line != action_call.raw_line.strip()
                            ):
                                # Increment redirect counter if this change is due to a redirect
                                if repo_was_redirected:
                                    self._redirect_updates += 1

                                # Check if this is a validation error or has mismatched SHA (both considered "invalid")
                                is_validation_error = (
                                    validation_error_calls
                                    and (file_path, line_num)
                                    in validation_error_calls
                                )
                                # Note: has_mismatched_sha is already handled above, so it won't reach here
                                # when check_for_updates=False
                                is_invalid = is_validation_error

                                if not check_for_updates and not is_invalid:
                                    # When check_for_updates=False, only report non-invalid outdated actions
                                    # Invalid actions are always fixed
                                    outdated_actions_summary[
                                        relative_path
                                    ].append(
                                        {
                                            "line": line_num,
                                            "action": repo_key
                                            if repo_was_redirected
                                            else f"{action_call.organization}/{action_call.repository}",
                                            "current_ref": action_call.reference,
                                            "current_comment": action_call.comment,
                                            "latest_ref": target_sha,
                                            "latest_version": target_ref,
                                            "redirected": repo_was_redirected,
                                            "is_invalid": is_invalid,
                                        }
                                    )
                                    file_name = file_path.name
                                    if show_live_updates and live:
                                        check_msg = f"  Checking: {action_call.organization}/{action_call.repository} in {file_name}"
                                        live.update(
                                            Text(check_msg, style="dim")
                                        )
                                else:
                                    # When check_for_updates=True or for invalid items, apply the fix
                                    if file_path not in fixes_by_file:
                                        fixes_by_file[file_path] = {}
                                    fixes_by_file[file_path][line_num] = (
                                        action_call.raw_line.strip(),
                                        fixed_line,
                                    )
                                    file_name = file_path.name
                                    if show_live_updates and live:
                                        update_msg = f"  Updated: {action_call.organization}/{action_call.repository} in {file_name}"
                                        live.update(
                                            Text(update_msg, style="dim")
                                        )
            except Exception as e:
                self.logger.warning(
                    f"Failed to update {action_call.organization}/{action_call.repository}@{action_call.reference}: {e}"
                )

        return fixes_by_file, skipped_by_file, dict(outdated_actions_summary)

    async def _fix_action_call_with_redirect(
        self,
        action_call: ActionCall,
        validation_result: ValidationResult,
        live: Live | None = None,
        show_live_updates: bool = True,
    ) -> dict[str, Any] | None:
        """
        Fix a single action call and track redirects.

        Args:
            action_call: The action call to fix
            validation_result: The validation result that indicates what needs fixing
            live: Optional Rich Live display for showing redirect messages

        Returns:
            Dictionary with 'fixed_line' and optional redirect info, or None if couldn't be fixed
        """
        repo_key = f"{action_call.organization}/{action_call.repository}"
        base_repo_key = self._get_base_repository(repo_key)

        # Check if repository has been redirected/moved
        (
            repo_key,
            base_repo_key,
            redirect_info,
        ) = await self._resolve_redirect_for_fix(
            action_call, repo_key, base_repo_key, live
        )

        # Get repository information (if API available) - use base repo
        repo_info = await self._get_repository_info(base_repo_key)
        default_branch = (
            repo_info.get("default_branch", "main") if repo_info else "main"
        )

        # Determine the target reference
        original_ref = action_call.reference
        target_ref = await self._determine_target_ref(
            action_call, validation_result, base_repo_key, default_branch
        )

        # Resolve the target SHA and version comment (pinning as configured)
        (
            target_sha,
            version_comment,
            cannot_pin,
        ) = await self._resolve_sha_and_comment(
            action_call,
            validation_result,
            base_repo_key,
            target_ref,
            original_ref,
            default_branch,
        )
        if cannot_pin:
            # Without access to resolve SHAs, we can't fix NOT_PINNED_TO_SHA.
            return (
                {"fixed_line": None, "redirect_info": redirect_info}
                if redirect_info
                else None
            )

        # Check if we actually have a change to make
        final_ref = target_sha or target_ref
        repo_changed = base_repo_key != self._get_base_repository(
            f"{action_call.organization}/{action_call.repository}"
        )

        # Fix false update bug: Check if version comment actually changed
        existing_comment = None
        if action_call.comment:
            existing_comment = action_call.comment.strip().lstrip("#").strip()
        comment_changed = (
            (version_comment != existing_comment) if version_comment else False
        )

        if (
            final_ref == action_call.reference
            and not comment_changed
            and not repo_changed
        ):
            # No actual change needed
            return (
                {"fixed_line": None, "redirect_info": redirect_info}
                if redirect_info
                else None
            )

        # Build the fixed line - pass new repo if it changed
        fixed_line = self._build_fixed_line(
            action_call,
            final_ref,
            version_comment,
            repo_key if repo_changed else None,
        )

        return {"fixed_line": fixed_line, "redirect_info": redirect_info}

    async def _resolve_redirect_for_fix(
        self,
        action_call: ActionCall,
        repo_key: str,
        base_repo_key: str,
        live: Live | None,
    ) -> tuple[str, str, dict[str, Any] | None]:
        """Detect and apply a repository redirect for an action call.

        Returns the (possibly updated) ``repo_key`` and ``base_repo_key``
        alongside ``redirect_info`` (``None`` when the repository has not
        moved). Also records the redirect for statistics and, when a live
        display is supplied, surfaces a one-off "Action has moved" message.
        """
        new_base_repo = await self._detect_repository_redirect(base_repo_key)
        if not new_base_repo:
            return repo_key, base_repo_key, None

        # Repository has moved - update the repo key, preserving any path
        # component from the original reference.
        if len(repo_key.split("/")) > 2:
            path_component = "/".join(repo_key.split("/")[2:])
            repo_key = f"{new_base_repo}/{path_component}"
        else:
            repo_key = new_base_repo
        base_repo_key = new_base_repo
        self.logger.debug(
            f"Using redirected repository: {action_call.organization}/"
            f"{action_call.repository} -> {repo_key}"
        )

        old_repo = f"{action_call.organization}/{action_call.repository}"
        # Track unique redirected actions
        self._redirects_found.add(old_repo)

        if old_repo not in self._redirects_seen and live:
            self._redirects_seen.add(old_repo)
            await self._display_redirect_messages(old_repo, new_base_repo, live)

        redirect_info = {"old_repo": old_repo, "new_repo": new_base_repo}
        return repo_key, base_repo_key, redirect_info

    async def _display_redirect_messages(
        self, old_repo: str, new_base_repo: str, live: Live
    ) -> None:
        """Show the "Action has moved / New location" live-display messages."""
        # Show "Action has moved" message in orange
        moved_msg = Text()
        moved_msg.append("  Action has moved: ", style="dim")
        moved_msg.append(old_repo, style="orange3")
        live.update(moved_msg)
        await asyncio.sleep(0.5)  # Brief pause so user can see the message

        # Show "New location" message in green
        new_location_msg = Text()
        new_location_msg.append("  New location: ", style="dim")
        new_location_msg.append(new_base_repo, style="green")
        live.update(new_location_msg)
        await asyncio.sleep(0.5)  # Brief pause so user can see the message

    async def _determine_target_ref(
        self,
        action_call: ActionCall,
        validation_result: ValidationResult,
        base_repo_key: str,
        default_branch: str,
    ) -> str:
        """Choose the reference to fix an action call to.

        Uses the latest release/tag when ``update_actions`` is set, otherwise
        repairs an invalid reference (with a fallback), and finally falls
        back to the default branch. Non-fixable cases keep the current
        reference (e.g. NOT_PINNED_TO_SHA).
        """
        if self.config.update_actions:
            # Use latest release/tag if available - use base repo
            target_ref = await self._get_latest_release_or_tag(base_repo_key)
            if not target_ref:
                # Fall back to default branch
                target_ref = default_branch
        elif validation_result == ValidationResult.INVALID_REFERENCE:
            # Invalid reference, try to find a valid one - use base repo
            target_ref = await self._find_valid_reference(
                base_repo_key, action_call.reference
            )
            if not target_ref:
                target_ref = await self._get_fallback_reference(
                    base_repo_key, action_call.reference
                )
            if not target_ref:
                # Fall back to default branch
                target_ref = default_branch
        else:
            # Keep the current reference for NOT_PINNED_TO_SHA cases
            target_ref = action_call.reference
        return target_ref

    async def _resolve_sha_and_comment(
        self,
        action_call: ActionCall,
        validation_result: ValidationResult,
        base_repo_key: str,
        target_ref: str,
        original_ref: str,
        default_branch: str,
    ) -> tuple[str | None, str | None, bool]:
        """Resolve the commit SHA and version comment for a fix.

        Returns ``(target_sha, version_comment, cannot_pin)``. ``cannot_pin``
        is ``True`` only when a NOT_PINNED_TO_SHA reference could not be
        resolved to a SHA, signalling the caller to abandon the fix.
        """
        target_sha = None
        version_comment = None

        if not (
            self.config.require_pinned_sha
            or action_call.reference_type != ReferenceType.COMMIT_SHA
        ):
            return target_sha, version_comment, False

        # Try to get SHA (API or Git) - use base repo
        sha_info = await self._get_commit_sha_for_reference(
            base_repo_key, target_ref
        )
        if sha_info:
            target_sha = sha_info["sha"]
            # If target_ref looks like a version tag, use it in comment
            if (
                ActionCallPatterns.VERSION_TAG_PATTERN.match(target_ref)
                or target_ref != default_branch
            ):
                version_comment = target_ref
            elif (
                original_ref != default_branch
                and validation_result == ValidationResult.NOT_PINNED_TO_SHA
            ):
                # Preserve original branch name when falling back to default
                version_comment = original_ref
        # Without access to resolve SHAs, we can't fix NOT_PINNED_TO_SHA issues
        elif validation_result == ValidationResult.NOT_PINNED_TO_SHA:
            self.logger.debug(
                f"Cannot resolve SHA for {base_repo_key}@{target_ref}, "
                f"skipping SHA pinning"
            )
            return target_sha, version_comment, True

        # If we couldn't get SHA but target_ref is a version tag, still set the
        # comment. This handles cases where SHA resolution fails but we're
        # still updating the version.
        if (
            not target_sha
            and target_ref
            and ActionCallPatterns.VERSION_TAG_PATTERN.match(target_ref)
        ):
            version_comment = target_ref

        return target_sha, version_comment, False

    def _build_fixed_line(
        self,
        action_call: ActionCall,
        new_ref: str,
        version_comment: str | None = None,
        new_repo: str | None = None,
    ) -> str:
        """Build the fixed action call line."""
        original_line = action_call.raw_line

        # Match the full structure with optional dash
        # First try: indentation + "- " + "uses: "
        structure_match = re.match(r"^(\s*-\s*uses:\s*)", original_line)
        if structure_match:
            prefix = structure_match.group(1)
        else:
            # Second try: indentation + "uses: " (no dash)
            structure_match = re.match(r"^(\s*uses:\s*)", original_line)
            if structure_match:
                prefix = structure_match.group(1)
            else:
                # Fallback: extract indentation and add basic "uses: "
                indent_match = re.match(r"^(\s*)", original_line)
                indent = indent_match.group(1) if indent_match else ""
                prefix = f"{indent}uses: "

        # Build the new action reference
        # Use new_repo if provided (for repository redirects), otherwise use original
        if new_repo:
            new_action_ref = f"{new_repo}@{new_ref}"
        else:
            new_action_ref = (
                f"{action_call.organization}/{action_call.repository}@{new_ref}"
            )

        # Add version comment if needed
        comment_part = ""
        if version_comment and self.config.require_pinned_sha:
            comment_spacing = "  " if self.config.two_space_comments else " "
            comment_part = f"{comment_spacing}# {version_comment}"
        elif action_call.comment:
            # Preserve existing comment (which already includes the # symbol)
            comment_spacing = "  " if self.config.two_space_comments else " "
            # Strip leading # if present to avoid duplication
            clean_comment = action_call.comment.lstrip("#").strip()
            comment_part = f"{comment_spacing}# {clean_comment}"

        final_line = f"{prefix}{new_action_ref}{comment_part}"
        return final_line

    async def _apply_fixes_to_file(
        self, file_path: Path, line_fixes: dict[int, tuple[str, str]]
    ) -> list[dict[str, str]]:
        """Rewrite a workflow file with the supplied line fixes.

        The rewrite is delegated to
        :func:`~gha_workflow_linter.file_edit.replace_lines`, which
        publishes a sibling temporary file with a single
        :func:`os.replace`, so the workflow file is either fully updated
        or left byte-for-byte unchanged. Each rewritten line keeps the
        terminator it already had, so a CRLF file stays CRLF and a file
        without a trailing newline does not gain one.

        Args:
            file_path: Workflow file to rewrite.
            line_fixes: Mapping of 1-based line number to an
                ``(old_line, new_line)`` pair. Only ``new_line`` is
                written; the caller's ``old_line`` is not used. An empty
                mapping is a no-op that does not open or touch the file.

        Returns:
            One dict per fixed line, ordered by line number, with the
            keys ``line_number`` (stringified), ``old_line``, and
            ``new_line``. ``old_line`` is the content actually read from
            disk rather than the caller-supplied value, so a rendered
            diff cannot disagree with the file it describes.

        Raises:
            ValueError: If a line number is out of range for the file, or
                a replacement spans more than one line. Previously an
                out-of-range line was silently skipped; the whole file is
                now left untouched instead of partially rewritten.
            OSError: If the file cannot be read, or the replacement
                cannot be written or moved into place.
        """
        try:
            changes = replace_lines(
                file_path,
                {
                    line_number: new_line
                    for line_number, (_old, new_line) in line_fixes.items()
                },
            )
        except Exception as e:
            self.logger.error(f"Failed to apply fixes to {file_path}: {e}")
            raise

        return [
            {
                "line_number": str(change.line_number),
                "old_line": change.old_line,
                "new_line": change.new_line,
            }
            for change in changes
        ]
