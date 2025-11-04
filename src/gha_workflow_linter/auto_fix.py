# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Auto-fix functionality for GitHub Actions workflow issues."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import httpx

from .cache import ValidationCache
from .exceptions import GitHubAPIError, GitError, NetworkError
from .git_validator import GitValidationClient, _get_remote_branches, _get_remote_tags
from .models import (
    ActionCall,
    Config,
    ReferenceType,
    ValidationError,
    ValidationMethod,
    ValidationResult,
)


class AutoFixer:
    """Auto-fixes GitHub Actions workflow issues."""

    def __init__(self, config: Config) -> None:
        """
        Initialize the auto-fixer.

        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._http_client: httpx.AsyncClient | None = None
        self._cache = ValidationCache(config.cache)
        self._git_client: GitValidationClient | None = None


    async def __aenter__(self) -> AutoFixer:
        """Async context manager entry."""
        # Use the same validation method as the main validation process
        if self.config.validation_method == ValidationMethod.GITHUB_API:
            # Initialize HTTP client for additional API calls not covered by GraphQL
            if self.config.effective_github_token:
                self._http_client = httpx.AsyncClient(
                    timeout=self.config.network.timeout_seconds,
                    headers={
                        "User-Agent": "gha-workflow-linter",
                        "Accept": "application/vnd.github.v3+json",
                        "Authorization": f"token {self.config.effective_github_token}",
                    },
                )
        else:
            # Using Git validation method - initialize Git client
            self._git_client = GitValidationClient(self.config.git)

        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        if self._http_client:
            await self._http_client.aclose()

    async def fix_validation_errors(
        self, errors: list[ValidationError]
    ) -> dict[Path, list[dict[str, str]]]:
        """
        Fix validation errors in workflow files.

        Args:
            errors: List of validation errors to fix

        Returns:
            Dictionary mapping file paths to lists of change dictionaries
            Each change dict has 'old_line', 'new_line', and 'line_number' keys
        """
        if not self.config.auto_fix:
            return {}

        fixes_by_file: dict[Path, dict[int, tuple[str, str]]] = {}

        for error in errors:
            if error.result in [
                ValidationResult.INVALID_REFERENCE,
                ValidationResult.NOT_PINNED_TO_SHA,
            ]:
                try:
                    fixed_line = await self._fix_action_call(error.action_call, error.result)
                    if fixed_line:
                        if error.file_path not in fixes_by_file:
                            fixes_by_file[error.file_path] = {}
                        fixes_by_file[error.file_path][error.action_call.line_number] = (
                            error.action_call.raw_line.strip(),
                            fixed_line
                        )
                        self.logger.info(
                            f"Fixed {error.action_call.organization}/{error.action_call.repository}@{error.action_call.reference} "
                            f"in {error.file_path}:{error.action_call.line_number}"
                        )
                except Exception as e:
                    self.logger.warning(
                        f"Failed to fix {error.action_call.organization}/{error.action_call.repository}@{error.action_call.reference}: {e}"
                    )

        # Apply fixes to files
        applied_fixes: dict[Path, list[dict[str, str]]] = {}
        for file_path, line_fixes in fixes_by_file.items():
            try:
                changes = await self._apply_fixes_to_file(file_path, line_fixes)
                applied_fixes[file_path] = changes
            except Exception as e:
                self.logger.error(f"Failed to apply fixes to {file_path}: {e}")

        return applied_fixes

    async def _fix_action_call(self, action_call: ActionCall, validation_result: ValidationResult) -> str | None:
        """
        Fix a single action call.

        Args:
            action_call: The action call to fix
            validation_result: The validation result that indicates what needs fixing

        Returns:
            Fixed line content or None if couldn't be fixed
        """
        repo_key = f"{action_call.organization}/{action_call.repository}"

        # Get repository information (if API available)
        repo_info = await self._get_repository_info(repo_key)
        default_branch = repo_info.get("default_branch", "main") if repo_info else "main"

        # Determine the target reference
        original_ref = action_call.reference
        if self.config.auto_latest:
            # Use latest release/tag if available
            target_ref = await self._get_latest_release_or_tag(repo_key)
            if not target_ref:
                # Fall back to default branch
                target_ref = default_branch
        else:
            # Try to fix the current reference based on validation error type
            if validation_result == ValidationResult.INVALID_REFERENCE:
                # Invalid reference, try to find a valid one
                target_ref = await self._find_valid_reference(repo_key, action_call.reference)
                if not target_ref:
                    target_ref = await self._get_fallback_reference(repo_key, action_call.reference)

                if not target_ref:
                    # Fall back to default branch
                    target_ref = default_branch
            else:
                # Keep the current reference for NOT_PINNED_TO_SHA cases
                target_ref = action_call.reference

        # Get commit SHA for the target reference if we need to pin to SHA
        target_sha = None
        version_comment = None

        if self.config.require_pinned_sha or action_call.reference_type != ReferenceType.COMMIT_SHA:
            # Try to get SHA (API or Git)
            sha_info = await self._get_commit_sha_for_reference(repo_key, target_ref)
            if sha_info:
                target_sha = sha_info["sha"]
                # If target_ref looks like a version tag, use it in comment
                if re.match(r"^v?\d+\.\d+", target_ref):
                    version_comment = target_ref
                elif target_ref != default_branch:
                    version_comment = target_ref
                elif original_ref != default_branch and validation_result == ValidationResult.NOT_PINNED_TO_SHA:
                    # Preserve original branch name when falling back to default branch
                    version_comment = original_ref
            else:
                # Without access to resolve SHAs, we can't fix NOT_PINNED_TO_SHA issues
                if validation_result == ValidationResult.NOT_PINNED_TO_SHA:
                    self.logger.debug(f"Cannot resolve SHA for {repo_key}@{target_ref}, skipping SHA pinning")
                    return None

        # Check if we actually have a change to make
        final_ref = target_sha or target_ref
        if final_ref == action_call.reference and not version_comment:
            # No actual change needed
            return None

        # Build the fixed line
        return self._build_fixed_line(action_call, final_ref, version_comment)

    async def _get_repository_info(self, repo_key: str) -> dict[str, Any] | None:
        """Get repository information using the configured validation method."""
        # Use API if we're in GitHub API validation mode
        if self.config.validation_method == ValidationMethod.GITHUB_API and self._http_client:
            try:
                response = await self._http_client.get(f"https://api.github.com/repos/{repo_key}")
                response.raise_for_status()
                return response.json()  # type: ignore[no-any-return]
            except Exception as e:
                self.logger.debug(f"Failed to get repository info via API for {repo_key}: {e}")

        # Use Git operations if we're in Git validation mode
        if self.config.validation_method == ValidationMethod.GIT and self._git_client:
            try:
                url = f"https://github.com/{repo_key}.git"
                branches = _get_remote_branches(url, self.config.git)

                # Determine default branch from available branches
                default_branch = "main"
                if "main" in branches:
                    default_branch = "main"
                elif "master" in branches:
                    default_branch = "master"
                elif branches:
                    # Use the first branch if neither main nor master exists
                    default_branch = sorted(branches)[0]

                return {"default_branch": default_branch}
            except GitError as e:
                self.logger.debug(f"Failed to get repository info via Git for {repo_key}: {e}")

        return None

    async def _get_fallback_reference(self, repo_key: str, invalid_ref: str) -> str | None:
        """Get fallback reference using Git operations or cached data."""
        # First check cache for known valid references for this repository
        cached_entry = self._cache.get(repo_key, "main")
        if cached_entry and cached_entry.result == ValidationResult.VALID:
            return "main"

        cached_entry = self._cache.get(repo_key, "master")
        if cached_entry and cached_entry.result == ValidationResult.VALID:
            return "master"

        # Try Git operations if we have the client
        if self._git_client:
            try:
                url = f"https://github.com/{repo_key}.git"
                branches = _get_remote_branches(url, self.config.git)

                # Common fallbacks for invalid references
                if invalid_ref == "master" and "main" in branches:
                    return "main"
                elif invalid_ref == "main" and "master" in branches:
                    return "master"
                elif invalid_ref.startswith("invalid"):
                    # Return the first common default branch found
                    for default_branch in ["main", "master"]:
                        if default_branch in branches:
                            return default_branch

                # Try to find similar branch names
                for branch in branches:
                    if branch.endswith(invalid_ref) or invalid_ref in branch:
                        return branch

            except GitError as e:
                self.logger.debug(f"Git fallback failed for {repo_key}: {e}")

        # Final fallbacks without Git access
        if invalid_ref == "master":
            return "main"
        elif invalid_ref == "main":
            return "master"
        elif invalid_ref.startswith("invalid"):
            return "main"
        return None

    async def _get_latest_release_or_tag(self, repo_key: str) -> str | None:
        """Get the latest release or tag for a repository."""
        # Use API if we're in GitHub API validation mode
        if self.config.validation_method == ValidationMethod.GITHUB_API and self._http_client:
            # Try to get latest release first
            try:
                response = await self._http_client.get(f"https://api.github.com/repos/{repo_key}/releases/latest")
                if response.status_code == 200:
                    release_data = response.json()
                    return release_data.get("tag_name")  # type: ignore[no-any-return]
            except Exception:
                pass

            # Fall back to getting latest tag via API
            try:
                response = await self._http_client.get(f"https://api.github.com/repos/{repo_key}/tags?per_page=1")
                response.raise_for_status()
                tags = response.json()
                if tags:
                    return tags[0]["name"]  # type: ignore[no-any-return]
            except Exception as e:
                self.logger.debug(f"Failed to get latest tag via API for {repo_key}: {e}")

        # Use Git operations if we're in Git validation mode
        if self.config.validation_method == ValidationMethod.GIT and self._git_client:
            try:
                url = f"https://github.com/{repo_key}.git"
                git_tags = _get_remote_tags(url, self.config.git)

                if git_tags:
                    # Convert to sorted list (Git ls-remote doesn't guarantee order)
                    tag_list = sorted(git_tags, reverse=True)

                    # Try to find semantic version tags first
                    version_tags = [tag for tag in tag_list if re.match(r'^v?\d+\.\d+', tag)]
                    if version_tags:
                        return version_tags[0]

                    # Otherwise return the first tag
                    return tag_list[0]

            except GitError as e:
                self.logger.debug(f"Git tag enumeration failed for {repo_key}: {e}")

        return None

    async def _find_valid_reference(self, repo_key: str, invalid_ref: str) -> str | None:
        """Try to find a valid reference similar to the invalid one."""
        # Check cache first for known references
        for potential_ref in [invalid_ref, "main", "master"]:
            cached_entry = self._cache.get(repo_key, potential_ref)
            if cached_entry and cached_entry.result == ValidationResult.VALID:
                if potential_ref != invalid_ref:
                    return potential_ref

        # Use API if we're in GitHub API validation mode
        if self.config.validation_method == ValidationMethod.GITHUB_API and self._http_client:
            # For common patterns like "main" vs "master"
            if invalid_ref in ["main", "master"]:
                alternative = "master" if invalid_ref == "main" else "main"
                if await self._check_reference_exists(repo_key, alternative):
                    return alternative

            # Try to find similar tags/branches
            try:
                # Check if it's a partial version match
                if re.match(r"^v?\d+", invalid_ref):
                    api_tags = await self._get_tags(repo_key, limit=50)
                    for api_tag in api_tags:
                        if api_tag["name"].startswith(invalid_ref):
                            return api_tag["name"]  # type: ignore[no-any-return]

                # Check branches for partial matches
                api_branches = await self._get_branches(repo_key, limit=20)
                for api_branch in api_branches:
                    if api_branch["name"] == invalid_ref or api_branch["name"].endswith(invalid_ref):
                        return api_branch["name"]  # type: ignore[no-any-return]

            except Exception as e:
                self.logger.debug(f"Failed to find valid reference via API for {repo_key}@{invalid_ref}: {e}")

        # Use Git operations if we're in Git validation mode
        if self.config.validation_method == ValidationMethod.GIT and self._git_client:
            try:
                url = f"https://github.com/{repo_key}.git"

                # Get all branches and tags
                git_branches = _get_remote_branches(url, self.config.git)
                git_tags = _get_remote_tags(url, self.config.git)

                # For common patterns like "main" vs "master"
                if invalid_ref == "main" and "master" in git_branches:
                    return "master"
                elif invalid_ref == "master" and "main" in git_branches:
                    return "main"

                # Check if it's a partial version match in tags
                if re.match(r"^v?\d+", invalid_ref):
                    for git_tag in sorted(git_tags, reverse=True):
                        if git_tag.startswith(invalid_ref):
                            return git_tag

                # Check branches for partial matches
                for git_branch in git_branches:
                    if git_branch == invalid_ref or git_branch.endswith(invalid_ref):
                        return git_branch

            except GitError as e:
                self.logger.debug(f"Git reference search failed for {repo_key}@{invalid_ref}: {e}")

        return None

    async def _check_reference_exists(self, repo_key: str, ref: str) -> bool:
        """Check if a specific reference exists."""
        if self.config.validation_method == ValidationMethod.GITHUB_API and self._http_client:
            try:
                response = await self._http_client.get(f"https://api.github.com/repos/{repo_key}/git/refs/heads/{ref}")
                if response.status_code == 200:
                    return True

                response = await self._http_client.get(f"https://api.github.com/repos/{repo_key}/git/refs/tags/{ref}")
                return bool(response.status_code == 200)
            except Exception:
                pass

        # Use Git operations if we're in Git validation mode
        if self.config.validation_method == ValidationMethod.GIT and self._git_client:
            try:
                url = f"https://github.com/{repo_key}.git"
                git_branches = _get_remote_branches(url, self.config.git)
                git_tags = _get_remote_tags(url, self.config.git)
                return ref in git_branches or ref in git_tags
            except GitError:
                pass

        return False

    async def _get_tags(self, repo_key: str, limit: int = 30) -> list[dict[str, Any]]:
        """Get repository tags."""
        if self.config.validation_method == ValidationMethod.GITHUB_API and self._http_client:
            try:
                response = await self._http_client.get(f"https://api.github.com/repos/{repo_key}/tags?per_page={limit}")
                response.raise_for_status()
                return response.json()  # type: ignore[no-any-return]
            except Exception:
                pass

        # Use Git operations if we're in Git validation mode - convert to API-like format
        if self.config.validation_method == ValidationMethod.GIT and self._git_client:
            try:
                url = f"https://github.com/{repo_key}.git"
                git_tags = _get_remote_tags(url, self.config.git)
                # Convert to API-like format for compatibility
                return [{"name": tag} for tag in sorted(git_tags, reverse=True)[:limit]]
            except GitError:
                pass

        return []

    async def _get_branches(self, repo_key: str, limit: int = 20) -> list[dict[str, Any]]:
        """Get repository branches."""
        if self.config.validation_method == ValidationMethod.GITHUB_API and self._http_client:
            try:
                response = await self._http_client.get(f"https://api.github.com/repos/{repo_key}/branches?per_page={limit}")
                response.raise_for_status()
                return response.json()  # type: ignore[no-any-return]
            except Exception:
                pass

        # Use Git operations if we're in Git validation mode - convert to API-like format
        if self.config.validation_method == ValidationMethod.GIT and self._git_client:
            try:
                url = f"https://github.com/{repo_key}.git"
                git_branches = _get_remote_branches(url, self.config.git)
                # Convert to API-like format for compatibility
                return [{"name": branch} for branch in sorted(git_branches)[:limit]]
            except GitError:
                pass

        return []

    async def _get_commit_sha_for_reference(self, repo_key: str, ref: str) -> dict[str, Any] | None:
        """Get commit SHA for a specific reference."""
        # Use API if we're in GitHub API validation mode
        if self.config.validation_method == ValidationMethod.GITHUB_API and self._http_client:
            try:
                # Try as branch first
                response = await self._http_client.get(f"https://api.github.com/repos/{repo_key}/git/refs/heads/{ref}")
                if response.status_code == 200:
                    ref_data = response.json()
                    return {"sha": ref_data["object"]["sha"], "type": "branch"}

                # Try as tag
                response = await self._http_client.get(f"https://api.github.com/repos/{repo_key}/git/refs/tags/{ref}")
                if response.status_code == 200:
                    ref_data = response.json()
                    sha = ref_data["object"]["sha"]

                    # If it's an annotated tag, get the commit SHA
                    if ref_data["object"]["type"] == "tag":
                        tag_response = await self._http_client.get(f"https://api.github.com/repos/{repo_key}/git/tags/{sha}")
                        if tag_response.status_code == 200:
                            tag_data = tag_response.json()
                            sha = tag_data["object"]["sha"]

                    return {"sha": sha, "type": "tag"}

                # Try as commit SHA
                response = await self._http_client.get(f"https://api.github.com/repos/{repo_key}/commits/{ref}")
                if response.status_code == 200:
                    commit_data = response.json()
                    return {"sha": commit_data["sha"], "type": "commit"}

            except Exception as e:
                self.logger.debug(f"Failed to get commit SHA via API for {repo_key}@{ref}: {e}")

        # Use Git operations if we're in Git validation mode
        if self.config.validation_method == ValidationMethod.GIT and self._git_client:
            try:
                url = f"https://github.com/{repo_key}.git"

                # Use git ls-remote to get the SHA for the reference
                import subprocess

                # Try as branch
                cmd = ["git", "ls-remote", "--heads", url, ref]
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True,
                        timeout=self.config.git.timeout_seconds, check=True
                    )
                    if result.stdout.strip():
                        sha = result.stdout.strip().split('\t')[0]
                        return {"sha": sha, "type": "branch"}
                except subprocess.CalledProcessError:
                    pass

                # Try as tag
                cmd = ["git", "ls-remote", "--tags", url, ref]
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True,
                        timeout=self.config.git.timeout_seconds, check=True
                    )
                    if result.stdout.strip():
                        sha = result.stdout.strip().split('\t')[0]
                        return {"sha": sha, "type": "tag"}
                except subprocess.CalledProcessError:
                    pass

            except Exception as e:
                self.logger.debug(f"Git SHA resolution failed for {repo_key}@{ref}: {e}")

        return None

    def _build_fixed_line(self, action_call: ActionCall, new_ref: str, version_comment: str | None = None) -> str:
        """Build the fixed action call line."""
        # Extract indentation and YAML structure from original line
        original_line = action_call.raw_line

        # Match the full structure with optional dash
        # First try: indentation + "- " + "uses: "
        structure_match = re.match(r'^(\s*-\s*uses:\s*)', original_line)
        if structure_match:
            prefix = structure_match.group(1)
        else:
            # Second try: indentation + "uses: " (no dash)
            structure_match = re.match(r'^(\s*uses:\s*)', original_line)
            if structure_match:
                prefix = structure_match.group(1)
            else:
                # Fallback: extract indentation and add basic "uses: "
                indent_match = re.match(r'^(\s*)', original_line)
                indent = indent_match.group(1) if indent_match else ""
                prefix = f"{indent}uses: "

        # Build the new action reference
        new_action_ref = f"{action_call.organization}/{action_call.repository}@{new_ref}"

        # Add version comment if needed
        comment_part = ""
        if version_comment and self.config.require_pinned_sha:
            comment_spacing = "  " if self.config.two_space_comments else " "
            comment_part = f"{comment_spacing}# {version_comment}"
        elif action_call.comment:
            # Preserve existing comment
            comment_spacing = "  " if self.config.two_space_comments else " "
            comment_part = f"{comment_spacing}# {action_call.comment}"

        final_line = f"{prefix}{new_action_ref}{comment_part}"
        return final_line

    async def _apply_fixes_to_file(
        self, file_path: Path, line_fixes: dict[int, tuple[str, str]]
    ) -> list[dict[str, str]]:
        """Apply fixes to a workflow file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # Apply fixes (line numbers are 1-based)
            changes = []
            for i, line in enumerate(lines, 1):
                if i in line_fixes:
                    old_line, new_line = line_fixes[i]
                    lines[i - 1] = new_line + '\n'
                    changes.append({
                        'line_number': str(i),
                        'old_line': old_line,
                        'new_line': new_line
                    })

            # Write back to file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)

            return changes

        except Exception as e:
            self.logger.error(f"Failed to apply fixes to {file_path}: {e}")
            raise
