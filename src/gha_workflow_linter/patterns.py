# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Regular expression patterns for parsing GitHub Actions calls."""

from __future__ import annotations

import re

from .models import ActionCall, ActionCallType, ReferenceType


class ActionCallPatterns:
    """Regex patterns for matching GitHub Actions calls."""

    # GitHub organization name pattern (max 39 chars, alphanumeric + hyphens)
    ORG_PATTERN = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"

    # Repository name pattern (allows dots, underscores, hyphens, slashes for workflows)
    REPO_PATTERN = r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*"

    # Git reference pattern (commit SHA, tag, or branch)
    # SHA: 40 hex characters
    # Tag/Branch: alphanumeric, dots, hyphens, underscores, slashes
    REF_PATTERN = r"[A-Za-z0-9._/-]+"

    # Comment pattern (starts with # and continues to end of line)
    COMMENT_PATTERN = r"#.*"

    # Main action call pattern with optional leading dash and spaces
    ACTION_CALL_PATTERN = re.compile(
        rf"^(?P<indent>\s*)"  # Leading whitespace
        rf"(?P<dash>-\s*)?"  # Optional dash and space(s)
        rf"uses:\s+"  # 'uses:' keyword with space(s)
        rf"(?P<org>{ORG_PATTERN})/"  # Organization name
        rf"(?P<repo>{REPO_PATTERN})"  # Repository (may include paths for workflows)
        rf"@(?P<ref>{REF_PATTERN})"  # @ symbol and reference
        rf"(?:\s*(?P<comment>{COMMENT_PATTERN}))?"  # Optional trailing comment
        rf"(?P<trailing>\s*)$",  # Optional trailing whitespace
        re.MULTILINE,
    )

    # Pattern to detect if this is a workflow call vs action call
    WORKFLOW_PATH_PATTERN = re.compile(r"\.github/workflows/.+\.ya?ml$")

    # Pattern to detect commit SHA (40 hex characters)
    COMMIT_SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)

    # Pattern to detect semantic version tags
    SEMVER_PATTERN = re.compile(
        r"^v?(?P<major>0|[1-9]\d*)"
        r"\.(?P<minor>0|[1-9]\d*)"
        r"\.(?P<patch>0|[1-9]\d*)"
        r"(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
        r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))"
        r"?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
    )

    @classmethod
    def parse_action_call(
        cls, line: str, line_number: int
    ) -> ActionCall | None:
        """
        Parse a single line to extract action call information.

        Args:
            line: The line to parse
            line_number: Line number in the file

        Returns:
            ActionCall object if valid action call found, None otherwise
        """
        match = cls.ACTION_CALL_PATTERN.match(line)
        if not match:
            return None

        try:
            org = match.group("org")
            repo = match.group("repo")
            ref = match.group("ref")
            comment = match.group("comment")

            # Determine call type (action vs workflow)
            call_type = ActionCallType.ACTION
            if cls.WORKFLOW_PATH_PATTERN.search(repo):
                call_type = ActionCallType.WORKFLOW

            # Determine reference type
            ref_type = cls._determine_reference_type(ref)

            return ActionCall(
                raw_line=line,
                line_number=line_number,
                organization=org,
                repository=repo,
                reference=ref,
                comment=comment.strip() if comment else None,
                call_type=call_type,
                reference_type=ref_type,
            )
        except (ValueError, AttributeError):
            # Invalid organization or repository name
            return None

    @classmethod
    def _determine_reference_type(cls, reference: str) -> ReferenceType:
        """
        Determine the type of Git reference.

        Args:
            reference: The Git reference string

        Returns:
            ReferenceType enum value
        """
        # Check if it's a commit SHA (40 hex characters)
        if cls.COMMIT_SHA_PATTERN.match(reference):
            return ReferenceType.COMMIT_SHA

        # Check if it's a semantic version tag
        if cls.SEMVER_PATTERN.match(reference):
            return ReferenceType.TAG

        # Check for other common tag patterns
        if reference.startswith("v") and any(c.isdigit() for c in reference):
            return ReferenceType.TAG

        # Common branch names
        if reference in {"main", "master", "develop", "dev", "HEAD"}:
            return ReferenceType.BRANCH

        # If it contains only version-like characters, likely a tag
        if re.match(r"^[v]?[0-9]+(\.[0-9]+)*([.-][a-zA-Z0-9]+)*$", reference):
            return ReferenceType.TAG

        # Default to branch for other patterns
        return ReferenceType.BRANCH

    @classmethod
    def extract_action_calls(cls, content: str) -> dict[int, ActionCall]:
        """
        Extract all action calls from workflow file content.

        Args:
            content: The workflow file content

        Returns:
            Dictionary mapping line numbers to ActionCall objects
        """
        action_calls = {}

        for line_num, line in enumerate(content.splitlines(), 1):
            action_call = cls.parse_action_call(line, line_num)
            if action_call:
                action_calls[line_num] = action_call

        return action_calls

    @classmethod
    def is_valid_organization_name(cls, name: str) -> bool:
        """
        Validate GitHub organization name according to GitHub rules.

        Args:
            name: Organization name to validate

        Returns:
            True if valid, False otherwise
        """
        if not name or len(name) > 39:
            return False

        if name.startswith("-") or name.endswith("-"):
            return False

        if "--" in name:
            return False

        return bool(re.match(r"^[A-Za-z0-9-]+$", name))

    @classmethod
    def is_valid_repository_name(cls, name: str) -> bool:
        """
        Validate GitHub repository name.

        Args:
            name: Repository name to validate (may include paths)

        Returns:
            True if valid, False otherwise
        """
        if not name:
            return False

        # Allow repository names with paths for workflow calls
        return bool(re.match(r"^[A-Za-z0-9._/-]+$", name))
