# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Simple tests for patterns module to improve coverage."""

from __future__ import annotations

from gha_workflow_linter.models import ActionCall
from gha_workflow_linter.patterns import ActionCallPatterns


class TestActionCallPatterns:
    """Test the ActionCallPatterns class."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.patterns = ActionCallPatterns()

    def test_init(self) -> None:
        """Test ActionCallPatterns initialization."""
        assert self.patterns is not None
        assert hasattr(self.patterns, "ACTION_CALL_PATTERN")
        assert hasattr(self.patterns, "ORG_PATTERN")
        assert hasattr(self.patterns, "REPO_PATTERN")
        assert hasattr(self.patterns, "REF_PATTERN")

    def test_org_pattern_valid(self) -> None:
        """Test organization pattern matching with valid names."""
        import re

        org_regex = re.compile(self.patterns.ORG_PATTERN)

        # Valid organization names
        assert org_regex.fullmatch("actions")
        assert org_regex.fullmatch("microsoft")
        assert org_regex.fullmatch("setup-java")
        assert org_regex.fullmatch("docker-actions")
        assert org_regex.fullmatch("a")  # Single character
        assert org_regex.fullmatch("a1b2c3")  # Alphanumeric

    def test_org_pattern_invalid(self) -> None:
        """Test organization pattern matching with invalid names."""
        import re

        org_regex = re.compile(self.patterns.ORG_PATTERN)

        # Invalid organization names
        assert not org_regex.fullmatch("-actions")  # Starts with hyphen
        assert not org_regex.fullmatch("actions-")  # Ends with hyphen
        assert not org_regex.fullmatch("act@ions")  # Contains @
        assert not org_regex.fullmatch("")  # Empty string

    def test_repo_pattern_valid(self) -> None:
        """Test repository pattern matching with valid names."""
        import re

        repo_regex = re.compile(self.patterns.REPO_PATTERN)

        # Valid repository names
        assert repo_regex.fullmatch("checkout")
        assert repo_regex.fullmatch("setup-node")
        assert repo_regex.fullmatch("repo_name")
        assert repo_regex.fullmatch("my.repo")
        assert repo_regex.fullmatch("workflows/deploy.yml")  # Workflow paths

    def test_ref_pattern_valid(self) -> None:
        """Test reference pattern matching with valid references."""
        import re

        ref_regex = re.compile(self.patterns.REF_PATTERN)

        # Valid references
        assert ref_regex.fullmatch("v4")
        assert ref_regex.fullmatch("v1.2.3")
        assert ref_regex.fullmatch("main")
        assert ref_regex.fullmatch("develop")
        assert ref_regex.fullmatch("feature/branch-name")
        assert ref_regex.fullmatch(
            "a1b2c3d4e5f6789012345678901234567890abcd"
        )  # SHA

    def test_action_call_pattern_basic(self) -> None:
        """Test basic action call pattern matching."""
        pattern = self.patterns.ACTION_CALL_PATTERN

        # Basic uses statement
        match = pattern.match("      uses: actions/checkout@v4")
        assert match is not None
        assert match.group("org") == "actions"
        assert match.group("repo") == "checkout"
        assert match.group("ref") == "v4"

    def test_action_call_pattern_with_dash(self) -> None:
        """Test action call pattern matching with dash."""
        pattern = self.patterns.ACTION_CALL_PATTERN

        # Uses statement with dash
        match = pattern.match("    - uses: actions/setup-node@v3")
        assert match is not None
        assert match.group("dash") is not None
        assert match.group("org") == "actions"
        assert match.group("repo") == "setup-node"
        assert match.group("ref") == "v3"

    def test_action_call_pattern_with_comment(self) -> None:
        """Test action call pattern matching with comment."""
        pattern = self.patterns.ACTION_CALL_PATTERN

        # Uses statement with comment
        match = pattern.match("      uses: actions/checkout@v4 # Checkout code")
        assert match is not None
        assert match.group("org") == "actions"
        assert match.group("repo") == "checkout"
        assert match.group("ref") == "v4"
        assert match.group("comment") == "# Checkout code"

    def test_action_call_pattern_workflow_call(self) -> None:
        """Test action call pattern matching workflow calls."""
        pattern = self.patterns.ACTION_CALL_PATTERN

        # Workflow call with relative path
        match = pattern.match(
            "      uses: octocat/hello-world/.github/workflows/deploy.yml@main"
        )
        assert match is not None
        assert match.group("org") == "octocat"
        assert match.group("repo") == "hello-world/.github/workflows/deploy.yml"
        assert match.group("ref") == "main"

    def test_action_call_pattern_no_match(self) -> None:
        """Test action call pattern with non-matching strings."""
        pattern = self.patterns.ACTION_CALL_PATTERN

        # Non-uses statements
        assert pattern.match("      run: echo hello") is None
        assert pattern.match("      name: Test step") is None
        assert (
            pattern.match("uses:invalid") is None
        )  # Missing space after uses:
        assert (
            pattern.match("uses: invalid-format") is None
        )  # Missing @ and ref

    def test_extract_action_calls_basic(self) -> None:
        """Test extracting action calls from workflow content."""
        content = """
name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
"""

        action_calls = self.patterns.extract_action_calls(content)

        assert len(action_calls) >= 1  # Should find at least one
        # Check that we get a dict with line numbers as keys
        assert isinstance(action_calls, dict)
        for line_num, action_call in action_calls.items():
            assert isinstance(line_num, int)
            assert isinstance(action_call, ActionCall)

    def test_extract_action_calls_empty_content(self) -> None:
        """Test extracting action calls from empty content."""
        action_calls = self.patterns.extract_action_calls("")
        assert action_calls == {}

    def test_extract_action_calls_no_uses(self) -> None:
        """Test extracting action calls from content with no uses statements."""
        content = """
name: Test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Run tests
        run: npm test
"""

        action_calls = self.patterns.extract_action_calls(content)
        assert action_calls == {}

    def test_extract_action_calls_complex(self) -> None:
        """Test extracting action calls from complex workflow."""
        content = """
name: Complex Workflow
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4  # Get the code
      - uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - uses: actions/cache@v3
        with:
          path: ~/.cache
          key: cache-key

  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v3
      - uses: ./.github/workflows/deploy.yml@main
"""

        action_calls = self.patterns.extract_action_calls(content)

        # Should find multiple action calls
        assert len(action_calls) >= 3

        # Check that we have the expected repositories
        repos = [call.repository for call in action_calls.values()]
        assert any("checkout" in repo for repo in repos)
        assert any("setup-python" in repo for repo in repos)

    def test_regex_patterns_exist(self) -> None:
        """Test that all expected patterns exist."""
        assert hasattr(self.patterns, "ORG_PATTERN")
        assert hasattr(self.patterns, "REPO_PATTERN")
        assert hasattr(self.patterns, "REF_PATTERN")
        assert hasattr(self.patterns, "COMMENT_PATTERN")
        assert hasattr(self.patterns, "ACTION_CALL_PATTERN")

        # Test that patterns are strings or compiled regex
        assert isinstance(self.patterns.ORG_PATTERN, str)
        assert isinstance(self.patterns.REPO_PATTERN, str)
        assert isinstance(self.patterns.REF_PATTERN, str)
        assert isinstance(self.patterns.COMMENT_PATTERN, str)
