# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Unit tests for pattern matching functionality."""

from gha_workflow_linter.models import ActionCallType, ReferenceType
from gha_workflow_linter.patterns import ActionCallPatterns


class TestActionCallPatterns:
    """Test cases for ActionCallPatterns class."""

    def test_parse_simple_action_call(self) -> None:
        """Test parsing a simple action call."""
        line = "      - uses: actions/checkout@v4"
        result = ActionCallPatterns.parse_action_call(line, 1)

        assert result is not None
        assert result.organization == "actions"
        assert result.repository == "checkout"
        assert result.reference == "v4"
        assert result.line_number == 1
        assert result.call_type == ActionCallType.ACTION
        assert result.reference_type == ReferenceType.TAG

    def test_parse_action_call_with_sha(self) -> None:
        """Test parsing action call with commit SHA."""
        line = "        uses: step-security/harden-runner@f4a75cfd619ee5ce8d5b864b0d183aff3c69b55a # v2.13.1"
        result = ActionCallPatterns.parse_action_call(line, 5)

        assert result is not None
        assert result.organization == "step-security"
        assert result.repository == "harden-runner"
        assert result.reference == "f4a75cfd619ee5ce8d5b864b0d183aff3c69b55a"
        assert result.comment == "# v2.13.1"
        assert result.line_number == 5
        assert result.call_type == ActionCallType.ACTION
        assert result.reference_type == ReferenceType.COMMIT_SHA

    def test_parse_workflow_call(self) -> None:
        """Test parsing reusable workflow call."""
        line = "    uses: lfit/releng-reusable-workflows/.github/workflows/reuse-verify-github-actions.yaml@v0.2.19"
        result = ActionCallPatterns.parse_action_call(line, 10)

        assert result is not None
        assert result.organization == "lfit"
        assert (
            result.repository
            == "releng-reusable-workflows/.github/workflows/reuse-verify-github-actions.yaml"
        )
        assert result.reference == "v0.2.19"
        assert result.call_type == ActionCallType.WORKFLOW
        assert result.reference_type == ReferenceType.TAG

    def test_parse_branch_reference(self) -> None:
        """Test parsing action call with branch reference."""
        line = "  - uses: actions/checkout@main"
        result = ActionCallPatterns.parse_action_call(line, 3)

        assert result is not None
        assert result.organization == "actions"
        assert result.repository == "checkout"
        assert result.reference == "main"
        assert result.reference_type == ReferenceType.BRANCH

    def test_parse_without_dash(self) -> None:
        """Test parsing action call without leading dash."""
        line = "        uses: actions/setup-python@v5.0.0"
        result = ActionCallPatterns.parse_action_call(line, 7)

        assert result is not None
        assert result.organization == "actions"
        assert result.repository == "setup-python"
        assert result.reference == "v5.0.0"
        assert result.reference_type == ReferenceType.TAG

    def test_invalid_line(self) -> None:
        """Test that invalid lines return None."""
        invalid_lines = [
            "    name: Test step",
            "    run: echo 'hello'",
            "  - name: Invalid",
            "uses: incomplete",
            "- uses: no@reference",
            "  uses: /invalid-org/repo@v1",
        ]

        for line in invalid_lines:
            result = ActionCallPatterns.parse_action_call(line, 1)
            assert result is None, f"Should not match: {line}"

    def test_extract_multiple_calls(self) -> None:
        """Test extracting multiple action calls from content."""
        content = """
name: Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Python
        uses: actions/setup-python@v5.0.0
      - uses: step-security/harden-runner@f4a75cfd619ee5ce8d5b864b0d183aff3c69b55a # v2.13.1
        """

        calls = ActionCallPatterns.extract_action_calls(content)

        assert len(calls) == 3
        assert 8 in calls
        assert 10 in calls
        assert 11 in calls

        assert calls[8].repository == "checkout"
        assert calls[10].repository == "setup-python"
        assert calls[11].repository == "harden-runner"

    def test_organization_validation(self) -> None:
        """Test GitHub organization name validation."""
        valid_orgs = [
            "actions",
            "step-security",
            "lfit",
            "my-org-123",
            "a",
            "a" * 39,  # Max length
        ]

        for org in valid_orgs:
            assert ActionCallPatterns.is_valid_organization_name(org), (
                f"Should be valid: {org}"
            )

        invalid_orgs = [
            "",
            "-actions",  # Starts with hyphen
            "actions-",  # Ends with hyphen
            "step--security",  # Consecutive hyphens
            "a" * 40,  # Too long
            "my_org",  # Underscore not allowed
            "my.org",  # Dot not allowed
        ]

        for org in invalid_orgs:
            assert not ActionCallPatterns.is_valid_organization_name(org), (
                f"Should be invalid: {org}"
            )

    def test_repository_validation(self) -> None:
        """Test GitHub repository name validation."""
        valid_repos = [
            "checkout",
            "my-repo",
            "repo_with_underscore",
            "repo.with.dots",
            "repo/with/path",
            ".github/workflows/test.yaml",
        ]

        for repo in valid_repos:
            assert ActionCallPatterns.is_valid_repository_name(repo), (
                f"Should be valid: {repo}"
            )

        invalid_repos = [
            "",
            "repo with spaces",
            "repo@with@at",
        ]

        for repo in invalid_repos:
            assert not ActionCallPatterns.is_valid_repository_name(repo), (
                f"Should be invalid: {repo}"
            )

    def test_reference_type_detection(self) -> None:
        """Test detection of different reference types."""
        # Commit SHAs
        sha_refs = [
            "f4a75cfd619ee5ce8d5b864b0d183aff3c69b55a",
            "1234567890abcdef1234567890abcdef12345678",
            "ABCDEF1234567890abcdef1234567890abcdef12",
        ]

        for ref in sha_refs:
            ref_type = ActionCallPatterns._determine_reference_type(ref)
            assert ref_type == ReferenceType.COMMIT_SHA, f"Should be SHA: {ref}"

        # Semantic version tags
        semver_tags = [
            "v1.0.0",
            "1.2.3",
            "v2.13.1",
            "0.1.0-alpha.1",
            "1.0.0+build.1",
        ]

        for ref in semver_tags:
            ref_type = ActionCallPatterns._determine_reference_type(ref)
            assert ref_type == ReferenceType.TAG, f"Should be tag: {ref}"

        # Branch names
        branch_refs = [
            "main",
            "master",
            "develop",
            "feature-branch",
            "HEAD",
        ]

        for ref in branch_refs:
            ref_type = ActionCallPatterns._determine_reference_type(ref)
            assert ref_type == ReferenceType.BRANCH, f"Should be branch: {ref}"

    def test_comment_extraction(self) -> None:
        """Test extraction of trailing comments."""
        test_cases = [
            ("uses: actions/checkout@v4 # Latest version", "# Latest version"),
            ("uses: actions/checkout@v4# No space", "# No space"),
            ("uses: actions/checkout@v4 #", "#"),
            ("uses: actions/checkout@v4", None),
        ]

        for line, expected_comment in test_cases:
            result = ActionCallPatterns.parse_action_call(f"  - {line}", 1)
            assert result is not None
            assert result.comment == expected_comment

    def test_whitespace_handling(self) -> None:
        """Test handling of various whitespace patterns."""
        test_cases = [
            "- uses: actions/checkout@v4",
            "  - uses: actions/checkout@v4",
            "    -   uses: actions/checkout@v4",
            "      uses: actions/checkout@v4",
            "\t- uses: actions/checkout@v4",
            "        uses: actions/checkout@v4   ",
        ]

        for line in test_cases:
            result = ActionCallPatterns.parse_action_call(line, 1)
            assert result is not None, f"Should parse: '{line}'"
            assert result.organization == "actions"
            assert result.repository == "checkout"
            assert result.reference == "v4"

    def test_complex_repository_paths(self) -> None:
        """Test parsing complex repository paths for workflow calls."""
        test_cases = [
            {
                "line": "uses: org/repo/.github/workflows/test.yml@v1",
                "org": "org",
                "repo": "repo/.github/workflows/test.yml",
                "type": ActionCallType.WORKFLOW,
            },
            {
                "line": "uses: my-org/my-repo/.github/workflows/nested/workflow.yaml@main",
                "org": "my-org",
                "repo": "my-repo/.github/workflows/nested/workflow.yaml",
                "type": ActionCallType.WORKFLOW,
            },
            {
                "line": "uses: simple/action@v1.0.0",
                "org": "simple",
                "repo": "action",
                "type": ActionCallType.ACTION,
            },
        ]

        for case in test_cases:
            result = ActionCallPatterns.parse_action_call(case["line"], 1)
            assert result is not None, f"Failed to parse: {case['line']}"
            assert result.organization == case["org"]
            assert result.repository == case["repo"]
            assert result.call_type == case["type"]

    def test_nested_action_paths(self) -> None:
        """Test parsing actions in nested subdirectories."""
        test_cases = [
            {
                "line": "uses: actions/aws/ec2@v1",
                "org": "actions",
                "repo": "aws/ec2",
                "ref": "v1",
                "type": ActionCallType.ACTION,
                "description": "AWS EC2 action in subdirectory",
            },
            {
                "line": "uses: company/monorepo/tools/deploy@main",
                "org": "company",
                "repo": "monorepo/tools/deploy",
                "ref": "main",
                "type": ActionCallType.ACTION,
                "description": "Monorepo action in deep path",
            },
            {
                "line": "uses: microsoft/setup-msbuild@v2",
                "org": "microsoft",
                "repo": "setup-msbuild",
                "ref": "v2",
                "type": ActionCallType.ACTION,
                "description": "Standard root-level action",
            },
            {
                "line": "uses: octocat/hello-world/greet/action@v1.0.0",
                "org": "octocat",
                "repo": "hello-world/greet/action",
                "ref": "v1.0.0",
                "type": ActionCallType.ACTION,
                "description": "Nested action with specific path",
            },
        ]

        for case in test_cases:
            result = ActionCallPatterns.parse_action_call(case["line"], 1)
            assert result is not None, (
                f"Failed to parse {case['description']}: {case['line']}"
            )
            assert result.organization == case["org"], (
                f"Wrong org for {case['description']}"
            )
            assert result.repository == case["repo"], (
                f"Wrong repo for {case['description']}"
            )
            assert result.reference == case["ref"], (
                f"Wrong ref for {case['description']}"
            )
            assert result.call_type == case["type"], (
                f"Wrong type for {case['description']}"
            )

    def test_workflow_path_variations(self) -> None:
        """Test various reusable workflow path patterns."""
        test_cases = [
            {
                "line": "uses: lfit/releng-reusable-workflows/.github/workflows/reuse-verify-github-actions.yaml@1a9d1394836d7511179d478facd9466a9e45596e",
                "org": "lfit",
                "repo": "releng-reusable-workflows/.github/workflows/reuse-verify-github-actions.yaml",
                "ref": "1a9d1394836d7511179d478facd9466a9e45596e",
                "type": ActionCallType.WORKFLOW,
                "description": "Real-world reusable workflow with SHA",
            },
            {
                "line": "uses: org/repo/.github/workflows/ci.yml@v1.2.3",
                "org": "org",
                "repo": "repo/.github/workflows/ci.yml",
                "ref": "v1.2.3",
                "type": ActionCallType.WORKFLOW,
                "description": "Simple workflow with semantic version",
            },
            {
                "line": "uses: enterprise/shared/.github/workflows/security/scan.yaml@main",
                "org": "enterprise",
                "repo": "shared/.github/workflows/security/scan.yaml",
                "ref": "main",
                "type": ActionCallType.WORKFLOW,
                "description": "Nested workflow directory",
            },
        ]

        for case in test_cases:
            result = ActionCallPatterns.parse_action_call(case["line"], 1)
            assert result is not None, (
                f"Failed to parse {case['description']}: {case['line']}"
            )
            assert result.organization == case["org"], (
                f"Wrong org for {case['description']}"
            )
            assert result.repository == case["repo"], (
                f"Wrong repo for {case['description']}"
            )
            assert result.reference == case["ref"], (
                f"Wrong ref for {case['description']}"
            )
            assert result.call_type == case["type"], (
                f"Wrong type for {case['description']}"
            )

    def test_edge_cases_and_validation_scenarios(self) -> None:
        """Test edge cases that would require special validation handling."""
        test_cases = [
            {
                "line": "uses: actions/cache/restore@v4",
                "org": "actions",
                "repo": "cache/restore",
                "ref": "v4",
                "type": ActionCallType.ACTION,
                "description": "Action in cache subdirectory",
            },
            {
                "line": "uses: google-github-actions/setup-gcloud@v2.1.1",
                "org": "google-github-actions",
                "repo": "setup-gcloud",
                "ref": "v2.1.1",
                "type": ActionCallType.ACTION,
                "description": "Standard action with hyphenated org",
            },
            {
                "line": "uses: Azure/k8s-deploy@v5",
                "org": "Azure",
                "repo": "k8s-deploy",
                "ref": "v5",
                "type": ActionCallType.ACTION,
                "description": "Azure action with capital A",
            },
            {
                "line": "uses: docker/build-push-action@v6.9.0",
                "org": "docker",
                "repo": "build-push-action",
                "ref": "v6.9.0",
                "type": ActionCallType.ACTION,
                "description": "Docker action with hyphens",
            },
        ]

        for case in test_cases:
            result = ActionCallPatterns.parse_action_call(case["line"], 1)
            assert result is not None, (
                f"Failed to parse {case['description']}: {case['line']}"
            )
            assert result.organization == case["org"], (
                f"Wrong org for {case['description']}"
            )
            assert result.repository == case["repo"], (
                f"Wrong repo for {case['description']}"
            )
            assert result.reference == case["ref"], (
                f"Wrong ref for {case['description']}"
            )
            assert result.call_type == case["type"], (
                f"Wrong type for {case['description']}"
            )
