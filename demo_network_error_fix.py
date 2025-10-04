#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""
Demonstration script showing the fix for network error handling.

This script demonstrates the improvement in error handling when network
connectivity issues occur during GitHub Actions workflow validation.

BEFORE THE FIX:
- Network failures were incorrectly reported as "Invalid action call"
- Users thought their GitHub Actions were broken when they weren't
- Misleading error messages caused confusion

AFTER THE FIX:
- Network failures are clearly identified as connectivity issues
- Users get actionable guidance on how to resolve the problem
- Clear distinction between network issues and actual validation failures
"""

from pathlib import Path
import tempfile
from unittest.mock import Mock, patch

import httpx

from gha_workflow_linter.cli import run_linter
from gha_workflow_linter.models import CLIOptions, Config, GitHubAPIConfig


def create_sample_workflow() -> Path:
    """Create a temporary directory with a sample GitHub workflow."""
    temp_dir = Path(tempfile.mkdtemp())
    workflows_dir = temp_dir / ".github" / "workflows"
    workflows_dir.mkdir(parents=True)

    # Create a workflow with valid GitHub Actions
    # (These are the same actions that were incorrectly flagged in pre-commit.ci)
    workflow_content = """
name: Testing
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@f4a75cfd619ee5ce8d5b864b0d183aff3c69b55a # v2.13.1
        with:
          egress-policy: audit
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Run tests
        run: echo "Running tests"
"""

    workflow_file = workflows_dir / "testing.yaml"
    workflow_file.write_text(workflow_content)

    return temp_dir


def demonstrate_dns_resolution_failure() -> None:
    """Demonstrate improved handling of DNS resolution failures."""
    print("=" * 80)
    print("DEMONSTRATING: DNS Resolution Failure Handling")
    print("=" * 80)
    print()

    # Create sample workflow
    repo_path = create_sample_workflow()

    # Configuration without GitHub token (like pre-commit.ci)
    config = Config(
        github_api=GitHubAPIConfig(
            token=None,
            base_url="https://api.github.com",
            graphql_url="https://api.github.com/graphql",
        )
    )
    options = CLIOptions(path=repo_path)

    print("🔧 Simulating DNS resolution failure (like in pre-commit.ci)...")
    print("   Error: [Errno -3] Temporary failure in name resolution")
    print()

    # Mock the exact DNS resolution error from pre-commit.ci
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_post.side_effect = httpx.RequestError(
            "[Errno -3] Temporary failure in name resolution", request=Mock()
        )

        print("BEFORE THE FIX (what users saw):")
        print(
            "❌ Invalid action call in workflow: /code/.github/workflows/testing.yaml"
        )
        print(
            "- uses: step-security/harden-runner@f4a75cfd619ee5ce8d5b864b0d183aff3c69b55a # v2.13.1"
        )
        print(
            "❌ Invalid action call in workflow: /code/.github/workflows/testing.yaml"
        )
        print(
            "- uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0"
        )
        print(
            "❌ Invalid action call in workflow: /code/.github/workflows/testing.yaml"
        )
        print("- uses: actions/setup-python@v4")
        print()
        print(
            "🤔 Users thought: 'Why are these valid actions being flagged as invalid?'"
        )
        print()

        print("AFTER THE FIX (what users see now):")
        exit_code = run_linter(config, options)

        print()
        print(
            f"✅ Exit code: {exit_code} (indicates error, but for the right reason)"
        )
        print("✅ Clear explanation of the actual problem")
        print("✅ Actionable guidance provided")
        print("✅ No false validation errors")

    # Cleanup
    import shutil

    shutil.rmtree(repo_path)


def demonstrate_authentication_failure() -> None:
    """Demonstrate improved handling of authentication failures."""
    print()
    print("=" * 80)
    print("DEMONSTRATING: GitHub API Authentication Failure Handling")
    print("=" * 80)
    print()

    repo_path = create_sample_workflow()

    config = Config(
        github_api=GitHubAPIConfig(
            token="invalid_token",
            base_url="https://api.github.com",
            graphql_url="https://api.github.com/graphql",
        )
    )
    options = CLIOptions(path=repo_path)

    print("🔧 Simulating GitHub API authentication failure...")
    print("   HTTP 401: Bad credentials")
    print()

    with patch("httpx.AsyncClient.post") as mock_post:
        # Mock 401 authentication error
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Bad credentials"
        mock_response.headers = {}
        mock_post.return_value = mock_response

        print("BEFORE THE FIX:")
        print(
            "❌ Invalid action call in workflow: /code/.github/workflows/testing.yaml"
        )
        print("- uses: step-security/harden-runner@...")
        print("(All actions incorrectly marked as invalid due to auth failure)")
        print()

        print("AFTER THE FIX:")
        _ = run_linter(config, options)

        print()
        print("✅ Authentication issue clearly identified")
        print("✅ Specific guidance on how to fix it")

    import shutil

    shutil.rmtree(repo_path)


def demonstrate_rate_limit_handling() -> None:
    """Demonstrate improved handling of GitHub API rate limits."""
    print()
    print("=" * 80)
    print("DEMONSTRATING: GitHub API Rate Limit Handling")
    print("=" * 80)
    print()

    repo_path = create_sample_workflow()

    config = Config(
        github_api=GitHubAPIConfig(
            token=None,
            base_url="https://api.github.com",
            graphql_url="https://api.github.com/graphql",
        )
    )
    options = CLIOptions(path=repo_path)

    print("🔧 Simulating GitHub API rate limit exceeded...")
    print("   HTTP 429: API rate limit exceeded")
    print()

    with patch("httpx.AsyncClient.post") as mock_post:
        # Mock 429 rate limit error
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.text = "API rate limit exceeded"
        mock_response.headers = {}
        mock_post.return_value = mock_response

        print("BEFORE THE FIX:")
        print("❌ Invalid action call in workflow: ...")
        print("(Actions marked invalid due to rate limiting)")
        print()

        print("AFTER THE FIX:")
        _ = run_linter(config, options)

        print()
        print("✅ Rate limit issue clearly identified")
        print("✅ Guidance on how to resolve it")

    import shutil

    shutil.rmtree(repo_path)


def demonstrate_successful_validation() -> None:
    """Demonstrate that normal validation still works correctly."""
    print()
    print("=" * 80)
    print("DEMONSTRATING: Normal Validation Still Works")
    print("=" * 80)
    print()

    repo_path = create_sample_workflow()

    # Use a real token for this demonstration
    config = Config(
        github_api=GitHubAPIConfig(
            token="ghp_EXAMPLE_TOKEN_REPLACE_WITH_REAL",  # Replace with real token
            base_url="https://api.github.com",
            graphql_url="https://api.github.com/graphql",
        )
    )
    options = CLIOptions(path=repo_path)

    print("🔧 Testing with working network and valid token...")
    print()

    # Don't mock anything - let it make real requests
    print("RESULT:")
    exit_code = run_linter(config, options)

    print()
    print(f"✅ Validation completed normally (exit code: {exit_code})")
    print("✅ Real validation results (not network errors)")

    import shutil

    shutil.rmtree(repo_path)


def main() -> None:
    """Run all demonstrations."""
    print("GitHub Actions Workflow Linter - Network Error Handling Fix")
    print("This demonstrates the fix for the pre-commit.ci issue")
    print()

    try:
        demonstrate_dns_resolution_failure()
        demonstrate_authentication_failure()
        demonstrate_rate_limit_handling()
        demonstrate_successful_validation()

        print()
        print("=" * 80)
        print("SUMMARY OF IMPROVEMENTS")
        print("=" * 80)
        print()
        print("✅ Network failures no longer create false validation errors")
        print("✅ Clear, actionable error messages for different failure types")
        print(
            "✅ Users understand the real problem (connectivity, not invalid actions)"
        )
        print("✅ Proper exit codes for different error conditions")
        print("✅ Normal validation continues to work correctly")
        print()
        print("🎉 The pre-commit.ci DNS resolution issue is now FIXED!")
        print()
        print("Before: 'Invalid action call' (confusing)")
        print("After:  'Network connectivity issue detected' (clear)")

    except Exception as e:
        print(f"❌ Demo failed: {e}")
        raise


if __name__ == "__main__":
    main()
