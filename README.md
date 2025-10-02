<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# 🔍 Call Linter

[![GitHub Actions](https://github.com/lfit/call-linter/workflows/CI/badge.svg)](https://github.com/lfit/call-linter/actions)
[![PyPI version](https://badge.fury.io/py/call-linter.svg)](https://badge.fury.io/py/call-linter)
[![Python Support](https://img.shields.io/pypi/pyversions/call-linter.svg)](https://pypi.org/project/call-linter/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A comprehensive GitHub Actions workflow linter that validates action and
workflow calls against remote repositories. Call Linter ensures your GitHub
Actions workflows reference valid repositories, branches, tags, and commit SHAs.

## Features

<!-- markdownlint-disable MD013 -->
- **🔒 SHA Pinning Enforcement**: Requires actions using commit SHAs for security (configurable)
- **Multi-format Support**: Works as CLI tool, pre-commit hook, and GitHub Action
- **Comprehensive Validation**: Validates repositories, references, and syntax
- **Parallel Processing**: Multi-threaded validation for faster execution
- **Flexible Configuration**: YAML/JSON config files with environment overrides
- **Rich Output**: Clear error reporting with file paths and line numbers
- **SSH Support**: Respects SSH configuration and agent for private repositories
- **Rate Limiting**: Built-in throttling to respect API limits
<!-- markdownlint-enable MD013 -->

## Installation

### From PyPI

```bash
pip install call-linter
```

### From Source

```bash
git clone https://github.com/lfit/call-linter.git
cd call-linter
uv pip install -e .
```

### Development Installation

```bash
git clone https://github.com/lfit/call-linter.git
cd call-linter
uv pip install -e ".[dev]"
```

## Authentication

Call Linter uses the GitHub GraphQL API for efficient validation. Authentication
is **optional** but **highly recommended** to avoid rate limiting.

### Setting up GitHub Token

1. **Create a Personal Access Token:**
   - Go to [GitHub Settings > Developer settings > Personal access tokens](https://github.com/settings/tokens)
   - Click "Generate new token (classic)"
   - Select scopes: `public_repo` (for public repositories) or `repo` (for
     private repositories)
   - Copy the generated token

2. **Set the token via environment variable (recommended):**

   ```bash
   export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
   call-linter
   ```

3. **Or pass the token via CLI flag:**

   ```bash
   call-linter --github-token ghp_xxxxxxxxxxxxxxxxxxxx
   ```

### Rate Limits

| Authentication | Requests/Hour | Recommended Use |
|---------------|---------------|-----------------|
| **With Token** | 5,000 | ✅ Production, CI/CD, large repositories |
| **Without Token** | 60 | ⚠️ Small repositories, testing purposes |

**Without a token, you'll see:** `⚠️ No GitHub token provided; risk of rate-limiting`

## Usage

### Command Line Interface

```bash
# Show help with version
call-linter --help

# Scan current directory (with environment token)
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
call-linter

# Scan specific path with CLI token
call-linter /path/to/project --github-token ghp_xxxxxxxxxxxxxxxxxxxx

# Use custom configuration
call-linter --config config.yaml

# JSON output format
call-linter --format json

# Verbose output with 8 parallel workers
call-linter --verbose --workers 8

# Exclude patterns
call-linter --exclude "**/test/**" --exclude "**/docs/**"

# Disable SHA pinning policy (allow tags/branches)
call-linter --no-require-pinned-sha

# Run without token (limited to 60 requests/hour)
call-linter  # Shows: ⚠️ No GitHub token provided; risk of rate-limiting
```

### As a Pre-commit Hook

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/lfit/call-linter
    rev: v1.0.0  # Use the ref you want
    hooks:
      - id: call-linter
```

### As a GitHub Action

```yaml
name: Check GitHub Actions
on: [push, pull_request]

jobs:
  check-actions:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@f4a75cfd619ee5ce8d5b864b0d183aff3c69b55a
      - name: Check action calls (strict SHA pinning)
        uses: lfit/call-linter@v1.0.0
        with:
          path: .
          fail-on-error: true
          parallel: true
          workers: 4
          require-pinned-sha: true  # Default: require SHA pinning
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  check-actions-allow-tags:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4  # This would fail in strict mode above
      - name: Check action calls (allow tags/branches)
        uses: lfit/call-linter@v1.0.0
        with:
          path: .
          require-pinned-sha: false  # Allow @v4, @main, etc.
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Configuration

Call Linter is configurable via YAML files, environment variables, or
command-line arguments. Configuration loads in this order:

1. Command-line arguments (highest priority)
2. Environment variables with `CALL_LINTER_` prefix
3. Configuration file (lowest priority)

### Configuration File

Create `~/.config/call-linter/config.yaml` or use `--config`:

```yaml
# Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
log_level: INFO

# Number of parallel workers (1-32)
parallel_workers: 4

# File extensions to scan
scan_extensions:
  - ".yml"
  - ".yaml"

# Patterns to exclude from scanning
exclude_patterns:
  - "**/node_modules/**"
  - "**/vendor/**"

# Require actions using commit SHAs (default: true)
require_pinned_sha: true

# Git configuration
git:
  timeout_seconds: 30
  use_ssh_agent: true

# Network configuration
network:
  timeout_seconds: 30
  max_retries: 3
  retry_delay_seconds: 1.0
  rate_limit_delay_seconds: 0.1
```

### Environment Variables

```bash
export CALL_LINTER_LOG_LEVEL=DEBUG
export CALL_LINTER_PARALLEL_WORKERS=8
export CALL_LINTER_REQUIRE_PINNED_SHA=false
export CALL_LINTER_GIT__TIMEOUT_SECONDS=60
```

## Validation Rules

Call Linter validates GitHub Actions workflow calls using these rules:

### Action Call Format

Valid action call patterns:

```yaml
# Standard action with version tag
- uses: actions/checkout@v4

# Action with commit SHA
- uses: actions/checkout@8f4d7d2c3f1b2a9d8e5c6a7b4f3e2d1c0b9a8f7e

# Action with branch reference
- uses: actions/checkout@main

# Reusable workflow call
- uses: org/repo/.github/workflows/workflow.yaml@v1.0.0

# With trailing comment
- uses: actions/setup-python@v5.0.0  # Latest stable
```

### Repository Validation

- Organization names: 1-39 characters, alphanumeric and hyphens
- Cannot start/end with hyphen or contain consecutive hyphens
- Repository names: alphanumeric, dots, underscores, hyphens, slashes

### Reference Validation

Call Linter validates that references exist using `git ls-remote`:

- **Commit SHAs**: 40-character hexadecimal strings
- **Tags**: Semantic versions (v1.0.0) and other tag formats
- **Branches**: main, master, develop, feature branches

### Supported Reference Types

<!-- markdownlint-disable MD013 -->
| Type | Example | Validation Method | SHA Pinning |
|------|---------|-------------------|-------------|
| Commit SHA | `f4a75cfd619ee5ce8d5b864b0d183aff3c69b55a` | `git ls-remote` | ✅ **Required by default** |
| Semantic Version | `v1.2.3`, `1.0.0` | `git ls-remote --tags` | ❌ Fails unless `--no-require-pinned-sha` |
| Branch | `main`, `develop` | `git ls-remote --heads` | ❌ Fails unless `--no-require-pinned-sha` |
<!-- markdownlint-enable MD013 -->

### SHA Pinning Enforcement

By default, call-linter **requires all action calls use commit SHAs** for
security best practices. This helps prevent supply chain attacks and ensures
reproducible builds.

```bash
# Default behavior - fails on non-SHA references
call-linter  # Fails on @v4, @main, etc.

# Disable SHA pinning policy
call-linter --no-require-pinned-sha  # Allows @v4, @main, etc.
```

**Security Recommendation**: Keep SHA pinning enabled in production environments
and use automated tools like Dependabot to keep SHA references updated.

## Security Considerations

### SHA Pinning Benefits

- **Supply Chain Security**: Prevents malicious code injection through
compromised action versions
- **Reproducible Builds**: Ensures consistent behavior across builds and environments
- **Immutable References**: SHA references stay fixed, unlike tags and branches
- **Audit Trail**: Clear tracking of exact code versions used in workflows

### Migration Strategy

```bash
# Step 1: Identify unpinned actions
call-linter --format json | jq '.errors[] | select(.validation_result == "not_pinned_to_sha")'

# Step 2: Temporarily allow unpinned actions during migration
call-linter --no-require-pinned-sha

# Step 3: Use tools like Dependabot to pin and update SHA references automatically
```

### Dependabot Configuration

Add to `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    commit-message:
      prefix: "ci"
      include: "scope"
```

## Output Formats

### Text Output (Default)

```text
🏷️ call-linter version 1.0.0

                                     Scan Summary
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric                ┃ Count ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Workflow files        │    12 │
│ Total action calls    │    45 │
│ Action calls          │    38 │
│ Workflow calls        │     7 │
│ SHA references        │    35 │
│ Tag references        │     8 │
│ Branch references     │     2 │
└───────────────────────┴───────┘

❌ Found 8 validation errors

  - 8 actions not pinned to SHA

Validation Errors:
❌ Invalid action call in workflow: .github/workflows/test.yaml
      - uses: actions/checkout@v4 [not_pinned_to_sha]

❌ Invalid action call in workflow: .github/workflows/test.yaml
      - uses: actions/setup-python@v5 [not_pinned_to_sha]
```

### JSON Output

```bash
call-linter --format json
```

```json
{
  "scan_summary": {
    "total_files": 12,
    "total_calls": 45,
    "action_calls": 38,
    "workflow_calls": 7,
    "sha_references": 42,
    "tag_references": 2,
    "branch_references": 1
  },
  "validation_summary": {
    "total_errors": 8,
    "invalid_repositories": 0,
    "invalid_references": 0,
    "syntax_errors": 0,
    "network_errors": 0,
    "timeouts": 0,
    "not_pinned_to_sha": 8
  },
  "errors": [
    {
      "file_path": ".github/workflows/test.yaml",
      "line_number": 8,
      "raw_line": "      - uses: actions/checkout@v4",
      "organization": "actions",
      "repository": "checkout",
      "reference": "v4",
      "call_type": "action",
      "reference_type": "tag",
      "validation_result": "not_pinned_to_sha",
      "error_message": "Action not pinned to commit SHA"
    }
  ]
}
```

## GitHub Action Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `path` | Path to scan for workflows | No | `.` |
| `config-file` | Path to configuration file | No | |
| `github-token` | GitHub API token | No | |
| `log-level` | Logging level | No | `INFO` |
| `output-format` | Output format (text, json) | No | `text` |
| `fail-on-error` | Exit with error on failures | No | `true` |
| `parallel` | Enable parallel processing | No | `true` |
| `workers` | Number of parallel workers | No | `4` |
| `exclude` | Comma-separated exclude patterns | No | |
| `require-pinned-sha` | Require actions pinned to commit SHAs | No | `true` |

## GitHub Action Outputs

| Output | Description |
|--------|-------------|
| `errors-found` | Number of validation errors |
| `total-calls` | Total action calls scanned |
| `scan-summary` | JSON summary of results |

## CLI Options

```text
Usage: call-linter [OPTIONS] [PATH]

  Scan GitHub Actions workflows for invalid action and workflow calls.

Arguments:
  [PATH]  Path to scan for workflows (default: current directory)

Options:
  -c, --config FILE          Configuration file path
  --github-token TEXT        GitHub API token (or set GITHUB_TOKEN env var)
  -v, --verbose              Enable verbose output
  -q, --quiet                Suppress all output except errors
  --log-level LEVEL          Set logging level
  -f, --format FORMAT        Output format (text, json)
  --fail-on-error            Exit with error code if failures found
  --no-fail-on-error         Don't exit with error code
  --parallel                 Enable parallel processing
  --no-parallel              Disable parallel processing
  -j, --workers INTEGER      Number of parallel workers (1-32)
  -e, --exclude PATTERN      Patterns to exclude (multiples accepted)
  --require-pinned-sha       Require actions pinned to commit SHAs (default)
  --no-require-pinned-sha    Allow actions with tags/branches
  --version                  Show version and exit
  --help                     Show this message and exit
```

## Integration Examples

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Check Actions') {
            steps {
                sh 'pip install call-linter'
                sh 'call-linter --format json > results.json'
                archiveArtifacts artifacts: 'results.json'
            }
        }
    }
}
```

### Docker Usage

```bash
# Using published image
docker run --rm -v "$(pwd):/workspace" \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  ghcr.io/lfit/call-linter:latest /workspace

# Build local image
docker build -t call-linter .
docker run --rm -v "$(pwd):/workspace" \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  call-linter /workspace
```

## Error Types

| Error Type | Description | Resolution |
|------------|-------------|------------|
| `invalid_repository` | Repository not found | Check org/repo name spelling |
| `invalid_reference` | Branch/tag/SHA not found | Verify reference exists |
| `invalid_syntax` | Malformed action call | Fix YAML syntax |
| `network_error` | Connection failed | Check network/credentials |
| `timeout` | Validation timed out | Increase timeout settings |
<!-- markdownlint-disable MD013 -->
| `not_pinned_to_sha` | Action not using SHA | Pin to commit SHA or use `--no-require-pinned-sha` |
<!-- markdownlint-enable MD013 -->

## Development

### Setup Development Environment

```bash
git clone https://github.com/lfit/call-linter.git
cd call-linter
uv pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=call_linter

# Run specific test categories
pytest -m unit
pytest -m integration
pytest -m "not slow"
```

### Code Quality

```bash
# Format code
ruff format .

# Lint code
ruff check .

# Type checking
mypy src/call_linter

# Pre-commit hooks
pre-commit run --all-files
```

### Building and Publishing

```bash
# Build package
uv build

# Publish to PyPI
uv publish
```

## Architecture

Call Linter follows a modular architecture with clear separation of concerns:

- **CLI Interface**: Typer-based command-line interface
- **Configuration**: Pydantic models with YAML/env support
- **Scanner**: Workflow file discovery and parsing
- **Patterns**: Regex-based action call extraction
- **Validator**: Git-based remote validation
- **Models**: Type-safe data structures

## Performance

Call Linter performance optimizations:

- **Parallel Processing**: Multi-threaded validation
- **Caching**: Repository and reference validation caching
- **Rate Limiting**: Configurable delays to respect API limits
- **Efficient Git Operations**: Uses `git ls-remote` vs full clones

Typical performance on a repository with 50 workflows and 200 action calls:

- **Serial**: ~60 seconds
- **Parallel (4 workers)**: ~15 seconds
- **Cached**: ~2 seconds (follow-up runs)

## Security Notes

- **Token Security**: Tokens are never logged or stored permanently
- **Environment Variables**: Recommended method for token management
- **Private Repositories**: Requires appropriate token permissions
- **Rate Limiting**: Proactive management prevents API abuse
- **API Efficiency**: Batch queries reduce API surface area

### Pre-commit Hook

The repository includes a pre-commit hook that runs call-linter on its own workflows:

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: call-linter
      name: call-linter - Check GitHub Actions/workflows
      entry: python
      args: [-m, call_linter.cli, ., --quiet]
      language: system
      files: '^\.github/workflows/.*\.ya?ml$'
```

### Development Setup

For contributors, use the development setup script:

```bash
# Install development environment with self-linting
./scripts/setup-dev.sh

# This sets up:
# - Development dependencies
# - Pre-commit hooks (including call-linter)
# - GitHub token configuration
# - Self-linting test
```

## Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run the test suite and linting (including self-linting)
5. Submit a pull request

## License

Licensed under the Apache License 2.0. See the LICENSE file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/lfit/call-linter/issues)
- **Discussions**: [GitHub Discussions](https://github.com/lfit/call-linter/discussions)
- **Documentation**: [Read the Docs](https://call-linter.readthedocs.io)

## Acknowledgments

Built with modern Python tooling:

- [Typer](https://typer.tiangolo.com/) for CLI interface
- [Pydantic](https://docs.pydantic.dev/) for data validation
- [Rich](https://rich.readthedocs.io/) for beautiful terminal output
- [uv](https://docs.astral.sh/uv/) for dependency management
- [pytest](https://pytest.org/) for testing
