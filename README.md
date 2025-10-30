<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# 🔍 GHA Workflow Linter

[![GitHub Actions](https://github.com/modeseven-lfit/gha-workflow-linter/actions/workflows/build-test.yaml/badge.svg)](https://github.com/modeseven-lfit/gha-workflow-linter/actions/workflows/build-test.yaml)
[![PyPI version](https://img.shields.io/pypi/v/gha-workflow-linter.svg)](https://pypi.org/project/gha-workflow-linter/)
[![Python Support](https://img.shields.io/pypi/pyversions/gha-workflow-linter.svg)](https://devguide.python.org/versions/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A comprehensive GitHub Actions workflow linter that validates action and
workflow calls against remote repositories. GHA Workflow Linter ensures your GitHub
Actions workflows reference valid repositories, branches, tags, and commit SHAs.

## Features

<!-- markdownlint-disable MD013 -->

- **🔒 SHA Pinning Enforcement**: Requires actions using commit SHAs for security (configurable)
- **🔑 Automatic Authentication**: Auto-detects GitHub tokens from GitHub CLI when available
- **📦 Local Caching**: Stores validation results locally to improve performance and reduce API calls
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
uv add gha-workflow-linter
```

### From Source

```bash
git clone https://github.com/modeseven-lfit/gha-workflow-linter.git
cd gha-workflow-linter
uv pip install -e .
```

### Development Installation

```bash
git clone https://github.com/modeseven-lfit/gha-workflow-linter.git
cd gha-workflow-linter
uv pip install -e ".[dev]"
```

## Authentication

GHA Workflow Linter uses the GitHub GraphQL API for efficient validation. Authentication
is **optional** but **highly recommended** to avoid rate limiting.

### Automatic Authentication (Recommended)

If you have [GitHub CLI](https://cli.github.com/) installed and authenticated,
the linter will **automatically** get a token when needed:

```bash
# No token setup required if GitHub CLI has authentication!
gha-workflow-linter lint
```

When no token exists, you'll see:

```text
⚠️ No GitHub token found; attempting to get using GitHub CLI
✅ GitHub token retrieved from GitHub CLI
```

### Manual Token Setup

If you don't use GitHub CLI or prefer manual setup:

1. **Create a Personal Access Token:**

   <!-- markdownlint-disable MD013 -->

   - Go to [GitHub Settings > Developer settings > Personal access tokens](https://github.com/settings/tokens)
   - Click "Generate new token (classic)"
   - Select scopes: `public_repo` (for public repositories) or `repo` (for
     private repositories)
   - Copy the generated token

   <!-- markdownlint-enable MD013 -->

2. **Set the token via environment variable:**

   ```bash
   export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
   gha-workflow-linter lint
   ```

3. **Or pass the token via CLI flag:**

   ```bash
   gha-workflow-linter lint --github-token ghp_xxxxxxxxxxxxxxxxxxxx
   ```

### Authentication Priority

The linter uses the following priority order:

1. **CLI flag** (`--github-token`)
2. **Environment variable** (`GITHUB_TOKEN`)
3. **GitHub CLI fallback** (`gh auth token`)

### Rate Limits

<!-- markdownlint-disable MD013 -->

| Authentication | Requests/Hour | Recommended Use |
|---------------|---------------|-----------------|
| **With Token** | 5,000 | ✅ Production, CI/CD, large repositories |
| **Without Token** | 60 | ⚠️ Small repositories, testing purposes |

<!-- markdownlint-enable MD013 -->

**Without any authentication, you'll see:**
`⚠️ No GitHub token available; API requests may be rate-limited`

## Usage

### Command Line Interface

```bash
# Show help with version
gha-workflow-linter --help

# Scan current directory (automatic authentication via GitHub CLI)
gha-workflow-linter lint

# Scan with environment token
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
gha-workflow-linter lint

# Scan specific path with CLI token
gha-workflow-linter lint /path/to/project --github-token ghp_xxxxxxxxxxxxxxxxxxxx

# Use custom configuration
gha-workflow-linter lint --config config.yaml

# JSON output format
gha-workflow-linter lint --format json

# Verbose output with 8 parallel workers
gha-workflow-linter lint --verbose --workers 8

# Exclude patterns
gha-workflow-linter lint --exclude "**/test/**" --exclude "**/docs/**"

# Disable SHA pinning policy (allow tags/branches)
gha-workflow-linter lint --no-require-pinned-sha

# Run without any authentication (limited to 60 requests/hour)
# This happens when GitHub CLI is not installed/authenticated AND no token exists
# Shows: ⚠️ No GitHub token available; API requests may be rate-limited
gha-workflow-linter lint
```

### As a Pre-commit Hook

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/modeseven-lfit/gha-workflow-linter
    rev: d86993e21bbcddcfa9dac63cd43213b6a58fa6fb  # frozen: v0.1.1
    hooks:
      - id: gha-workflow-linter
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
        uses: modeseven-lfit/gha-workflow-linter@d86993e21bbcddcfa9dac63cd43213b6a58fa6fb
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
        uses: modeseven-lfit/gha-workflow-linter@d86993e21bbcddcfa9dac63cd43213b6a58fa6fb
        with:
          path: .
          require-pinned-sha: false  # Allow @v4, @main, etc.
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Configuration

GHA Workflow Linter is configurable via YAML files, environment variables, or
command-line arguments. Configuration loads in this order:

1. Command-line arguments (highest priority)
2. Environment variables with `GHA_WORKFLOW_LINTER_` prefix
3. Configuration file (lowest priority)

### Configuration File

Create `~/.config/gha-workflow-linter/config.yaml` or use `--config`:

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

# Local caching configuration
cache:
  enabled: true
  cache_dir: ~/.cache/gha-workflow-linter
  cache_file: validation_cache.json
  default_ttl_seconds: 604800  # 7 days
  max_cache_size: 10000
  cleanup_on_startup: true
```

### Environment Variables

```bash
export GHA_WORKFLOW_LINTER_LOG_LEVEL=DEBUG
export GHA_WORKFLOW_LINTER_PARALLEL_WORKERS=8
export GHA_WORKFLOW_LINTER_REQUIRE_PINNED_SHA=false
export GHA_WORKFLOW_LINTER_GIT__TIMEOUT_SECONDS=60
export GHA_WORKFLOW_LINTER_CACHE__ENABLED=true
export GHA_WORKFLOW_LINTER_CACHE__DEFAULT_TTL_SECONDS=86400
```

## Local Caching

GHA Workflow Linter includes a local caching system that stores validation
results to improve performance and reduce API calls for later runs.

### Cache Features

- **Automatic Caching**: Validation results are automatically cached locally
- **Version-Based Invalidation**: Tool purges cache when version changes
- **Configurable TTL**: Cache entries expire after seven days by default
- **Size Limits**: Cache size limits prevent excessive disk usage
- **Persistence**: Cache survives between CLI invocations and system restarts
- **Smart Cleanup**: Expired entries are automatically removed

### Cache Commands

```bash
# Show cache information
gha-workflow-linter cache --info

# Remove expired cache entries
gha-workflow-linter cache --cleanup

# Clear all cache entries
gha-workflow-linter cache --purge
```

### Cache Options

```bash
# Bypass cache for a single run
gha-workflow-linter lint --no-cache

# Clear cache and exit
gha-workflow-linter lint --purge-cache

# Override default cache TTL (in seconds)
gha-workflow-linter lint --cache-ttl 3600  # 1 hour
```

### Cache Benefits

- **Performance**: Later runs are faster for validated actions
- **API Efficiency**: Reduces GitHub API calls and respects rate limits better
- **Offline Support**: Validated actions work without network access
- **Bandwidth Savings**: Useful in CI/CD environments with repeated workflows

### Cache Location

By default, cache files go in:

- **Linux/macOS**: `~/.cache/gha-workflow-linter/validation_cache.json`
- **Windows**: `%LOCALAPPDATA%\gha-workflow-linter\validation_cache.json`

You can customize the cache location via configuration file or environment variables.

### Version-Based Cache Invalidation

The cache system automatically detects when you've upgraded to a new version of
the tool and purges all cached entries to ensure consistency. This prevents
issues where validation logic changes between versions could result in stale
cached data.

When the tool detects a version mismatch, you'll see a message like:

```text
INFO Cache version mismatch (cache: 0.1.3, current: 0.1.4). Purging cache.
```

This ensures that:

- Validation logic improvements are always applied
- Bug fixes in validation don't get masked by old cache entries
- New validation features work properly from the first run

**Note**: Caching works for CLI and pre-commit hook usage. GitHub Actions
runners use ephemeral containers, so caching provides no benefit in that
environment.

## Validation Rules

GHA Workflow Linter validates GitHub Actions workflow calls using these rules:

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

GHA Workflow Linter validates that references exist using GitHub's GraphQL API:

- **Commit SHAs**: 40-character hexadecimal strings
- **Tags**: Semantic versions (v1.0.0) and other tag formats
- **Branches**: main, master, develop, feature branches

### Supported Reference Types

<!-- markdownlint-disable MD013 -->

| Type | Example | Validation Method | SHA Pinning |
|------|---------|-------------------|-------------|
| Commit SHA | `f4a75cfd619ee5ce8d5b864b0d183aff3c69b55a` | GitHub GraphQL API | ✅ **Required by default** |
| Semantic Version | `v1.2.3`, `1.0.0` | GitHub GraphQL API | ❌ Fails unless `--no-require-pinned-sha` |
| Branch | `main`, `develop` | GitHub GraphQL API | ❌ Fails unless `--no-require-pinned-sha` |

<!-- markdownlint-enable MD013 -->

### SHA Pinning Enforcement

By default, gha-workflow-linter **requires all action calls use commit SHAs** for
security best practices. This helps prevent supply chain attacks and ensures
reproducible builds.

```bash
# Default behavior - fails on non-SHA references
gha-workflow-linter lint  # Fails on @v4, @main, etc.

# Disable SHA pinning policy
gha-workflow-linter lint --no-require-pinned-sha  # Allows @v4, @main, etc.
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
gha-workflow-linter lint --format json | jq '.errors[] | \
  select(.validation_result == "not_pinned_to_sha")'

# Step 2: Temporarily allow unpinned actions during migration
gha-workflow-linter lint --no-require-pinned-sha

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
🏷️ gha-workflow-linter version 1.0.0

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
gha-workflow-linter lint --format json
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

<!-- markdownlint-disable MD013 -->

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

<!-- markdownlint-enable MD013 -->

## GitHub Action Outputs

<!-- markdownlint-disable MD013 -->

| Output | Description |
|--------|-------------|
| `errors-found` | Number of validation errors |
| `total-calls` | Total action calls scanned |
| `scan-summary` | JSON summary of results |

<!-- markdownlint-enable MD013 -->

## CLI Options

```text
Usage: gha-workflow-linter lint [OPTIONS] [PATH]

  Scan GitHub Actions workflows for invalid action and workflow calls.

Arguments:
  [PATH]  Path to scan for workflows (default: current directory)

Options:
  -c, --config FILE          Configuration file path
  --github-token TEXT        GitHub API token (auto-detects from GitHub CLI)
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
                sh 'pip install gha-workflow-linter'
                sh 'gha-workflow-linter lint --format json > results.json'
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
  ghcr.io/modeseven-lfit/gha-workflow-linter:latest lint /workspace

# Build local image
docker build -t gha-workflow-linter .
docker run --rm -v "$(pwd):/workspace" \
  -e GITHUB_TOKEN=$GITHUB_TOKEN \
  gha-workflow-linter lint /workspace
```

## Error Types

<!-- markdownlint-disable MD013 -->

| Error Type | Description | Resolution |
|------------|-------------|------------|
| `invalid_repository` | Repository not found | Check org/repo name spelling |
| `invalid_reference` | Branch/tag/SHA not found | Verify reference exists |
| `invalid_syntax` | Malformed action call | Fix YAML syntax |
| `network_error` | Connection failed | Check network/credentials |
| `timeout` | Validation timed out | Increase timeout settings |
| `not_pinned_to_sha` | Action not using SHA | Pin to commit SHA or use `--no-require-pinned-sha` |

<!-- markdownlint-enable MD013 -->

## Development

### Setup Development Environment

```bash
git clone https://github.com/modeseven-lfit/gha-workflow-linter.git
cd gha-workflow-linter
uv pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=gha_workflow_linter

# Run specific test categories
uv run pytest -m unit
uv run pytest -m integration
uv run pytest -m "not slow"
```

### Code Quality

```bash
# Format code
ruff format .

# Lint code
ruff check .

# Type checking
mypy src/gha_workflow_linter

# Pre-commit hooks
pre-commit run --all-files
```

### Building and Publishing

**Local Builds:**

```bash
uv build
```

This project uses automated CI/CD workflows for building and publishing:

**Development/Testing:**

- Pull requests trigger the `build-test.yaml` workflow
- Automatically runs tests, audits, linting
- Validates the package builds without errors

**Releases:**

- The `build-test-release.yaml` workflow performs publishing/releasing
- Triggered by pushing a git tag to the repository
- Automatically builds, tests and publishes the package

## Architecture

GHA Workflow Linter follows a modular architecture with clear separation of
concerns:

- **CLI Interface**: Typer-based command-line interface
- **Configuration**: Pydantic models with YAML/env support
- **Scanner**: Workflow file discovery and parsing
- **Patterns**: Regex-based action call extraction
- **Validator**: Git-based remote validation
- **Models**: Type-safe data structures

## Performance

GHA Workflow Linter performance optimizations:

- **Parallel Processing**: Multi-threaded validation
- **Caching**: Repository and reference validation caching
- **Rate Limiting**: Configurable delays to respect API limits
- **Efficient API Operations**: Uses GitHub GraphQL API

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

The repository includes a pre-commit hook that runs gha-workflow-linter
on its own workflows:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/modeseven-lfit/gha-workflow-linter
    rev: d86993e21bbcddcfa9dac63cd43213b6a58fa6fb  # frozen: v0.1.1
    hooks:
      - id: gha-workflow-linter
```

### Development Setup

For contributors, use the development setup script:

```bash
# Install development environment with self-linting
./scripts/setup-dev.sh

# This sets up:
# - Development dependencies
# - Pre-commit hooks (including gha-workflow-linter)
# - GitHub authentication (GitHub CLI recommended)
# - Self-linting test
```

## Troubleshooting

### Authentication Issues

**GitHub CLI not found:**

```text
❌ Unable to get GitHub token from any source
💡 Authentication options:
   • Install GitHub CLI: https://cli.github.com/
   • Or set environment variable: export GITHUB_TOKEN=ghp_xxx
   • Or use --github-token flag with your personal access token
```

**GitHub CLI not authenticated:**

```bash
# Check authentication status
gh auth status

# Login if not authenticated
gh auth login
```

**Token permissions:**

- Ensure your token has `public_repo` scope for public repositories
- Use `repo` scope for private repositories
- Check token validity: `gh auth token` should return a valid token

**Rate limiting:**

- Without authentication: 60 requests/hour
- With GitHub token: 5,000 requests/hour
- Large repositories may require authentication to avoid limits

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

- **Issues**: [GitHub Issues](https://github.com/modeseven-lfit/gha-workflow-linter/issues)
- **Discussions**: [GitHub Discussions](https://github.com/modeseven-lfit/gha-workflow-linter/discussions)
- **Documentation**: [Read the Docs](https://gha-workflow-linter.readthedocs.io)

## Acknowledgments

Built with modern Python tooling:

- [Typer](https://typer.tiangolo.com/) for CLI interface
- [Pydantic](https://docs.pydantic.dev/) for data validation
- [Rich](https://rich.readthedocs.io/) for beautiful terminal output
- [uv](https://docs.astral.sh/uv/) for dependency management
- [pytest](https://pytest.org/) for testing
