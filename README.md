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

- **🔧 Auto-Fix**: Automatically fix invalid references and pin actions to commit SHAs
- **🧪 Testing Skip**: Auto-fixing skips actions with 'test' in comments by default (use `--fix-test-calls` to enable)
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

<!-- markdownlint-disable MD060 -->

| Authentication    | Requests/Hour | Recommended Use                          |
| ----------------- | ------------- | ---------------------------------------- |
| **With Token**    | 5,000         | ✅ Production, CI/CD, large repositories |
| **Without Token** | 60            | ⚠️ Small repositories, testing purposes  |

<!-- markdownlint-enable MD060 -->

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

# Auto-fix invalid references and pin to SHAs
gha-workflow-linter lint --auto-fix

# Auto-fix including actions with 'test' in comments (default skips them)
gha-workflow-linter lint --auto-fix --fix-test-calls

# Auto-fix without using latest versions (keeps current version)
gha-workflow-linter lint --auto-fix --no-update-actions

# Run without any authentication (limited to 60 requests/hour)
# This happens when GitHub CLI is not installed/authenticated AND no token exists
# Shows: ⚠️ No GitHub token available; API requests may be rate-limited
gha-workflow-linter lint
```

### Auto-Fix Feature

The linter can automatically fix invalid action references and pin them to
commit SHAs:

```bash
# Enable auto-fix (default: enabled unless overridden in config)
gha-workflow-linter lint --auto-fix

# Disable auto-fix
gha-workflow-linter lint --no-auto-fix

# Auto-fix with latest versions (default: disabled unless overridden in config)
gha-workflow-linter lint --auto-fix --update-actions

# Auto-fix without using latest versions (keeps current version)
gha-workflow-linter lint --auto-fix --no-update-actions
```

**Skip Testing Actions**: By default, auto-fix skips actions with 'test' in
their comments (case-insensitive). This is useful when you have experimental or
testing branches that you don't want to update yet. Use `--fix-test-calls` to
enable auto-fixing for these actions:

```yaml
# The tool skips these by default (unless you use --fix-test-calls)
- uses: actions/checkout@master  # Testing
- uses: myorg/my-action@test-branch  # testing new feature
- uses: myorg/my-action@experimental  # Test version
```

Example output (default behavior, test actions skipped):

```text
⏩ Skipped 3 testing action(s) in 1 file(s):

📄 .github/workflows/build.yaml
  ⏩ uses: actions/checkout@master  # Testing
  ⏩ uses: myorg/my-action@test-branch  # testing new feature
  ⏩ uses: myorg/my-action@experimental  # Test version

🔧 Auto-fixed issues in 1 file(s):

📄 .github/workflows/build.yaml
  - - uses: actions/cache@v3
  + - uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830 # v4.3.0
```

### Exit Codes

<!-- markdownlint-disable MD013 -->

| Code | Meaning                                                               |
| ---- | --------------------------------------------------------------------- |
| `0`  | No failing findings                                                   |
| `1`  | Defects found, or a fixer modified files, or the run itself failed    |
| `2`  | Command-line usage error (reserved by the argument parser)            |
| `3`  | `--verify-allow-list` and stale allow-list pins remain                |
| `4`  | `--verify-allow-list` and the tool could not reach the latest release |
| `5`  | `--verify-actions` and outdated action calls remain                   |

<!-- markdownlint-enable MD013 -->

When more than one applies, the most significant wins: `4`, then `3`,
then `5`, then `1`. A check that could not run outranks a stale result,
because enforcement reporting success when it never looked is worse than
useless. A condition you asked about by name outranks the generic `1`,
and nothing masks it.

Codes `3`, `4` and `5` require the matching `--verify-*` flag. Without
it, the linter reports those findings and leaves the exit code alone.

### Verifying Action Currency

`--verify-actions` treats outdated action calls as errors, mirroring
`--verify-allow-list`:

```bash
# Report outdated actions but do not fail (the default)
gha-workflow-linter lint

# Fail when any action call has a newer release available
gha-workflow-linter lint --verify-actions
```

This is useful in a scheduled compliance run, where you want to know
that something has fallen behind, without blocking a developer's commit
over it.

### Update Cooldown

To guard against supply-chain attacks and retracted releases, the linter
can refuse to update an action call to a release until that release has
been public for a set number of days. This mirrors the
[Dependabot `cooldown`](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference#cooldown-)
policy.

```bash
# Update to releases at least 7 days old
gha-workflow-linter lint --auto-fix --update-actions --cooldown 7

# Disable the cooldown (the default behaviour)
gha-workflow-linter lint --auto-fix --update-actions --cooldown 0
```

When `--cooldown` is not supplied, the linter walks up from the scanned
path to find a `.github/dependabot.yml` (or `.yaml`) file and reuses its
`cooldown.default-days` value, preferring the `github-actions` ecosystem.
The linter reports that value once:

```text
Using cooldown timer/value [7] from dependabot configuration 🤖
```

When the linter finds no Dependabot configuration (and no flag sets a
value) the cooldown defaults to `0`, preserving the original behaviour.
The linter picks the newest release that satisfies the cooldown window,
so it still updates an action to an older-but-eligible release when the
latest release remains inside the window.

> Note: the cooldown relies on a verifiable publication timestamp for
> each candidate: the release publish date (GitHub API GraphQL/REST) or
> an annotated tag's tagger date. Lightweight tags carry no creation
> timestamp of their own, and the Git validation method cannot expose
> release dates, so the linter skips candidates it cannot date while a
> cooldown applies.

### Allow-List Pin Checking

The `lfreleng-actions` organisation pins its
[`step-security/harden-runner`](https://github.com/step-security/harden-runner)
egress allow-list using a custom `uses:`-style coordinate consumed by
[`harden-runner-block-action`][hrba]:

[hrba]: https://github.com/lfreleng-actions/harden-runner-block-action

<!-- markdownlint-disable MD013 -->

```yaml
# Internal workflow, shorthand form
- uses: lfreleng-actions/harden-runner-block-action@6db537b3...  # v0.2.1
  with:
    config: '@18d9c4446bea555d0783e850f6d295f844fe8f67'  # v0.1.1

# Reusable-workflow input default, explicit path form
harden_runner_allowlist:
  type: string
  default: 'lfreleng-actions//.github/harden-runner/lfreleng-actions/allow_list.txt@bf6642f6...'  # v0.12.2
```

<!-- markdownlint-enable MD013 -->

These are values of `config:` and `default:` keys, **not** `uses:`
references, so Dependabot cannot see or bump them. They drift without
warning, and a stale pin means a block-mode job lacks newly allow-listed
endpoints, producing confusing `ECONNREFUSED` failures long after
someone corrected the allow-list itself.

The linter detects these pins, resolves the host repository's latest
release (dereferencing the annotated tag to its commit), and reports
pins that lag behind.

```bash
# Detect stale pins; reports them but never fails (the default)
gha-workflow-linter lint

# Fail the run when stale pins remain
gha-workflow-linter lint --verify-allow-list

# Skip the check entirely
gha-workflow-linter lint --no-allow-list

# Show pins silenced by a suppression directive
gha-workflow-linter lint --show-suppressed

# Rewrite stale pins in place
gha-workflow-linter lint --update-allow-list
```

`--update-allow-list` changes the reference and its version comment and
nothing else. Quoting style, the spacing before `#`, the comment's
position (inside or outside the quotes) and any suppression directive
all survive the edit, so the resulting diff stays reviewable. Writes are
atomic and preserve the file's existing line endings. As with the action
fixer, a run that modifies files exits `1` so a pre-commit hook or CI job
notices that the tree changed.

This check follows an `lfreleng-actions` convention rather than
GitHub-native validation, so it stays **advisory by default**: the
linter reports findings as warnings and leaves the exit code alone.
Enforcement is opt-in via `--verify-allow-list`. When the linter cannot
resolve the latest release (no token, no network, rate limited), the
default mode prints a notice and carries on; under
`--verify-allow-list` it exits `4` instead of passing.

A pin counts as stale when the target is newer, and not otherwise.
It leaves a repository already ahead of the cooldown-eligible release
alone, so a cooldown never recommends a downgrade.

#### Suppressing a deliberate pin

A repository may hold a pin at an older version on purpose. The linter
accepts either of two forms:

<!-- markdownlint-disable MD013 -->

```yaml
    # gha-workflow-linter: allow-list-pin-ok -- waiting on ONAP rollout
    config: '@8f4f0cf83e6a015957e83261ed379fd811fc060e'  # v0.5.1

    config: '@8f4f0cf83e6a015957e83261ed379fd811fc060e'  # v0.5.1 allow-list-pin-ok
```

<!-- markdownlint-enable MD013 -->

The preceding-line form must sit on the line directly above the pin, at
any indentation. An optional reason may follow ` -- ` and appears in
reports. Both forms stay inert at run time: the action never sees them.

The linter excludes a suppressed pin from reporting, enforcement **and
remediation**: `--update-allow-list` leaves it alone. It still lists it
under `--format json` with
`"suppressed": true`, and every run prints a one-line count so
suppressions stay visible.

Suppression covers **currency** and nothing else. A pin whose version comment
disagrees with its SHA, or whose spec breaks the grammar, counts as a
defect regardless of intent and stays reported.

#### Resolving the organisation

The `@<sha>` shorthand resolves its host organisation from the workflow's
own organisation. The linter infers this from `GITHUB_REPOSITORY_OWNER`,
then the `upstream` git remote, then `origin`. Contributors working from
a personal fork should pass `--allow-list-org` explicitly, since `origin`
would otherwise resolve to a `.github` repository that does not exist.

### What Gets Scanned

The linter walks the tree below the path you give it, collecting
`.github/workflows/*.y{a,}ml` at any depth plus `action.y{a,}ml` files.

Scanning **stops at nested repository boundaries**. Git worktrees,
submodules and vendored clones each place a `.git` entry at their own
root, and anything beneath one belongs to a different repository, or to
a second checkout of this one. A repository that keeps worktrees under
`.worktrees/` would otherwise report every finding once per checked-out
branch, against files the working tree does not contain.

The scan root itself never counts as a boundary, so pointing the linter
at a worktree scans that worktree. Pointing it at a directory that
merely *contains* repositories finds nothing, since each child is a
boundary.

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

# Number of parallel workers (1-32, auto-detected if not specified)
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

# Auto-fix broken/invalid references (default: true)
auto_fix: true

# Use latest versions when auto-fixing (default: false)
update_actions: false

# Allow prerelease versions when finding latest versions (default: false)
allow_prerelease: false

# Use two spaces before inline comments when fixing (default: true)
two_space_comments: true

# Skip scanning action.yaml/action.yml files (default: false)
skip_actions: false

# Enable auto-fixing action calls with 'test' in comments (default: false)
fix_test_calls: false

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

<!-- markdownlint-disable MD013 MD060 -->

| Type             | Example                                    | Validation Method  | SHA Pinning                               |
| ---------------- | ------------------------------------------ | ------------------ | ----------------------------------------- |
| Commit SHA       | `f4a75cfd619ee5ce8d5b864b0d183aff3c69b55a` | GitHub GraphQL API | ✅ **Required by default**                |
| Semantic Version | `v1.2.3`, `1.0.0`                          | GitHub GraphQL API | ❌ Fails unless `--no-require-pinned-sha` |
| Branch           | `main`, `develop`                          | GitHub GraphQL API | ❌ Fails unless `--no-require-pinned-sha` |

<!-- markdownlint-enable MD013 MD060 -->

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
    "invalid_paths": 0,
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

| Input                | Description                                  | Required | Default |
| -------------------- | -------------------------------------------- | -------- | ------- |
| `path`               | Path to scan for workflows                   | No       | `.`     |
| `config-file`        | Path to configuration file                   | No       |         |
| `validation-method`  | Validation method (github-api or git)        | No       | auto    |
| `log-level`          | Logging level                                | No       | `INFO`  |
| `output-format`      | Output format (text, json)                   | No       | `text`  |
| `fail-on-error`      | Exit with error on failures                  | No       | `true`  |
| `parallel`           | Enable parallel processing                   | No       | `true`  |
| `workers`            | Number of parallel workers                   | No       | Auto    |
| `exclude`            | Comma-separated exclude patterns             | No       |         |
| `require-pinned-sha` | Require actions pinned to commit SHAs        | No       | `true`  |
| `auto-fix`           | Auto-fix broken/invalid references           | No       | `true`  |
| `update-actions`     | Update action calls to the latest release    | No       | `false` |
| `allow-prerelease`   | Allow prerelease versions for latest         | No       | `false` |
| `two-space-comments` | Use two spaces before inline comments        | No       | `false` |
| `skip-actions`       | Skip scanning action.yaml/action.yml files   | No       | `false` |
| `fix-test-calls`     | Fix actions with 'test' in comments          | No       | `false` |
| `cooldown`           | Days a release must have been public         | No       |         |
| `allow-list`         | Detect stale harden-runner allow-list pins   | No       | `true`  |
| `verify-allow-list`  | Fail when stale allow-list pins remain       | No       | `false` |
| `update-allow-list`  | Rewrite stale allow-list pins in place       | No       | `false` |
| `allow-list-org`     | Org for the allow-list `@` shorthand         | No       |         |

<!-- markdownlint-enable MD013 -->

## GitHub Action Outputs

<!-- markdownlint-disable MD013 -->

| Output         | Description                 |
| -------------- | --------------------------- |
| `errors-found` | Number of validation errors |
| `total-calls`  | Total action calls scanned  |
| `scan-summary` | JSON summary of results     |

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
  -j, --workers INTEGER      Number of parallel workers (1-32, auto-detected)
  -e, --exclude PATTERN      Patterns to exclude (multiples accepted)
  --require-pinned-sha       Require actions pinned to commit SHAs (default)
  --no-require-pinned-sha    Allow actions with tags/branches
  --auto-fix                 Auto-fix broken/invalid references
  --no-auto-fix              Disable auto-fixing
  --update-actions           Update action calls to the latest release
  --no-update-actions        Keep the current action versions
  --allow-prerelease         Allow prerelease versions for latest
  --no-allow-prerelease      Disallow prerelease versions
  --two-space-comments       Use two spaces before inline comments
  --no-two-space-comments    Use single space before inline comments
  --skip-actions             Skip scanning action.yaml/action.yml files
  --no-skip-actions          Scan action.yaml/action.yml files (default)
  --fix-test-calls           Fix actions with 'test' in comments
  --cooldown INTEGER         Days a release must be public before updating
                             (defaults to the Dependabot cooldown setting,
                             then 0)
  --version                  Show version and exit
  --help                     Show this message and exit

Note: Most boolean options use config file defaults when not specified.
      CLI flags override config file settings.
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

| Error Type           | Description                                              | Resolution                                                              |
| -------------------- | -------------------------------------------------------- | ----------------------------------------------------------------------- |
| `invalid_repository` | Repository not found                                     | Check org/repo name spelling                                            |
| `invalid_reference`  | Branch/tag/SHA not found                                 | Verify reference exists                                                 |
| `invalid_path`       | Subdirectory action path not found at the referenced ref | Check the subdirectory path (e.g. `owner/repo/path`) exists at that ref |
| `invalid_syntax`     | Malformed action call                                    | Fix YAML syntax                                                         |
| `network_error`      | Connection failed                                        | Check network/credentials                                               |
| `timeout`            | Validation timed out                                     | Increase timeout settings                                               |
| `not_pinned_to_sha`  | Action not using SHA                                     | Pin to commit SHA or use `--no-require-pinned-sha`                      |

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
