#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Development setup script for gha-workflow-linter
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

# Check if we're in the right directory
if [[ ! -f "pyproject.toml" ]] || [[ ! -f "action.yaml" ]]; then
    error "This script must be run from the gha-workflow-linter repository root"
fi

info "Setting up gha-workflow-linter development environment..."

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)" 2>/dev/null; then
    error "Python 3.9+ required, found: $python_version"
fi
success "Python version check passed: $python_version"

# Install uv if not present
if ! command -v uv &> /dev/null; then
    info "Installing uv package manager..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$PATH"
    success "uv installed successfully"
else
    success "uv already installed"
fi

# Install development dependencies
info "Installing gha-workflow-linter in development mode..."
uv pip install -e ".[dev]"
success "Development dependencies installed"

# Install pre-commit
info "Installing pre-commit hooks..."
if ! command -v pre-commit &> /dev/null; then
    uv pip install pre-commit
fi

pre-commit install
success "Pre-commit hooks installed"

# Set up GitHub token if not present
if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    warning "No GITHUB_TOKEN environment variable found"
    echo ""
    echo "To avoid rate limiting, set up a GitHub token:"
    echo "1. Go to https://github.com/settings/tokens"
    echo "2. Create a new token with 'public_repo' scope"
    echo "3. Add to your shell profile:"
    echo "   export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx"
    echo ""
else
    success "GitHub token found in environment"
fi

# Test the installation
info "Testing gha-workflow-linter installation..."
if command -v gha-workflow-linter &> /dev/null; then
    # Test CLI command
    python -m gha_workflow_linter.cli --help > /dev/null
    success "gha-workflow-linter CLI working"
else
    warning "gha-workflow-linter command not in PATH, use: python -m gha_workflow_linter.cli"
fi

# Run self-linting test with local development version
info "Running self-linting test with local development version..."
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    python -m gha_workflow_linter.cli . --quiet
    success "Self-linting test passed (local version)"
else
    warning "Skipping self-linting test (no GitHub token)"
fi

# Test pre-commit
info "Testing pre-commit setup..."
pre-commit run --all-files > /dev/null 2>&1 || {
    warning "Some pre-commit checks failed (this is normal on first run)"
    info "Run 'pre-commit run --all-files' to see details"
}
success "Pre-commit setup complete (uses published version for consistency)"

echo ""
success "Development environment setup complete!"
echo ""
echo "Next steps:"
echo "1. Set GITHUB_TOKEN environment variable (if not done)"
echo "2. Run tests: uv run pytest"
echo "3. Run linting: pre-commit run --all-files (uses published version)"
echo "4. Test local CLI: python -m gha_workflow_linter.cli --help"
echo "5. Test local changes: python -m gha_workflow_linter.cli . --quiet"
echo ""
echo "Happy coding! 🚀"
