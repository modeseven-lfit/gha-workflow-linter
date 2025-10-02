# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

FROM python:3.11-slim

# Set labels for container metadata
LABEL org.opencontainers.image.title="gha-workflow-linter"
LABEL org.opencontainers.image.description="GitHub Actions workflow linter for validating action and workflow calls"
LABEL org.opencontainers.image.vendor="The Linux Foundation"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/lfit/gha-workflow-linter"

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        openssh-client \
        ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd --gid 1000 linter && \
    useradd --uid 1000 --gid linter --shell /bin/bash --create-home linter

# Set working directory
WORKDIR /app

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ src/

# Install uv package manager
RUN pip install --no-cache-dir uv==0.5.11

# Install gha-workflow-linter
RUN uv pip install --system --no-cache .

# Switch to non-root user
USER linter

# Set up Git configuration for the container user
RUN git config --global user.name "GHA Workflow Linter" && \
    git config --global user.email "gha-workflow-linter@linuxfoundation.org" && \
    git config --global init.defaultBranch main

# Set default working directory for scans
WORKDIR /workspace

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD gha-workflow-linter --help > /dev/null || exit 1

# Default entrypoint
ENTRYPOINT ["gha-workflow-linter"]

# Default command (scan current directory)
CMD ["lint", "."]
