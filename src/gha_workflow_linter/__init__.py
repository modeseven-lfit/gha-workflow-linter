# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""GitHub Actions workflow linter."""

try:
    from ._version import __version__
except ImportError:
    __version__ = "dev"

__all__ = ["__version__"]
