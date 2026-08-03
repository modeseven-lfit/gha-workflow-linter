# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""GitHub Actions workflow linter."""

# ``_version.py`` is generated at build time by hatch-vcs and is not in
# version control, so a static analyser running against a bare checkout
# (as the basedpyright pre-commit hook does) cannot resolve it. Binding
# through an intermediate name with an explicit annotation gives the
# public symbol a definite type either way.
try:
    from ._version import __version__ as _generated_version
except ImportError:  # pragma: no cover - only when not built
    _generated_version = "dev"

__version__: str = _generated_version

__all__ = ["__version__"]
