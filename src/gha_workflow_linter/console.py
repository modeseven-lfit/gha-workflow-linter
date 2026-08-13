# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Shared Rich console singleton.

Every module that needs to emit user-facing output should import the
``console`` instance from here, rather than constructing its own
``Console()``. Sharing a single instance ensures:

- Output is serialized through one Rich renderer (no interleaving with a
  ``Live`` / ``Progress`` widget owned by the CLI layer).
- Style / theme / file changes apply uniformly.
- Testing can monkey-patch the singleton in one place.

The CLI layer enforces a soft contract that no out-of-band ``console.print``
calls happen while a ``rich.progress.Progress`` block is open; see
``cli.run_linter`` for the prepare / scan-validate / report phase split.
"""

from __future__ import annotations

from rich.console import Console

console: Console = Console()

#: Companion writing to standard error. Deprecation notices and similar
#: out-of-band messages use this so ``--format json`` keeps standard
#: output machine-readable.
err_console: Console = Console(stderr=True)

__all__ = ["console", "err_console"]
