# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Configuration management for gha-workflow-linter."""

from __future__ import annotations

import logging
import os
from pathlib import Path
import textwrap
from typing import Any

from pydantic import BaseModel, ValidationError
import yaml

from .models import Config

#: Header prepended to generated configuration files. Everything below
#: the header comes from the configuration model, so the template cannot
#: drift as fields are added.
_CONFIG_HEADER = """\
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

# gha-workflow-linter configuration file
#
# Generated from the configuration model: every setting the tool
# understands appears below, commented with its purpose and set to its
# default value. Delete an entry to keep the built-in default.
#
# Full documentation:
# https://github.com/lfit/gha-workflow-linter#configuration
---
"""

#: Width used for wrapped comment text and emitted YAML scalars. One
#: below the yamllint default line-length limit of 80.
_LINE_WIDTH = 79

#: Dotted paths of fields that must never carry a value in a generated
#: template, however the running configuration was populated.
_REDACTED_PATHS = frozenset({"github_api.token"})

#: Explanation emitted alongside every redacted field.
_REDACTED_NOTES = {
    "github_api.token": (
        "Deliberately left empty: the token normally comes from the "
        "GITHUB_TOKEN environment variable or the GitHub CLI, and a token "
        "held in memory is never written to this file."
    )
}


class _BlockDumper(yaml.SafeDumper):
    """YAML dumper that indents sequences beneath their parent key.

    PyYAML emits block sequences at the same indentation as the mapping
    key that owns them, which yamllint rejects under its default
    ``indent-sequences: true`` setting.
    """

    def increase_indent(
        self, flow: bool = False, indentless: bool = False
    ) -> None:
        """Increase emitter indentation, never indentless.

        Args:
            flow: Whether the collection is being emitted in flow style.
            indentless: Ignored; sequences are always indented.

        Returns:
            None.
        """
        del indentless
        super().increase_indent(flow, False)


def _comment_lines(text: str, indent: int) -> list[str]:
    """Render descriptive text as wrapped, indented YAML comments.

    Args:
        text: Description text to render.
        indent: Number of leading spaces for the comment block.

    Returns:
        Comment lines, each already indented and prefixed with ``# ``.
    """
    prefix = f"{' ' * indent}# "
    return textwrap.wrap(
        " ".join(text.split()),
        width=_LINE_WIDTH,
        initial_indent=prefix,
        subsequent_indent=prefix,
        break_long_words=False,
        break_on_hyphens=False,
    )


def _value_lines(name: str, value: Any, indent: int) -> list[str]:
    """Render a single ``key: value`` entry as indented YAML lines.

    Args:
        name: Field name to emit as the mapping key.
        value: JSON-compatible value produced by ``model_dump``.
        indent: Number of leading spaces for the entry.

    Returns:
        Indented YAML lines for the entry, without a trailing newline.
    """
    dumped = yaml.dump(
        {name: value},
        Dumper=_BlockDumper,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=_LINE_WIDTH,
    )
    pad = " " * indent
    return [f"{pad}{line}" if line else "" for line in dumped.splitlines()]


def _model_lines(
    model: BaseModel, indent: int = 0, path: str = ""
) -> list[str]:
    """Render a pydantic model as commented YAML in declaration order.

    Each field is preceded by its ``Field(description=...)`` text, so the
    generated file documents itself straight from the model.

    Args:
        model: Model instance to render.
        indent: Number of leading spaces for this block.
        path: Dotted path of the parent block, empty at the top level.

    Returns:
        YAML lines for the model, without trailing newlines.
    """
    lines: list[str] = []

    dumped = model.model_dump(mode="json")
    for name, field in type(model).model_fields.items():
        field_path = f"{path}.{name}" if path else name
        value = getattr(model, name)

        if lines:
            lines.append("")
        if field.description:
            lines.extend(_comment_lines(field.description, indent))

        if isinstance(value, BaseModel):
            lines.append(f"{' ' * indent}{name}:")
            lines.extend(_model_lines(value, indent + 2, field_path))
        elif field_path in _REDACTED_PATHS:
            note = _REDACTED_NOTES.get(field_path)
            if note:
                lines.extend(_comment_lines(note, indent))
            lines.append(f"{' ' * indent}{name}:")
        else:
            lines.extend(_value_lines(name, dumped[name], indent))

    return lines


class ConfigManager:
    """Manager for loading and validating configuration."""

    def __init__(self) -> None:
        """Initialize the configuration manager."""
        self.logger = logging.getLogger(__name__)

    def load_config(self, config_file: Path | None = None) -> Config:
        """
        Load configuration from file and environment variables.

        Args:
            config_file: Optional path to configuration file

        Returns:
            Validated Config object

        Raises:
            ValueError: If configuration is invalid
        """
        config_data: dict[str, Any] = {}

        # Load from default location if no file specified
        if config_file is None:
            config_file = self._find_default_config_file()

        # Load from file if it exists
        if config_file and config_file.exists():
            self.logger.debug(f"Loading config from: {config_file}")
            config_data = self._load_config_file(config_file)
        else:
            self.logger.debug("No config file found, using defaults")

        # Create Config object (will load from environment variables)
        if "auto_latest" in config_data:
            self.logger.warning(
                "Configuration key 'auto_latest' is deprecated; rename it "
                "to 'update_actions'. The old name still loads and will be "
                "removed in a future major release"
            )
            if "update_actions" in config_data:
                # Both present: the canonical key wins, matching how the
                # CLI resolves --update-actions against --auto-latest.
                del config_data["auto_latest"]

        try:
            config = Config(**config_data)
            self.logger.debug("Configuration loaded successfully")
            return config
        except ValidationError as e:
            self.logger.error(f"Invalid configuration: {e}")
            raise ValueError(f"Configuration validation failed: {e}") from e

    def _find_default_config_file(self) -> Path | None:
        """
        Find default configuration file location.

        Returns:
            Path to config file if found, None otherwise
        """
        for filename in [
            "gha-workflow-linter.yaml",
            "gha-workflow-linter.yml",
            ".gha-workflow-linter.yaml",
        ]:
            config_path = Path.cwd() / filename
            if config_path.exists():
                return config_path

        config_dir = self._get_config_directory()
        if config_dir:
            for filename in ["config.yaml", "config.yml"]:
                config_path = config_dir / filename
                if config_path.exists():
                    return config_path

        return None

    def _get_config_directory(self) -> Path | None:
        """
        Get user configuration directory.

        Returns:
            Path to config directory, None if not available
        """
        # Use XDG_CONFIG_HOME if set
        xdg_config = os.environ.get("XDG_CONFIG_HOME")
        if xdg_config:
            return Path(xdg_config) / "gha-workflow-linter"

        # Use ~/.config on Unix-like systems
        home = Path.home()
        if home.exists():
            config_dir = home / ".config" / "gha-workflow-linter"
            return config_dir

        return None

    def _load_config_file(self, config_file: Path) -> dict[str, Any]:
        """
        Load configuration from YAML file.

        Args:
            config_file: Path to configuration file

        Returns:
            Dictionary with configuration data

        Raises:
            ValueError: If file cannot be loaded or parsed
        """
        try:
            with open(config_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not isinstance(data, dict):
                raise ValueError(
                    "Configuration file must contain a YAML object"
                )

            return data

        except OSError as e:
            self.logger.error(f"Cannot read config file {config_file}: {e}")
            raise ValueError(f"Cannot read configuration file: {e}") from e
        except yaml.YAMLError as e:
            self.logger.error(f"Invalid YAML in config file {config_file}: {e}")
            raise ValueError(f"Invalid YAML in configuration file: {e}") from e

    def save_default_config(self, output_path: Path | None = None) -> Path:
        """
        Save default configuration to file.

        The template is generated from :class:`~.models.Config` rather
        than hand-written, so every field the model gains appears here
        automatically. The generated file round-trips: loading it back
        yields a ``Config`` equal to the defaults.

        Args:
            output_path: Optional path to save config file

        Returns:
            Path where config was saved

        Raises:
            ValueError: If the file cannot be written
        """
        if output_path is None:
            config_dir = self._get_config_directory()
            if config_dir is None:
                output_path = Path.cwd() / "gha-workflow-linter.yaml"
            else:
                config_dir.mkdir(parents=True, exist_ok=True)
                output_path = config_dir / "config.yaml"

        lines = [_CONFIG_HEADER.rstrip("\n"), ""]
        lines.extend(_model_lines(Config()))
        yaml_content = "\n".join(lines) + "\n"

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(yaml_content)

            self.logger.info(f"Default configuration saved to: {output_path}")
            return output_path

        except OSError as e:
            self.logger.error(f"Cannot write config file {output_path}: {e}")
            raise ValueError(f"Cannot write configuration file: {e}") from e

    def validate_config_file(self, config_file: Path) -> bool:
        """
        Validate configuration file without loading it.

        Args:
            config_file: Path to configuration file

        Returns:
            True if valid, False otherwise
        """
        try:
            self.load_config(config_file)
            return True
        except (ValueError, ValidationError):
            return False
