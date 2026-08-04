# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for the generated default configuration template.

The template is generated from :class:`~gha_workflow_linter.models.Config`
rather than hand-written. These tests exist to keep it that way: the
round-trip assertion is what makes drift impossible, and the
``model_fields``-driven coverage assertions fail the moment a new field
is added to the model without appearing in the template.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import TYPE_CHECKING, Any

import pytest
import yaml

from gha_workflow_linter.config import ConfigManager, _model_lines
from gha_workflow_linter.models import (
    AllowListConfig,
    CacheConfig,
    Config,
    GitConfig,
    GitHubAPIConfig,
    LogLevel,
    NetworkConfig,
)

if TYPE_CHECKING:
    from pydantic import BaseModel

NESTED_BLOCKS: list[tuple[str, type[BaseModel]]] = [
    ("network", NetworkConfig),
    ("git", GitConfig),
    ("github_api", GitHubAPIConfig),
    ("cache", CacheConfig),
    ("allow_list", AllowListConfig),
]


@pytest.fixture
def generated_path(tmp_path: Path) -> Path:
    """Write the default configuration template to a temporary file.

    Args:
        tmp_path: pytest-provided temporary directory.

    Returns:
        Path to the generated configuration file.
    """
    return ConfigManager().save_default_config(tmp_path / "config.yaml")


@pytest.fixture
def generated_text(generated_path: Path) -> str:
    """Read the generated configuration template.

    Args:
        generated_path: Path to the generated configuration file.

    Returns:
        Raw text of the generated file.
    """
    return generated_path.read_text(encoding="utf-8")


@pytest.fixture
def generated_data(generated_text: str) -> dict[str, Any]:
    """Parse the generated configuration template.

    Args:
        generated_text: Raw text of the generated file.

    Returns:
        Parsed mapping from the generated file.
    """
    data: Any = yaml.safe_load(generated_text)
    assert isinstance(data, dict)
    return data


class TestGeneratedTemplateRoundTrip:
    """The generated template must reproduce the default configuration."""

    def test_round_trip_equals_default_config(
        self, generated_path: Path
    ) -> None:
        """Loading the generated file yields the default Config."""
        loaded = ConfigManager().load_config(generated_path)

        assert loaded == Config()

    def test_round_trip_is_stable(self, generated_path: Path) -> None:
        """Regenerating from the loaded config produces identical text."""
        first = generated_path.read_text(encoding="utf-8")
        second_path = generated_path.parent / "again.yaml"
        ConfigManager().save_default_config(second_path)

        assert second_path.read_text(encoding="utf-8") == first

    def test_template_is_parsable_yaml(
        self, generated_data: dict[str, Any]
    ) -> None:
        """The generated file parses as a YAML mapping."""
        assert generated_data


class TestGeneratedTemplateCoverage:
    """Every model field must appear in the generated template."""

    def test_all_top_level_fields_present(
        self, generated_data: dict[str, Any]
    ) -> None:
        """Each Config field appears as a top-level key."""
        missing = set(Config.model_fields) - set(generated_data)

        assert not missing, f"template omits Config fields: {sorted(missing)}"

    def test_no_unexpected_top_level_keys(
        self, generated_data: dict[str, Any]
    ) -> None:
        """The template does not invent keys the model cannot accept."""
        unexpected = set(generated_data) - set(Config.model_fields)

        assert not unexpected

    @pytest.mark.parametrize(("block", "model"), NESTED_BLOCKS)
    def test_nested_block_present_with_all_fields(
        self,
        generated_data: dict[str, Any],
        block: str,
        model: type[BaseModel],
    ) -> None:
        """Each nested block appears with every field of its model."""
        nested: Any = generated_data[block]

        assert isinstance(nested, dict)
        missing = set(model.model_fields) - set(nested)
        assert not missing, f"{block} omits: {sorted(missing)}"

    def test_field_order_follows_model_declaration(
        self, generated_data: dict[str, Any]
    ) -> None:
        """Keys are not alphabetised; they follow the model's order."""
        assert list(generated_data) == list(Config.model_fields)

    def test_previously_omitted_fields_present(
        self, generated_data: dict[str, Any]
    ) -> None:
        """Fields the hand-written template silently dropped are back."""
        for key in (
            "validation_method",
            "allow_prerelease",
            "fix_test_calls",
            "cooldown_days",
            "git",
            "cache",
        ):
            assert key in generated_data

    def test_field_descriptions_emitted_as_comments(
        self, generated_text: str
    ) -> None:
        """Comments come from the model, so they cannot drift either."""
        for name, field in Config.model_fields.items():
            if field.description:
                first_word = field.description.split()[0]
                assert f"# {first_word}" in generated_text, name


class TestGeneratedTemplateSerialisation:
    """Values must serialise as portable YAML scalars."""

    def test_cache_dir_is_a_string(
        self, generated_data: dict[str, Any]
    ) -> None:
        """Path values serialise as strings, not Python objects."""
        cache: Any = generated_data["cache"]
        cache_dir: Any = cache["cache_dir"]

        assert isinstance(cache_dir, str)
        assert Path(cache_dir) == CacheConfig().cache_dir

    def test_no_python_object_tags(self, generated_text: str) -> None:
        """No value relies on PyYAML's Python-specific tags."""
        assert "!!python" not in generated_text

    def test_enum_values_are_strings(
        self, generated_data: dict[str, Any], generated_text: str
    ) -> None:
        """Enums serialise as their string values."""
        assert generated_data["log_level"] == LogLevel.INFO.value
        assert isinstance(generated_data["log_level"], str)
        assert "log_level: INFO" in generated_text

    def test_optional_enum_serialises_as_null(
        self, generated_data: dict[str, Any], generated_text: str
    ) -> None:
        """An unset ValidationMethod round-trips as null, not a tag."""
        assert generated_data["validation_method"] is None
        assert "validation_method: null" in generated_text

    def test_booleans_use_yaml_literals(self, generated_text: str) -> None:
        """Booleans are lowercase YAML, not Python repr."""
        assert "require_pinned_sha: true" in generated_text
        assert "update_actions: false" in generated_text
        offenders = re.findall(
            r"^\s*\w+: (?:True|False)$", generated_text, re.M
        )
        assert not offenders

    def test_lists_render_as_indented_sequences(
        self, generated_data: dict[str, Any], generated_text: str
    ) -> None:
        """Sequences are indented under their key, as yamllint expects."""
        assert generated_data["scan_extensions"] == [".yml", ".yaml"]
        assert "scan_extensions:\n  - .yml\n  - .yaml\n" in generated_text


class TestGeneratedTemplateToken:
    """The template must never carry a GitHub token."""

    def test_token_is_empty(self, generated_data: dict[str, Any]) -> None:
        """No token value is written to the template."""
        github_api: Any = generated_data["github_api"]

        assert not github_api["token"]

    def test_token_line_carries_no_value(self, generated_text: str) -> None:
        """The token key is emitted with an empty value."""
        assert re.search(r"^  token:[ \t]*$", generated_text, re.MULTILINE)

    def test_token_not_written_when_present(self) -> None:
        """A token held in the running config is never serialised."""
        secret = "ghp_notarealtokenbutitlookslikeone"
        rendered = "\n".join(
            _model_lines(
                GitHubAPIConfig(token=secret),
                indent=2,
                path="github_api",
            )
        )

        assert secret not in rendered
        assert re.search(r"^  token:[ \t]*$", rendered, re.MULTILINE)

    def test_token_documented(self, generated_text: str) -> None:
        """The template explains where the token comes from."""
        assert "GITHUB_TOKEN" in generated_text
        assert "GitHub CLI" in generated_text


class TestGeneratedTemplateHeader:
    """The static header must survive generation."""

    def test_starts_with_spdx_lines(self, generated_text: str) -> None:
        """The file opens with the project's SPDX convention."""
        lines = generated_text.splitlines()

        # REUSE-IgnoreStart
        assert lines[0] == "# SPDX-License-Identifier: Apache-2.0"
        # REUSE-IgnoreEnd
        assert lines[1] == (
            "# SPDX-FileCopyrightText: 2026 The Linux Foundation"
        )

    def test_header_notes_generation_and_docs(
        self, generated_text: str
    ) -> None:
        """The header says the file is generated and points at the docs."""
        assert "gha-workflow-linter configuration file" in generated_text
        assert "Generated from the configuration model" in generated_text
        assert (
            "https://github.com/lfit/gha-workflow-linter#configuration"
            in generated_text
        )

    def test_document_start_marker_present(self, generated_text: str) -> None:
        """A document start marker follows the header comment."""
        assert "\n---\n" in generated_text


class TestGeneratedTemplateFormatting:
    """Output should satisfy the repository's YAML lint conventions."""

    def test_no_trailing_whitespace(self, generated_text: str) -> None:
        """No line carries trailing whitespace."""
        offenders = [
            line
            for line in generated_text.splitlines()
            if line.rstrip() != line
        ]

        assert not offenders

    def test_lines_within_line_length(self, generated_text: str) -> None:
        """Every line fits the 80 column limit."""
        offenders = [
            line for line in generated_text.splitlines() if len(line) > 80
        ]

        assert not offenders

    def test_ends_with_single_newline(self, generated_text: str) -> None:
        """The file ends with exactly one newline."""
        assert generated_text.endswith("\n")
        assert not generated_text.endswith("\n\n")

    def test_indentation_is_two_spaces(self, generated_text: str) -> None:
        """Nested keys are indented by two spaces."""
        assert "\ngithub_api:\n" in generated_text
        assert "\n  base_url: https://api.github.com\n" in generated_text
