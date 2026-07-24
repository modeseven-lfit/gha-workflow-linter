# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Unit tests for version tag resolution."""

from gha_workflow_linter.version_utils import (
    _find_most_specific_version_tag,
    _get_version_specificity,
    _parse_version,
)


class TestVersionSpecificity:
    """Test version specificity calculation."""

    def test_major_only(self):
        """Test specificity of major-only version."""
        assert _get_version_specificity("v8") == 1
        assert _get_version_specificity("8") == 1

    def test_major_minor(self):
        """Test specificity of major.minor version."""
        assert _get_version_specificity("v8.0") == 2
        assert _get_version_specificity("8.0") == 2

    def test_major_minor_patch(self):
        """Test specificity of major.minor.patch version."""
        assert _get_version_specificity("v8.0.0") == 3
        assert _get_version_specificity("8.0.0") == 3


class TestFindMostSpecificVersionTag:
    """Test finding the most specific version tag."""

    def test_v8_resolves_to_v8_0_0(self):
        """Test that v8 resolves to v8.0.0 when both exist."""
        all_tags = [
            ("v8.0.0", "ed597411d8f924073f98dfc5c65a23a2325f34cd"),
            ("v8", "ed597411d8f924073f98dfc5c65a23a2325f34cd"),
        ]
        result = _find_most_specific_version_tag(
            "v8", "ed597411d8f924073f98dfc5c65a23a2325f34cd", all_tags
        )
        assert result == "v8.0.0"

    def test_v8_0_0_stays_v8_0_0(self):
        """Test that v8.0.0 stays as v8.0.0."""
        all_tags = [
            ("v8.0.0", "ed597411d8f924073f98dfc5c65a23a2325f34cd"),
            ("v8", "ed597411d8f924073f98dfc5c65a23a2325f34cd"),
        ]
        result = _find_most_specific_version_tag(
            "v8.0.0", "ed597411d8f924073f98dfc5c65a23a2325f34cd", all_tags
        )
        assert result == "v8.0.0"

    def test_v7_resolves_to_v7_0_0(self):
        """Test that v7 resolves to the most specific v7.0.0 tag when they share the same SHA."""
        all_tags = [
            ("v7.1.0", "different_sha"),  # Different SHA, not a candidate
            ("v7", "f28e40c7f34bde8b3046d885e986cb6290c5673b"),
            ("v7.0.0", "f28e40c7f34bde8b3046d885e986cb6290c5673b"),
        ]
        result = _find_most_specific_version_tag(
            "v7", "f28e40c7f34bde8b3046d885e986cb6290c5673b", all_tags
        )
        # Should pick v7.0.0 as it's the most specific tag with the same base version and SHA
        assert result == "v7.0.0"

    def test_no_matching_tags(self):
        """Test behavior when no tags match the SHA."""
        all_tags = [
            ("v8.0.0", "different_sha"),
        ]
        result = _find_most_specific_version_tag(
            "v7", "ed597411d8f924073f98dfc5c65a23a2325f34cd", all_tags
        )
        # Should return the original tag
        assert result == "v7"

    def test_different_major_versions(self):
        """Test that different major versions are not mixed."""
        all_tags = [
            ("v8.0.0", "sha_v8"),
            ("v7.0.0", "sha_v7"),
            ("v7", "sha_v7"),
        ]
        result = _find_most_specific_version_tag("v7", "sha_v7", all_tags)
        assert result == "v7.0.0"
        # Should not pick v8.0.0 even though it's more specific

    def test_github_script_example(self):
        """Test with real data from actions/github-script."""
        all_tags = [
            ("v8.0.0", "ed597411d8f924073f98dfc5c65a23a2325f34cd"),
            ("v8", "ed597411d8f924073f98dfc5c65a23a2325f34cd"),
            ("v7.1.0", "f28e40c7f34bde8b3046d885e986cb6290c5673b"),
            ("v7", "f28e40c7f34bde8b3046d885e986cb6290c5673b"),
            ("v7.0.1", "60a0d83039c74a4aee543508d2ffcb1c3799cdea"),
            ("v7.0.0", "e69ef5462fd455e02edcaf4dd7708eda96b9eda0"),
        ]

        # v8 should resolve to v8.0.0
        result = _find_most_specific_version_tag(
            "v8", "ed597411d8f924073f98dfc5c65a23a2325f34cd", all_tags
        )
        assert result == "v8.0.0"

        # v7 should stay as v7 because v7 (7,0,0) and v7.1.0 (7,1,0)
        # parse to different version tuples
        result = _find_most_specific_version_tag(
            "v7", "f28e40c7f34bde8b3046d885e986cb6290c5673b", all_tags
        )
        assert result == "v7"

        # v7.0.1 should stay as v7.0.1
        result = _find_most_specific_version_tag(
            "v7.0.1", "60a0d83039c74a4aee543508d2ffcb1c3799cdea", all_tags
        )
        assert result == "v7.0.1"

    def test_v8_0_resolves_to_v8_0_0(self):
        """Test that v8.0 resolves to v8.0.0 when available."""
        all_tags = [
            ("v8.0.0", "ed597411d8f924073f98dfc5c65a23a2325f34cd"),
            ("v8.0", "ed597411d8f924073f98dfc5c65a23a2325f34cd"),
            ("v8", "ed597411d8f924073f98dfc5c65a23a2325f34cd"),
        ]
        result = _find_most_specific_version_tag(
            "v8.0", "ed597411d8f924073f98dfc5c65a23a2325f34cd", all_tags
        )
        assert result == "v8.0.0"


class TestParseVersion:
    """Test version parsing."""

    def test_parse_major_only(self):
        """Test parsing major-only version."""
        assert _parse_version("v8") == (8, 0, 0)
        assert _parse_version("8") == (8, 0, 0)

    def test_parse_major_minor(self):
        """Test parsing major.minor version."""
        assert _parse_version("v8.0") == (8, 0, 0)
        assert _parse_version("8.0") == (8, 0, 0)

    def test_parse_major_minor_patch(self):
        """Test parsing full semantic version."""
        assert _parse_version("v8.0.0") == (8, 0, 0)
        assert _parse_version("8.0.0") == (8, 0, 0)
        assert _parse_version("v7.1.0") == (7, 1, 0)
        assert _parse_version("1.2.3") == (1, 2, 3)
