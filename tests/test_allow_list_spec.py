# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Tests for allow-list ``config`` coordinate parsing.

The first half of this file is a port of the upstream conformance
corpus: ``tests/test_resolve_config_source.py`` (the parsing sections,
lines 1-180) in ``lfreleng-actions/harden-runner-block-action``, itself
mirrored byte-for-byte into ``lfreleng-actions/python-audit-action``.

Those cases are the *specification* for the grammar, not merely tests of
this module. Keep them in step with upstream: when the grammar changes
there, port the change here in the same cycle. Add local cases to the
sections below the corpus rather than editing the corpus itself.
"""

from __future__ import annotations

import pytest

from gha_workflow_linter.allow_list_spec import (
    ResolvedSpec,
    SpecError,
    parse_spec,
    render_spec,
    resolve_spec,
    split_comment,
)

# A real, verified pin from the estate: the shorthand form, which is
# what every internal workflow uses.
ESTATE_SHORTHAND = "@18d9c4446bea555d0783e850f6d295f844fe8f67"

# A real, verified pin in fully explicit form. Split for line length;
# the value is a single scalar.
ESTATE_EXPLICIT = (
    "lfreleng-actions"
    "//.github/harden-runner/lfreleng-actions/allow_list.txt"
    "@bf6642f68d58c1b81bbe993e676d6cc339ac3654"
)

# The commit (not tag-object) SHA of .github v0.12.2.
ESTATE_EXPLICIT_SHA = "bf6642f68d58c1b81bbe993e676d6cc339ac3654"


def _resolve(
    spec: str, org: str = "onap", family: str = "python-audit"
) -> ResolvedSpec:
    """Resolve with the upstream corpus defaults.

    Args:
        spec: The config spec to resolve.
        org: Workflow org.
        family: Config family.

    Returns:
        The resolved spec.
    """
    return resolve_spec(spec, workflow_org=org, family=family)


# ---------------------------------------------------------------------
# Upstream corpus: comment splitting
# ---------------------------------------------------------------------


class TestSplitComment:
    """Ported from the upstream ``test_split_comment`` corpus."""

    @pytest.mark.parametrize(
        ("value", "expected_spec", "expected_comment"),
        [
            ("lfit@v1.1.0", "lfit@v1.1.0", ""),
            ("lfit@v1.1.0 # hello", "lfit@v1.1.0", "hello"),
            ("lfit@v1.1.0  # two spaces", "lfit@v1.1.0", "two spaces"),
            ("lfit@v1.1.0\t# tab", "lfit@v1.1.0", "tab"),
            (
                "lfit//f.txt@v1 # many words here",
                "lfit//f.txt@v1",
                "many words here",
            ),
        ],
    )
    def test_split_comment(
        self, value: str, expected_spec: str, expected_comment: str
    ) -> None:
        """The separator is one or more spaces or tabs before ``#``."""
        spec, comment = split_comment(value)
        assert spec == expected_spec
        assert comment == expected_comment


# ---------------------------------------------------------------------
# Upstream corpus: resolution + search candidates
# ---------------------------------------------------------------------


class TestResolution:
    """Ported from the upstream resolution corpus."""

    def test_org_only_default_branch(self) -> None:
        """An org plus a branch takes every other default."""
        resolved = _resolve("lfreleng-actions@main")
        assert resolved.host_org == "lfreleng-actions"
        assert resolved.repo == ".github"
        assert resolved.ref == "main"
        assert resolved.candidates == (
            ".github/python-audit/onap/allow_list.txt",
            ".github/python-audit/allow_list.txt",
        )
        assert resolved.path_explicit is False

    def test_no_ref_defaults_to_head(self) -> None:
        """An omitted ref means the host repo's default branch."""
        resolved = _resolve("lfit")
        assert resolved.ref == "HEAD"

    def test_sha_ref_with_comment(self) -> None:
        """An in-scalar comment is captured but ignored."""
        resolved = _resolve(
            "lfit@ab7a9404c0f3da075243ca237b5fac12c98deaa5 # v1.0.0"
        )
        assert resolved.host_org == "lfit"
        assert resolved.ref == "ab7a9404c0f3da075243ca237b5fac12c98deaa5"
        assert resolved.comment == "v1.0.0"

    def test_filename_only_keeps_default_dir_search(self) -> None:
        """A bare filename overrides the file, not the directories."""
        resolved = _resolve("lfit//custom_list.txt@v1.1.0")
        assert resolved.candidates == (
            ".github/python-audit/onap/custom_list.txt",
            ".github/python-audit/custom_list.txt",
        )
        assert resolved.path_explicit is False

    def test_bare_double_slash_uses_defaults(self) -> None:
        """A bare ``//`` resolves exactly as no ``//`` at all."""
        resolved = _resolve(
            "lfit//@ab7a9404c0f3da075243ca237b5fac12c98deaa5  # note"
        )
        assert resolved.candidates == (
            ".github/python-audit/onap/allow_list.txt",
            ".github/python-audit/allow_list.txt",
        )
        assert resolved.ref == "ab7a9404c0f3da075243ca237b5fac12c98deaa5"

    def test_explicit_directory_disables_search(self) -> None:
        """A subpath containing ``/`` is used verbatim, with no search."""
        resolved = _resolve("lfit//configs/onap/list.txt@main")
        assert resolved.candidates == ("configs/onap/list.txt",)
        assert resolved.path_explicit is True

    def test_explicit_repo_override(self) -> None:
        """``<org>/<repo>`` overrides the default ``.github`` repo."""
        resolved = _resolve("lfit/special-repo//list.txt@main")
        assert resolved.host_org == "lfit"
        assert resolved.repo == "special-repo"

    def test_empty_host_org_defaults_to_workflow_org(self) -> None:
        """An omitted host org falls back to the workflow's own org."""
        resolved = _resolve("//team_list.txt@main", org="onap")
        assert resolved.host_org == "onap"
        assert (
            resolved.candidates[0] == ".github/python-audit/onap/team_list.txt"
        )

    def test_family_appears_in_default_path(self) -> None:
        """The family names the directory under ``.github/``."""
        resolved = _resolve("lfit@main", family="harden-runner")
        assert resolved.candidates == (
            ".github/harden-runner/onap/allow_list.txt",
            ".github/harden-runner/allow_list.txt",
        )


# ---------------------------------------------------------------------
# Upstream corpus: rejections
# ---------------------------------------------------------------------


class TestRejections:
    """Ported from the upstream rejection corpus."""

    @pytest.mark.parametrize(
        "spec",
        [
            "",
            "lfit@",
            "lfit@a@b",
            "lfit//a//b@main",
            "lfit/repo/extra@main",
            "bad org@main",
            "lfit//../escape.txt@main",
            "lfit///abs/path.txt@main",
            "lfit//a\\b.txt@main",
            "lfit@-badref",
            "lfit@ref..with..dots",
            "lfit@ref@{0}",
            "lfit//evil;rm.txt@main",
        ],
    )
    def test_invalid_specs_raise(self, spec: str) -> None:
        """Every malformed shape is a hard error."""
        with pytest.raises(SpecError):
            _resolve(spec)

    def test_newline_in_config_rejected(self) -> None:
        """A newline anywhere in the spec is rejected."""
        with pytest.raises(SpecError):
            _resolve("lfit@main\nevil")

    def test_newline_disguised_as_comment_rejected(self) -> None:
        """A newline before ``#`` must not act as a separator.

        Otherwise the trailing line would slip past the newline
        rejection by masquerading as a comment.
        """
        with pytest.raises(SpecError):
            _resolve("lfit@main\n# hidden")

    def test_split_comment_ignores_newline_separator(self) -> None:
        """``split_comment`` leaves a newline-separated ``#`` alone."""
        spec, comment = split_comment("lfit@main\n# hidden")
        assert spec == "lfit@main\n# hidden"
        assert comment == ""


# ---------------------------------------------------------------------
# Local: the README `config` examples table
# ---------------------------------------------------------------------

_README_SHA = "ab7a9404c0f3da075243ca237b5fac12c98deaa5"
_DEFAULT_CHAIN = (
    ".github/harden-runner/onap/allow_list.txt",
    ".github/harden-runner/allow_list.txt",
)
_CUSTOM_CHAIN = (
    ".github/harden-runner/onap/custom_list.txt",
    ".github/harden-runner/custom_list.txt",
)
_TEAM_CHAIN = (
    ".github/harden-runner/onap/team_list.txt",
    ".github/harden-runner/team_list.txt",
)


class TestReadmeExamples:
    """Every row of the action README's ``config`` examples table.

    The table assumes a workflow running in org ``onap``.
    """

    @pytest.mark.parametrize(
        ("spec", "host_org", "repo", "ref", "candidates", "path_explicit"),
        [
            (
                "lfreleng-actions@main",
                "lfreleng-actions",
                ".github",
                "main",
                _DEFAULT_CHAIN,
                False,
            ),
            (
                "lfit@v1.1.0",
                "lfit",
                ".github",
                "v1.1.0",
                _DEFAULT_CHAIN,
                False,
            ),
            (
                f"lfit@{_README_SHA} # v1.0.0",
                "lfit",
                ".github",
                _README_SHA,
                _DEFAULT_CHAIN,
                False,
            ),
            (
                "lfit//custom_list.txt@v1.1.0  # ONAP",
                "lfit",
                ".github",
                "v1.1.0",
                _CUSTOM_CHAIN,
                False,
            ),
            (
                f"lfit//@{_README_SHA}",
                "lfit",
                ".github",
                _README_SHA,
                _DEFAULT_CHAIN,
                False,
            ),
            (
                "lfit//configs/onap/list.txt@main",
                "lfit",
                ".github",
                "main",
                ("configs/onap/list.txt",),
                True,
            ),
            (
                "//team_list.txt@main",
                "onap",
                ".github",
                "main",
                _TEAM_CHAIN,
                False,
            ),
        ],
    )
    def test_readme_row(
        self,
        spec: str,
        host_org: str,
        repo: str,
        ref: str,
        candidates: tuple[str, ...],
        path_explicit: bool,
    ) -> None:
        """Each documented example resolves as documented."""
        resolved = _resolve(spec, family="harden-runner")
        assert resolved.host_org == host_org
        assert resolved.repo == repo
        assert resolved.ref == ref
        assert resolved.candidates == candidates
        assert resolved.path_explicit is path_explicit

    def test_comment_is_ignored_for_resolution(self) -> None:
        """The commented and uncommented forms resolve identically."""
        with_comment = _resolve(
            "lfit//custom_list.txt@v1.1.0  # ONAP", family="harden-runner"
        )
        without = _resolve(
            "lfit//custom_list.txt@v1.1.0", family="harden-runner"
        )
        assert with_comment.comment == "ONAP"
        assert without.comment == ""
        assert with_comment.candidates == without.candidates
        assert with_comment.ref == without.ref


# ---------------------------------------------------------------------
# Local: real values from the estate
# ---------------------------------------------------------------------


class TestEstateValues:
    """Verified ``config`` values taken from live workflows."""

    def test_shorthand_sha_pin(self) -> None:
        """``@<sha>`` is the dominant form; it takes every default."""
        resolved = resolve_spec(
            ESTATE_SHORTHAND, workflow_org="lfreleng-actions"
        )
        assert resolved.host_org == "lfreleng-actions"
        assert resolved.repo == ".github"
        assert resolved.ref == "18d9c4446bea555d0783e850f6d295f844fe8f67"
        assert resolved.candidates == (
            ".github/harden-runner/lfreleng-actions/allow_list.txt",
            ".github/harden-runner/allow_list.txt",
        )
        assert resolved.path_explicit is False
        assert resolved.comment == ""

    def test_shorthand_matches_fully_explicit_form(self) -> None:
        """The explicit form names the shorthand's first candidate."""
        shorthand = resolve_spec(
            ESTATE_SHORTHAND, workflow_org="lfreleng-actions"
        )
        explicit = resolve_spec(
            ESTATE_EXPLICIT, workflow_org="lfreleng-actions"
        )
        assert explicit.host_org == "lfreleng-actions"
        assert explicit.repo == ".github"
        assert explicit.ref == ESTATE_EXPLICIT_SHA
        assert explicit.path_explicit is True
        assert explicit.candidates == (shorthand.candidates[0],)

    def test_yaml_quoted_value_with_surrounding_space(self) -> None:
        """Surrounding whitespace is stripped before parsing."""
        resolved = resolve_spec(
            f"  {ESTATE_SHORTHAND}  ", workflow_org="lfreleng-actions"
        )
        assert resolved.ref == "18d9c4446bea555d0783e850f6d295f844fe8f67"

    def test_branch_ref_resolves(self) -> None:
        """A branch pin is valid grammar; currency is judged later."""
        resolved = resolve_spec(
            "lfreleng-actions@main", workflow_org="lfreleng-actions"
        )
        assert resolved.ref == "main"


# ---------------------------------------------------------------------
# Local: the family is always caller-supplied
# ---------------------------------------------------------------------


class TestFamilyIsCallerSupplied:
    """The parser holds no per-action constants."""

    def test_python_audit_family(self) -> None:
        """``python-audit`` yields the sibling action's directories."""
        resolved = resolve_spec(
            ESTATE_SHORTHAND,
            workflow_org="lfreleng-actions",
            family="python-audit",
        )
        assert resolved.candidates == (
            ".github/python-audit/lfreleng-actions/allow_list.txt",
            ".github/python-audit/allow_list.txt",
        )

    def test_family_only_changes_the_directory(self) -> None:
        """Everything but the directory is family-independent."""
        harden = resolve_spec(
            "lfit@main", workflow_org="onap", family="harden-runner"
        )
        audit = resolve_spec(
            "lfit@main", workflow_org="onap", family="python-audit"
        )
        assert harden.host_org == audit.host_org
        assert harden.repo == audit.repo
        assert harden.ref == audit.ref
        assert harden.candidates != audit.candidates

    def test_explicit_path_ignores_the_family(self) -> None:
        """An explicit path is not rewritten by the family."""
        resolved = resolve_spec(
            "lfit//configs/list.txt@main",
            workflow_org="onap",
            family="python-audit",
        )
        assert resolved.candidates == ("configs/list.txt",)

    def test_default_family_is_harden_runner(self) -> None:
        """Our own default serves the allow-list action."""
        resolved = resolve_spec("lfit@main", workflow_org="onap")
        assert resolved.candidates[0].startswith(".github/harden-runner/")


# ---------------------------------------------------------------------
# Local: raw component parsing
# ---------------------------------------------------------------------


class TestParseSpec:
    """The raw component split, before defaults apply."""

    def test_bare_double_slash_differs_from_no_subpath(self) -> None:
        """Both resolve alike, but the raw parse keeps them distinct."""
        bare = parse_spec("lfit//@main")
        absent = parse_spec("lfit@main")
        assert bare.has_subpath is True
        assert bare.subpath == ""
        assert absent.has_subpath is False
        assert absent.subpath == ""

    def test_omitted_ref_is_empty_not_head(self) -> None:
        """``HEAD`` is a resolution default, not a parse result."""
        assert parse_spec("lfit").ref == ""

    def test_hash_without_leading_space_is_not_a_comment(self) -> None:
        """``foo#bar`` is one token, so it reaches the validators."""
        spec, comment = split_comment("lfit//a#b.txt@main")
        assert spec == "lfit//a#b.txt@main"
        assert comment == ""
        with pytest.raises(SpecError):
            _resolve("lfit//a#b.txt@main")


# ---------------------------------------------------------------------
# Local: render_spec
# ---------------------------------------------------------------------

_ROUND_TRIP_SPECS = [
    "lfit",
    "lfit@main",
    "lfit@v1.1.0",
    "lfit/special-repo//list.txt@main",
    "lfit//custom_list.txt@v1.1.0",
    "lfit//@main",
    "lfit//",
    "//team_list.txt@main",
    "//",
    "lfit//configs/onap/list.txt@main",
    "lfit@HEAD",
    ESTATE_SHORTHAND,
    ESTATE_EXPLICIT,
]


class TestRenderSpecRoundTrip:
    """Rendering a spec with its own ref reproduces its source form."""

    @pytest.mark.parametrize("spec", _ROUND_TRIP_SPECS)
    def test_round_trip_preserves_source_form(self, spec: str) -> None:
        """Parse then render is the identity on the source form."""
        resolved = _resolve(spec)
        assert render_spec(resolved, ref=resolved.ref) == spec

    @pytest.mark.parametrize("spec", _ROUND_TRIP_SPECS)
    def test_round_trip_output_reparses_identically(self, spec: str) -> None:
        """The rendered form resolves to the same coordinates."""
        resolved = _resolve(spec)
        reparsed = _resolve(render_spec(resolved, ref=resolved.ref))
        assert reparsed == resolved

    def test_round_trip_drops_the_trailing_comment(self) -> None:
        """The source form excludes any in-scalar comment.

        Comment rewriting belongs to the caller, which owns both the
        in-scalar and the YAML comment positions.
        """
        resolved = _resolve("lfit@main  # v1.0.0")
        assert resolved.comment == "v1.0.0"
        assert render_spec(resolved, ref=resolved.ref) == "lfit@main"

    def test_round_trip_normalises_surrounding_whitespace(self) -> None:
        """Whitespace around the spec is not part of the source form."""
        resolved = _resolve("  lfit@main  ")
        assert render_spec(resolved, ref=resolved.ref) == "lfit@main"

    def test_head_is_re_emitted_only_when_written(self) -> None:
        """An omitted ref stays omitted; an explicit ``@HEAD`` stays.

        Rendering ``HEAD`` onto a spec that named a different ref
        therefore writes ``@HEAD`` rather than dropping the ref, which
        would silently change the coordinate's meaning for a reader.
        """
        implicit = _resolve("lfit")
        explicit = _resolve("lfit@HEAD")
        assert render_spec(implicit, ref="HEAD") == "lfit"
        assert render_spec(explicit, ref="HEAD") == "lfit@HEAD"
        assert render_spec(_resolve("lfit@main"), ref="HEAD") == "lfit@HEAD"


class TestRenderSpecRefBump:
    """Rewriting the ref, which is what remediation needs."""

    def test_bump_shorthand_sha(self) -> None:
        """The dominant estate form bumps to a bare ``@<sha>``."""
        resolved = resolve_spec(
            ESTATE_SHORTHAND, workflow_org="lfreleng-actions"
        )
        assert (
            render_spec(resolved, ref=ESTATE_EXPLICIT_SHA)
            == f"@{ESTATE_EXPLICIT_SHA}"
        )

    def test_bump_explicit_path_keeps_the_path(self) -> None:
        """Only the ref changes; the path survives untouched."""
        resolved = resolve_spec(
            ESTATE_EXPLICIT, workflow_org="lfreleng-actions"
        )
        rendered = render_spec(resolved, ref="18d9c4446bea555d0783e85")
        assert rendered == (
            "lfreleng-actions"
            "//.github/harden-runner/lfreleng-actions/allow_list.txt"
            "@18d9c4446bea555d0783e85"
        )

    def test_bump_adds_a_ref_the_author_omitted(self) -> None:
        """Pinning an unpinned coordinate is a ref addition."""
        assert render_spec(_resolve("lfit"), ref="v2.0.0") == "lfit@v2.0.0"

    def test_bump_of_bare_double_slash(self) -> None:
        """A bare ``//`` is preserved rather than normalised away."""
        assert render_spec(_resolve("lfit//"), ref="v2") == "lfit//@v2"

    def test_bump_preserves_an_omitted_org(self) -> None:
        """The shorthand's empty source is not filled in on render."""
        resolved = _resolve("//team_list.txt@main")
        assert render_spec(resolved, ref="v2") == "//team_list.txt@v2"

    @pytest.mark.parametrize(
        "ref",
        ["", "-badref", "/badref", "ref..dots", "ref@{0}", "bad ref"],
    )
    def test_invalid_target_ref_rejected(self, ref: str) -> None:
        """A bad replacement ref never reaches a workflow file."""
        resolved = _resolve("lfit@main")
        with pytest.raises(SpecError):
            render_spec(resolved, ref=ref)

    def test_over_long_target_ref_rejected(self) -> None:
        """The 255-character ceiling applies on render too."""
        resolved = _resolve("lfit@main")
        with pytest.raises(SpecError):
            render_spec(resolved, ref="a" * 256)
