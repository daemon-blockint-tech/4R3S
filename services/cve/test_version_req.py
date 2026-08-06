from __future__ import annotations

import pytest

from version_req import UnsupportedVersionReq, Version, VersionReq, matches_any


class TestExactAndComparisonOperators:
    def test_bare_version_defaults_to_caret_not_exact(self):
        # Cargo treats a bare "1.2.3" as ^1.2.3, not =1.2.3 -- a matcher that
        # got this wrong would under-report every advisory pinned this way.
        assert VersionReq.parse("1.2.3").matches("1.9.9")
        assert not VersionReq.parse("1.2.3").matches("2.0.0")

    def test_explicit_equals(self):
        assert VersionReq.parse("=1.2.3").matches("1.2.3")
        assert not VersionReq.parse("=1.2.3").matches("1.2.4")

    def test_gte_and_lt_from_a_real_advisory(self):
        # RUSTSEC-2026-0144 (anchor-lang): patched = [">= 1.0.2"]
        req = VersionReq.parse(">= 1.0.2")
        assert req.matches("1.0.2")
        assert req.matches("2.0.0")
        assert not req.matches("1.0.1")

    def test_lt_from_a_real_advisory(self):
        # RUSTSEC-2026-0144 (anchor-lang): unaffected = ["< 1.0.0"]
        req = VersionReq.parse("< 1.0.0")
        assert req.matches("0.9.9")
        assert not req.matches("1.0.0")

    def test_lte_and_gt(self):
        assert VersionReq.parse("<= 1.0.0").matches("1.0.0")
        assert not VersionReq.parse("<= 1.0.0").matches("1.0.1")
        assert VersionReq.parse("> 1.0.0").matches("1.0.1")
        assert not VersionReq.parse("> 1.0.0").matches("1.0.0")


class TestCaretAndTilde:
    def test_caret_nonzero_major_allows_minor_and_patch_bumps(self):
        req = VersionReq.parse("^1.2.3")
        assert req.matches("1.2.3")
        assert req.matches("1.9.0")
        assert not req.matches("1.2.2")
        assert not req.matches("2.0.0")

    def test_caret_zero_major_nonzero_minor_only_allows_patch_bumps(self):
        # borsh RUSTSEC-2023-0033: patched includes "^0.10.4"
        req = VersionReq.parse("^0.10.4")
        assert req.matches("0.10.9")
        assert not req.matches("0.11.0")
        assert not req.matches("0.10.3")

    def test_caret_zero_major_zero_minor_is_exact_patch_only(self):
        req = VersionReq.parse("^0.0.3")
        assert req.matches("0.0.3")
        assert not req.matches("0.0.4")

    def test_tilde_pins_minor(self):
        req = VersionReq.parse("~1.2.3")
        assert req.matches("1.2.9")
        assert not req.matches("1.3.0")
        assert not req.matches("1.2.2")

    def test_partial_version_defaults_missing_components_and_behaves_caretlike(self):
        req = VersionReq.parse("1.2")
        assert req.matches("1.2.0")
        assert req.matches("1.9.9")
        assert not req.matches("2.0.0")


class TestConjunctionAcrossCommas:
    def test_comma_is_and_not_or(self):
        # A real multi-clause pattern: patched = [">= 1.2.3, < 1.3.0"]
        req = VersionReq.parse(">= 1.2.3, < 1.3.0")
        assert req.matches("1.2.5")
        assert not req.matches("1.1.0")
        assert not req.matches("1.3.0")


class TestMatchesAnyIsOrAcrossArrayEntries:
    def test_any_one_entry_matching_is_sufficient(self):
        # RustSec's own EXAMPLE_ADVISORY.md: patched = [">= 1.2.3, < 1.3.0", ">= 1.3.4"]
        entries = [">= 1.2.3, < 1.3.0", ">= 1.3.4"]
        assert matches_any("1.2.5", entries)
        assert matches_any("1.4.0", entries)
        assert not matches_any("1.3.1", entries)

    def test_empty_requirements_list_matches_nothing(self):
        # RUSTSEC-2021-0120 (abomonation): patched = [] -- no version is patched.
        assert not matches_any("99.0.0", [])


class TestWildcard:
    def test_star_matches_everything(self):
        assert VersionReq.parse("*").matches("0.0.1")
        assert VersionReq.parse("*").matches("999.999.999")


class TestPreReleaseOrdering:
    def test_prerelease_sorts_below_its_release(self):
        assert Version.parse("1.0.0-alpha").sort_key() < Version.parse("1.0.0").sort_key()

    def test_gte_prerelease_boundary_from_a_real_advisory(self):
        # RUSTSEC-2026-0146 (anchor-lang): patched = [">= 1.0.0-rc.2"], unaffected = ["< 1.0.0-rc.1"]
        patched = VersionReq.parse(">= 1.0.0-rc.2")
        assert patched.matches("1.0.0-rc.2")
        assert patched.matches("1.0.0")
        assert not patched.matches("1.0.0-rc.1")

        unaffected = VersionReq.parse("< 1.0.0-rc.1")
        assert unaffected.matches("1.0.0-rc.0")
        assert not unaffected.matches("1.0.0-rc.1")


class TestFailsLoudlyRatherThanSilentlyNotMatching:
    """The module's central safety property: an unparseable requirement must
    raise, never resolve to a quiet non-match. See the module docstring and
    ORC2-F7 (a dropped result that looked identical to a clean one)."""

    def test_garbage_string_raises(self):
        with pytest.raises(UnsupportedVersionReq):
            VersionReq.parse("not a version")

    def test_empty_string_raises(self):
        with pytest.raises(UnsupportedVersionReq):
            VersionReq.parse("")

    def test_trailing_comma_raises_rather_than_ignoring_the_gap(self):
        with pytest.raises(UnsupportedVersionReq):
            VersionReq.parse(">= 1.0.0,")

    def test_matches_any_propagates_the_error_not_a_false_result(self):
        with pytest.raises(UnsupportedVersionReq):
            matches_any("1.0.0", ["garbage"])

    def test_version_with_wrong_component_count_raises(self):
        with pytest.raises(UnsupportedVersionReq):
            Version.parse("1.0")  # bare component count is only valid inside a requirement,
            # not when parsing a concrete dependency version off a lockfile.
