from __future__ import annotations

import pytest

from severity import UnsupportedCvssVector, score_cvss31, severity_for_advisory


class TestKnownReferenceVectors:
    """Scores below are widely-cited canonical CVSS v3.1 examples used
    throughout FIRST.org's own documentation and repeated across many
    real-world published CVE scores using these exact vectors -- used here
    as an independent oracle for the base-score arithmetic, not derived from
    this module itself."""

    def test_full_impact_no_auth_no_interaction_is_9_8_critical(self):
        scored = score_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert scored.base_score == 9.8
        assert scored.severity == "critical"

    def test_full_impact_requiring_user_interaction_is_8_8_high(self):
        scored = score_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")
        assert scored.base_score == 8.8
        assert scored.severity == "high"


class TestRealCorpusVectors:
    """Vectors pulled verbatim from the vendored RustSec corpus (anchor-lang
    advisories), so the mapping is checked against data this service will
    actually see, not only spec examples."""

    def test_rustsec_2026_0144_anchor_lang(self):
        # confidentiality-low/integrity-high/availability-none, scope unchanged
        scored = score_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N")
        assert scored.severity in ("high", "critical")  # pin the band, not the float
        assert 7.0 <= scored.base_score <= 10.0


class TestScopeChanged:
    def test_scope_changed_formula_path_runs_and_produces_a_valid_band(self):
        scored = score_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert scored.severity == "critical"


class TestZeroImpactIsInfoNotAnErrorOrAGuess:
    def test_no_impact_scores_zero_and_maps_to_info(self):
        scored = score_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert scored.base_score == 0.0
        assert scored.severity == "info"


class TestRejectsWhatItCannotScore:
    def test_missing_cvss31_prefix_raises(self):
        with pytest.raises(UnsupportedCvssVector):
            score_cvss31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_cvss_v4_vector_is_rejected_not_misscored(self):
        # Real shape from RUSTSEC-2026-0146 (anchor-lang) -- CVSS v4.0 uses a
        # different metric set entirely; must not be run through the v3.1
        # formula and must not silently produce a number.
        v4_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N"
        with pytest.raises(UnsupportedCvssVector):
            score_cvss31(v4_vector)

    def test_missing_a_required_metric_raises(self):
        with pytest.raises(UnsupportedCvssVector):
            score_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")  # missing A

    def test_unrecognized_metric_value_raises(self):
        with pytest.raises(UnsupportedCvssVector):
            score_cvss31("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


class TestSeverityForAdvisoryNeverGuesses:
    def test_no_vector_is_unrated_with_a_stated_reason(self):
        severity, basis = severity_for_advisory(None)
        assert severity is None
        assert basis == "no-cvss-vector"

    def test_v4_vector_is_unrated_with_a_distinct_reason_from_missing(self):
        severity, basis = severity_for_advisory(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N"
        )
        assert severity is None
        assert basis == "unsupported-cvss-version"

    def test_valid_v31_vector_yields_a_severity_and_a_basis(self):
        severity, basis = severity_for_advisory("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert severity == "critical"
        assert basis == "cvss31-base-score"

    def test_garbage_string_is_unrated_not_a_crash(self):
        severity, basis = severity_for_advisory("not a vector")
        assert severity is None
        assert basis == "malformed-cvss-vector"
