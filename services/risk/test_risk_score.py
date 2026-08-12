from __future__ import annotations

import pytest

from risk_score import (
    _OWASP_TO_ARES_SEVERITY,
    _SEVERITY_MATRIX,
    _level,
    RiskVector,
    UnsupportedRiskFactor,
    score_risk,
)


class TestOwaspWorkedExampleArithmetic:
    """The OWASP Risk Rating Methodology page's own "Example Risk" section is
    used as an independent oracle for the averaging + matrix arithmetic, the
    same role the two canonical CVSS vectors play in test_severity.py.

    Quoted verbatim from the page (confirmed via two independent fetches, not
    a transcription slip on this end): threat agent + vulnerability factors
    "Skill level: 5, Motive: 2, Opportunity: 7, Size: 1, Ease of discovery: 3,
    Ease of exploit: 6, Awareness: 9, Intrusion detection: 2" -> "Overall
    likelihood=4.375 (MEDIUM)". Impact factors "Loss of confidentiality: 9,
    Loss of integrity: 7, Loss of availability: 5, Loss of accountability: 8,
    Financial damage: 1, Reputation damage: 2, Non-compliance: 1, Privacy
    violation: 5" -> "Overall technical impact=7.25 (HIGH)" and "Overall
    business impact=2.25 (LOW)". Conclusion: "the overall severity is best
    described as low", because business impact is used once it is estimable.

    Known discrepancy, not silently worked around: three of the example's own
    factor values (Motive=2, Size=1, Intrusion detection=2) are not among the
    options OWASP's own factor table enumerates for those factors (Motive is
    {1,4,9}; Size is {2,4,5,6,9}; Intrusion detection is {1,3,8,9}) -- an
    inconsistency in OWASP's page between its table and its own worked
    example, not an error in this module. score_risk()'s public API validates
    strictly against the table (the page separately instructs analysts to
    "select one of the options associated with each factor"), so it cannot
    accept the example's literal input. This test instead reproduces the
    example's stated *averages* and final severity directly against the
    module's average-to-level and matrix logic, which is what the example is
    actually claiming to demonstrate.
    """

    def test_stated_averages_map_to_the_stated_levels(self):
        likelihood_average = (5 + 2 + 7 + 1 + 3 + 6 + 9 + 2) / 8
        technical_impact_average = (9 + 7 + 5 + 8) / 4
        business_impact_average = (1 + 2 + 1 + 5) / 4

        assert likelihood_average == pytest.approx(4.375)
        assert technical_impact_average == pytest.approx(7.25)
        assert business_impact_average == pytest.approx(2.25)

        assert _level(likelihood_average) == "medium"
        assert _level(technical_impact_average) == "high"
        assert _level(business_impact_average) == "low"

    def test_stated_final_severity_is_reproduced_end_to_end(self):
        # The example's *conclusion* -- "the likelihood is medium and the
        # technical impact is high, so from a purely technical perspective
        # it appears that the overall severity is high. However, note that
        # the business impact is actually low, so the overall severity is
        # best described as low as well" -- run through the real public
        # score_risk() path, using only OWASP-table-valid factor values.
        # This is the behaviour that matters: a low business impact must
        # override a high technical impact.
        scored = score_risk(
            RiskVector(
                likelihood={
                    "skill_level": 5, "motive": 4, "opportunity": 4, "size": 4,
                    "ease_of_discovery": 3, "ease_of_exploit": 3,
                    "awareness": 4, "intrusion_detection": 3,
                },  # average 3.75 -> MEDIUM, as in the example
                technical_impact={
                    "loss_of_confidentiality": 9, "loss_of_integrity": 9,
                    "loss_of_availability": 9, "loss_of_accountability": 9,
                },  # 9.0 -> HIGH, as in the example
                business_impact={
                    "financial_damage": 1, "reputation_damage": 1,
                    "non_compliance": 2, "privacy_violation": 3,
                },  # 1.75 -> LOW, as in the example
            )
        )
        assert scored.likelihood_level == "medium"
        assert scored.technical_impact_score == 9.0  # the "purely technical" HIGH
        assert scored.impact_level == "low"  # ...overridden by business impact
        assert scored.impact_basis == "business"
        assert scored.severity == "low"


class TestSeverityMatrixIsSymmetricSoOrientationCannotBeTestedByValue:
    """OWASP's 3x3 matrix is symmetric: swapping likelihood and impact
    always yields the same severity (verified by the test below, not
    assumed). A consequence worth stating explicitly, because it is
    counter-intuitive: NO test that only inspects severity output can
    detect a transposed row/column in _SEVERITY_MATRIX. An earlier version
    of this file claimed exactly that protection; it was wrong.

    What the cell-by-cell test below actually protects against is a wrong
    *value* in a cell (e.g. high/high scoring "high" instead of
    "critical"), and the band thresholds drifting."""

    def test_matrix_is_symmetric(self):
        levels = ("low", "medium", "high")
        for a in levels:
            for b in levels:
                assert _SEVERITY_MATRIX[(a, b)] == _SEVERITY_MATRIX[(b, a)]

    def test_every_cell_matches_the_published_table(self):
        # Transcribed from the methodology page's "Overall Risk Severity"
        # table, keyed (impact, likelihood) exactly as the page lays it out
        # (rows = Impact, columns = Likelihood).
        published = {
            ("high", "low"): "medium", ("high", "medium"): "high", ("high", "high"): "critical",
            ("medium", "low"): "low", ("medium", "medium"): "medium", ("medium", "high"): "high",
            ("low", "low"): "note", ("low", "medium"): "low", ("low", "high"): "medium",
        }
        assert _SEVERITY_MATRIX == published
        # ...and that "note" is the only label renamed on the way out.
        assert _OWASP_TO_ARES_SEVERITY["note"] == "info"


class TestSeverityMatrixCoversAllNineCells:
    """Drives all nine cells through the real public score_risk() path, by
    constructing vectors whose averages land in each band -- so the
    average -> level -> matrix chain is exercised end to end, not just the
    lookup table in isolation."""

    LOW_LIKELIHOOD = {
        "skill_level": 1, "motive": 1, "opportunity": 0, "size": 2,
        "ease_of_discovery": 1, "ease_of_exploit": 1, "awareness": 1,
        "intrusion_detection": 1,
    }  # average = 1.0 -> low
    MEDIUM_LIKELIHOOD = {
        "skill_level": 5, "motive": 4, "opportunity": 4, "size": 4,
        "ease_of_discovery": 3, "ease_of_exploit": 3, "awareness": 4,
        "intrusion_detection": 3,
    }  # average = 3.75 -> medium
    HIGH_LIKELIHOOD = {
        "skill_level": 9, "motive": 9, "opportunity": 9, "size": 9,
        "ease_of_discovery": 9, "ease_of_exploit": 9, "awareness": 9,
        "intrusion_detection": 9,
    }  # average = 9.0 -> high

    LOW_IMPACT = {
        "loss_of_confidentiality": 2, "loss_of_integrity": 1,
        "loss_of_availability": 1, "loss_of_accountability": 1,
    }  # average = 1.25 -> low
    MEDIUM_IMPACT = {
        "loss_of_confidentiality": 6, "loss_of_integrity": 3,
        "loss_of_availability": 5, "loss_of_accountability": 1,
    }  # average = 3.75 -> medium
    HIGH_IMPACT = {
        "loss_of_confidentiality": 9, "loss_of_integrity": 9,
        "loss_of_availability": 9, "loss_of_accountability": 9,
    }  # average = 9.0 -> high

    @pytest.mark.parametrize(
        "likelihood,impact,expected",
        [
            (LOW_LIKELIHOOD, LOW_IMPACT, "info"),
            (MEDIUM_LIKELIHOOD, LOW_IMPACT, "low"),
            (HIGH_LIKELIHOOD, LOW_IMPACT, "medium"),
            (LOW_LIKELIHOOD, MEDIUM_IMPACT, "low"),
            (MEDIUM_LIKELIHOOD, MEDIUM_IMPACT, "medium"),
            (HIGH_LIKELIHOOD, MEDIUM_IMPACT, "high"),
            (LOW_LIKELIHOOD, HIGH_IMPACT, "medium"),
            (MEDIUM_LIKELIHOOD, HIGH_IMPACT, "high"),
            (HIGH_LIKELIHOOD, HIGH_IMPACT, "critical"),
        ],
    )
    def test_matrix_cell(self, likelihood, impact, expected):
        scored = score_risk(RiskVector(likelihood=likelihood, technical_impact=impact))
        assert scored.severity == expected


class TestImpactBasisFallsBackToTechnicalWithoutBusinessData:
    def test_no_business_impact_uses_technical(self):
        scored = score_risk(
            RiskVector(
                likelihood=TestSeverityMatrixCoversAllNineCells.HIGH_LIKELIHOOD,
                technical_impact=TestSeverityMatrixCoversAllNineCells.HIGH_IMPACT,
            )
        )
        assert scored.impact_basis == "technical"
        assert scored.business_impact_score is None
        assert scored.severity == "critical"


class TestRejectsWhatItCannotScore:
    def test_missing_likelihood_factor_raises(self):
        incomplete = dict(TestSeverityMatrixCoversAllNineCells.HIGH_LIKELIHOOD)
        del incomplete["motive"]
        with pytest.raises(UnsupportedRiskFactor):
            score_risk(
                RiskVector(
                    likelihood=incomplete,
                    technical_impact=TestSeverityMatrixCoversAllNineCells.HIGH_IMPACT,
                )
            )

    def test_unknown_factor_name_raises(self):
        bad = dict(TestSeverityMatrixCoversAllNineCells.HIGH_LIKELIHOOD)
        bad["not_a_real_factor"] = 5
        with pytest.raises(UnsupportedRiskFactor):
            score_risk(
                RiskVector(
                    likelihood=bad,
                    technical_impact=TestSeverityMatrixCoversAllNineCells.HIGH_IMPACT,
                )
            )

    def test_score_not_in_owasp_table_raises(self):
        # Motive only defines {1, 4, 9} -- 5 is not a valid OWASP score.
        bad = dict(TestSeverityMatrixCoversAllNineCells.HIGH_LIKELIHOOD)
        bad["motive"] = 5
        with pytest.raises(UnsupportedRiskFactor):
            score_risk(
                RiskVector(
                    likelihood=bad,
                    technical_impact=TestSeverityMatrixCoversAllNineCells.HIGH_IMPACT,
                )
            )

    def test_partial_business_impact_raises_rather_than_averaging_over_missing_data(self):
        with pytest.raises(UnsupportedRiskFactor):
            score_risk(
                RiskVector(
                    likelihood=TestSeverityMatrixCoversAllNineCells.HIGH_LIKELIHOOD,
                    technical_impact=TestSeverityMatrixCoversAllNineCells.HIGH_IMPACT,
                    business_impact={"financial_damage": 1},
                )
            )
