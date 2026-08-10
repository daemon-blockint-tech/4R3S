"""OWASP Risk Rating Methodology -- likelihood/impact factors to severity.

Scope: this implements the OWASP Risk Rating Methodology's scoring
arithmetic only (average the 8 likelihood sub-factors, average the 4
impact sub-factors, map each average to LOW/MEDIUM/HIGH, then combine via
the methodology's own 3x3 severity matrix). It does not infer factor
values from anything -- the caller (a human analyst, or
catalog_calibration.py's documented per-category template) supplies them.
This mirrors severity.py's posture: the arithmetic is spec-derived and
verified against the methodology's own published worked example
(test_risk_score.py), never a guessed number.

Overall impact: the methodology directs analysts to use the business
impact when it can be estimated, and fall back to technical impact
otherwise ("Note: if you are unsure...it may be worth using the average of
the technical and business impact"). This module takes the simpler of the
two supported paths explicitly: business impact if the caller supplied
all four business factors, else technical impact. It does not average the
two, since that reading of the spec is not the one exercised by the
methodology's own worked example (business impact alone, not an average,
determines the "Final Severity: LOW" result there -- see
test_risk_score.py::TestOwaspWorkedExample).

The five resulting severity bands are OWASP's own (Note/Low/Medium/High/
Critical). "Note" is remapped to ARES's "info" so the output lands in the
same five-value Severity vocabulary used everywhere else in this repo
(src/knowledge/finding.ts's Severity type) -- Note and info mean the same
thing (no real security impact) under different names.
"""
from __future__ import annotations

from dataclasses import dataclass

from factors import (
    BUSINESS_IMPACT_FACTORS,
    LIKELIHOOD_FACTORS,
    TECHNICAL_IMPACT_FACTORS,
)

Severity = str  # one of: "critical" | "high" | "medium" | "low" | "info"
Level = str  # one of: "low" | "medium" | "high"

# OWASP's own 3x3 matrix (Impact rows x Likelihood columns). Values are
# OWASP's literal labels, lowercased; "note" is remapped to "info" by
# _OWASP_TO_ARES_SEVERITY below, once, rather than baking the rename into
# this table and losing the traceability back to the source table.
_SEVERITY_MATRIX: dict[tuple[Level, Level], str] = {
    ("high", "low"): "medium",
    ("high", "medium"): "high",
    ("high", "high"): "critical",
    ("medium", "low"): "low",
    ("medium", "medium"): "medium",
    ("medium", "high"): "high",
    ("low", "low"): "note",
    ("low", "medium"): "low",
    ("low", "high"): "medium",
}
_OWASP_TO_ARES_SEVERITY = {
    "note": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


class UnsupportedRiskFactor(ValueError):
    """Raised when a factor name is unknown, a required factor is missing,
    or a supplied score is not one of the discrete values the OWASP table
    defines for that factor. Never silently coerced or clamped."""


@dataclass(frozen=True)
class RiskVector:
    """Caller-supplied factor scores. `likelihood` must supply all 8 keys
    in LIKELIHOOD_FACTORS; `technical_impact` must supply all 4 keys in
    TECHNICAL_IMPACT_FACTORS. `business_impact`, if given at all, must
    supply all 4 keys in BUSINESS_IMPACT_FACTORS -- a partial business
    vector is rejected rather than averaged against missing data."""

    likelihood: dict[str, int]
    technical_impact: dict[str, int]
    business_impact: dict[str, int] | None = None


@dataclass(frozen=True)
class ScoredRisk:
    likelihood_score: float
    likelihood_level: Level
    technical_impact_score: float
    business_impact_score: float | None
    impact_score: float
    impact_level: Level
    impact_basis: str  # "business" | "technical"
    severity: Severity


def _validated_average(values: dict[str, int], table: dict[str, dict[int, str]], vector_name: str) -> float:
    missing = [name for name in table if name not in values]
    if missing:
        raise UnsupportedRiskFactor(f"{vector_name} is missing factors: {missing}")
    extra = [name for name in values if name not in table]
    if extra:
        raise UnsupportedRiskFactor(f"{vector_name} has unknown factors: {extra}")
    for name, score in values.items():
        valid_scores = table[name]
        if score not in valid_scores:
            raise UnsupportedRiskFactor(
                f"{vector_name}.{name}={score!r} is not one of the OWASP-defined "
                f"scores for this factor: {sorted(valid_scores)}"
            )
    return sum(values.values()) / len(table)


def _level(average: float) -> Level:
    # OWASP "Likelihood and Impact Levels" table: 0 to <3 LOW, 3 to <6
    # MEDIUM, 6 to 9 HIGH.
    if average < 3:
        return "low"
    if average < 6:
        return "medium"
    return "high"


def score_risk(vector: RiskVector) -> ScoredRisk:
    likelihood_score = _validated_average(vector.likelihood, LIKELIHOOD_FACTORS, "likelihood")
    technical_impact_score = _validated_average(
        vector.technical_impact, TECHNICAL_IMPACT_FACTORS, "technical_impact"
    )

    business_impact_score: float | None = None
    if vector.business_impact is not None:
        business_impact_score = _validated_average(
            vector.business_impact, BUSINESS_IMPACT_FACTORS, "business_impact"
        )

    if business_impact_score is not None:
        impact_score = business_impact_score
        impact_basis = "business"
    else:
        impact_score = technical_impact_score
        impact_basis = "technical"

    likelihood_level = _level(likelihood_score)
    impact_level = _level(impact_score)
    owasp_severity = _SEVERITY_MATRIX[(impact_level, likelihood_level)]

    return ScoredRisk(
        likelihood_score=likelihood_score,
        likelihood_level=likelihood_level,
        technical_impact_score=technical_impact_score,
        business_impact_score=business_impact_score,
        impact_score=impact_score,
        impact_level=impact_level,
        impact_basis=impact_basis,
        severity=_OWASP_TO_ARES_SEVERITY[owasp_severity],
    )
