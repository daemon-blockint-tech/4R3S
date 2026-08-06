"""CVSS vector -> ARES severity enum.

Scope, deliberately narrow: this implements the CVSS v3.1 BASE score formula
only (FIRST.org CVSS v3.1 specification document, section 8.1 -- the score is
recomputed from the vector's metrics rather than trusted as a pre-rendered
number, since no advisory record carries one).

Real advisories in the vendored corpus carry BOTH "CVSS:3.1/..." and
"CVSS:4.0/..." vectors (confirmed: RUSTSEC-2026-0144 is 3.1, RUSTSEC-2026-0146
is 4.0 -- two anchor-lang advisories eight days apart). CVSS v4.0 uses a
different metric set and an entirely different scoring formula; applying the
v3.1 formula to a v4.0 vector would silently produce a wrong number that
looks exactly as confident as a correct one. This module recognizes the
"CVSS:3.1/" prefix ONLY and returns `unrated` for anything else -- including
v4.0 -- rather than guessing. Extending to v4.0 is future work, not a gap to
paper over here.

No numeric severity backing exists on the TS side to reuse: `severityFromMatrix`
in src/knowledge/severity.ts is test-only, and the live path (`resolveSeverity`
in src/graph/util.ts) resolves severity from LLM text with a category-default
fallback. This mapping is therefore defined fresh, against the CVSS v3.1
spec's own qualitative rating table (section 5), not against anything else in
this repo.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

Severity = str  # one of: "critical" | "high" | "medium" | "low" | "info"

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

_REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class UnsupportedCvssVector(ValueError):
    """Raised for a vector this module cannot score -- including any CVSS
    version other than 3.1. Callers must map this to an explicit "unrated"
    result, never to a guessed severity."""


@dataclass(frozen=True)
class ScoredCvss:
    base_score: float
    severity: Severity


def _roundup(value: float) -> float:
    # The official CVSS "Roundup" function (spec section 8.1, Appendix A):
    # operates on the value scaled to an integer to avoid the float
    # representation error that a naive round(x, 1) can introduce right at a
    # score boundary (e.g. 4.0 vs 3.9999999999).
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000.0
    return (math.floor(int_input / 10_000) + 1) / 10.0


def _parse_vector(vector: str) -> dict[str, str]:
    if not vector.startswith("CVSS:3.1/"):
        raise UnsupportedCvssVector(
            f"only CVSS:3.1 vectors are scored by this module, got: {vector!r}"
        )
    body = vector[len("CVSS:3.1/") :]
    metrics: dict[str, str] = {}
    for piece in body.split("/"):
        if not piece or ":" not in piece:
            raise UnsupportedCvssVector(f"malformed metric segment {piece!r} in {vector!r}")
        key, _, val = piece.partition(":")
        metrics[key] = val
    missing = [m for m in _REQUIRED_METRICS if m not in metrics]
    if missing:
        raise UnsupportedCvssVector(f"vector {vector!r} is missing base metrics: {missing}")
    return metrics


def score_cvss31(vector: str) -> ScoredCvss:
    """Compute the CVSS v3.1 base score and map it to an ARES severity.
    Raises UnsupportedCvssVector for anything not a well-formed CVSS:3.1
    vector with all eight base metrics present."""
    m = _parse_vector(vector)
    scope_changed = m["S"] == "C"

    try:
        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
        ui = _UI[m["UI"]]
        c = _CIA[m["C"]]
        i = _CIA[m["I"]]
        a = _CIA[m["A"]]
    except KeyError as exc:
        raise UnsupportedCvssVector(f"unrecognized metric value in {vector!r}: {exc}") from exc

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    if impact <= 0:
        base_score = 0.0
    else:
        exploitability = 8.22 * av * ac * pr * ui
        combined = (1.08 * (impact + exploitability)) if scope_changed else (impact + exploitability)
        base_score = _roundup(min(combined, 10.0))

    return ScoredCvss(base_score=base_score, severity=_qualitative(base_score))


def _qualitative(score: float) -> Severity:
    # CVSS v3.1 spec section 5, "Qualitative Severity Rating Scale".
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def severity_for_advisory(cvss: str | None) -> tuple[Severity | None, str]:
    """Returns (severity, basis). severity is None -- never guessed -- when
    there is no vector or it can't be scored by this module; `basis` always
    explains why, so a report can distinguish "genuinely unrated upstream"
    from "we don't support this CVSS version yet"."""
    if cvss is None:
        return None, "no-cvss-vector"
    try:
        scored = score_cvss31(cvss)
    except UnsupportedCvssVector:
        if cvss.startswith("CVSS:") and not cvss.startswith("CVSS:3.1/"):
            return None, "unsupported-cvss-version"
        return None, "malformed-cvss-vector"
    return scored.severity, "cvss31-base-score"
