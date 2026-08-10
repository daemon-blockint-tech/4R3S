"""Recalibrate `src/knowledge/vuln-catalog.generated.json` against the
OWASP-methodology risk engine (risk_score.py).

Each catalog entry carries a static `defaultSeverity` that was assigned by
hand when the entry was written -- it was never derived from a scoring
model. This module assigns one documented OWASP RiskVector *per category*
(not per entry: 13 categories cover 34 entries, and a category is the
right grain for a threat-agent/vulnerability profile -- "how does an
attacker generally reach and exploit this class of bug" doesn't vary
entry-by-entry the way business impact would) and computes what severity
the engine would assign, then diffs that against each entry's
`defaultSeverity`.

This is expert-judgment input, not a measurement: the factor values below
are the same kind of call a human auditor makes when filling in an OWASP
risk worksheet, made once per category and documented with a one-line
rationale so the choice can be challenged. What *is* mechanically
reproducible, and what this module's tests hold fixed, is the arithmetic
that turns those judgment calls into a severity, and the resulting
mismatch list -- not the judgment calls themselves.

No business-impact factors are used: financial/reputation/compliance/
privacy magnitude depends on a specific protocol's TVL and user base,
which a generic category can't know. Impact is technical-impact-only
here, which is a real limitation of category-level calibration -- see
services/risk/README.md's "What this does not do".

Per GOLDEN RULE 3 (no trust-me numbers), this module never overwrites
`defaultSeverity` in solana-vulns.ts -- see docs/SVC-RISK-1-ASSUMPTIONS.md
for why that's deliberately left to a human call.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from risk_score import RiskVector, score_risk

CATALOG_PATH = (
    Path(__file__).resolve().parents[2] / "src" / "knowledge" / "vuln-catalog.generated.json"
)


class CatalogCalibrationError(ValueError):
    """Raised when the catalog file is missing/malformed, or contains a
    category this module has no documented risk template for -- a new
    category must get a template, not a silent skip."""


# One RiskVector per catalog category. Likelihood factors model "a
# permissionless on-chain actor attacking this bug class in general";
# technical_impact factors model "what breaks if it's exploited". Each
# entry's `rationale` is the reasoning a reviewer needs to challenge the
# specific numbers -- the numbers themselves are a judgment call, not a
# derived fact.
#
# Three factor values are held constant across every template, because they
# are properties of the Solana execution environment rather than of any one
# bug class. They are stated here once instead of being repeated in 13
# rationales:
#
#   intrusion_detection = 8 ("Logged without review"). Every Solana
#     transaction is permanently recorded in the public ledger, so 9 ("Not
#     logged") is not merely pessimistic, it is impossible on-chain. Whether
#     anyone *reviews* those logs is protocol-specific; most protocols have
#     no real-time alerting on anomalous instruction patterns, so 8 is the
#     accurate generic default and 3 ("Logged and reviewed") would be the
#     value for a target with active monitoring. This choice is load-bearing:
#     at 9 the `pda` category scores exactly 6.000 and lands HIGH; at 8 it is
#     5.875 and lands MEDIUM (see test_catalog_calibration.py).
#
#   loss_of_confidentiality = 2 ("Minimal non-sensitive data disclosed"). All
#     on-chain account data is already world-readable by construction, so a
#     Solana program bug almost never *causes* a confidentiality loss.
#
#   loss_of_accountability = 7 ("Possibly traceable"). On-chain actions are
#     permanently attributable to a pubkey, but a pubkey is pseudonymous and
#     freshly generated per attack, so neither 1 (fully traceable) nor 9
#     (completely anonymous) is right.
#
# The last two have a consequence worth stating plainly, because it limits
# what this calibration can mean: with two of OWASP's four technical-impact
# factors pinned, the impact average is structurally compressed and every
# catalog entry currently lands in the MEDIUM impact band. Severity here is
# therefore effectively *likelihood-ranked* -- the impact axis does no
# discriminating work. See README.md's "The impact axis does not
# discriminate" and the test that pins this.
CATEGORY_RISK_TEMPLATES: dict[str, dict[str, Any]] = {
    "access-control": {
        "likelihood": {
            "skill_level": 3, "motive": 9, "opportunity": 9, "size": 9,
            "ease_of_discovery": 7, "ease_of_exploit": 5,
            "awareness": 9, "intrusion_detection": 8,
        },
        "technical_impact": {
            "loss_of_confidentiality": 2, "loss_of_integrity": 9,
            "loss_of_availability": 5, "loss_of_accountability": 7,
        },
        "rationale": (
            "Missing/wrong signer/owner checks: any anonymous transaction "
            "sender can trigger it (opportunity/size high), the missing "
            "check is visible from decompiled/IDL inspection (discovery "
            "high), it's the most publicly documented Solana vuln class "
            "(awareness high), and a successful call can corrupt account "
            "state arbitrarily (integrity high)."
        ),
    },
    "cpi": {
        "likelihood": {
            "skill_level": 5, "motive": 9, "opportunity": 7, "size": 9,
            "ease_of_discovery": 7, "ease_of_exploit": 5,
            "awareness": 6, "intrusion_detection": 8,
        },
        "technical_impact": {
            "loss_of_confidentiality": 2, "loss_of_integrity": 9,
            "loss_of_availability": 5, "loss_of_accountability": 7,
        },
        "rationale": (
            "Exploiting an unchecked CPI target/return usually requires "
            "deploying an attacker-controlled program first (opportunity a "
            "notch below access-control), and is well-known to specialists "
            "but less broadly than missing-signer bugs (awareness medium)."
        ),
    },
    "pda": {
        "likelihood": {
            "skill_level": 5, "motive": 9, "opportunity": 7, "size": 6,
            "ease_of_discovery": 3, "ease_of_exploit": 3,
            "awareness": 6, "intrusion_detection": 8,
        },
        "technical_impact": {
            "loss_of_confidentiality": 2, "loss_of_integrity": 7,
            "loss_of_availability": 1, "loss_of_accountability": 7,
        },
        "rationale": (
            "PDA seed-collision/bump bugs require deriving a specific seed "
            "collision, harder to find and exploit than a plain missing "
            "check (discovery/exploit low)."
        ),
    },
    "initialization": {
        "likelihood": {
            "skill_level": 3, "motive": 9, "opportunity": 7, "size": 6,
            "ease_of_discovery": 7, "ease_of_exploit": 5,
            "awareness": 6, "intrusion_detection": 8,
        },
        "technical_impact": {
            "loss_of_confidentiality": 2, "loss_of_integrity": 7,
            "loss_of_availability": 1, "loss_of_accountability": 7,
        },
        "rationale": (
            "Re-initialization / init-order bugs usually need the account "
            "in a specific lifecycle state (opportunity a notch below "
            "access-control), but the missing guard itself is easy to spot "
            "once looking for it."
        ),
    },
    "arithmetic": {
        "likelihood": {
            "skill_level": 3, "motive": 9, "opportunity": 9, "size": 9,
            "ease_of_discovery": 7, "ease_of_exploit": 5,
            "awareness": 9, "intrusion_detection": 8,
        },
        "technical_impact": {
            "loss_of_confidentiality": 2, "loss_of_integrity": 7,
            "loss_of_availability": 1, "loss_of_accountability": 7,
        },
        "rationale": (
            "Integer overflow/precision bugs: no special access needed, "
            "unchecked arithmetic is visible in source, and it's one of "
            "the best-known Solana/Rust vuln classes (awareness high)."
        ),
    },
    "lifecycle": {
        "likelihood": {
            "skill_level": 5, "motive": 9, "opportunity": 7, "size": 6,
            "ease_of_discovery": 3, "ease_of_exploit": 3,
            "awareness": 4, "intrusion_detection": 8,
        },
        "technical_impact": {
            "loss_of_confidentiality": 2, "loss_of_integrity": 9,
            "loss_of_availability": 1, "loss_of_accountability": 7,
        },
        "rationale": (
            "Account close/revival bugs need specific rent/close-mechanics "
            "understanding (discovery/exploit low, awareness hidden "
            "relative to access-control), but a successful revival can "
            "fully corrupt account state."
        ),
    },
    "framework": {
        "likelihood": {
            "skill_level": 5, "motive": 4, "opportunity": 7, "size": 6,
            "ease_of_discovery": 3, "ease_of_exploit": 3,
            "awareness": 4, "intrusion_detection": 8,
        },
        "technical_impact": {
            "loss_of_confidentiality": 2, "loss_of_integrity": 5,
            "loss_of_availability": 1, "loss_of_accountability": 7,
        },
        "rationale": (
            "Anchor constraint gaps require deep framework-internals "
            "knowledge to spot and exploit, and impact varies a lot by "
            "which constraint is missing, so this sits at a moderate "
            "profile rather than the high end."
        ),
    },
    "oracle": {
        "likelihood": {
            "skill_level": 6, "motive": 9, "opportunity": 4, "size": 4,
            "ease_of_discovery": 3, "ease_of_exploit": 3,
            "awareness": 6, "intrusion_detection": 8,
        },
        "technical_impact": {
            "loss_of_confidentiality": 2, "loss_of_integrity": 7,
            "loss_of_availability": 1, "loss_of_accountability": 9,
        },
        "rationale": (
            "Price-manipulation attacks need capital/flash-loan "
            "infrastructure (opportunity/size lower -- fewer actors can "
            "mount one), usually executed through anonymous bot "
            "infrastructure (accountability = completely anonymous)."
        ),
    },
    "spl": {
        "likelihood": {
            "skill_level": 3, "motive": 9, "opportunity": 9, "size": 9,
            "ease_of_discovery": 7, "ease_of_exploit": 5,
            "awareness": 6, "intrusion_detection": 8,
        },
        "technical_impact": {
            "loss_of_confidentiality": 2, "loss_of_integrity": 7,
            "loss_of_availability": 1, "loss_of_accountability": 7,
        },
        "rationale": (
            "SPL authority/extension checks: same permissionless-caller "
            "profile as access-control, but token-program-specific "
            "knowledge is somewhat less widely known (awareness medium)."
        ),
    },
    "defi": {
        "likelihood": {
            "skill_level": 6, "motive": 9, "opportunity": 7, "size": 6,
            "ease_of_discovery": 7, "ease_of_exploit": 5,
            "awareness": 6, "intrusion_detection": 8,
        },
        "technical_impact": {
            "loss_of_confidentiality": 2, "loss_of_integrity": 5,
            "loss_of_availability": 1, "loss_of_accountability": 9,
        },
        "rationale": (
            "Missing slippage protection is exploited via sandwich/MEV "
            "bots -- visible from a missing parameter, needs bot "
            "infrastructure to execute profitably, near-always anonymous."
        ),
    },
    "availability": {
        "likelihood": {
            "skill_level": 3, "motive": 4, "opportunity": 9, "size": 9,
            "ease_of_discovery": 7, "ease_of_exploit": 5,
            "awareness": 6, "intrusion_detection": 8,
        },
        "technical_impact": {
            "loss_of_confidentiality": 2, "loss_of_integrity": 1,
            "loss_of_availability": 7, "loss_of_accountability": 7,
        },
        "rationale": (
            "DoS/crash bugs: griefing has a lower direct payoff than fund "
            "theft (motive medium, not high), and the impact is service "
            "loss rather than data corruption (integrity low, "
            "availability high)."
        ),
    },
    "logic": {
        "likelihood": {
            "skill_level": 5, "motive": 9, "opportunity": 7, "size": 6,
            "ease_of_discovery": 3, "ease_of_exploit": 3,
            "awareness": 4, "intrusion_detection": 8,
        },
        "technical_impact": {
            "loss_of_confidentiality": 2, "loss_of_integrity": 7,
            "loss_of_availability": 1, "loss_of_accountability": 7,
        },
        "rationale": (
            "Business-logic errors need protocol-specific understanding "
            "to find and exploit (discovery/exploit low, awareness "
            "hidden), since by definition they aren't a generic pattern."
        ),
    },
    "governance": {
        "likelihood": {
            "skill_level": 6, "motive": 9, "opportunity": 4, "size": 4,
            "ease_of_discovery": 3, "ease_of_exploit": 3,
            "awareness": 4, "intrusion_detection": 8,
        },
        "technical_impact": {
            "loss_of_confidentiality": 2, "loss_of_integrity": 9,
            "loss_of_availability": 5, "loss_of_accountability": 7,
        },
        "rationale": (
            "Upgrade-authority capture requires special access to the "
            "governance/upgrade process (opportunity/size lower), but a "
            "successful capture is a full protocol takeover (integrity 9)."
        ),
    },
}


@dataclass(frozen=True)
class CalibrationEntry:
    id: str
    category: str
    catalog_default_severity: str
    computed_severity: str
    likelihood_level: str
    impact_level: str

    @property
    def is_match(self) -> bool:
        return self.catalog_default_severity == self.computed_severity


@dataclass(frozen=True)
class CalibrationReport:
    total: int
    matches: tuple[CalibrationEntry, ...]
    mismatches: tuple[CalibrationEntry, ...]


def _load_catalog(path: Path) -> list[dict[str, Any]]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CatalogCalibrationError(f"could not read catalog at {path}: {exc}") from exc
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CatalogCalibrationError(f"catalog at {path} is not valid JSON: {exc}") from exc
    if not isinstance(entries, list):
        raise CatalogCalibrationError(f"catalog at {path} must be a JSON array, got {type(entries)}")
    if not entries:
        # A zero-entry catalog would otherwise calibrate "successfully" to
        # 0 matches and 0 mismatches -- indistinguishable from a catalog
        # that agrees with every template. The real catalog is generated
        # from solana-vulns.ts and is never empty, so this means the export
        # broke, not that there is nothing to check. Same reasoning as the
        # CVE service's refusal to let a degraded run look like a clean one.
        raise CatalogCalibrationError(
            f"catalog at {path} is empty -- refusing to report a vacuous clean "
            f"calibration; the generated catalog should never have zero entries"
        )
    for i, entry in enumerate(entries):
        # Validated up front rather than indexed optimistically: a catalog
        # regenerated from a solana-vulns.ts that dropped a field would
        # otherwise raise a bare KeyError/TypeError, which reaches the API as
        # an unhandled 500 instead of the documented 503.
        if not isinstance(entry, dict):
            raise CatalogCalibrationError(
                f"catalog at {path} entry {i} must be an object, got {type(entry).__name__}"
            )
        missing = [k for k in ("id", "category", "defaultSeverity") if k not in entry]
        if missing:
            raise CatalogCalibrationError(
                f"catalog at {path} entry {i} ({entry.get('id', '<no id>')!r}) "
                f"is missing required fields: {missing}"
            )
    return entries


def calibrate(path: Path = CATALOG_PATH) -> CalibrationReport:
    entries = _load_catalog(path)
    results: list[CalibrationEntry] = []

    for entry in entries:
        category = entry["category"]
        template = CATEGORY_RISK_TEMPLATES.get(category)
        if template is None:
            raise CatalogCalibrationError(
                f"catalog entry {entry['id']!r} has category {category!r}, which has "
                f"no risk template in CATEGORY_RISK_TEMPLATES -- add one rather than "
                f"skipping this entry."
            )
        scored = score_risk(
            RiskVector(
                likelihood=template["likelihood"],
                technical_impact=template["technical_impact"],
            )
        )
        results.append(
            CalibrationEntry(
                id=entry["id"],
                category=category,
                catalog_default_severity=entry["defaultSeverity"],
                computed_severity=scored.severity,
                likelihood_level=scored.likelihood_level,
                impact_level=scored.impact_level,
            )
        )

    matches = tuple(r for r in results if r.is_match)
    mismatches = tuple(r for r in results if not r.is_match)
    return CalibrationReport(total=len(results), matches=matches, mismatches=mismatches)
