"""OWASP Risk Rating Methodology -- factor tables.

Source: OWASP Risk Rating Methodology
(https://owasp.org/www-community/OWASP_Risk_Rating_Methodology), the
"Threat Agent Factors" / "Vulnerability Factors" / "Technical Impact
Factors" / "Business Impact Factors" tables. Every score below is copied
from that table, not invented -- each factor accepts only the handful of
discrete scores the methodology actually defines (e.g. Motive is 1, 4, or
9; there is no such thing as Motive=5). A caller supplying a value outside
this set gets a hard error (see risk_score.py's UnsupportedRiskFactor),
the same "never silently guess" posture severity.py uses for CVSS vectors.

Two Threat Agent Factors happen to share a score in the source table
(Skill Level's "Developers" and "System administrators" descriptions are
both scored 2) -- that is the spec, not a transcription slip.
"""
from __future__ import annotations

# Threat Agent Factors -- name -> {score: description}
SKILL_LEVEL = {
    1: "No technical skills",
    3: "Some technical skills",
    5: "Advanced computer user",
    6: "Network and programming skills",
    9: "Security penetration skills",
}
MOTIVE = {
    1: "Low or no reward",
    4: "Possible reward",
    9: "High reward",
}
OPPORTUNITY = {
    0: "Full access or expensive resources required",
    4: "Special access or resources required",
    7: "Some access or resources required",
    9: "No access or resources required",
}
SIZE = {
    2: "Developers / System administrators",
    4: "Intranet users",
    5: "Partners",
    6: "Authenticated users",
    9: "Anonymous Internet users",
}

# Vulnerability Factors
EASE_OF_DISCOVERY = {
    1: "Practically impossible",
    3: "Difficult",
    7: "Easy",
    9: "Automated tools available",
}
EASE_OF_EXPLOIT = {
    1: "Theoretical",
    3: "Difficult",
    5: "Easy",
    9: "Automated tools available",
}
AWARENESS = {
    1: "Unknown",
    4: "Hidden",
    6: "Obvious",
    9: "Public knowledge",
}
INTRUSION_DETECTION = {
    1: "Active detection in application",
    3: "Logged and reviewed",
    8: "Logged without review",
    9: "Not logged",
}

# Technical Impact Factors
LOSS_OF_CONFIDENTIALITY = {
    2: "Minimal non-sensitive data disclosed",
    6: "Minimal critical, or extensive non-sensitive, data disclosed",
    7: "Extensive critical data disclosed",
    9: "All data disclosed",
}
LOSS_OF_INTEGRITY = {
    1: "Minimal slightly corrupt data",
    3: "Minimal seriously corrupt data",
    5: "Extensive slightly corrupt data",
    7: "Extensive seriously corrupt data",
    9: "All data totally corrupt",
}
LOSS_OF_AVAILABILITY = {
    1: "Minimal secondary services interrupted",
    5: "Minimal primary or extensive secondary services interrupted",
    7: "Extensive primary services interrupted",
    9: "All services completely lost",
}
LOSS_OF_ACCOUNTABILITY = {
    1: "Fully traceable",
    7: "Possibly traceable",
    9: "Completely anonymous",
}

# Business Impact Factors
FINANCIAL_DAMAGE = {
    1: "Less than the cost to fix the vulnerability",
    3: "Minor effect on annual profit",
    7: "Significant effect on annual profit",
    9: "Bankruptcy",
}
REPUTATION_DAMAGE = {
    1: "Minimal damage",
    4: "Loss of major accounts",
    5: "Loss of goodwill",
    9: "Brand damage",
}
NON_COMPLIANCE = {
    2: "Minor violation",
    5: "Clear violation",
    7: "High profile violation",
}
PRIVACY_VIOLATION = {
    3: "One individual",
    5: "Hundreds of people",
    7: "Thousands of people",
    9: "Millions of people",
}

LIKELIHOOD_FACTORS: dict[str, dict[int, str]] = {
    "skill_level": SKILL_LEVEL,
    "motive": MOTIVE,
    "opportunity": OPPORTUNITY,
    "size": SIZE,
    "ease_of_discovery": EASE_OF_DISCOVERY,
    "ease_of_exploit": EASE_OF_EXPLOIT,
    "awareness": AWARENESS,
    "intrusion_detection": INTRUSION_DETECTION,
}

TECHNICAL_IMPACT_FACTORS: dict[str, dict[int, str]] = {
    "loss_of_confidentiality": LOSS_OF_CONFIDENTIALITY,
    "loss_of_integrity": LOSS_OF_INTEGRITY,
    "loss_of_availability": LOSS_OF_AVAILABILITY,
    "loss_of_accountability": LOSS_OF_ACCOUNTABILITY,
}

BUSINESS_IMPACT_FACTORS: dict[str, dict[int, str]] = {
    "financial_damage": FINANCIAL_DAMAGE,
    "reputation_damage": REPUTATION_DAMAGE,
    "non_compliance": NON_COMPLIANCE,
    "privacy_violation": PRIVACY_VIOLATION,
}
