import json
from pathlib import Path

import pytest

from convert_ares_core_reports import (
    SEVERITY_MAP,
    bucket_confidence,
    convert_all,
    convert_report,
    map_category,
    map_severity,
)

CATEGORY_MAPPING = json.loads(
    (Path(__file__).parent / "mappings" / "ares-core-categories.json").read_text()
)


def make_finding(category="type-cosplay", confidence=0.95, severity="Critical"):
    return {
        "id": "F-001",
        "title": "t",
        "description": "d",
        "severity": severity,
        "category": category,
        "location": {
            "file": "",
            "line_start": None,
            "line_end": None,
            "column_start": None,
            "column_end": None,
            "function": None,
            "commit": None,
        },
        "proof_of_concept": None,
        "recommendation": "r",
        "references": [],
        "confidence": confidence,
    }


def test_category_mapping_covers_all_21_rust_variants():
    expected = {
        "type-cosplay", "ownership-check", "signer-authorization", "arbitrary-cpi",
        "initialization-frontrunning", "reentrancy-risk", "duplicate-mutable-accounts",
        "arithmetic-overflow", "close-account", "account-reloading", "re-initialization",
        "revival-attack", "account-data-matching", "pda-privileges", "fuzzing-crash",
        "invariant-violation", "missing-signer", "missing-revalidation", "unchecked-cast",
        "state-transition-gap", "generic",
    }
    assert set(CATEGORY_MAPPING["categories"].keys()) == expected


def test_map_category_exact_matches():
    assert map_category("type-cosplay", CATEGORY_MAPPING) == "type-cosplay"
    assert map_category("arbitrary-cpi", CATEGORY_MAPPING) == "arbitrary-cpi"
    assert map_category("account-data-matching", CATEGORY_MAPPING) == "account-data-matching"


def test_map_category_now_exact_matches():
    # ENG-2 gave these Rust categories real VULN_CATALOG entries; they were
    # previously unmapped and scored as "other" (see
    # test_map_category_unmapped_becomes_other below, which used to assert
    # pda-privileges landed on "other" -- it no longer does).
    assert map_category("pda-privileges", CATEGORY_MAPPING) == "pda-privileges"
    assert map_category("reentrancy-risk", CATEGORY_MAPPING) == "reentrancy-risk"
    assert map_category("missing-revalidation", CATEGORY_MAPPING) == "missing-revalidation"
    assert map_category("fuzzing-crash", CATEGORY_MAPPING) == "fuzzing-crash"
    assert map_category("state-transition-gap", CATEGORY_MAPPING) == "state-transition-gap"


def test_map_category_semantic_mismatch_handled():
    # Rust's plural vs Python's singular -- this is the whole point of the mapping file.
    assert map_category("duplicate-mutable-accounts", CATEGORY_MAPPING) == "duplicate-mutable-account"


def test_map_category_unmapped_becomes_other():
    assert map_category("generic", CATEGORY_MAPPING) == "other"


def test_map_category_unknown_rust_category_becomes_other():
    # Defensive: a category string not in the mapping at all (e.g. Rust added
    # a 21st variant) must not raise -- it's unmapped, same as the null case.
    assert map_category("some-future-category", CATEGORY_MAPPING) == "other"


def test_bucket_confidence_thresholds():
    assert bucket_confidence(0.70) == "low"
    assert bucket_confidence(0.79) == "low"
    assert bucket_confidence(0.80) == "medium"
    assert bucket_confidence(0.89) == "medium"
    assert bucket_confidence(0.90) == "high"
    assert bucket_confidence(1.0) == "high"


def test_map_severity_informational_is_not_a_naive_lowercase():
    # The one entry where .lower() alone would be wrong: "Informational" -> "info".
    assert map_severity("Informational") == "info"
    assert "informational" not in SEVERITY_MAP.values()


def test_map_severity_all_five_values():
    assert map_severity("Critical") == "critical"
    assert map_severity("High") == "high"
    assert map_severity("Medium") == "medium"
    assert map_severity("Low") == "low"


def test_map_severity_rejects_unknown_value():
    with pytest.raises(ValueError, match="unrecognized Rust severity"):
        map_severity("Extreme")


def test_convert_report_produces_expected_columns():
    report = {"findings": [make_finding()]}
    rows = convert_report(report, "sealevel-attacks:0-signer-authorization", CATEGORY_MAPPING)
    assert len(rows) == 1
    row = rows[0]
    assert row["target_id"] == "sealevel-attacks:0-signer-authorization"
    assert row["category"] == "type-cosplay"
    assert row["confidence"] == "high"
    assert row["status"] == "suspected"
    assert row["speculative"] is False
    assert row["severity"] == "critical"


def test_convert_report_empty_findings_produces_no_rows():
    assert convert_report({"findings": []}, "x", CATEGORY_MAPPING) == []


def test_convert_all_skips_missing_reports_without_error(tmp_path):
    manifest = {"a": "src:a", "b": "src:b"}
    report_a = {"findings": [make_finding()]}
    (tmp_path / "ares-report-a.json").write_text(json.dumps(report_a))
    # deliberately no ares-report-b.json -- must not raise, must contribute 0 rows

    predictions, total, other_count = convert_all(tmp_path, manifest, CATEGORY_MAPPING)
    assert total == 1
    assert other_count == 0
    assert list(predictions["target_id"]) == ["src:a"]


def test_convert_all_counts_other_category_coverage(tmp_path):
    manifest = {"a": "src:a"}
    report = {"findings": [make_finding(category="generic"), make_finding(category="type-cosplay")]}
    (tmp_path / "ares-report-a.json").write_text(json.dumps(report))

    predictions, total, other_count = convert_all(tmp_path, manifest, CATEGORY_MAPPING)
    assert total == 2
    assert other_count == 1
