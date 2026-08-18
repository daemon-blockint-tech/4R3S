import json
from pathlib import Path

import pandas as pd
import pytest

from score_suppression import (
    AVOIDED_FP,
    LOST_TP,
    NO_EFFECT,
    analyse,
    classify_effects,
    collect_rows,
    effects_by,
    suppressed_rows,
)

# Minimal category mapping, same shape as eval/mappings/ares-core-categories.json.
# `made-up-category` is deliberately absent so the "other" fallback is exercised.
MAPPING = {
    "mapping_kind": "category-vocabulary",
    "categories": {
        "type-cosplay": {"vuln_catalog_id": "type-cosplay", "confidence": "exact"},
        "ownership-check": {"vuln_catalog_id": "missing-owner-check", "confidence": "semantic"},
        "arbitrary-cpi": {"vuln_catalog_id": "arbitrary-cpi", "confidence": "exact"},
        "made-up-category": {"vuln_catalog_id": None, "confidence": "unmapped"},
    },
}


def finding(category: str, *, confidence: float = 0.85, severity: str = "High") -> dict:
    """A Finding as ares-core serializes it -- only the fields the converter reads."""
    return {"category": category, "confidence": confidence, "severity": severity}


def report(findings: list[dict], suppressed: list[tuple[dict, str]]) -> dict:
    """An AuditReport as ares-core serializes it."""
    return {
        "findings": findings,
        "suppressed_findings": [
            {"finding": f, "reason": "because", "suppressed_by": by} for f, by in suppressed
        ],
    }


def write_report(reports_dir: Path, safe_name: str, payload: dict) -> None:
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / f"ares-report-{safe_name}.json").write_text(json.dumps(payload))


def truth_frame(pairs: list[tuple[str, str]]) -> pd.DataFrame:
    return pd.DataFrame(pairs, columns=["target_id", "category"])


# --------------------------------------------------------------------------
# extraction
# --------------------------------------------------------------------------


def test_suppressed_findings_are_extracted_with_their_suppressor():
    rows = suppressed_rows(
        report([], [(finding("type-cosplay"), "local_judge"), (finding("arbitrary-cpi"), "llm_judge")]),
        "neodyme-workshop:level3",
        MAPPING,
    )

    assert [r["category"] for r in rows] == ["type-cosplay", "arbitrary-cpi"]
    assert [r["suppressed_by"] for r in rows] == ["local_judge", "llm_judge"]
    assert all(r["target_id"] == "neodyme-workshop:level3" for r in rows)


def test_suppressed_rows_keep_status_suspected():
    """`false-positive` would be silently dropped by score_detections' default filter."""
    rows = suppressed_rows(
        report([], [(finding("type-cosplay"), "local_judge")]), "t1", MAPPING
    )
    assert rows[0]["status"] == "suspected"


def test_unmapped_category_becomes_other_rather_than_being_dropped():
    rows = suppressed_rows(
        report([], [(finding("made-up-category"), "local_judge")]), "t1", MAPPING
    )
    assert rows[0]["category"] == "other"


def test_report_with_no_suppressed_findings_key_is_not_an_error():
    assert suppressed_rows({"findings": []}, "t1", MAPPING) == []


# --------------------------------------------------------------------------
# collect_rows / the empty-run guard
# --------------------------------------------------------------------------


def test_collect_rows_reads_retained_and_suppressed(tmp_path):
    write_report(
        tmp_path,
        "level3",
        report([finding("arbitrary-cpi")], [(finding("type-cosplay"), "local_judge")]),
    )

    retained, suppressed, missing = collect_rows(
        tmp_path, {"level3": "neodyme-workshop:level3"}, MAPPING
    )

    assert list(retained["category"]) == ["arbitrary-cpi"]
    assert list(suppressed["category"]) == ["type-cosplay"]
    assert missing == []


def test_one_missing_report_is_zero_findings_not_an_error(tmp_path):
    write_report(tmp_path, "level3", report([finding("arbitrary-cpi")], []))

    retained, _, missing = collect_rows(
        tmp_path, {"level3": "t:3", "level4": "t:4"}, MAPPING
    )

    assert missing == ["level4"]
    assert len(retained) == 1


def test_every_report_missing_raises_rather_than_reporting_zeros(tmp_path):
    """The `--fuzz false` trap: all scans abort, the dir is empty, zeros look real."""
    with pytest.raises(ValueError, match="fuzz false"):
        collect_rows(tmp_path, {"level3": "t:3", "level4": "t:4"}, MAPPING)


# --------------------------------------------------------------------------
# effect classification -- the three outcomes
# --------------------------------------------------------------------------


def test_suppressing_a_labelled_key_with_no_survivor_is_a_lost_true_positive():
    retained = pd.DataFrame(columns=["target_id", "category"])
    suppressed = pd.DataFrame(
        [{"target_id": "t:1", "category": "type-cosplay", "suppressed_by": "local_judge"}]
    )
    truth = truth_frame([("t:1", "type-cosplay")])

    effects = classify_effects(retained, suppressed, truth)

    assert list(effects["effect"]) == [LOST_TP]


def test_suppressing_an_unlabelled_key_with_no_survivor_avoids_a_false_positive():
    retained = pd.DataFrame(columns=["target_id", "category"])
    suppressed = pd.DataFrame(
        [{"target_id": "t:1", "category": "type-cosplay", "suppressed_by": "local_judge"}]
    )
    truth = truth_frame([("t:1", "arbitrary-cpi")])

    effects = classify_effects(retained, suppressed, truth)

    assert list(effects["effect"]) == [AVOIDED_FP]


def test_suppression_has_no_effect_when_a_retained_finding_covers_the_same_key():
    """build_confusion dedups on the key, so removing a duplicate moves nothing."""
    retained = pd.DataFrame([{"target_id": "t:1", "category": "type-cosplay"}])
    suppressed = pd.DataFrame(
        [{"target_id": "t:1", "category": "type-cosplay", "suppressed_by": "local_judge"}]
    )
    truth = truth_frame([("t:1", "type-cosplay")])

    effects = classify_effects(retained, suppressed, truth)

    assert list(effects["effect"]) == [NO_EFFECT]


def test_duplicate_suppressions_collapse_to_one_key_but_keep_their_count():
    retained = pd.DataFrame(columns=["target_id", "category"])
    suppressed = pd.DataFrame(
        [{"target_id": "t:1", "category": "type-cosplay", "suppressed_by": "local_judge"}] * 3
    )
    truth = truth_frame([("t:1", "arbitrary-cpi")])

    effects = classify_effects(retained, suppressed, truth)

    assert len(effects) == 1
    assert int(effects.iloc[0]["suppressed"]) == 3


def test_effects_are_split_per_suppressor():
    retained = pd.DataFrame(columns=["target_id", "category"])
    suppressed = pd.DataFrame(
        [
            {"target_id": "t:1", "category": "type-cosplay", "suppressed_by": "local_judge"},
            {"target_id": "t:2", "category": "arbitrary-cpi", "suppressed_by": "llm_judge"},
        ]
    )
    truth = truth_frame([("t:9", "type-cosplay")])

    table = effects_by(classify_effects(retained, suppressed, truth), "suppressed_by")

    assert set(table.index) == {"local_judge", "llm_judge"}
    assert int(table.loc["local_judge", AVOIDED_FP]) == 1


def test_classify_effects_on_no_suppressions_returns_an_empty_table():
    empty = pd.DataFrame(columns=["target_id", "category", "suppressed_by"])
    effects = classify_effects(
        pd.DataFrame(columns=["target_id", "category"]), empty, truth_frame([("t:1", "x")])
    )
    assert effects.empty
    assert effects_by(effects, "category").empty


# --------------------------------------------------------------------------
# analyse -- the counterfactual
# --------------------------------------------------------------------------


def test_disabling_a_judge_that_killed_only_false_positives_lowers_precision():
    retained = pd.DataFrame([{"target_id": "t:1", "category": "type-cosplay"}])
    suppressed = pd.DataFrame(
        [
            {"target_id": "t:1", "category": "arbitrary-cpi", "suppressed_by": "local_judge"},
            {"target_id": "t:2", "category": "arbitrary-cpi", "suppressed_by": "local_judge"},
        ]
    )
    truth = truth_frame([("t:1", "type-cosplay")])

    result = analyse(truth, retained, suppressed)

    # One TP, no FP -> perfect precision as scored.
    assert result["actual"]["precision"] == pytest.approx(1.0)
    # Put the two suppressed FPs back: 1 TP out of 3 predictions.
    disabled = result["per_suppressor"]["local_judge"]["disabled"]
    assert disabled["precision"] == pytest.approx(1 / 3)
    assert result["per_suppressor"]["local_judge"]["delta"]["precision"] == pytest.approx(2 / 3)


def test_disabling_a_judge_that_killed_a_real_finding_raises_recall():
    retained = pd.DataFrame(columns=["target_id", "category"])
    suppressed = pd.DataFrame(
        [{"target_id": "t:1", "category": "type-cosplay", "suppressed_by": "local_judge"}]
    )
    truth = truth_frame([("t:1", "type-cosplay")])

    result = analyse(truth, retained, suppressed)

    assert result["actual"]["recall"] == pytest.approx(0.0)
    assert result["per_suppressor"]["local_judge"]["disabled"]["recall"] == pytest.approx(1.0)
    # Negative delta: the judge cost us recall.
    assert result["per_suppressor"]["local_judge"]["delta"]["recall"] == pytest.approx(-1.0)


def test_analyse_reports_an_inert_judge_as_zero_rather_than_failing():
    retained = pd.DataFrame([{"target_id": "t:1", "category": "type-cosplay"}])
    suppressed = pd.DataFrame(columns=["target_id", "category", "suppressed_by"])
    truth = truth_frame([("t:1", "type-cosplay")])

    result = analyse(truth, retained, suppressed)

    assert result["suppressed_total"] == 0
    assert result["per_suppressor"] == {}
    assert result["actual"]["tp"] == 1


def test_analyse_counts_the_vocabulary_gap():
    retained = pd.DataFrame(columns=["target_id", "category"])
    suppressed = pd.DataFrame(
        [{"target_id": "t:1", "category": "other", "suppressed_by": "local_judge"}]
    )

    result = analyse(truth_frame([("t:1", "type-cosplay")]), retained, suppressed)

    assert result["unmapped_categories"] == 1
