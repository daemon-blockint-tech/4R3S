import json

import pandas as pd
import pytest

from score_detections import (
    attach_truth_metadata,
    build_confusion,
    filter_predictions,
    load_table,
    main,
    score,
    score_frame,
)

KEY = ["target_id", "category"]


def frame(rows):
    return pd.DataFrame(rows, columns=KEY)


def test_score_math():
    s = score(tp=9, fp=1, fn=1)
    assert s.precision == pytest.approx(0.9)
    assert s.recall == pytest.approx(0.9)
    assert s.f1 == pytest.approx(0.9)


def test_score_handles_empty_prediction_set():
    s = score(tp=0, fp=0, fn=4)
    assert (s.precision, s.recall, s.f1) == (0.0, 0.0, 0.0)


def test_perfect_match():
    rows = [["prog1", "missing-signer-check"], ["prog2", "integer-overflow-underflow"]]
    s = score_frame(build_confusion(frame(rows), frame(rows), KEY))
    assert (s.tp, s.fp, s.fn) == (2, 0, 0)
    assert s.f1 == pytest.approx(1.0)


def test_counts_misses_and_spurious_findings():
    truth = frame([["prog1", "missing-signer-check"], ["prog1", "arbitrary-cpi"]])
    predictions = frame([["prog1", "missing-signer-check"], ["prog1", "precision-loss"]])
    s = score_frame(build_confusion(truth, predictions, KEY))
    assert (s.tp, s.fp, s.fn) == (1, 1, 1)
    assert s.precision == pytest.approx(0.5)
    assert s.recall == pytest.approx(0.5)


def test_same_class_on_different_targets_is_not_a_match():
    truth = frame([["prog1", "arbitrary-cpi"]])
    predictions = frame([["prog2", "arbitrary-cpi"]])
    s = score_frame(build_confusion(truth, predictions, KEY))
    assert (s.tp, s.fp, s.fn) == (0, 1, 1)


def test_duplicate_reports_collapse_to_one_hit():
    truth = frame([["prog1", "arbitrary-cpi"]])
    predictions = frame([["prog1", "arbitrary-cpi"]] * 3)
    s = score_frame(build_confusion(truth, predictions, KEY))
    assert (s.tp, s.fp, s.fn) == (1, 0, 0)


def test_location_can_join_the_match_key():
    key = KEY + ["location"]
    truth = pd.DataFrame([["prog1", "arbitrary-cpi", "withdraw"]], columns=key)
    predictions = pd.DataFrame([["prog1", "arbitrary-cpi", "deposit"]], columns=key)
    s = score_frame(build_confusion(truth, predictions, key))
    assert (s.tp, s.fp, s.fn) == (0, 1, 1)


def test_verify_rejects_and_speculation_are_dropped_by_default():
    predictions = pd.DataFrame(
        {
            "target_id": ["p1", "p1", "p1"],
            "category": ["a", "b", "c"],
            "status": ["confirmed", "false-positive", "suspected"],
            "speculative": [False, False, True],
        }
    )
    kept = filter_predictions(predictions, None, ("false-positive",), include_speculative=False)
    assert list(kept["category"]) == ["a"]
    kept_spec = filter_predictions(predictions, None, ("false-positive",), include_speculative=True)
    assert list(kept_spec["category"]) == ["a", "c"]


def test_min_confidence_filters_by_rank():
    predictions = pd.DataFrame(
        {"target_id": ["p1"] * 3, "category": ["a", "b", "c"], "confidence": ["low", "medium", "high"]}
    )
    kept = filter_predictions(predictions, "medium", (), include_speculative=True)
    assert list(kept["category"]) == ["b", "c"]


def test_unknown_confidence_value_is_rejected():
    predictions = pd.DataFrame({"target_id": ["p1"], "category": ["a"], "confidence": ["very-high"]})
    with pytest.raises(ValueError, match="unknown confidence"):
        filter_predictions(predictions, "medium", (), include_speculative=True)


def test_false_positives_are_bucketed_as_unlabeled_in_severity_slice():
    truth = pd.DataFrame([["prog1", "arbitrary-cpi", "high"]], columns=KEY + ["severity"])
    predictions = frame([["prog1", "precision-loss"]])
    confusion = build_confusion(truth, predictions[KEY], KEY)
    joined = attach_truth_metadata(confusion, truth, KEY, "severity")
    assert set(joined["severity"]) == {"high", "unlabeled"}


def test_missing_required_column_is_reported(tmp_path):
    path = tmp_path / "truth.csv"
    path.write_text("target_id,vuln\nprog1,arbitrary-cpi\n")
    with pytest.raises(ValueError, match="missing required column"):
        load_table(path)


def test_jsonl_input_loads(tmp_path):
    path = tmp_path / "preds.jsonl"
    path.write_text('{"target_id": "prog1", "category": "arbitrary-cpi"}\n')
    assert load_table(path).iloc[0]["category"] == "arbitrary-cpi"


def test_cli_exits_nonzero_when_target_f1_is_missed(tmp_path, capsys):
    truth = tmp_path / "truth.csv"
    truth.write_text("target_id,category,severity\nprog1,arbitrary-cpi,high\nprog1,precision-loss,low\n")
    preds = tmp_path / "preds.csv"
    preds.write_text("target_id,category\nprog1,arbitrary-cpi\n")
    out = tmp_path / "out.json"

    code = main(
        [
            "--truth", str(truth),
            "--predictions", str(preds),
            "--by", "category", "severity",
            "--target-f1", "0.94",
            "--json-out", str(out),
        ]
    )

    assert code == 1
    assert "NOT MET" in capsys.readouterr().out
    payload = json.loads(out.read_text())
    assert payload["overall"]["f1"] == pytest.approx(2 / 3)
    assert payload["misses"] == [{"target_id": "prog1", "category": "precision-loss"}]


def test_cli_exits_zero_when_target_is_met(tmp_path):
    truth = tmp_path / "truth.csv"
    truth.write_text("target_id,category\nprog1,arbitrary-cpi\n")
    preds = tmp_path / "preds.csv"
    preds.write_text("target_id,category\nprog1,arbitrary-cpi\n")
    assert main(["--truth", str(truth), "--predictions", str(preds), "--target-f1", "0.94"]) == 0
