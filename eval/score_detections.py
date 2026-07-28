#!/usr/bin/env python3
"""Score ARES vulnerability detections against a labeled ground truth set.

Reads two tabular files (CSV or JSONL), aligns them on a match key, and reports
precision / recall / F1 overall and per slice. It computes nothing about a run
it was not given: every number printed comes from the two input files.

See eval/README.md for the input schema.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

import numpy as np
import pandas as pd

CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
DEFAULT_KEY = ("target_id", "category")
REQUIRED_COLUMNS = set(DEFAULT_KEY)


@dataclass(frozen=True)
class Scores:
    support: int
    predicted: int
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float


def load_table(path: Path) -> pd.DataFrame:
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        frame = pd.read_json(path, lines=True)
    elif path.suffix.lower() == ".json":
        frame = pd.json_normalize(json.loads(path.read_text()))
    else:
        frame = pd.read_csv(path)
    missing = REQUIRED_COLUMNS - set(frame.columns)
    if missing:
        raise ValueError(f"{path}: missing required column(s) {sorted(missing)}")
    for column in frame.columns:
        if frame[column].dtype == object:
            frame[column] = frame[column].astype("string").str.strip()
    return frame


def filter_predictions(
    predictions: pd.DataFrame,
    min_confidence: str | None,
    drop_statuses: tuple[str, ...],
    include_speculative: bool,
) -> pd.DataFrame:
    kept = predictions
    if drop_statuses and "status" in kept.columns:
        kept = kept[~kept["status"].str.lower().isin(drop_statuses)]
    if min_confidence:
        if "confidence" not in kept.columns:
            raise ValueError("--min-confidence given but predictions have no `confidence` column")
        floor = CONFIDENCE_RANK[min_confidence]
        ranks = kept["confidence"].str.lower().map(CONFIDENCE_RANK)
        if ranks.isna().any():
            bad = sorted(set(kept.loc[ranks.isna(), "confidence"].dropna()))
            raise ValueError(f"unknown confidence value(s) {bad}; expected one of {sorted(CONFIDENCE_RANK)}")
        kept = kept[ranks >= floor]
    if not include_speculative and "speculative" in kept.columns:
        kept = kept[~as_bool(kept["speculative"])]
    return kept


TRUE_TOKENS = {"true", "1", "yes", "y", "t"}
FALSE_TOKENS = {"false", "0", "no", "n", "f", ""}


def as_bool(column: pd.Series) -> pd.Series:
    """Interpret a loosely-typed boolean column, mirroring `confidence` above.

    `.astype(bool)` is wrong here in three ways, and every one of them silently
    discards real predictions rather than raising:

    * `eval/README.md` documents `speculative` as optional, so a JSONL with the
      value missing on some rows arrives as float64 `[0.0, nan]` — and
      `nan.astype(bool)` is True, so a prediction nobody flagged is dropped and
      scores as a false negative.
    * The CSV form with a blank cell raises `TypeError: boolean value of NA is
      ambiguous`, naming no column.
    * Anything pandas does not parse into a native bool becomes `StringDtype`,
      where *every* non-empty string is truthy — so `speculative` written as
      `no,no`, or as the JSON string `"false"`, drops **every** prediction and
      reports F1 0.0 for a system that detected everything.

    Absent means not speculative, matching `Boolean(f.speculative ?? false)` on
    the TypeScript side. An unrecognized value raises rather than guessing: this
    feeds the release gate, and a metric quietly computed over the wrong subset
    is worse than a failed run.
    """
    if column.dtype == bool:
        return column
    if pd.api.types.is_numeric_dtype(column):
        return column.fillna(0).astype(bool)

    text = column.astype("string").str.strip().str.lower().fillna("")
    unknown = sorted(set(text) - TRUE_TOKENS - FALSE_TOKENS)
    if unknown:
        raise ValueError(
            f"unrecognized `speculative` value(s) {unknown}; "
            f"expected one of {sorted(TRUE_TOKENS | FALSE_TOKENS - {''})} or empty"
        )
    return text.isin(TRUE_TOKENS)


def score(tp: int, fp: int, fn: int) -> Scores:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return Scores(
        support=tp + fn,
        predicted=tp + fp,
        tp=tp,
        fp=fp,
        fn=fn,
        precision=precision,
        recall=recall,
        f1=f1,
    )


def build_confusion(truth: pd.DataFrame, predictions: pd.DataFrame, key: list[str]) -> pd.DataFrame:
    """One row per distinct key, labeled TP / FP / FN.

    Duplicate rows on the same key collapse: a vulnerability class is either
    detected on a target or it is not, so a second report of the same class
    is neither a new hit nor a new miss.
    """
    truth_keys = truth[key].drop_duplicates()
    pred_keys = predictions[key].drop_duplicates()
    merged = truth_keys.assign(_truth=True).merge(
        pred_keys.assign(_pred=True), on=key, how="outer"
    )
    merged[["_truth", "_pred"]] = merged[["_truth", "_pred"]].notna()
    merged["outcome"] = np.select(
        [merged["_truth"] & merged["_pred"], ~merged["_truth"] & merged["_pred"]],
        ["tp", "fp"],
        default="fn",
    )
    return merged.drop(columns=["_truth", "_pred"])


def score_frame(confusion: pd.DataFrame) -> Scores:
    counts = confusion["outcome"].value_counts()
    return score(int(counts.get("tp", 0)), int(counts.get("fp", 0)), int(counts.get("fn", 0)))


def score_by(confusion: pd.DataFrame, column: str) -> pd.DataFrame:
    rows = {
        value: asdict(score_frame(group))
        for value, group in confusion.groupby(column, dropna=False)
    }
    return pd.DataFrame.from_dict(rows, orient="index").sort_values("support", ascending=False)


def attach_truth_metadata(confusion: pd.DataFrame, truth: pd.DataFrame, key: list[str], column: str) -> pd.DataFrame:
    """Carry a ground-truth column (e.g. severity) onto the confusion rows.

    False positives have no ground-truth row, so they land in an `unlabeled`
    bucket rather than silently disappearing from the breakdown.
    """
    if column not in truth.columns:
        raise ValueError(f"ground truth has no `{column}` column to slice by")
    labels = truth[key + [column]].drop_duplicates(subset=key)
    joined = confusion.merge(labels, on=key, how="left")
    joined[column] = joined[column].fillna("unlabeled")
    return joined


def format_report(overall: Scores, slices: dict[str, pd.DataFrame], target: float | None) -> str:
    lines = [
        "ARES detection scoring",
        "",
        f"  matched pairs (TP): {overall.tp}",
        f"  false positives    : {overall.fp}",
        f"  false negatives    : {overall.fn}",
        f"  ground truth size  : {overall.support}",
        "",
        f"  precision : {overall.precision:.4f}",
        f"  recall    : {overall.recall:.4f}",
        f"  f1        : {overall.f1:.4f}",
    ]
    if target is not None:
        verdict = "MET" if overall.f1 >= target else "NOT MET"
        lines += ["", f"  target f1 {target:.4f}: {verdict} (delta {overall.f1 - target:+.4f})"]
    for name, frame in slices.items():
        lines += ["", f"per-{name}:", frame.round(4).to_string()]
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--truth", type=Path, required=True, help="labeled ground truth (CSV/JSON/JSONL)")
    parser.add_argument("--predictions", type=Path, required=True, help="ARES detection output (CSV/JSON/JSONL)")
    parser.add_argument(
        "--key",
        nargs="+",
        default=list(DEFAULT_KEY),
        help="columns a prediction and a label must agree on to count as a match",
    )
    parser.add_argument("--min-confidence", choices=sorted(CONFIDENCE_RANK), help="drop predictions below this confidence")
    parser.add_argument(
        "--drop-status",
        nargs="*",
        default=["false-positive"],
        help="prediction `status` values to discard before scoring",
    )
    parser.add_argument("--include-speculative", action="store_true", help="keep predictions flagged speculative")
    parser.add_argument("--by", nargs="*", default=["category"], help="columns to break the metrics down by")
    parser.add_argument("--target-f1", type=float, help="compare the measured F1 against a claimed target")
    parser.add_argument("--json-out", type=Path, help="write the full result as JSON")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    truth = load_table(args.truth)
    predictions = filter_predictions(
        load_table(args.predictions),
        args.min_confidence,
        tuple(s.lower() for s in args.drop_status),
        args.include_speculative,
    )

    confusion = build_confusion(truth, predictions, args.key)
    overall = score_frame(confusion)

    slices: dict[str, pd.DataFrame] = {}
    for column in args.by:
        frame = confusion if column in confusion.columns else attach_truth_metadata(confusion, truth, args.key, column)
        slices[column] = score_by(frame, column)

    print(format_report(overall, slices, args.target_f1))

    if args.json_out:
        payload = {
            "key": args.key,
            "filters": {
                "min_confidence": args.min_confidence,
                "drop_status": args.drop_status,
                "include_speculative": args.include_speculative,
            },
            "overall": asdict(overall),
            "slices": {name: frame.to_dict(orient="index") for name, frame in slices.items()},
            "misses": confusion[confusion["outcome"] == "fn"][args.key].to_dict(orient="records"),
            "false_positives": confusion[confusion["outcome"] == "fp"][args.key].to_dict(orient="records"),
        }
        args.json_out.write_text(json.dumps(payload, indent=2))

    if args.target_f1 is not None and overall.f1 < args.target_f1:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
