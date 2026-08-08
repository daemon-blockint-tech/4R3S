#!/usr/bin/env python3
"""Prove the Verify-Claims release gate rejects and accepts for the right reasons.

This checks the gate MECHANISM, on synthetic predictions derived from a real
ground truth file. That is a different question from how ARES scores, and it
stays worth asking now that eval/predictions/ares-latest.csv exists: a threshold
comparison that quietly stopped rejecting would wave any real score through, and
looking at the real score cannot reveal it. So the target passed here describes
the synthetic cases below — never the system.

  perfect       every label reproduced           -> F1 1.00 -> exit 0
  degraded      a fraction of labels dropped     -> F1 < target -> exit 1
  empty         nothing reported                 -> F1 0.00 -> exit 1

The numbers here describe the synthetic inputs, not ARES. Nothing this script
prints may be published as a system score.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

import score_detections


def perfect(truth: pd.DataFrame) -> pd.DataFrame:
    return truth[["target_id", "category"]].copy()


def degraded(truth: pd.DataFrame, keep: float, seed: int = 0) -> pd.DataFrame:
    return perfect(truth).sample(frac=keep, random_state=seed)


def run_gate(truth_path: Path, predictions: pd.DataFrame, target_f1: float, tmp_dir: Path, name: str) -> int:
    path = tmp_dir / f"predictions-{name}.csv"
    predictions.to_csv(path, index=False)
    return score_detections.main(
        ["--truth", str(truth_path), "--predictions", str(path), "--target-f1", str(target_f1)]
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--truth", type=Path, required=True, help="ground truth CSV from fetch_datasets.py")
    parser.add_argument("--target-f1", type=float, default=0.94, help="F1 the gate demands")
    parser.add_argument("--keep", type=float, default=0.5, help="label fraction the degraded case reports")
    parser.add_argument("--tmp-dir", type=Path, default=Path("eval/data/selftest"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    truth = pd.read_csv(args.truth)
    if truth.empty:
        print("ground truth is empty; nothing to self-test", file=sys.stderr)
        return 1
    args.tmp_dir.mkdir(parents=True, exist_ok=True)

    cases = [
        ("perfect", perfect(truth), 0),
        ("degraded", degraded(truth, args.keep), 1),
        ("empty", perfect(truth).iloc[0:0], 1),
    ]

    failures = []
    for name, predictions, expected in cases:
        print(f"\n=== gate case: {name} (expect exit {expected}) ===")
        actual = run_gate(args.truth, predictions, args.target_f1, args.tmp_dir, name)
        if actual != expected:
            failures.append(f"{name}: expected exit {expected}, got {actual}")

    print()
    if failures:
        for failure in failures:
            print(f"GATE SELF-TEST FAILED — {failure}", file=sys.stderr)
        return 1
    print(f"gate self-test passed: {len(cases)} cases behaved as specified at --target-f1 {args.target_f1}")
    print("These are synthetic predictions — nothing here is an ARES score.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
