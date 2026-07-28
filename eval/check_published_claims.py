#!/usr/bin/env python3
"""Fail if README.md publishes an accuracy number that nothing can re-derive.

GOLDEN RULE 3: any metric that appears in a README, report, slide or sale must
be reproducible via `eval/`. The CI step guarding this only fired on
`release: published` — a webhook that arrives *after* GitHub has created the tag
and the release page, so it was a post-mortem: a red check appeared in the
Actions tab and the release stayed up. There is no pre-publication release
event, so a true pre-publish gate on that trigger is impossible.

This guards the claim instead of the release, which can run on every push. The
harm is not "a release happened"; it is "a number is published that nobody
measured", and that becomes true the moment the README is edited and merged.

Checks, in order of what they catch:

1. README states a numeric metric while `eval/predictions/ares-latest.csv` does
   not exist -> fail. Nothing could have produced that number.
2. README states a numeric metric and a score run exists -> the two must agree.
   A stale figure left behind after the numbers moved is the same defect as an
   invented one.

"not measured" is the honest state and always passes.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
PREDICTIONS = ROOT / "eval" / "predictions" / "ares-latest.csv"
SCORE = ROOT / "eval" / "data" / "score.json"

# `| Precision | 0.94 | verified |` — metric, value, status.
ROW = re.compile(
    r"^\|\s*(Precision|Recall|F1)\s*\|\s*([^|]+?)\s*\|", re.IGNORECASE | re.MULTILINE
)
NUMBER = re.compile(r"^\d*\.?\d+$")
TOLERANCE = 0.005


def published_metrics(text: str) -> dict[str, float]:
    """Numeric metric claims in the README, keyed lowercase."""
    found: dict[str, float] = {}
    for metric, value in ROW.findall(text):
        cleaned = value.strip().strip("*`")
        if NUMBER.match(cleaned):
            found[metric.lower()] = float(cleaned)
    return found


def main() -> int:
    if not README.exists():
        print("no README.md; nothing to check")
        return 0

    claims = published_metrics(README.read_text())
    if not claims:
        print("README publishes no numeric accuracy metric — nothing to verify.")
        return 0

    if not PREDICTIONS.exists():
        print(
            f"README publishes {claims} but {PREDICTIONS.relative_to(ROOT)} does not "
            "exist, so no run produced those numbers.\n"
            "Either commit the predictions the figures came from, or state "
            "'not measured' until they are.",
            file=sys.stderr,
        )
        return 1

    if not SCORE.exists():
        print(
            f"README publishes {claims} but no score.json was produced this run; "
            "cannot verify the figures.",
            file=sys.stderr,
        )
        return 1

    overall = json.loads(SCORE.read_text())["overall"]
    mismatched = {
        metric: (claimed, overall[metric])
        for metric, claimed in claims.items()
        if abs(overall[metric] - claimed) > TOLERANCE
    }
    if mismatched:
        for metric, (claimed, actual) in mismatched.items():
            print(
                f"README claims {metric}={claimed} but the scored run measured "
                f"{actual:.4f}",
                file=sys.stderr,
            )
        return 1

    print(f"README metrics {claims} match the scored run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
