#!/usr/bin/env python3
"""Fail if a README publishes an accuracy number that nothing can re-derive.

GOLDEN RULE 3: any metric that appears in a README, report, slide or sale must
be reproducible via `eval/`. The CI step guarding this only fired on
`release: published` — a webhook that arrives *after* GitHub has created the tag
and the release page, so it was a post-mortem: a red check appeared in the
Actions tab and the release stayed up. There is no pre-publication release
event, so a true pre-publish gate on that trigger is impossible.

This guards the claim instead of the release, which can run on every push. The
harm is not "a release happened"; it is "a number is published that nobody
measured", and that becomes true the moment a README is edited and merged.

`4R3S` ships two products (CLAUDE.md #1), so one root README was never the whole
surface: a figure in `apps/ares-sec/README.md` shipped unguarded. Every README a
product publishes from is checked here, and each is paired with the run that
could produce its numbers. ares-sec has no eval harness yet — SEC-1 lands its
source, P3 — so a figure there is unverifiable by construction rather than by
disagreement, and says so.

Checks, per guarded README, in order of what they catch:
1. The product has no harness that could measure the claim -> fail.
2. README states a numeric metric while `eval/predictions/ares-latest.csv` does
   not exist -> fail. Nothing could have produced that number.
3. README states a numeric metric and a score run exists -> the two must agree.
   A stale figure left behind after the numbers moved is the same defect as an
   invented one.

"not measured" is the honest state and always passes. So does a README that does
not exist: ares-sec is a skeleton, and a gate that failed on absent files would
block the repo rather than the claim.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PREDICTIONS = ROOT / "eval" / "predictions" / "ares-latest.csv"
SCORE = ROOT / "eval" / "data" / "score.json"

# (README path relative to ROOT, can the Auditor eval re-derive its numbers?)
# False means the product has no harness at all, not that it failed one.
GUARDED_READMES = (
    ("README.md", True),
    ("apps/auditor-api/README.md", True),
    ("apps/auditor-web/README.md", True),
    ("apps/ares-sec/README.md", False),
)

# `| Precision | 0.94 | verified |` — metric, value, status.
ROW = re.compile(
    r"^\|\s*(Precision|Recall|F1)\s*\|\s*([^|]+?)\s*\|", re.IGNORECASE | re.MULTILINE
)
NUMBER = re.compile(r"^\d*\.?\d+$")
TOLERANCE = 0.005


def published_metrics(text: str) -> dict[str, float]:
    """Numeric metric claims in a README, keyed lowercase."""
    found: dict[str, float] = {}
    for metric, value in ROW.findall(text):
        cleaned = value.strip().strip("*`")
        if NUMBER.match(cleaned):
            found[metric.lower()] = float(cleaned)
    return found


def unverifiable(relative_path: str, scoreable: bool) -> str | None:
    """The reason this README's figures cannot be re-derived, or None."""
    readme = ROOT / relative_path
    if not readme.exists():
        return None
    claims = published_metrics(readme.read_text())
    if not claims:
        return None

    if not scoreable:
        return (
            f"{relative_path} publishes {claims}, but that product has no eval "
            "harness — nothing can re-derive those numbers."
        )
    if not PREDICTIONS.exists():
        return (
            f"{relative_path} publishes {claims} but "
            f"{PREDICTIONS.relative_to(ROOT)} does not exist, so no run produced "
            "those numbers."
        )
    if not SCORE.exists():
        return (
            f"{relative_path} publishes {claims} but no score.json was produced "
            "this run; cannot verify the figures."
        )

    overall = json.loads(SCORE.read_text())["overall"]
    mismatched = [
        f"{metric}={claimed} but the scored run measured {overall[metric]:.4f}"
        for metric, claimed in claims.items()
        if abs(overall[metric] - claimed) > TOLERANCE
    ]
    if mismatched:
        return f"{relative_path} claims " + "; ".join(mismatched)
    return None


def main() -> int:
    failures = []
    for relative_path, scoreable in GUARDED_READMES:
        reason = unverifiable(relative_path, scoreable)
        if reason:
            failures.append(reason)

    if failures:
        for reason in failures:
            print(reason, file=sys.stderr)
        print(
            "\nEither commit the run these figures came from, or state "
            "'not measured' until it exists.",
            file=sys.stderr,
        )
        return 1

    print(f"No unverifiable metric across {len(GUARDED_READMES)} guarded README(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
