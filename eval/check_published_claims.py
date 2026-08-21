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
could produce its numbers.

`apps/ares-sec/README.md` stays `scoreable=False` here, but not because ares-sec
has no harness -- it has one, and as of SEC-5 a more thorough one than this
script: `npm run verify-claims` (apps/ares-sec/scripts/verify-claims.mjs)
re-derives ares-sec's headline numbers from its own committed bench/ artifacts,
gated in its own CI job (ares-sec-ci.yml), and exact-matches them against the
README's literal printed numbers -- not just the floor-style regression checks
this repo started with. `scoreable=False` means this SPECIFIC script does not
verify those claims, because it cannot: the regex vocabulary below only
recognizes Precision/Recall/F1-style ML metrics, and ares-sec's claims are pass
rates, ratios, and tool/operator counts against a Node/JSON pipeline this
script has no access to. A Precision/Recall/F1-shaped figure appearing on that
README regardless is still correctly rejected below -- see
`test_ares_sec_cannot_publish_a_figure_while_it_has_no_harness` in
test_check_published_claims.py -- because this script cannot tell that figure
apart from one nothing verified, and laundering it against the wrong pipeline's
score.json would be worse than refusing it.

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

Two holes closed after `core/README.md` shipped an `F1-0.94` badge and "97%
micro-averaged recall" — the very figure the root README disowns — past a green
check. First, that file was not in GUARDED_READMES at all. Second, and worse,
adding it would have changed nothing: detection matched only markdown table rows
in one exact shape, so a badge, a sentence, or even `| Micro F1 |` was invisible.
A gate that inspects one syntax is not a gate; it is a naming convention.

There is a third honest state alongside "not measured" and "measured and
re-derivable": **explicitly retracted**. Deleting a real measurement destroys
evidence, so a README may keep the figure if it publishes a `## Measurement
status` section that says what the number is and is not — and that section must
come BEFORE the figure, so a reader meets the caveat first. Adding the heading
without the substance defeats the check rather than satisfying it; CLAUDE.md's
rule applies here as everywhere: fix the claim, don't weaken the gate.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PREDICTIONS = ROOT / "eval" / "predictions" / "ares-latest.csv"
SCORE = ROOT / "eval" / "data" / "score.json"

# (README path relative to ROOT, can THIS script's eval/ pipeline re-derive its
# numbers?) False does not mean the product has no harness -- see the
# docstring above re: ares-sec's own separate, already-passing verify-claims
# gate. It means this script's Precision/Recall/F1 vocabulary and eval/
# artifacts cannot verify that product's claims, so it must not try to.
GUARDED_READMES = (
    ("README.md", True),
    ("apps/auditor-api/README.md", True),
    ("apps/auditor-web/README.md", True),
    ("apps/ares-sec/README.md", False),
    # core/ was missing, and it was the file publishing the loudest figures: an
    # `F1-0.94` shields badge and "97% micro-averaged recall" in its opening
    # paragraph — the same 0.94 the root README explicitly disowns. It is
    # `scoreable=False` because `ares benchmark` is not the Auditor eval: it scores
    # a different pipeline (it calls `ast_scanner`, which `ares scan` does not) on a
    # different corpus, so its output cannot be re-derived by `verify-claims`.
    ("core/README.md", False),
)

# A metric claim is anything a reader would take as this system's accuracy. All
# three forms below were live in this repo at some point, and only the first was
# ever detected, so a figure could be published simply by not putting it in a
# table:
#
#   1. table row  — `| Micro F1 | **0.94** |`
#   2. badge      — `img.shields.io/badge/F1-0.94-brightgreen.svg`
#   3. prose      — "achieving 97% micro-averaged recall and 0.94 F1"
#
# The optional qualifier in ROW is what let `| Micro Precision |` through: the
# original anchored on the metric word alone, so any adjective defeated it.
QUALIFIER = r"(?:[A-Za-z][A-Za-z-]*\s+){0,3}"
METRIC = r"(Precision|Recall|F1)"
ROW = re.compile(
    rf"^\|\s*{QUALIFIER}{METRIC}\s*\|\s*([^|]+?)\s*\|", re.IGNORECASE | re.MULTILINE
)
BADGE = re.compile(rf"badge/{METRIC}-(\d*\.?\d+)", re.IGNORECASE)
PROSE_VALUE_FIRST = re.compile(rf"(\d*\.?\d+)\s*%?\s+{QUALIFIER}{METRIC}\b", re.IGNORECASE)
PROSE_METRIC_FIRST = re.compile(rf"{METRIC}\s+of\s+(\d*\.?\d+)", re.IGNORECASE)

# A figure under an accuracy-status section is not a claim. This is the third
# honest state, alongside "not measured" and "measured and re-derivable": a number
# kept on the page as a record of a past build, or quoted precisely in order to
# disown it, with the status stated ABOVE it so a reader meets the caveat before
# the figure. Position is the whole point — a disclaimer under the tables is not a
# disclaimer.
#
# Without this, the gate cannot tell an assertion from a retraction, and it
# punishes exactly the honest behaviour it exists to encourage: the root README's
# sentence "no ... F1 figure for this system is published — including the 0.94 F1
# that has been quoted internally" reads to a regex as a 0.94 F1 claim. Failing
# that file would teach the next author to delete the disownment rather than write
# one. Both spellings below are section names this repo actually uses.
RETRACTION = re.compile(
    r"^#{2,}\s*(?:Measurement status|Detection accuracy)\b", re.IGNORECASE | re.MULTILINE
)

NUMBER = re.compile(r"^\d*\.?\d+$")
TOLERANCE = 0.005


def _claims_with_positions(text: str) -> list[tuple[str, float, int]]:
    """Every (metric, value, offset) a reader could take as an accuracy claim."""
    found: list[tuple[str, float, int]] = []

    for match in ROW.finditer(text):
        metric, value = match.group(1), match.group(2)
        cleaned = value.strip().strip("*`")
        if NUMBER.match(cleaned):
            found.append((metric.lower(), float(cleaned), match.start()))

    for pattern, metric_first in (
        (BADGE, True),
        (PROSE_METRIC_FIRST, True),
        (PROSE_VALUE_FIRST, False),
    ):
        for match in pattern.finditer(text):
            metric = match.group(1) if metric_first else match.group(2)
            value = match.group(2) if metric_first else match.group(1)
            # A percentage is the same claim written differently: 97% recall and
            # 0.97 recall must not be treated as two different assertions.
            number = float(value)
            if number > 1:
                number /= 100
            found.append((metric.lower(), number, match.start()))

    return found


def is_retracted(text: str) -> bool:
    """True when every figure is published under a retraction that precedes it."""
    marker = RETRACTION.search(text)
    if not marker:
        return False
    claims = _claims_with_positions(text)
    return all(offset > marker.start() for _, _, offset in claims)


def published_metrics(text: str) -> dict[str, float]:
    """Numeric metric claims in a README, keyed lowercase.

    Empty when the figures are explicitly retracted — such a README asserts
    nothing, so there is nothing for the gate to demand a run for.
    """
    if is_retracted(text):
        return {}
    return {metric: value for metric, value, _ in _claims_with_positions(text)}


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