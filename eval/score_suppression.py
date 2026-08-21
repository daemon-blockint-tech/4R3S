#!/usr/bin/env python3
"""Measure what the deterministic suppressors actually remove, per vulnerability class.

ENG-5. Every `ares scan` writes an `AuditReport` whose `suppressed_findings[]`
records each finding a suppressor removed, why, and which suppressor did it
(`suppressed_by`). Nothing in `eval/` has ever read that array --
`convert_ares_core_reports.py` reads `findings[]` only -- so the local judge's
effect on precision has never been measured. That is the gap this script closes,
and it is why ENG-5 cannot start by writing new judge rules: there is no baseline
to improve against.

Four suppressors write into the same array, in this order
(core/crates/ares-cli/src/commands/scan.rs) -- confirmed by reading scan.rs
directly; the struct's own doc comment on `suppressed_by` only names the middle
two ("local_judge" or "llm_judge") and is stale:

    SemanticValidator  ->  LocalJudge  ->  LlmJudge  ->  Triager

Triager is the confidence-threshold filter (scan.rs "[5/5] Triager", cutoff
0.70) -- a plain sort, but it removes findings the same as the other three and
is measured the same way here.

They are reported separately here, never as one total. The ordering matters when
reading the output: anything an earlier suppressor removed never reached a later
one, so each suppressor's ceiling is bounded by what survives to it.

WHAT "GOOD" AND "BAD" MEAN HERE

`score_detections.build_confusion` collapses duplicate rows on the match key --
a class is either detected on a target or it is not, so a second report of the
same class on the same target changes no metric. Suppression must be scored the
same way, which makes three outcomes rather than two:

  lost_tp     the key is in ground truth and NOTHING retained still covers it
              -> the suppressor destroyed a real detection. Recall damage.
  avoided_fp  the key is absent from ground truth and nothing retained covers it
              -> the suppressor removed a genuine false positive. Precision gain.
  no_effect   something retained still covers the key
              -> the suppressor removed a duplicate. Scores did not move at all.

Counting a suppression as a "win" without the `no_effect` case would credit the
judge for removals that changed nothing, which is precisely the kind of
unreproducible number GOLDEN RULE 3 exists to stop.

REPRODUCING THE INPUT

The reports this reads come from a full corpus run. `--fuzz false` is mandatory,
not a preference: fuzzing defaults ON and Trident's init aborts on a staged dir
("Anchor.toml was not found in any parent directory"), so without it every scan
fails and this script would be handed an empty directory. It refuses to score
one rather than reporting zeros -- see `collect_rows`.

    python eval/fetch_datasets.py --out-dir eval/data
    python eval/fetch_sealevel_attacks.py --out-dir eval/data
    python eval/fetch_neodyme_workshop.py --out-dir eval/data
    python eval/build_incident_repros.py --out-dir eval/data
    python eval/stage_ares_core_targets.py \
      --ground-truth eval/data/ground_truth.csv \
      --corpus eval/data/corpus --staging-root eval/data/staging
    (cd core && cargo build --release -p ares-v3)
    for d in eval/data/staging/*/; do
      core/target/release/ares scan "$d" --fuzz false -o eval/data/reports
    done
    python eval/score_suppression.py \
      --reports-dir eval/data/reports \
      --staging-manifest eval/data/staging/staging_manifest.json \
      --truth eval/data/ground_truth.csv

Run the scan loop a second time with `--ast-scan` into a separate reports dir to
measure the ENG-3/ENG-4 taint path, which is opt-in and therefore contributes
nothing to the committed numbers today (scan.rs:213). Do not flip that default
here; producing the evidence is this script's job, changing the default is not.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict
from pathlib import Path

import pandas as pd

from convert_ares_core_reports import (
    CSV_COLUMNS,
    bucket_confidence,
    convert_report,
    map_category,
    map_severity,
)
from score_detections import DEFAULT_KEY, build_confusion, load_table, score_frame

KEY = list(DEFAULT_KEY)  # ("target_id", "category")
SUPPRESSION_COLUMNS = CSV_COLUMNS + ["suppressed_by", "reason"]

# Effect of a single suppressed key on the scored set. See the module docstring.
LOST_TP = "lost_tp"
AVOIDED_FP = "avoided_fp"
NO_EFFECT = "no_effect"


def suppressed_rows(report: dict, target_id: str, category_mapping: dict) -> list[dict]:
    """Convert one report's `suppressed_findings[]` into prediction-shaped rows.

    Same six columns `convert_ares_core_reports.convert_report` produces, plus
    `suppressed_by` and `reason`, so a suppressed set can be handed straight to
    `score_detections.py` if someone wants to score it on its own.

    `status` stays "suspected" rather than "false-positive" even though a
    suppressor just called it one. `score_detections.py` drops
    status == "false-positive" by default, so writing the suppressor's verdict
    into that column would make these rows invisible to the very scorer that is
    supposed to check whether the verdict was correct. The verdict lives in
    `suppressed_by` / `reason`, where it cannot silently filter anything.
    """
    rows = []
    for entry in report.get("suppressed_findings", []):
        finding = entry["finding"]
        rows.append(
            {
                "target_id": target_id,
                "category": map_category(finding["category"], category_mapping),
                "confidence": bucket_confidence(finding["confidence"]),
                "status": "suspected",
                "speculative": False,
                "severity": map_severity(finding["severity"]),
                "suppressed_by": entry.get("suppressed_by", "unknown"),
                "reason": entry.get("reason", ""),
            }
        )
    return rows


def collect_rows(
    reports_dir: Path, manifest: dict[str, str], category_mapping: dict
) -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    """Read every staged target's report. Returns (retained, suppressed, missing).

    A single missing report means that target produced nothing -- the same
    reading `convert_ares_core_reports.py` takes, and correct for one target.
    *Every* report missing means the scan loop never ran or aborted (the
    `--fuzz false` trap in the module docstring), and reporting all-zeros for
    that is worse than failing: it looks exactly like a judge that suppresses
    nothing, which is one of the real outcomes this script exists to detect.
    """
    retained: list[dict] = []
    suppressed: list[dict] = []
    missing: list[str] = []

    for safe_name, target_id in sorted(manifest.items()):
        report_path = reports_dir / f"ares-report-{safe_name}.json"
        if not report_path.exists():
            missing.append(safe_name)
            continue
        report = json.loads(report_path.read_text())
        retained.extend(convert_report(report, target_id, category_mapping))
        suppressed.extend(suppressed_rows(report, target_id, category_mapping))

    if manifest and len(missing) == len(manifest):
        raise ValueError(
            f"no report found for any of the {len(manifest)} staged target(s) in "
            f"{reports_dir}. The scan loop did not run, or every scan aborted -- "
            "the usual cause is a missing `--fuzz false`, which makes Trident's "
            "init fail on a staged dir. Refusing to report zeros for a run that "
            "did not happen."
        )

    return (
        pd.DataFrame(retained, columns=CSV_COLUMNS),
        pd.DataFrame(suppressed, columns=SUPPRESSION_COLUMNS),
        missing,
    )


def classify_effects(
    retained: pd.DataFrame, suppressed: pd.DataFrame, truth: pd.DataFrame
) -> pd.DataFrame:
    """Label every (suppressor, target, category) with its effect on the scored set.

    Returns one row per distinct suppressed key, carrying how many findings
    collapsed into it and which of the three outcomes it produced.
    """
    if suppressed.empty:
        return pd.DataFrame(
            columns=["suppressed_by", *KEY, "suppressed", "effect"]
        )

    retained_keys = set(map(tuple, retained[KEY].drop_duplicates().to_numpy()))
    truth_keys = set(map(tuple, truth[KEY].drop_duplicates().to_numpy()))

    counts = (
        suppressed.groupby(["suppressed_by", *KEY], dropna=False)
        .size()
        .reset_index(name="suppressed")
    )

    def effect(row) -> str:
        key = (row["target_id"], row["category"])
        if key in retained_keys:
            return NO_EFFECT
        return LOST_TP if key in truth_keys else AVOIDED_FP

    counts["effect"] = counts.apply(effect, axis=1)
    return counts


def effects_by(effects: pd.DataFrame, column: str) -> pd.DataFrame:
    """Aggregate labelled keys into a per-`column` table, one row per value."""
    if effects.empty:
        return pd.DataFrame(
            columns=["suppressed", "keys", AVOIDED_FP, LOST_TP, NO_EFFECT]
        )

    grouped = effects.groupby(column, dropna=False)
    table = pd.DataFrame(
        {
            "suppressed": grouped["suppressed"].sum(),
            "keys": grouped.size(),
            AVOIDED_FP: grouped["effect"].apply(lambda s: int((s == AVOIDED_FP).sum())),
            LOST_TP: grouped["effect"].apply(lambda s: int((s == LOST_TP).sum())),
            NO_EFFECT: grouped["effect"].apply(lambda s: int((s == NO_EFFECT).sum())),
        }
    )
    return table.sort_values("suppressed", ascending=False)


def analyse(truth: pd.DataFrame, retained: pd.DataFrame, suppressed: pd.DataFrame) -> dict:
    """Full result: actual scores, per-suppressor counterfactuals, per-class effects.

    The counterfactual for a suppressor is "score the world where it had never
    run" -- its removals put back into the prediction set. It reuses
    `score_detections`' own confusion builder rather than recomputing precision
    here, so this script and the release gate can never disagree about what a
    true positive is.
    """
    actual = score_frame(build_confusion(truth, retained, KEY))
    effects = classify_effects(retained, suppressed, truth)

    names = sorted(suppressed["suppressed_by"].unique()) if not suppressed.empty else []
    per_suppressor: dict[str, dict] = {}
    for name in names:
        restored = suppressed[suppressed["suppressed_by"] == name]
        combined = pd.concat([retained[KEY], restored[KEY]], ignore_index=True)
        disabled = score_frame(build_confusion(truth, combined, KEY))
        per_suppressor[name] = {
            "disabled": asdict(disabled),
            "delta": {
                "precision": actual.precision - disabled.precision,
                "recall": actual.recall - disabled.recall,
                "f1": actual.f1 - disabled.f1,
            },
            "by_category": effects_by(
                effects[effects["suppressed_by"] == name], "category"
            ).to_dict(orient="index"),
        }

    return {
        "actual": asdict(actual),
        "suppressed_total": int(len(suppressed)),
        "by_suppressor": effects_by(effects, "suppressed_by").to_dict(orient="index"),
        "per_suppressor": per_suppressor,
        "unmapped_categories": int((suppressed["category"] == "other").sum())
        if not suppressed.empty
        else 0,
    }


def format_report(result: dict, missing: list[str], truth_meta: dict) -> str:
    lines = [
        "ARES suppression scoring (ENG-5)",
        "",
        f"  ground truth      : {truth_meta['rows']} row(s), sha256 {truth_meta['sha256'][:12]}",
        f"  retained findings : scored at precision {result['actual']['precision']:.4f} "
        f"/ recall {result['actual']['recall']:.4f} / f1 {result['actual']['f1']:.4f}",
        f"  suppressed        : {result['suppressed_total']} finding(s)",
    ]
    if missing:
        lines.append(f"  targets with no report: {len(missing)}")
    if result["unmapped_categories"]:
        lines.append(
            f"  vocabulary gap    : {result['unmapped_categories']} suppressed finding(s) "
            "mapped to category 'other' (no VULN_CATALOG equivalent)"
        )

    if result["suppressed_total"] == 0:
        lines += [
            "",
            "No suppressor removed anything on this corpus. That is a result, not an",
            "error: it means the deterministic judge is inert here and cannot be tuned",
            "into relevance by adding rules of the same shape.",
        ]
        return "\n".join(lines)

    lines += ["", "per-suppressor:", pd.DataFrame.from_dict(result["by_suppressor"], orient="index").to_string()]

    for name, payload in result["per_suppressor"].items():
        delta = payload["delta"]
        lines += [
            "",
            f"{name} - effect on the scored set:",
            f"  precision {delta['precision']:+.4f}   "
            f"recall {delta['recall']:+.4f}   f1 {delta['f1']:+.4f}",
            f"  (disabling it would score precision {payload['disabled']['precision']:.4f} "
            f"/ recall {payload['disabled']['recall']:.4f} / f1 {payload['disabled']['f1']:.4f})",
        ]
        by_category = payload["by_category"]
        if by_category:
            frame = pd.DataFrame.from_dict(by_category, orient="index")
            lines += ["", f"  per-category ({name}):", frame.to_string()]

    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--reports-dir", type=Path, required=True)
    parser.add_argument("--staging-manifest", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument(
        "--category-mapping", type=Path, default=Path("eval/mappings/ares-core-categories.json")
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="optional CSV of the suppressed findings, in the predictions schema",
    )
    parser.add_argument("--json-out", type=Path, help="write the full result as JSON")
    return parser.parse_args(argv)


def truth_metadata(path: Path, truth: pd.DataFrame) -> dict:
    """Stamp what the truth set was.

    `eval/data/` is gitignored and the fetchers pull live upstream data -- the
    set has already moved 152 -> 170 rows between two runs of the same CI job.
    Without this stamp a future comparison cannot tell "the detector changed"
    from "the corpus changed".
    """
    return {
        "path": str(path),
        "rows": int(len(truth)),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    manifest = json.loads(args.staging_manifest.read_text())
    category_mapping = json.loads(args.category_mapping.read_text())
    truth = load_table(args.truth)

    try:
        retained, suppressed, missing = collect_rows(args.reports_dir, manifest, category_mapping)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    result = analyse(truth, retained, suppressed)
    meta = truth_metadata(args.truth, truth)
    print(format_report(result, missing, meta))

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        suppressed.to_csv(args.out, index=False)
        print(f"\nwrote {len(suppressed)} suppressed row(s) to {args.out}")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(
                {
                    "truth": meta,
                    "reports_dir": str(args.reports_dir),
                    "targets_without_report": missing,
                    **result,
                },
                indent=2,
                sort_keys=True,
            )
        )
        print(f"wrote {args.json_out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
