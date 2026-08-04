#!/usr/bin/env python3
"""Convert `ares-cli scan` output into eval/predictions/ares-latest.csv.

STATUS: smoke-tested only, against hand-written synthetic report fixtures
that match the real AuditReport/Finding struct shape -- never run against
real ares-cli output. This proves the conversion logic is wired correctly,
not that the category mapping holds up against real findings.

Reads one `ares-report-<safe_name>.json` per staged target (written by
`ares-cli scan <staging_root>/<safe_name> -o <reports-dir>` -- the filename is
exactly `ares-report-{report.target.name}.json`, and `target.name` is the
staging directory's own name, per core/crates/ares-cli/src/commands/scan.rs:
`program_path.file_name()`), maps each `Finding` into the 6-column schema
`eval/score_detections.py` expects, and writes `eval/predictions/ares-latest.csv`.

Column decisions, verified directly against source before being hardcoded here
(see eval/mappings/ares-core-categories.json's notes for the category side):

  category    -- looked up in the category-mapping file. An unmapped Rust
                 category becomes the literal string "other", never dropped --
                 an unmapped category genuinely has no ground-truth
                 correspondence to be credited against, and hiding it would
                 flatter precision by making the vocabulary gap invisible.
  confidence  -- Finding.confidence is a float pre-filtered by the Triager to
                 [0.70, 1.0] before the report is even written (scan.rs's
                 Triager, confidence_threshold = 0.70) -- bucketed into
                 low/medium/high INSIDE that narrowed range, not [0.0, 1.0]:
                 < 0.80 -> low, [0.80, 0.90) -> medium, >= 0.90 -> high.
  status      -- always "suspected". Finding.validation stays None after a
                 plain `scan` (only `ares confirm` sets it, out of scope for
                 this pass) -- "suspected" is the only truthful value that
                 also survives score_detections.py's default drop-filter
                 (which drops status == "false-positive").
  speculative -- always False, written explicitly for legibility in a
                 committed CSV.
  severity    -- Finding.severity has NO serde rename_all (verified directly
                 in core/crates/ares-core/src/lib.rs -- the enum derives
                 Serialize/Deserialize with no #[serde(rename_all = ...)]), so
                 the JSON value is the exact Rust variant name:
                 "Critical"/"High"/"Medium"/"Low"/"Informational". The Python
                 severity vocabulary (src/knowledge/finding.ts) is
                 "critical"/"high"/"medium"/"low"/"info" -- NOTE "Informational"
                 maps to "info", not a naive .lower() (which would wrongly
                 produce "informational").
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

SEVERITY_MAP = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Informational": "info",
}

CSV_COLUMNS = ["target_id", "category", "confidence", "status", "speculative", "severity"]


def bucket_confidence(value: float) -> str:
    if value >= 0.90:
        return "high"
    if value >= 0.80:
        return "medium"
    return "low"


def map_category(rust_category: str, category_mapping: dict) -> str:
    entry = category_mapping["categories"].get(rust_category)
    if entry is None or entry.get("vuln_catalog_id") is None:
        return "other"
    return entry["vuln_catalog_id"]


def map_severity(rust_severity: str) -> str:
    try:
        return SEVERITY_MAP[rust_severity]
    except KeyError:
        raise ValueError(
            f"unrecognized Rust severity {rust_severity!r}; expected one of {sorted(SEVERITY_MAP)}"
        ) from None


def convert_report(report: dict, target_id: str, category_mapping: dict) -> list[dict]:
    """Convert one ares-report-*.json's findings into predictions rows."""
    rows = []
    for finding in report.get("findings", []):
        rows.append(
            {
                "target_id": target_id,
                "category": map_category(finding["category"], category_mapping),
                "confidence": bucket_confidence(finding["confidence"]),
                "status": "suspected",
                "speculative": False,
                "severity": map_severity(finding["severity"]),
            }
        )
    return rows


def convert_all(
    reports_dir: Path, staging_manifest: dict[str, str], category_mapping: dict
) -> tuple[pd.DataFrame, int, int]:
    """Returns (predictions_df, total_findings, other_category_count)."""
    all_rows: list[dict] = []
    for safe_name, target_id in sorted(staging_manifest.items()):
        report_path = reports_dir / f"ares-report-{safe_name}.json"
        if not report_path.exists():
            # No report for this target means zero findings for it -- not an
            # error. A target ares-cli found nothing for should contribute no
            # prediction rows, same semantics as an empty findings list.
            continue
        report = json.loads(report_path.read_text())
        all_rows.extend(convert_report(report, target_id, category_mapping))

    predictions = pd.DataFrame(all_rows, columns=CSV_COLUMNS)
    total = len(predictions)
    other_count = int((predictions["category"] == "other").sum()) if total else 0
    return predictions, total, other_count


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reports-dir", type=Path, required=True)
    parser.add_argument("--staging-manifest", type=Path, required=True)
    parser.add_argument(
        "--category-mapping", type=Path, default=Path("eval/mappings/ares-core-categories.json")
    )
    parser.add_argument("--out", type=Path, default=Path("eval/predictions/ares-latest.csv"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    staging_manifest = json.loads(args.staging_manifest.read_text())
    category_mapping = json.loads(args.category_mapping.read_text())

    predictions, total, other_count = convert_all(args.reports_dir, staging_manifest, category_mapping)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    predictions.to_csv(args.out, index=False)

    print(f"wrote {len(predictions)} prediction row(s) to {args.out}")
    if total:
        print(
            f"vocabulary coverage: {other_count}/{total} finding(s) "
            f"({other_count / total:.0%}) mapped to category 'other' "
            "(no VULN_CATALOG equivalent) -- see eval/mappings/ares-core-categories.json"
        )
    else:
        print("no findings across any staged target")
    return 0


if __name__ == "__main__":
    sys.exit(main())
