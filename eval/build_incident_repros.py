#!/usr/bin/env python3
"""Build the incident-repros ground truth from committed, hand-authored fixtures.

Unlike `fetch_sealevel_attacks.py` / `fetch_neodyme_workshop.py`, there is no
upstream repo here to fetch from -- replaying the real Wormhole/Cashio/Mango
hacks against actual historical bridge/oracle/protocol state is infeasible.
These three targets are STYLIZED, DIDACTIC reproductions authored for this
repo (see `eval/mappings/incident-repros.json`'s `notes` for the full
disclaimer and the acknowledged-stretch category mapping for Wormhole).

Emits the same layout as the other two EVAL-3 fetchers, so `score_detections.py`
consumes it unchanged:

  <out-dir>/ground_truth.csv                schema documented in eval/README.md
  <out-dir>/corpus/<id>.rs                  the committed illustrative snippet
  <out-dir>/idl/<id>.json                   the paired invented IDL fixture
  <out-dir>/manifest.incident-repros.json   counts, for provenance

No network access, no `--repo` flag -- the absence itself documents that this
source is authored, not fetched. Named `build_*`, not `fetch_*`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

import pandas as pd

DATASET_SLUG = "incident-repros"
FIXTURE_RS_DIR = Path(__file__).parent / "fixtures" / "rs" / "incident-repros"
FIXTURE_IDL_DIR = Path(__file__).parent / "fixtures" / "idl" / "incident-repros"


def to_camel(snake: str) -> str:
    """Snake_case identifier -> camelCase (matches how the IDL names instructions)."""
    head, *rest = snake.split("_")
    return head + "".join(word[:1].upper() + word[1:] for word in rest)


def target_id_for(key: str) -> str:
    return f"{DATASET_SLUG}:{key}"


def content_digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def read_source(entry: dict) -> str:
    return (FIXTURE_RS_DIR / entry["rs"]).read_text()


def load_idl(entry: dict) -> dict:
    return json.loads((FIXTURE_IDL_DIR / entry["idl"]).read_text())


def validate_idl(idl: dict, entry: dict) -> None:
    """Fail loudly if a fixture IDL drifts from what the mapping asserts."""
    if idl.get("name") != entry["program_name"]:
        raise ValueError(
            f"IDL name {idl.get('name')!r} != mapping program_name {entry['program_name']!r}"
        )
    want = to_camel(entry["instruction"])
    have = {ins.get("name") for ins in idl.get("instructions", [])}
    if want not in have:
        raise ValueError(f"IDL for {entry['program_name']} lacks instruction {want!r}; has {sorted(have)}")


def build_ground_truth(mapping: dict, digests: dict[str, str]) -> pd.DataFrame:
    rows = []
    for key, entry in mapping["programs"].items():
        rows.append(
            {
                "target_id": target_id_for(key),
                "category": entry["category"],
                "severity": entry["severity"],
                "location": entry["location"],
                "source_ref": f"incident:{entry['incident_label']} sha256:{digests[key]}",
            }
        )
    truth = pd.DataFrame(rows, columns=["target_id", "category", "severity", "location", "source_ref"])
    return truth.drop_duplicates(subset=["target_id", "category"]).sort_values(["target_id", "category"])


def write_corpus(sources: dict[str, str], out_dir: Path) -> int:
    corpus = out_dir / "corpus"
    corpus.mkdir(parents=True, exist_ok=True)
    for key, code in sources.items():
        name = target_id_for(key).replace(":", "_")
        (corpus / f"{name}.rs").write_text(code)
    return len(sources)


def write_idls(mapping: dict, out_dir: Path) -> int:
    idl_out = out_dir / "idl"
    idl_out.mkdir(parents=True, exist_ok=True)
    for key, entry in mapping["programs"].items():
        name = target_id_for(key).replace(":", "_")
        shutil.copyfile(FIXTURE_IDL_DIR / entry["idl"], idl_out / f"{name}.json")
    return len(mapping["programs"])


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--mapping",
        type=Path,
        default=Path(__file__).parent / "mappings" / "incident-repros.json",
        help="incident-key to VULN_CATALOG mapping",
    )
    parser.add_argument("--out-dir", type=Path, default=Path("eval/data"), help="where to write outputs")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    mapping = json.loads(args.mapping.read_text())
    args.out_dir.mkdir(parents=True, exist_ok=True)

    sources: dict[str, str] = {}
    digests: dict[str, str] = {}
    for key, entry in mapping["programs"].items():
        validate_idl(load_idl(entry), entry)
        code = read_source(entry)
        sources[key] = code
        digests[key] = content_digest(code)

    truth = build_ground_truth(mapping, digests)
    truth_path = args.out_dir / "ground_truth.csv"

    # Append to any existing ground_truth.csv (from the other two sources)
    # rather than clobbering it, so corpora compose. De-dupe on the full row.
    if truth_path.exists():
        existing = pd.read_csv(truth_path).astype(str)
        combined = pd.concat([existing, truth.astype(str)], ignore_index=True)
        truth = combined.drop_duplicates().sort_values(["target_id", "category"])
    truth.to_csv(truth_path, index=False)

    corpus_size = write_corpus(sources, args.out_dir)
    idl_size = write_idls(mapping, args.out_dir)

    per_source_truth = build_ground_truth(mapping, digests)
    manifest = {
        "dataset": mapping["dataset"],
        "source_kind": mapping["source_kind"],
        "programs_ingested": corpus_size,
        "idls_written": idl_size,
        "ground_truth_rows_this_source": int(len(per_source_truth)),
        "labels_per_category": per_source_truth["category"].value_counts().to_dict(),
        "source_digests": digests,
        "mapping_file": str(args.mapping),
    }
    (args.out_dir / "manifest.incident-repros.json").write_text(json.dumps(manifest, indent=2))

    print(json.dumps(manifest, indent=2))
    print(f"\nwrote {truth_path}, {corpus_size} corpus file(s), {idl_size} IDL(s) under {args.out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
