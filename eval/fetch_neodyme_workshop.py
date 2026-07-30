#!/usr/bin/env python3
"""Fetch the neodyme-labs/neodyme-breakpoint-workshop corpus and emit ground truth.

The Neodyme workshop is a git repo of 4 progressive challenge programs
(level1..level4), each a NATIVE Solana program (raw solana_program + Borsh, not
Anchor) with one documented vulnerability. The mapping from level directory to
`VULN_CATALOG` category lives in `eval/mappings/neodyme-workshop.json` — read its
`notes` (especially the native-IDL flag rule) before trusting a score.

Emits the same layout as `fetch_datasets.py` / `fetch_sealevel_attacks.py`, so
`score_detections.py` consumes it unchanged:

  <out-dir>/ground_truth.csv                 schema documented in eval/README.md
  <out-dir>/corpus/<id>.rs                   lib.rs + processor.rs, concatenated
  <out-dir>/idl/<id>.json                    the paired IDL-equivalent fixture
  <out-dir>/manifest.neodyme-workshop.json   revision + counts, for provenance

The bug spans two files (interface in lib.rs, logic in processor.rs), so each
corpus entry concatenates both with file markers. Source is a local clone
(`--repo PATH`) or, by default, GitHub raw pinned to the mapping's `revision`.
The paired IDL-equivalents are committed fixtures under
`eval/fixtures/idl/neodyme-workshop/`; this script validates and copies them.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import urllib.request
from pathlib import Path

import pandas as pd

RAW_URL = "https://raw.githubusercontent.com/{repo}/{revision}/{path}"
SRC_FILES = ("src/lib.rs", "src/processor.rs")
DATASET_SLUG = "neodyme-workshop"
FIXTURE_IDL_DIR = Path(__file__).parent / "fixtures" / "idl" / "neodyme-workshop"


def to_camel(snake: str) -> str:
    """Snake_case identifier -> camelCase (matches how the IDL names instructions)."""
    head, *rest = snake.split("_")
    return head + "".join(word[:1].upper() + word[1:] for word in rest)


def target_id_for(program_dir: str) -> str:
    return f"{DATASET_SLUG}:{program_dir}"


def content_digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def read_source(program_dir: str, mapping: dict, repo_root: Path | None) -> str:
    """Concatenate lib.rs + processor.rs for a level, with file markers."""
    sections = []
    for rel_file in SRC_FILES:
        rel = f"{program_dir}/{rel_file}"
        if repo_root is not None:
            body = (repo_root / rel).read_text()
        else:
            repo = mapping["repo_url"].removeprefix("https://github.com/")
            url = RAW_URL.format(repo=repo, revision=mapping["revision"], path=rel)
            with urllib.request.urlopen(url) as response:
                body = response.read().decode()
        sections.append(f"// ==== {rel} ====\n{body}")
    return "\n\n".join(sections)


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
    revision = mapping["revision"]
    rows = []
    for program_dir, entry in mapping["programs"].items():
        rows.append(
            {
                "target_id": target_id_for(program_dir),
                "category": entry["category"],
                "severity": entry["severity"],
                "location": entry["location"],
                "source_ref": f"git://{mapping['repo_url']}@{revision[:12]} {program_dir} sha256:{digests[program_dir]}",
            }
        )
    truth = pd.DataFrame(rows, columns=["target_id", "category", "severity", "location", "source_ref"])
    return truth.drop_duplicates(subset=["target_id", "category"]).sort_values(["target_id", "category"])


def write_corpus(sources: dict[str, str], out_dir: Path) -> int:
    corpus = out_dir / "corpus"
    corpus.mkdir(parents=True, exist_ok=True)
    for program_dir, code in sources.items():
        name = target_id_for(program_dir).replace(":", "_")
        (corpus / f"{name}.rs").write_text(code)
    return len(sources)


def write_idls(mapping: dict, out_dir: Path) -> int:
    idl_out = out_dir / "idl"
    idl_out.mkdir(parents=True, exist_ok=True)
    for program_dir, entry in mapping["programs"].items():
        name = target_id_for(program_dir).replace(":", "_")
        shutil.copyfile(FIXTURE_IDL_DIR / entry["idl"], idl_out / f"{name}.json")
    return len(mapping["programs"])


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--mapping",
        type=Path,
        default=Path(__file__).parent / "mappings" / "neodyme-workshop.json",
        help="level-directory to VULN_CATALOG mapping",
    )
    parser.add_argument("--out-dir", type=Path, default=Path("eval/data"), help="where to write outputs")
    parser.add_argument(
        "--repo",
        type=Path,
        help="path to a local neodyme-breakpoint-workshop clone; if omitted, fetch raw files from GitHub at the pinned revision",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    mapping = json.loads(args.mapping.read_text())
    args.out_dir.mkdir(parents=True, exist_ok=True)

    sources: dict[str, str] = {}
    digests: dict[str, str] = {}
    for program_dir, entry in mapping["programs"].items():
        validate_idl(load_idl(entry), entry)
        code = read_source(program_dir, mapping, args.repo)
        sources[program_dir] = code
        digests[program_dir] = content_digest(code)

    truth = build_ground_truth(mapping, digests)
    truth_path = args.out_dir / "ground_truth.csv"

    # Append to any existing ground_truth.csv (from the other fetchers) rather
    # than clobbering it, so corpora compose. De-dupe on the full row.
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
        "revision": mapping["revision"],
        "source_kind": mapping["source_kind"],
        "programs_ingested": corpus_size,
        "idls_written": idl_size,
        "ground_truth_rows_this_source": int(len(per_source_truth)),
        "labels_per_category": per_source_truth["category"].value_counts().to_dict(),
        "source_digests": digests,
        "mapping_file": str(args.mapping),
    }
    (args.out_dir / "manifest.neodyme-workshop.json").write_text(json.dumps(manifest, indent=2))

    print(json.dumps(manifest, indent=2))
    print(f"\nwrote {truth_path}, {corpus_size} corpus file(s), {idl_size} IDL(s) under {args.out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
