#!/usr/bin/env python3
"""Fetch a public vulnerability dataset and emit the ground truth CSV.

Downloads the dataset parquet from Hugging Face, maps each row's label onto a
`VULN_CATALOG` category via a committed mapping file, and writes:

  <out-dir>/ground_truth.csv   the schema documented in eval/README.md
  <out-dir>/corpus/<id>.rs     the code for each target, so ARES can be run on it
  <out-dir>/manifest.json      dataset revision + row counts, for provenance

Labels come from the dataset. The mapping from dataset label to catalog category
is a human decision recorded in eval/mappings/*.json — read its `notes` before
trusting a score built on it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

import pandas as pd

HF_RESOLVE = "https://huggingface.co/datasets/{dataset}/resolve/{revision}/{path}"
DEFAULT_PARQUET = "data/train-00000-of-00001.parquet"
CODE_BLOCK = re.compile(r"```(.*?)```", re.DOTALL)
VERDICT = re.compile(r"classified as (?P<label>.+?) and is related to the code:\s*`(?P<location>.*?)`", re.DOTALL)
SWC = re.compile(r"SWC it is mapped with:\s*(?P<swc>[A-Za-z0-9\-]+)")

# Datasets from the SEC-5 brief that this fetcher cannot use, and why. Reported
# so the omission is visible instead of looking like an oversight.
UNSUPPORTED = {
    "almanax/insecure-solana-programs": (
        "gated (`gated: manual` on the HF API); needs an approved account and HF_TOKEN"
    ),
    "Ackee-Blockchain/trident-arena-benchmarks": "git repo, not a parquet dataset; no per-program label file",
    "sunblaze-ucb/cybergym": "git repo of CTF-style tasks; labels are not Solana vulnerability classes",
}


def download(dataset: str, revision: str, path: str, dest: Path) -> Path:
    url = HF_RESOLVE.format(dataset=dataset, revision=revision, path=path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as response, dest.open("wb") as handle:
        handle.write(response.read())
    return dest


def split_records(text: pd.Series) -> pd.DataFrame:
    """Pull the code block and the verdict turn out of each chat transcript.

    Each row is a two-turn chat: the first answer carries the verdict, the
    second only restates generic remediation advice and is discarded.
    """
    parts = text.str.split("[/INST]", n=1, regex=False, expand=True)
    if parts.shape[1] != 2:
        raise ValueError("expected every row to contain at least one [/INST] separator")
    code = parts[0].str.extract(CODE_BLOCK, expand=False)
    if code.isna().any():
        raise ValueError(f"{int(code.isna().sum())} row(s) have no ``` code block ```")
    verdict = parts[1].str.split("</s>", n=1, regex=False).str[0].str.strip()
    return pd.DataFrame({"code": code.str.strip(), "verdict": verdict})


def label_rows(records: pd.DataFrame, mapping: dict) -> pd.DataFrame:
    """Attach `category`, `severity`, `location`, `swc`; clean rows get NA."""
    labeled = records.copy()
    parsed = labeled["verdict"].str.extract(VERDICT)
    labeled["dataset_label"] = parsed["label"].str.strip()
    labeled["location"] = parsed["location"].str.strip()
    labeled["swc"] = labeled["verdict"].str.extract(SWC, expand=False)
    labeled["is_clean"] = labeled["verdict"].str.startswith(mapping["clean_answer_prefix"])

    unparsed = labeled["dataset_label"].isna() & ~labeled["is_clean"]
    if unparsed.any():
        examples = labeled.loc[unparsed, "verdict"].str.slice(0, 120).unique()[:3]
        raise ValueError(
            f"{int(unparsed.sum())} row(s) are neither a clean verdict nor a parseable "
            f"classification; the dataset format changed. Examples: {list(examples)}"
        )

    known = set(mapping["labels"])
    unknown = set(labeled["dataset_label"].dropna()) - known
    if unknown:
        raise ValueError(f"dataset label(s) {sorted(unknown)} are absent from {sorted(known)}; update the mapping")

    labeled["category"] = labeled["dataset_label"].map(lambda k: mapping["labels"][k]["category"] if pd.notna(k) else pd.NA)
    labeled["severity"] = labeled["dataset_label"].map(lambda k: mapping["labels"][k]["severity"] if pd.notna(k) else pd.NA)
    return labeled


def target_ids(records: pd.DataFrame, dataset: str, split: str) -> pd.Series:
    """Content-addressed ids, so a row reordering upstream does not shift labels."""
    slug = dataset.split("/")[-1]
    digest = records["code"].map(lambda code: hashlib.sha256(code.encode()).hexdigest()[:12])
    return slug + ":" + split + ":" + digest


def conflicting_targets(labeled: pd.DataFrame) -> list[str]:
    """Targets the dataset labels both clean and vulnerable.

    Identical snippets appear more than once, so this is possible. Such a target
    is scored as vulnerable; the clean row is ignored, and the count is reported
    in the manifest rather than being swallowed.
    """
    per_target = labeled.groupby("target_id")["is_clean"].nunique()
    return sorted(per_target[per_target > 1].index)


def build_ground_truth(labeled: pd.DataFrame, dataset: str, revision: str) -> pd.DataFrame:
    vulnerable = labeled[~labeled["is_clean"]]
    truth = pd.DataFrame(
        {
            "target_id": vulnerable["target_id"],
            "category": vulnerable["category"],
            "severity": vulnerable["severity"],
            "location": vulnerable["location"],
            "source_ref": vulnerable["swc"].fillna("").radd(f"hf://{dataset}@{revision[:12]} ").str.strip(),
        }
    )
    return truth.drop_duplicates(subset=["target_id", "category"]).sort_values(["target_id", "category"])


def write_corpus(labeled: pd.DataFrame, out_dir: Path) -> int:
    corpus = out_dir / "corpus"
    corpus.mkdir(parents=True, exist_ok=True)
    written = labeled.drop_duplicates(subset=["target_id"])
    for target_id, code in zip(written["target_id"], written["code"]):
        (corpus / f"{target_id.replace(':', '_')}.rs").write_text(code)
    return len(written)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--mapping",
        type=Path,
        default=Path(__file__).parent / "mappings" / "solana-vuln-rust.json",
        help="dataset-label to VULN_CATALOG mapping",
    )
    parser.add_argument("--out-dir", type=Path, default=Path("eval/data"), help="where to write outputs")
    parser.add_argument("--parquet-path", default=DEFAULT_PARQUET, help="path of the parquet inside the HF repo")
    parser.add_argument("--local-parquet", type=Path, help="use an already-downloaded parquet instead of fetching")
    parser.add_argument("--list-unsupported", action="store_true", help="print the datasets this script cannot ingest")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.list_unsupported:
        for dataset, reason in UNSUPPORTED.items():
            print(f"{dataset}: {reason}")
        return 0

    mapping = json.loads(args.mapping.read_text())
    dataset, revision, split = mapping["dataset"], mapping["revision"], mapping["split"]
    args.out_dir.mkdir(parents=True, exist_ok=True)

    parquet = args.local_parquet or download(
        dataset, revision, args.parquet_path, args.out_dir / "raw" / Path(args.parquet_path).name
    )
    frame = pd.read_parquet(parquet)
    if "text" not in frame.columns:
        raise ValueError(f"expected a `text` column, got {frame.columns.tolist()}")

    records = split_records(frame["text"])
    records["target_id"] = target_ids(records, dataset, split)
    labeled = label_rows(records, mapping)
    truth = build_ground_truth(labeled, dataset, revision)

    truth_path = args.out_dir / "ground_truth.csv"
    truth.to_csv(truth_path, index=False)
    corpus_size = write_corpus(labeled, args.out_dir)

    manifest = {
        "dataset": dataset,
        "revision": revision,
        "split": split,
        "rows_in_dataset": int(len(frame)),
        "unique_targets": corpus_size,
        "clean_targets": int(labeled.loc[labeled["is_clean"], "target_id"].nunique()),
        "targets_labeled_both_ways": len(conflicting_targets(labeled)),
        "ground_truth_rows": int(len(truth)),
        "labels_per_category": truth["category"].value_counts().to_dict(),
        "mapping_file": str(args.mapping),
    }
    (args.out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    print(json.dumps(manifest, indent=2))
    print(f"\nwrote {truth_path} and {corpus_size} corpus file(s) under {args.out_dir / 'corpus'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
