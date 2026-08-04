#!/usr/bin/env python3
"""Stage EVAL-3 corpus files for `ares-cli scan`.

STATUS: smoke-tested only, with synthetic corpus fixtures in a temp dir --
never run against the real 18-target eval/data/corpus/ produced by the three
EVAL-3 fetch/build scripts, and never fed into a real `ares-cli scan` run.

`ares-cli scan <PROGRAM_PATH>` expects PROGRAM_PATH to be a directory shaped
like an Anchor project: `MapperAgent::analyze()` (core/crates/ares-mapper)
only recognizes `<PROGRAM_PATH>/programs/` or `<PROGRAM_PATH>/src/` as the
source root, and silently returns zero findings (no error) if neither exists.
There is no way to point `scan` at a bare `.rs` file directly.

This script copies each `eval/data/corpus/<safe_name>.rs` into its own
`<staging_root>/<safe_name>/src/lib.rs` -- ONE DIRECTORY PER TARGET. Sharing
one `src/` across multiple corpus files would merge every target's findings
into a single `ares-report-<dirname>.json` (the report filename is just
`program_path.file_name()`), silently destroying per-target attribution and
breaking the whole scoring join. Do not "optimize" this into fewer directories.

It also writes `staging_manifest.json` (safe_name -> target_id) as the single
source of truth for that correspondence -- the converter reads this rather
than re-deriving target_id by guessing which underscore in a directory name
was originally a colon (ambiguous, since program directory names themselves
contain underscores).
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

import pandas as pd


def safe_name_for(target_id: str) -> str:
    return target_id.replace(":", "_")


def stage_targets(ground_truth: pd.DataFrame, corpus_dir: Path, staging_root: Path) -> dict[str, str]:
    """Copy each target's corpus file into its own staged directory.

    Returns the manifest dict (safe_name -> target_id) that was written.
    Raises FileNotFoundError early, with the missing path named, rather than
    silently staging a subset -- a missing corpus file for a target that's
    definitely in ground_truth.csv is a build-order bug worth surfacing loudly.
    """
    staging_root.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, str] = {}
    for target_id in sorted(ground_truth["target_id"].unique()):
        safe_name = safe_name_for(target_id)
        src = corpus_dir / f"{safe_name}.rs"
        if not src.exists():
            raise FileNotFoundError(
                f"corpus file missing for target_id {target_id!r}: {src} does not exist "
                "(did you run all three EVAL-3 fetch/build scripts first?)"
            )
        dest_dir = staging_root / safe_name / "src"
        dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest_dir / "lib.rs")
        manifest[safe_name] = target_id
    return manifest


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ground-truth", type=Path, default=Path("eval/data/ground_truth.csv"))
    parser.add_argument("--corpus-dir", type=Path, default=Path("eval/data/corpus"))
    parser.add_argument("--staging-root", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    ground_truth = pd.read_csv(args.ground_truth)
    manifest = stage_targets(ground_truth, args.corpus_dir, args.staging_root)

    manifest_path = args.staging_root / "staging_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    print(f"staged {len(manifest)} target(s) under {args.staging_root}")
    print(f"wrote {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
