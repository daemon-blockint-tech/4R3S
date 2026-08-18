# eval/baselines/

ENG-5 Step B measurement snapshots. Each file is the output of an existing script
(`score_detections.py` or `score_suppression.py`, both unmodified) run against a
real corpus scan — nothing here is hand-written or estimated.

Full write-up and what each number decides: [docs/ENG-5-MEASUREMENT.md](../../docs/ENG-5-MEASUREMENT.md).

## Files

| File | Script | Run |
|---|---|---|
| `eng5-<date>-default.json` | `score_detections.py --by category severity` | `ares scan --fuzz false` (documented default) |
| `eng5-<date>-default-suppression.json` | `score_suppression.py` | same run |
| `eng5-<date>-astscan.json` / `-suppression.json` | same two scripts | `ares scan --fuzz false --ast-scan true` |
| `eng5-<date>-extended.json` / `-suppression.json` | same two scripts | `ares scan --fuzz false` with `judge_extended = true` in `AresConfig` |

## Reproducing

```bash
cd core && cargo build --release -p ares-v3

python eval/fetch_datasets.py --out-dir eval/data           # MUST run first — it
python eval/fetch_sealevel_attacks.py --out-dir eval/data   # clobbers ground_truth.csv;
python eval/fetch_neodyme_workshop.py --out-dir eval/data   # the other three append
python eval/build_incident_repros.py --out-dir eval/data    # and de-dupe

python eval/stage_ares_core_targets.py \
  --ground-truth eval/data/ground_truth.csv \
  --corpus-dir eval/data/corpus --staging-root eval/data/staging

for d in eval/data/staging/*/; do
  core/target/release/ares scan "$d" --fuzz false -o eval/data/reports-default
done

python eval/convert_ares_core_reports.py \
  --reports-dir eval/data/reports-default \
  --staging-manifest eval/data/staging/staging_manifest.json \
  --out eval/data/predictions/default.csv

python eval/score_detections.py --truth eval/data/ground_truth.csv \
  --predictions eval/data/predictions/default.csv --by category severity

python eval/score_suppression.py --reports-dir eval/data/reports-default \
  --staging-manifest eval/data/staging/staging_manifest.json \
  --truth eval/data/ground_truth.csv
```

Repeat the scan loop with `--ast-scan true` appended, or with
`--config <a TOML with every AresConfig field, judge_extended = true>` prepended, for
the other two runs (see `docs/ENG-5-MEASUREMENT.md` for why every field is required —
`AresConfig` has no `#[serde(default)]`).

## Ground truth is not committed

`eval/data/` is gitignored; the fetchers pull live upstream data and the set has
already drifted once (152 → 170 rows between two runs of the CI job). Every JSON
here stamps the truth set's row count and sha256 at measurement time — compare
those before comparing the metrics themselves, or a corpus-drift difference will
look like a detector-behavior difference.

## What these are not

Not a publishable accuracy claim — `eval/check_published_claims.py` governs what
may appear in a README, and it reads `eval/predictions/ares-latest.csv`, not these
files. These measure the suppression layer specifically, which nothing previously
measured at all.
