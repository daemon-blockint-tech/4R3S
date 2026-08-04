# eval/predictions/

`ares-latest.csv` is the **committed real-scan output** that the `Verify-Claims`
CI gate scores against `eval/data/ground_truth.csv`. It is produced by running
the ARES engine end-to-end on the EVAL-3 corpus:

```bash
# 1. build the engine (Rust toolchain required)
(cd core && cargo build --release -p ares-cli)

# 2. fetch the corpus + ground truth
python eval/fetch_datasets.py --out-dir eval/data
python eval/fetch_sealevel_attacks.py --out-dir eval/data
python eval/fetch_neodyme_workshop.py --out-dir eval/data
python eval/build_incident_repros.py --out-dir eval/data

# 3. stage one Anchor-shaped dir per target
python eval/stage_ares_core_targets.py \
  --ground-truth eval/data/ground_truth.csv \
  --corpus eval/data/corpus --staging-root eval/data/staging

# 4. scan each staged target: for <staging>/<safe_name>/ run
#    core/target/release/ares scan <dir> -o eval/data/reports

# 5. convert the reports into the 6-column schema score_detections.py expects
python eval/convert_ares_core_reports.py \
  --reports eval/data/reports \
  --manifest eval/data/staging/staging_manifest.json \
  --out eval/predictions/ares-latest.csv
```

**The file is intentionally absent until that run happens.** When it is absent,
the gate reports `ARES is UNSCORED — any published F1 is unverified` and passes;
the guarded READMEs correspondingly say "not measured". A committed *empty*
placeholder was worse than nothing: the gate scored it as **F1 0.0** and failed
on a number ARES never actually produced (golden rule #3 — no trust-me numbers,
and equally no trust-me zeros).

Not run in this repo yet — it needs a Rust toolchain and is the **EVAL-2**
follow-up. The engine's own 20-protocol benchmark (the source of `core/README`'s
0.94) is a separate measurement, reproduced via `ares benchmark` inside `core/`.
