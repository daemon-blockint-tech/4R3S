# eval/predictions/

`ares-latest.csv` is the **committed real-scan output** that the `Verify-Claims`
CI gate scores against `eval/data/ground_truth.csv`. It is produced by running
the ARES engine end-to-end on the EVAL-3 corpus:

```bash
# 1. build the engine (Rust toolchain required)
#    The CLI crate has three names: directory `crates/ares-cli/`, package
#    `ares-v3`, binary `ares`. `-p` takes the *package*, so `-p ares-cli`
#    fails with "did not match any packages" — as this line used to say.
#    `-p` takes the PACKAGE name. The CLI crate has three: directory
#    `crates/ares-cli/`, package `ares-v3`, binary `ares`. This line said
#    `-p ares-cli`, which exits with "did not match any packages".
(cd core && cargo build --release -p ares-v3)

# 2. fetch the corpus + ground truth
python eval/fetch_datasets.py --out-dir eval/data
python eval/fetch_sealevel_attacks.py --out-dir eval/data
python eval/fetch_neodyme_workshop.py --out-dir eval/data
python eval/build_incident_repros.py --out-dir eval/data

# 3. stage one Anchor-shaped dir per target
python eval/stage_ares_core_targets.py \
  --ground-truth eval/data/ground_truth.csv \
  --corpus eval/data/corpus --staging-root eval/data/staging

# 4. scan each staged target.
#    `--fuzz false` is required, not optional. Fuzzing defaults to on, and
#    Trident's init needs an Anchor.toml that the staged dirs do not have, so
#    every one of the 159 scans aborts without it. It is also the right setting
#    on principle: this measures the deterministic static layer, and a fuzz
#    campaign is not reproducible (GOLDEN RULE 2).
#    `--fuzz false` is required, not a preference. Fuzzing defaults to ON, and
#    Trident's init aborts on a staged dir ("Anchor.toml was not found in any
#    parent directory") — so without it all 159 scans fail and step 5 converts
#    an empty directory. It is also the correct setting on principle: this
#    measures the deterministic static layer, and a fuzz campaign is not
#    reproducible (GOLDEN RULE 2).
for d in eval/data/staging/*/; do
  core/target/release/ares scan "$d" --fuzz false -o eval/data/reports
done

# 5. convert the reports into the 6-column schema score_detections.py expects
#    (the flags are --reports-dir / --staging-manifest; this block used to name
#     --reports / --manifest, which argparse rejects outright)
python eval/convert_ares_core_reports.py \
  --reports-dir eval/data/reports \
  --staging-manifest eval/data/staging/staging_manifest.json \
  --out eval/predictions/ares-latest.csv

# 6. score (this is what the CI gate runs)
python eval/score_detections.py \
  --truth eval/data/ground_truth.csv \
  --predictions eval/predictions/ares-latest.csv \
  --by category severity --target-f1 0.55
```

Two full runs of the loop above produce a byte-identical `ares-latest.csv`, which
is what makes the committed file meaningful as evidence rather than a snapshot.

When the file is *absent*, the gate reports `ARES is UNSCORED — any published F1
is unverified` and passes; the guarded READMEs correspondingly say "not
measured". A committed *empty* placeholder was worse than nothing: the gate
scored it as **F1 0.0** and failed on a number ARES never actually produced
(golden rule #3 — no trust-me numbers, and equally no trust-me zeros).

## Last measured run
# 6. score — this is what the Verify-Claims job runs
python eval/score_detections.py \
  --truth eval/data/ground_truth.csv \
  --predictions eval/predictions/ares-latest.csv \
  --by category severity
```

## What that run produces

| | |
|---|---|
| targets scanned | 159 (0 scan failures) |
| predictions | 220 rows |
| ground truth | 170 rows |
| precision | 0.7429 |
| recall | 0.4588 |
| **F1** | **0.5673** |

That is the whole basis for the CI gate's `--target-f1 0.55` floor. It is *not*
a publishable accuracy claim: recall is under 0.5, and four of the fourteen
categories in the truth set score 0.0000 because the static rule set emits
nothing for them at all. `eval/check_published_claims.py` is what decides which
of these numbers may appear in a README, and it reads this CSV — not this table.

The commands above had never worked as written before this run: step 1 named a
package that does not exist (`-p ares-cli`), step 4 omitted `--fuzz false` so
all 159 scans aborted, and step 5 used two flag names the script does not
accept. A documented-but-unrunnable reproduction is the same thing as no
reproduction, which is precisely what golden rule #3 exists to prevent.

The engine's own 20-protocol benchmark (the source of `core/README`'s 0.94) is a
separate measurement on a different corpus, reproduced via `ares benchmark`
inside `core/`. It is not comparable to the number above and must never be
presented as if it were.
Reproduced independently twice, from two separate checkouts, byte-identical
both times — which is what makes the committed CSV evidence rather than a
snapshot of one machine.

It is **not** a publishable accuracy claim: recall is below 0.5, and ten of the
fourteen categories in the truth set score 0.0000 because the static rule set
emits nothing for them at all. `eval/check_published_claims.py` decides what may
appear in a README, and it reads the CSV — not this table.

When the file is **absent**, the gate reports `ARES is UNSCORED — any published
F1 is unverified` and passes; the guarded READMEs correspondingly say "not
measured". A committed *empty* placeholder was worse than nothing: the gate
scored it as **F1 0.0** and failed on a number ARES never actually produced
(golden rule #3 — no trust-me numbers, and equally no trust-me zeros).

The engine's own 20-protocol benchmark (the source of `core/README`'s 0.94) is a
separate measurement on a different corpus, reproduced via `ares benchmark`
inside `core/`. It is not comparable to the table above and must never be
presented as though it were.
