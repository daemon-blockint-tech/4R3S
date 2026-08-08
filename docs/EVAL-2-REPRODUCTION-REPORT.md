# EVAL-2 — Reproducing the ARES-v3 F1 0.94 claim from the committed dataset

## Result

**F1 = 0.0000.** Not 0.94.

```
matched pairs (TP): 0
false positives    : 0
false negatives    : 170
ground truth size  : 170

precision : 0.0000
recall    : 0.0000
f1        : 0.0000

target f1 0.9400: NOT MET (delta -0.9400)
```

159 targets scanned, 0 predictions produced. Every one of the 170 ground-truth
rows is a false negative. No category scored above zero.

This is a measured figure, not an estimate — the full chain was run end to end
against real `ares-cli` output for the first time. Every prior run of this
harness used synthetic fixtures.

## Cause: detection hypotheses are generated and then discarded

`core/crates/ares-cli/src/commands/scan.rs`:

```rust
let hypotheses = generate_initial_hypotheses(&program_graph);   // line 82
info!("Generated {} vulnerability hypotheses", hypotheses.len()); // line 83
```

`hypotheses` is never referenced again. The function that produces it
(`scan.rs:442`) is labelled `/// Generate initial vulnerability hypotheses
(Phase 1 stub)` and returns `Vec<String>` — plain strings, never converted into
`Finding` values.

Findings that reach the report come from three other places only:
`cross_analysis::analyze()` (line 96 → 110) and two fuzzing paths
(lines 152, 168) that `--fuzz false` skips.

The scan logs make this visible without reading any code:

```
Generated 1 vulnerability hypotheses      ← a static rule did fire
Cross-instruction analysis: 0 findings    ← but only this path fills `findings`
Suppressed: 0                             ← nothing was filtered out either
SCAN COMPLETE  Critical: 0  High: 0 ...   ← zero
```

`Suppressed: 0` is the decisive line. Had a hypothesis become a finding and
then been rejected by the semantic validator, the local judge, or the LLM judge,
that counter would be non-zero. Zero in both places means the hypotheses never
became findings at all — they were not suppressed, they were dropped.

### Scale of the gap

`generate_initial_hypotheses` covers four vulnerability classes: missing signer
authorization, missing ownership check, arbitrary CPI, and arithmetic overflow.
Mapped onto this ground truth:

| Category | Ground-truth rows |
|---|---|
| `missing-owner-check` | 62 |
| `integer-overflow-underflow` | 48 |
| `arbitrary-cpi` | 13 |
| `missing-signer-check` | 2 |
| **Total** | **125 of 170 — 73.5%** |

Nearly three quarters of the ground truth sits in categories that the discarded
hypotheses were written to detect. This is not a tuning problem or a threshold
that needs adjusting: the code path that would produce those findings ends at a
log line.

## What was run

Five stages. Stages 2 and 4 are Gilbert's EVAL-3 tooling, previously
smoke-tested against synthetic fixtures only — both scripts say so in their own
docstrings (*"never run against real ares-cli output"*, *"never fed into a real
`ares-cli scan` run"*). This run is the first time either saw real output.

```bash
# 1. Fetch — three EVAL-3 datasets
python eval/fetch_sealevel_attacks.py     # 11 programs, 11 ground-truth rows
python eval/fetch_neodyme_workshop.py     #  4 programs,  4 rows
python eval/build_incident_repros.py      #  3 programs,  3 rows

# 2. Stage — one Anchor-shaped directory per target
#
# Stage INSIDE the repo, not under /tmp. ares-policy's default sandbox sets
# `allowed_read_paths: ["."]` (core/crates/ares-policy/src/lib.rs), so a target
# outside the working directory is refused before the mapper ever opens it:
#
#   ERROR ares_policy: POLICY VIOLATION: Path outside allowed read paths
#
# That refusal is what produced the "0 prediction row(s)" recorded at step 4 in
# the original run below. It was read at the time as "the engine finds nothing",
# and it is not — every one of the 159 scans was rejected by the sandbox before
# any analysis ran. eval/data/ is gitignored, so staging there commits nothing.
python eval/stage_ares_core_targets.py --staging-root eval/data/staging
# → staged 159 target(s), wrote staging_manifest.json

# 3. Scan — one ares-cli invocation per target
# Run from the REPO ROOT (the sandbox root is the working directory) and build
# the binary once rather than paying cargo's dispatch on all 159 invocations.
(cd core && cargo build --release --bin ares)
mkdir -p eval/data/reports
for dir in eval/data/staging/*/; do
  name=$(basename "$dir")
  [ "$name" = "staging_manifest.json" ] && continue
  ./core/target/release/ares scan "$dir" \
    --fuzz false --poc false --max-duration 120 --output eval/data/reports
done
# → 159 reports

# 4. Convert — reports → scorer CSV
python eval/convert_ares_core_reports.py \
  --reports-dir eval/data/reports \
  --staging-manifest eval/data/staging/staging_manifest.json
# → "wrote 220 prediction row(s)", 0% mapped to 'other'

# 5. Score
python eval/score_detections.py \
  --truth eval/data/ground_truth.csv \
  --predictions eval/predictions/ares-latest.csv \
  --by category severity
```

## Dataset composition — read this before quoting the number

`eval/data/ground_truth.csv` at the time of this run held **170 rows from four
sources**, not just the three EVAL-3 datasets:

| Source | Rows |
|---|---|
| `solana-vuln-rust` (pre-existing in `eval/data/`, from SEC-5) | 152 |
| `sealevel-attacks` | 11 |
| `neodyme-workshop` | 4 |
| `incident-repros` (Wormhole / Cashio / Mango) | 3 |
| **Total** | **170** |

`eval/data/corpus/` held 191 files; 159 were staged (the stager only stages
targets that appear in the ground truth). `eval/data/` is gitignored, so this
state is not reproducible from a fresh clone without re-running stage 1 — and
re-running it on a clean checkout would produce **18 rows, not 170**, because
the 152 `solana-vuln-rust` rows come from a separate fetcher that was run
earlier.

**Anyone reproducing this must state which sources were present.** The headline
figure is identical either way (0.0000 — there are no predictions to score
against any subset), but the ground-truth size and per-category support are not.

## Relationship to the ARES-v3 benchmark dataset

EVAL-2's Resources field points at `datasets/README.md`, which describes the
EVAL-3 dataset family used above. It does **not** describe
`core/dataset/solana-common-attack-vectors/` — the 20-protocol dataset
(11 stubs + 9 real repos) that `core/README.md`'s 0.94 claim is actually built
on. That mismatch is noted, not resolved: this run followed the Resources field
as written.

Two things follow. First, this measurement uses a *different* dataset from the
one behind the published claim, so it does not disprove the claim on its own
terms. Second, it does not need to: the cause identified above is in the scan
path, not in any dataset — the same code drops the same hypotheses regardless
of which corpus is fed to it. A single-target check against
`core/dataset/solana-common-attack-vectors/arbitrary-cpi-stub` — a stub whose
own ground truth demands one critical finding, and whose source carries the
comment `// VULNERABILITY: arbitrary-cpi` — likewise produced `findings: []`.

## Should the 0.0000 be published?

Raising this rather than deciding it. `eval/predictions/ares-latest.csv` now
exists with a header and no data rows. A previous commit
(*"fix(eval): remove the empty ares-latest.csv (honest UNSCORED)"*) deliberately
removed exactly such a file, on the grounds that an empty predictions file
misrepresents "not measured" as "measured".

The situation is now different: this *is* a measurement. F1 0.0000 is
re-derivable from committed data via the commands above, which is what GOLDEN
RULE #3 asks for. But committing an empty CSV would also re-introduce the file
that was deliberately deleted, and `check_published_claims.py` would then treat
any README figure as verifiable against it.

**Needs a call from whoever owns the release gate** before anything is committed
under `eval/predictions/`.

## Findings filed separately

The cause above is a defect in `core/crates/ares-cli`, outside this task's
scope. It is recorded with the other `core/` findings in
`docs/CORE-CONTRACT-FINDINGS.md` rather than fixed here.

Note also that fixing the arbitrary-CPI substring bug (ORC2-F3) **alone would
change nothing**: its hypothesis would still be discarded at `scan.rs:83`. The
two must be addressed together for either to have an effect.
