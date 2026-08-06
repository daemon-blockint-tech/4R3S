# Detection scoring

`score_detections.py` compares ARES audit output against a labeled ground truth
set and reports precision, recall, and F1.

## Honest status table

ARES has never been scored. No prediction output is committed, so every cell that
would hold a measurement is empty on purpose.

| Claim | Measured value | Status | Evidence |
|---|---|---|---|
| F1 = 0.94 | not measured | **unverified** | no `eval/predictions/ares-latest.csv` exists |
| Precision | not measured | **unverified** | same |
| Recall | not measured | **unverified** | same |
| Ground truth available | 152 labels over 173 targets, 6 classes | available | `FraChiacc99/solana-vuln-rust` @ `3155866` via `fetch_datasets.py` |
| Scorer verified | 3/3 gate cases behave at `--target-f1 0.94` | passing | `gate_selftest.py` in the `verify-claims` CI job, on synthetic predictions |

Do not publish 0.94, or any other figure, until the `Score ARES predictions` step
of the `verify-claims` job prints one. That step runs only when
`eval/predictions/ares-latest.csv` exists; without it, the job emits an UNSCORED
warning and a `release` event fails outright.

To fill the table: run ARES over `eval/data/corpus/*.rs`, serialize each run's
`verifiedFindings` with its `target_id` into `eval/predictions/ares-latest.csv`,
and push. CI then computes the numbers and the gate decides.

## Usage

```bash
pip install -r eval/requirements.txt

# 1. build ground_truth.csv + corpus/ + manifest.json under eval/data/
python eval/fetch_datasets.py

# 2. score predictions against it
python eval/score_detections.py \
  --truth eval/data/ground_truth.csv \
  --predictions eval/predictions/ares-latest.csv \
  --by category severity \
  --target-f1 0.94 \
  --json-out eval/data/score.json

# 3. check the gate itself still accepts and rejects correctly
python eval/gate_selftest.py --truth eval/data/ground_truth.csv --target-f1 0.94
```

Exit code is 1 when `--target-f1` is given and the measured F1 falls below it,
so the script can gate a release.

## Ground truth source

`fetch_datasets.py` downloads `FraChiacc99/solana-vuln-rust` (205 rows, single
parquet, ungated) pinned to revision `3155866`, parses the verdict turn of each
chat row, and maps its label onto a `VULN_CATALOG` id through
`eval/mappings/solana-vuln-rust.json`. It writes `ground_truth.csv`, one `.rs` file
per target under `corpus/`, and a `manifest.json` recording the revision and label
counts.

The mapping is a human judgement call, and the dataset's 6-label vocabulary is
coarser than the 28-class catalog: `Missing Key Check` collapses signer, owner, and
pubkey-equality checks into `missing-owner-check`. Read the `notes` array in the
mapping file before quoting any score derived from it. `label_rows` raises on a
label it does not recognize, so an upstream change surfaces as a CI failure instead
of a silently shrunken dataset.

The other datasets in the SEC-5 brief are not ingested; `python eval/fetch_datasets.py
--list-unsupported` prints why. `almanax/insecure-solana-programs` is the one worth
adding — it is Solana-specific and program-level, but `gated: manual` on the HF API,
so it needs an approved account and an `HF_TOKEN`.

### sealevel-attacks (EVAL-3)

`fetch_sealevel_attacks.py` ingests `coral-xyz/sealevel-attacks` (11 Anchor
programs, one vulnerability class each) pinned to revision `24555d04`. Unlike the
HF dataset, the source is a git repo whose vulnerabilities are labeled by
*directory*, so `eval/mappings/sealevel-attacks.json` is keyed by program
directory, not by an in-text label. It writes the same `ground_truth.csv` /
`corpus/` layout (appending to any existing `ground_truth.csv` rather than
clobbering it, so corpora compose), plus one Anchor **IDL** per target under
`idl/`, and a `manifest.sealevel-attacks.json`.

```bash
# default: fetch each lib.rs from GitHub raw at the pinned revision (no clone needed)
python eval/fetch_sealevel_attacks.py

# or read from a local clone
python eval/fetch_sealevel_attacks.py --repo /path/to/sealevel-attacks
```

Two caveats, both recorded in the mapping's `notes`. **(1)** Only the `insecure`
variant of each program is ingested; the `secure`/`recommended` fixes are not yet
scored as clean targets (future work — would strengthen the precision signal).
**(2)** The paired IDLs under `eval/fixtures/idl/sealevel-attacks/` are
**hand-authored**, not `anchor build` output: these programs deliberately omit
`#[account(mut)]`, so a literal build would emit `isMut:false` everywhere. The
fixtures instead follow a stated deterministic rule (isSigner from `Signer<>` /
`.is_signer` checks; isMut from state mutation in the instruction body) so they
carry the account flags POC-1 needs for precondition generation. `fetch_sealevel_attacks.py`
validates each fixture against the mapping before writing, so drift fails loudly.

### neodyme-workshop (EVAL-3)

`fetch_neodyme_workshop.py` ingests `neodyme-labs/neodyme-breakpoint-workshop`
(4 progressive challenge programs, `level1`..`level4`) pinned to revision
`d71ff2df`, mapped in `eval/mappings/neodyme-workshop.json`. One documented bug
per level: missing signer check (level1), integer overflow/underflow (level2),
type/account confusion (level3), arbitrary CPI (level4). Same
`ground_truth.csv` / `corpus/` / `idl/` layout, appending to compose with the
other sources; the level docs also ship real PoC exploit code (`pocs/`), useful
as an answer key when POC-1/POC-2 land.

```bash
python eval/fetch_neodyme_workshop.py                 # GitHub raw at pinned revision
python eval/fetch_neodyme_workshop.py --repo /path/to/neodyme-breakpoint-workshop
```

Two things to know, both in the mapping's `notes`. **(1)** These are **native**
Solana programs (raw `solana_program` + Borsh), **not Anchor** — there is no
generated IDL. The paired IDL-equivalents under `eval/fixtures/idl/neodyme-workshop/`
are hand-authored from the program's *advertised interface*: instructions from
the `WalletInstruction`/`TipInstruction` enum, accounts + flags from the builder
functions' `AccountMeta` list (`new`→isMut, `new_readonly`→readonly, signer bool
→isSigner). **(2)** For native programs the declared interface can diverge from
what the processor enforces, and that divergence *is* the bug in some levels
(level1 declares `authority` as a signer but never checks `is_signer`). The
divergence is carried by the mapping's `category` + `location`, not the IDL
shape — same discipline as the sealevel-attacks corpus. Each corpus entry is
`lib.rs` + `processor.rs` concatenated with file markers, since the bug spans
both.

### incident-repros (EVAL-3)

**Read this before quoting anything from this source.** Unlike the other two
EVAL-3 sources, these three targets are **hand-authored, stylized
illustrations** of real Solana incidents (Wormhole bridge, Feb 2022, ~$326M;
Cashio, Mar 2022, ~$52M; Mango Markets, Oct 2022, ~$116M) — not extracted from
any upstream repo, and not a replay of the actual historical exploit. Reproducing
the real hacks against real historical bridge/oracle/protocol state is
infeasible; `datasets/README.md`'s own scope note ("simplified") is what
authorizes this treatment. Each snippet under
`eval/fixtures/rs/incident-repros/` is a short, non-compiling, commented
fragment demonstrating one structural pattern inspired by the incident's
publicly documented root cause — same discipline the `solana-vuln-rust`
dataset already uses for its ingested snippets.

`eval/build_incident_repros.py` reads these committed fixtures directly (there
is nothing to fetch — no `--repo` flag, unlike the other two scripts) and
writes the same `ground_truth.csv` / `corpus/` / `idl/` layout, appending to
compose with the other sources:

```bash
python eval/build_incident_repros.py
```

Mapped categories: Wormhole → `sysvar-spoofing` (an **acknowledged stretch** —
no catalog id is an exact fit for "forged signature verification"; adding one
is future work). Cashio → `account-data-matching` (direct fit). Mango →
`oracle-price-manipulation` (direct fit). Full reasoning for each in
`eval/mappings/incident-repros.json`'s `notes`. The paired IDL fixtures are
likewise **invented** — they don't correspond to any real deployed program
interface for these protocols, included only for schema uniformity across
EVAL-3 sources.

### Scoring `core/`'s `ares-cli scan` output (EVAL-3 metrics)

EVAL-3's dataset half (the three sections above, 18 targets total) is
complete. This section fills in the ticket's remaining "recall/precision"
clause now that `ENG-1` has landed a real engine at `core/`.

**First real measurement (18 EVAL-3 targets, `ares scan --fuzz false --poc false`):
precision 0.0, recall 0.0, F1 0.0 — 0 true positives, 0 false positives, 18
false negatives.** This is a genuine result from real `ares-cli` output, not
a placeholder, and it is **not** a vocabulary-mapping artifact: every one of
the 18 scan reports came back with zero findings before the category mapping
ever ran. Root cause, confirmed by reading the source directly: `ares scan`'s
own pipeline (`MapperAgent` → `cross_analysis` → fuzzing) never invokes the
AST scanner or taint engine (`core/crates/ares-mapper/src/{ast_scanner,
taint_engine}.rs`) that actually contain the single-instruction
signer/owner/type-cosplay detectors — those two modules are wired only into
the separate `ares benchmark` command's pipeline
(`core/crates/ares-cli/src/commands/benchmark/execute.rs`), never into
`scan.rs`. `cross_analysis` alone only fires on multi-instruction
read/write patterns, so a single-instruction program like
`sealevel-attacks:0-signer-authorization` has nothing for it to catch. This
is a real gap in `ENG-1`'s `scan` command, not a bug in this eval pipeline —
flagged separately for whoever owns `core/`'s detection wiring.

This staging → conversion → scoring pipeline was also independently
verified against synthetic, hand-written `ares-report-*.json` fixtures
matching the real `AuditReport`/`Finding` struct shape byte-for-byte (see
`eval/test_stage_ares_core_targets.py`, `eval/test_convert_ares_core_reports.py`)
— confirming categories map, unmapped categories surface as `"other"`
instead of vanishing, and TP/FP/FN come out right on non-empty input. The
category mapping (`eval/mappings/ares-core-categories.json`) remains
functionally untested against a real non-empty finding, since none has
existed yet — that verification is still pending a future `scan` run that
actually produces output, once the AST-scanner/taint-engine wiring gap above
is fixed.

Scope: **`ares scan` static output only** (`--fuzz false --poc false`). PoC
generation/confirmation metrics (`--poc`, `ares confirm` against a forked
validator) are explicit follow-on work, not covered here — see the note at
the end of this section.

**New scripts**, run in sequence:

```bash
# 1. build the 18-row ground truth + corpus (if not already present)
python eval/fetch_sealevel_attacks.py
python eval/fetch_neodyme_workshop.py
python eval/build_incident_repros.py

# 2. build the CLI (requires a Rust toolchain; not available in every environment)
#    NOTE: the crate directory is named ares-cli, but its actual package name
#    (Cargo.toml [package].name) is ares-v3, and the compiled binary is named
#    `ares` (not ares-cli) -- `cargo build -p ares-cli` fails with "package ID
#    specification `ares-cli` did not match any packages".
cd core && cargo build --release -p ares-v3 && cd ..

# 3. stage each target into its own directory -- `ares scan` requires a
#    directory shaped like an Anchor project (<dir>/programs/ or <dir>/src/);
#    it silently returns zero findings for a bare .rs file or the wrong shape.
python eval/stage_ares_core_targets.py \
  --ground-truth eval/data/ground_truth.csv --corpus-dir eval/data/corpus \
  --staging-root ./ares-eval-staging

# 4. scan each staged target (one dir = one report; never share one dir
#    across targets, or their findings merge into a single report with no
#    per-target attribution)
for d in ./ares-eval-staging/*/; do
  ./core/target/release/ares scan "$d" --fuzz false --poc false -o ./ares-output
done

# 5. convert reports -> predictions CSV, then score
python eval/convert_ares_core_reports.py \
  --reports-dir ./ares-output \
  --staging-manifest ./ares-eval-staging/staging_manifest.json \
  --out eval/predictions/ares-latest.csv

python eval/score_detections.py \
  --truth eval/data/ground_truth.csv \
  --predictions eval/predictions/ares-latest.csv \
  --by category severity
```

No custom `ares.toml`/`ares-policy.toml` is required for this: verified
directly against `core/crates/ares-cli/src/main.rs` and
`core/crates/ares-policy/src/lib.rs` — a missing config file falls back to
`AresConfig::default()` (LLM judge disabled, no API key needed), and
`PolicyEngine::check_scan_permission` only *rejects* a path that matches
`blocked_paths` (`~/.ssh`, `~/.aws`, `/etc`, `/proc`, etc.) while *not*
matching `allowed_read_paths` — a staging directory outside those blocked
paths passes by default even with zero policy config.

One real toolchain requirement: `scan` unconditionally checks that a
`trident` binary exists on `PATH` (regardless of `--fuzz`), but never
inspects its output or exit code — a no-op stub (e.g. a `trident.bat`
printing anything) fully satisfies this for the static-only path; real
Trident/Anchor/Solana installs are not needed here.

**Category vocabulary gap, the biggest source of measurement noise**: 8 of
the Rust engine's 21 `VulnerabilityCategory` values match `VULN_CATALOG`'s
34 ids verbatim (`type-cosplay`, `arbitrary-cpi`, `account-data-matching`,
`pda-privileges`, `reentrancy-risk`, `missing-revalidation`, `fuzzing-crash`,
`state-transition-gap` — the last 5 added by ENG-2, which merged the two
catalogs' previously-unmapped categories into one canonical vocabulary).
The rest are mapped via `eval/mappings/ares-core-categories.json` — a human
judgement call, same `notes`-array honesty discipline as the dataset
mappings above. Categories with no defensible equivalent are mapped to the
literal string `"other"` (a guaranteed false positive against ground truth,
never silently dropped) — after ENG-2, only Rust's `generic` fallback still
falls into this bucket. **A first measurement's precision is expected to be
pulled down by this vocabulary gap, not necessarily by wrong findings** —
`convert_ares_core_reports.py` prints an "N/total mapped to other" coverage
line specifically so this is visible immediately, not buried in the CSV.

Do not confuse a real number produced here with `core/README.md`'s
self-reported 0.94 F1 / 0.97 recall badges — those come from `ares-cli
benchmark`'s own separate, hardcoded 20-protocol dataset
(`core/dataset/solana-common-attack-vectors/ground_truth.json`), a different
schema, different targets, and a different (though overlapping) category
vocabulary. That number is not validated by, and does not validate, anything
in this file.

PoC generation-rate and confirmation-rate metrics (`--poc`, `ares confirm`)
are deferred: they need target projects patched with
`solana-program-test`-compatible dev-dependencies, a heavier toolchain, and
are only even possible for the 11 sealevel-attacks + 4 neodyme-workshop
targets that actually compile — the 3 incident-repros targets are explicitly
non-compiling illustrative fragments (see above), so PoC confirmation is
fundamentally not applicable to them, not a 0% score.

## Input schema

Both files may be CSV, JSON, or JSONL. Column names are shared between them.

### Ground truth

| Column      | Required | Meaning |
|-------------|----------|---------|
| `target_id` | yes      | Audited program address or source path — the unit an audit runs on. |
| `category`  | yes      | Vulnerability class id from `VULN_CATALOG` in `src/knowledge/solana-vulns.ts`, or `other`. |
| `severity`  | no       | `info`/`low`/`medium`/`high`/`critical`. Used only for the `--by severity` breakdown. |
| `location`  | no       | Instruction, account, or `file:line`. Include in `--key` for location-level scoring. |
| `source_ref`| no       | Where the label came from (audit report URL, CVE, commit). Not scored; keep it for provenance. |

One row per vulnerability that ARES *should* report. A target that is clean
contributes no rows; it still affects precision, because anything reported on it
becomes a false positive.

### Predictions

Serialize the `Finding[]` from `AresState.verifiedFindings` (see `src/graph/state.ts`),
adding the `target_id` of the audit run.

| Column        | Required | Meaning |
|---------------|----------|---------|
| `target_id`   | yes      | Must match the ground truth vocabulary exactly. |
| `category`    | yes      | `Finding.category`. |
| `confidence`  | no       | `high`/`medium`/`low`. Enables `--min-confidence`. |
| `status`      | no       | `confirmed`/`suspected`/`false-positive` from the VERIFY pass. |
| `speculative` | no       | Boolean. Dropped unless `--include-speculative` is passed. |
| `severity`    | no       | Reported severity. Ignored when scoring; ground truth severity is used for slicing. |

## Matching rules

- A prediction counts as a true positive when it agrees with a label on every
  column in `--key`, default `target_id category`.
- Duplicates collapse first. Reporting `missing-signer-check` three times on one
  target is one true positive, not three.
- Default filters: `status == false-positive` and `speculative == true` rows are
  discarded before scoring. Override with `--drop-status` and `--include-speculative`.
- Severity is not part of the match key. A correct class with the wrong severity
  still scores as a hit; use the per-severity table to see where those land.
- `--json-out` writes every false negative and false positive key, so a low score
  can be traced to specific targets instead of being reported as a bare number.

## Caveats

- Only classes present in the ground truth vocabulary can be scored. Findings in
  classes nobody labeled inflate the false-positive count.
- Precision depends on labeling *complete* vulnerability sets per target. Partially
  labeled targets punish the system for correct detections.
- The score is a property of the dataset, not of ARES. Report the commit of both
  the dataset and the agent alongside any figure.
