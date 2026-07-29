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
