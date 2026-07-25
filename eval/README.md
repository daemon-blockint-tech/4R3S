# Detection scoring

`score_detections.py` compares ARES audit output against a labeled ground truth
set and reports precision, recall, and F1.

The repository currently ships **no ground truth dataset**. `src/knowledge/solana-vulns.ts`
is the vulnerability taxonomy (20 classes, no labels), `db/` holds schema DDL only,
and the `*.test.ts` files are unit tests. Any published F1 figure for ARES is
unverified until someone supplies the two files below and this script prints one.

## Usage

```bash
pip install pandas numpy            # see requirements.txt
python eval/score_detections.py \
  --truth path/to/ground-truth.csv \
  --predictions path/to/ares-findings.csv \
  --by category severity \
  --target-f1 0.94 \
  --json-out /tmp/ares-eval.json
```

Exit code is 1 when `--target-f1` is given and the measured F1 falls below it,
so the script can gate a release.

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
