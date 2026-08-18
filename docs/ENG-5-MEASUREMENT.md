# ENG-5 — Measuring the local judge before tuning it (Step B)

## Why this exists

ENG-5 asks to improve the local judge's false-positive suppression and measure
precision per class. Its dependencies, ENG-3 (taint sources/sinks) and EVAL-3
(benchmark + metrics), are both merged. But nobody had ever measured what the
judge currently does — every scan already records what each suppressor removed
and why (`AuditReport.suppressed_findings[]`), and nothing in `eval/` read it.

Step A (`eval/score_suppression.py`, `eval/test_score_suppression.py`) built the
reader. This is Step B: running it for real, on a freshly fetched corpus and a
freshly built engine, three ways.

**All figures below are re-derivable** from the committed files in
`eval/baselines/` (GOLDEN RULE 3) — see `eval/baselines/README.md` for the exact
commands. Ground truth for every run below: **170 rows, 159 targets, 14
categories, sha256 `e179a0906ce47953…`**. No accuracy claim in this document is
published anywhere else; `eval/check_published_claims.py` governs that
separately and reads `eval/predictions/ares-latest.csv`, not this file.

## Machine / corpus state at measurement time

- Engine rebuilt from `main` at commit `3f5f14b` (this branch's tip;
  `core/` itself unchanged since `dc51811`).
- Corpus fetched fresh: `fetch_datasets.py` (152 rows) then
  `fetch_sealevel_attacks.py`, `fetch_neodyme_workshop.py`,
  `build_incident_repros.py` (append + de-dupe) → 170 rows / 159 targets.
- Three scans, `--fuzz false` in all: **default** (documented flags, nothing
  added), **`--ast-scan true`** (the ENG-3/ENG-4 taint path, opt-in,
  `scan.rs:213`), **`judge_extended`** (the local judge's two dormant rules,
  reachable only via `AresConfig`, no CLI flag — see the config note below).
- All three: 159/159 targets scanned, 0 failures.

## Result 1 — the committed evidence is not stale

Run A's predictions (232 rows) are **byte-identical, after sorting, to the
committed `eval/predictions/ares-latest.csv`** — despite 9 commits touching
`core/` since that file was last regenerated (all six ENG-4 checkpoints, a
`cargo fmt`, a dependency bump). The plan flagged this as the likely failure
mode (R1); it didn't happen. DET-3/4/5's and EVAL-4's numbers still describe
`main` accurately.

## Result 2 — the local judge suppressed nothing, on any of the three runs

| Run | `local_judge` suppressions | `llm_judge` suppressions | Other suppressors |
|---|---|---|---|
| Default | **0** | 0 (disabled by default) | `semantic_validator`: 4 |
| `--ast-scan true` | **0** | 0 | `semantic_validator`: 4, `triager`: 7 |
| `judge_extended` | **0** | 0 | `semantic_validator`: 4 |

`LocalJudge` ([local_judge.rs](../core/crates/ares-mapper/src/local_judge.rs)) has
four rules plus two extended heuristics, targeting `TypeCosplay`,
`OwnershipCheck`, `SignerAuthorization`, `ArbitraryCpi`, `ReentrancyRisk`,
`UncheckedCast`, `DuplicateMutableAccounts`. Every one of those categories is
present in what it saw — type-cosplay (32-37 predictions across runs),
arbitrary-cpi (8-9), missing-signer-check (7-56) all reach the judge before the
triager or the LLM judge run. It suppressed none of them, in any run, including
the 169-finding-larger set from `--ast-scan`.

**Root cause, confirmed by direct read, not inference:** the judge decides from
`SourcePatterns` ([source_patterns.rs](../core/crates/ares-mapper/src/source_patterns.rs))
— 10 program-wide booleans (`is_anchor_heavy`, `has_raw_handler`, etc.),
populated once per program at
[lib.rs:974](../core/crates/ares-mapper/src/lib.rs:974). Across this 159-target
corpus — a mix of native Solana, Anchor, and incident-repro code — those
booleans and the judge's specific per-category conditions (e.g. Rule 1 requires
`is_anchor_heavy && unchecked_fields == 0`) never aligned. This is not a
tuning gap in the four rules; it's evidence the judge's *inputs* are too coarse
for this corpus's diversity to ever trigger a suppression.

A second, much richer field-level `SourcePatterns` (~30 booleans, tracking
individual struct fields rather than whole-program aggregates) already exists in
[benchmark/patterns.rs](../core/crates/ares-cli/src/commands/benchmark/patterns.rs),
but is wired only into `ares benchmark`, not `scan`. **This is the concrete Tier
2 direction:** give `LocalJudge` the benchmark's field-level view instead of
writing more program-wide rules of the same shape, which this measurement shows
don't fire.

The only thing that suppressed anything was `semantic_validator` (runs before
the local judge) and, once `--ast-scan` added lower-confidence findings,
`triager` (the 0.70 confidence-threshold filter, which runs last). Both are
outside ENG-5's scope. `semantic_validator`'s 4 removals were 3 correct FP kills
and 1 real finding wrongly dropped (see Result 4), all in `arbitrary-cpi`.

## Result 3 — flipping `--ast-scan` to default-on today would fail the CI gate

| | Default | `--ast-scan true` |
|---|---|---|
| Precision | 0.7731 | 0.4819 |
| Recall | 0.5412 | 0.5471 |
| **F1** | **0.6367** | **0.5124** |
| vs. CI floor (0.61) | pass | **fail** |

One extra true positive (92 → 93) for 73 extra false positives (27 → 100). The
damage concentrates in one category:

| Category | Default (TP/FP) | `--ast-scan` (TP/FP) |
|---|---|---|
| `missing-signer-check` | 0 / 7 | 1 / **55** |
| `type-cosplay` | 29 / 3 | 29 / 8 |
| `arbitrary-cpi` | 5 / 3 | 5 / 4 |
| `missing-reload-after-cpi` (new) | — | 0 / 7 |
| `unsafe-type-cast` (new) | — | 0 / 5 |

`missing-signer-check` precision is 0.0179. That heuristic is
`ast_scanner.rs`'s per-parameter signer check
([ast_scanner.rs:150,432](../core/crates/ares-mapper/src/ast_scanner.rs:150)) —
this is the specific detector to fix before that category can carry any weight,
named here rather than left as an aggregate number.

**This is exactly the evidence ENG-4 said it was waiting for before flipping the
default** ([scan.rs:205-213](../core/crates/ares-cli/src/commands/scan.rs:205)).
The answer today is *not yet*, with a named culprit. This document does not
change the flag — that stays ENG-4's call — but the two runs above are
reproducible inputs to it.

## Result 4 — `judge_extended`'s two dormant rules never fire on this corpus

Run C (`judge_extended = true`) is **byte-identical** to the default run: same
232 predictions, same suppression table, same F1. `judge_extended` has gated two
rules since it was added — a large-DEX unchecked-cast allowance and an
Anchor-heavy duplicate-mutable-accounts allowance — and neither has ever
executed in CI or in this measurement. Not urgent to remove or fix; recorded so
nobody spends time tuning a flag that provably does nothing on the available
corpus, and so enabling it isn't mistaken for a win without first checking why
it's silent.

## Result 5 — the one real defect found: `semantic_validator` deleted a true positive

Across every run, `semantic_validator` suppressed 4 `arbitrary-cpi` findings: 3
were not in ground truth (correct kills) and 1 was (`lost_tp` — a real finding
destroyed before the local judge, the triager, or the LLM judge ever saw it).
This is outside `local_judge.rs` and therefore outside ENG-5's direct scope, but
it is the only concrete false-negative-causing bug this measurement surfaced,
and it's worth a follow-up ticket against `validator.rs` rather than silently
noting it here and moving on.

## Determinism (GOLDEN RULE 2)

The default scan was run twice. The first pass showed 105/159 reports differing
— traced to two sources, both outside the scored fields: the `-o` output
directory path is baked into each finding's `proof_of_concept` field (the two
runs used different directories, by necessity, to compare them), and the
generated PoC `.rs` file's header carries a wall-clock `// Generated:` comment.
After normalizing both, **0 real differences across 159/159 targets** in
`findings`, `suppressed_findings`, and `summary` — the fields every score in
this document is built from. Determinism holds for everything that matters here;
it does not hold for two cosmetic fields that were never claimed to be
deterministic.

## What this justifies going forward

1. **Tier 2 is justified, and scoped:** give `LocalJudge` the field-level
   `SourcePatterns` that `benchmark/patterns.rs` already computes, rather than
   adding more program-wide rules — this measurement shows the existing shape of
   rule provably does not fire on real, diverse code.
2. **`--ast-scan`'s default should stay off** until `missing-signer-check`'s
   precision is fixed — that is ENG-4/ENG-3 territory, not this ticket's, but the
   number is now on record for whoever picks it up.
3. **`judge_extended` is inert, not proven, and not disproven** — worth
   understanding why before either removing it or promoting it.
4. **One bug filed, not fixed here:** `semantic_validator`'s `arbitrary-cpi`
   false-negative, owned by `validator.rs`, outside this ticket's file.

Nothing in `core/`, `.github/workflows/ci.yml`, or `eval/predictions/ares-latest.csv`
was changed to produce this document.
