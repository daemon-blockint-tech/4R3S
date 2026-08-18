# ENG-5 — Measuring the local judge before tuning it (Step B)

## Why this exists

ENG-5 asks to improve the local judge's false-positive suppression and measure
precision per class. Its dependencies, ENG-3 (taint sources/sinks) and EVAL-3
(benchmark + metrics), are both merged. But nobody had ever measured what the
judge currently does — every scan already records what each suppressor removed
and why (`AuditReport.suppressed_findings[]`), and nothing in `eval/` read it.

Step A (`eval/score_suppression.py`, `eval/test_score_suppression.py`) built the
reader. This is Step B: running it for real, on a freshly fetched corpus and a
freshly built engine, four ways.

**All figures below are re-derivable** from the committed files in
`eval/baselines/` (GOLDEN RULE 3) — see `eval/baselines/README.md` for the exact
commands. Ground truth for every run below: **170 rows, 159 targets, 14
categories, sha256 `e179a0906ce47953…`**. No accuracy claim in this document is
published anywhere else; `eval/check_published_claims.py` governs that
separately and reads `eval/predictions/ares-latest.csv`, not this file.

## Machine / corpus state at measurement time

- Engine rebuilt from `core/` as of `dc51811` (this branch changes no Rust code,
  so the engine measured here is exactly `main`'s).
- Corpus fetched fresh: `fetch_datasets.py` (152 rows) then
  `fetch_sealevel_attacks.py`, `fetch_neodyme_workshop.py`,
  `build_incident_repros.py` (append + de-dupe) → 170 rows / 159 targets.
- Four scans, `--fuzz false` in all: **A** default (documented flags, nothing
  added), **B** `--ast-scan true` (the ENG-3/ENG-4 taint path, opt-in,
  `scan.rs:213`), **C** `judge_extended = true` (the local judge's two dormant
  rules, reachable only via `AresConfig`, no CLI flag), and **D** both together —
  added after C alone turned out not to be a fair test of the extended rules
  (see Result 4).
- All four: 159/159 targets scanned, 0 failures.

## Result 1 — the committed evidence is not stale

Run A's predictions (232 rows) are **byte-identical, after sorting, to the
committed `eval/predictions/ares-latest.csv`** — despite 9 commits touching
`core/` since that file was last regenerated (all six ENG-4 checkpoints, a
`cargo fmt`, a dependency bump). The plan flagged this as the likely failure
mode (R1); it didn't happen. DET-3/4/5's and EVAL-4's numbers still describe
`main` accurately.

## Result 2 — the local judge suppressed nothing, in any of the four runs

| Run | `local_judge` suppressions | `llm_judge` suppressions | Other suppressors |
|---|---|---|---|
| A — default | **0** | 0 (disabled by default) | `semantic_validator`: 4 |
| B — `--ast-scan true` | **0** | 0 | `semantic_validator`: 4, `triager`: 7 |
| C — `judge_extended` | **0** | 0 | `semantic_validator`: 4 |
| D — both | **0** | 0 | `semantic_validator`: 4, `triager`: 7 |

`LocalJudge` ([local_judge.rs](../core/crates/ares-mapper/src/local_judge.rs)) has
four rules plus two extended heuristics, targeting `TypeCosplay`,
`OwnershipCheck`, `SignerAuthorization`, `ArbitraryCpi`, `ReentrancyRisk`,
`UncheckedCast`, `DuplicateMutableAccounts`. Every one of those categories is
present in what it saw — type-cosplay (32-37 predictions across runs),
arbitrary-cpi (8-9), missing-signer-check (7-56) all reach the judge before the
triager or the LLM judge run. It suppressed none of them, in any run, including
the 169-finding-larger set from `--ast-scan`.

**Root cause.** The judge decides from `SourcePatterns`
([source_patterns.rs](../core/crates/ares-mapper/src/source_patterns.rs)) — 10
program-wide booleans (`is_anchor_heavy`, `has_raw_handler`, …), populated once
per program at [lib.rs:974](../core/crates/ares-mapper/src/lib.rs:974). Each rule
is a conjunction over them plus a category test; Rule 1, for instance, needs
`is_anchor_heavy && unchecked_fields == 0`.

Being precise about what is established here, since it drives a design decision:
the rule conditions are read directly from the source, and the judge is confirmed
to have *executed* (it logs `Local Judge: Suppressed 0 false positives
deterministically` on every target). Given that it ran, and that findings in its
target categories were present, it follows that none of those conjunctions ever
held. What is **not** recoverable from the artifacts is *which* clause failed on
which target — `SourcePatterns` is never serialized into the report. Anyone doing
Tier 2 should log those booleans first; this measurement can prove the rules
don't fire but not, per target, why.

Either way the conclusion for ENG-5 is the same: this is not a tuning gap in the
four rules' thresholds, it is the judge's *inputs* being too coarse for a corpus
this varied.

A second, much richer field-level `SourcePatterns` (~30 booleans, tracking
individual struct fields rather than whole-program aggregates) already exists in
[benchmark/patterns.rs](../core/crates/ares-cli/src/commands/benchmark/patterns.rs),
but is wired only into `ares benchmark`, not `scan`. This remains a genuinely open
option — **not attempted tonight**, not disproven either. See "Tier 2 attempt"
below for what was tried instead, and why it didn't reach this option.

The only thing that suppressed anything was `semantic_validator` (runs before
the local judge) and, once `--ast-scan` added lower-confidence findings,
`triager` (the 0.70 confidence-threshold filter, which runs last). Both are
outside ENG-5's scope. `semantic_validator`'s 4 removals were 3 correct FP kills
and 1 real finding wrongly dropped (see Result 5), all in `arbitrary-cpi`.

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

"Fails the gate" here means verified by exit code, not read off a threshold:
`score_detections.py` returns 1 when F1 is under `--target-f1`
([score_detections.py:262](../eval/score_detections.py:262)), and the
`verify-claims` scoring step passes `--target-f1 0.61`
([ci.yml:400](../.github/workflows/ci.yml:400)). Running Run B's predictions
through that exact invocation exits **1**; Run A's exits **0**.

Note for whoever touches that job next: the comment directly above that command
claims it is "Scored WITHOUT `--target-f1`", which the command itself
contradicts. The 0.61 comparison *does* block; the separate non-blocking check
below it is the 0.94 one. Not corrected here — `ci.yml` belongs to DET-3/4/5.

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

## Result 4 — `judge_extended`'s two dormant rules never fire, even when given input

`judge_extended` gates two rules: a large-DEX unchecked-cast allowance
(`UncheckedCast`) and an Anchor-heavy duplicate-mutable-accounts allowance
(`DuplicateMutableAccounts`).

Run C (`judge_extended = true`, default detector path) is byte-identical to the
default run. **But Run C alone does not prove the rules are inert** — the default
path emits **zero** `unchecked-cast` and zero `duplicate-mutable-accounts`
findings, so neither rule had any input to act on. That is an unfair test, and
reporting it as proof would have been wrong.

`unchecked-cast` findings appear only with `--ast-scan` (11 of them), so a fourth
run was added to close the gap:

| Run | `--ast-scan` | `judge_extended` | `unchecked-cast` findings | `local_judge` suppressions |
|---|---|---|---|---|
| A | off | off | 0 | 0 |
| B | **on** | off | **11** | 0 |
| C | off | **on** | 0 | 0 |
| D | **on** | **on** | **11** | **0** |

**Run D is byte-identical to Run B.** So with its target category present and its
flag enabled, the extended unchecked-cast rule still suppressed nothing. Reading
the rule explains why: it additionally requires `patterns.is_large_dex`, defined
as `graph.instructions.len() > 100`
([lib.rs:983](../core/crates/ares-mapper/src/lib.rs:983)) — a threshold no
single-file staged target in this corpus reaches. The second rule
(`DuplicateMutableAccounts`) had zero input in every run, so it remains genuinely
untested rather than disproven.

Recorded so nobody mistakes enabling this flag for a fix, and so the distinction
between "tested and inert" (rule 1) and "never had input" (rule 2) is not lost.

## Result 5 — the one real defect found: `semantic_validator` deleted a true positive

Across every run, `semantic_validator` suppressed 4 `arbitrary-cpi` findings: 3
were not in ground truth (correct kills) and 1 was (`lost_tp` — a real finding
destroyed before the local judge, the triager, or the LLM judge ever saw it).

The lost one is named, not aggregated: **`sealevel-attacks:5-arbitrary-cpi`** —
the sealevel-attacks corpus's own textbook arbitrary-CPI example, where ground
truth records `arbitrary-cpi` as precisely the vulnerability being taught, and no
retained finding covers it. The detector found it and `validator.rs` threw it
away.

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
this document is built from. Determinism holds for everything that matters here.

Worth noting rather than burying, though: the `// Generated:` wall-clock stamp
means a generated PoC file is **not** byte-reproducible across runs, even for
identical input. That breaks nothing measured here and violates no current
claim — GOLDEN RULE 2 is about the *detection path*, which is clean — but if the
project ever wants to claim reproducible PoC artifacts, that timestamp is the
one thing standing in the way. Not changed here; `poc.rs` is outside this ticket.

## What this justifies going forward

1. **Tier 2 is justified, and scoped:** give `LocalJudge` the field-level
   `SourcePatterns` that `benchmark/patterns.rs` already computes, rather than
   adding more program-wide rules — this measurement shows the existing shape of
   rule provably does not fire on real, diverse code.
2. **`--ast-scan`'s default should stay off** until `missing-signer-check`'s
   precision is fixed — that is ENG-4/ENG-3 territory, not this ticket's, but the
   number is now on record for whoever picks it up.
3. **`judge_extended` is measured, and split:** its unchecked-cast rule is
   *tested and inert* (Run D gave it 11 findings of its target category and it
   still fired zero — blocked by `is_large_dex`, which no single-file target
   reaches); its duplicate-mutable-accounts rule is *still untested*, having had
   zero input in every run. Neither is a reason to enable the flag today.
4. **One bug filed, not fixed here:** `semantic_validator`'s `arbitrary-cpi`
   false-negative, owned by `validator.rs`, outside this ticket's file.

Nothing in `core/`, `.github/workflows/ci.yml`, or `eval/predictions/ares-latest.csv`
was changed to produce this document.

## Tier 2 attempt: three rule ideas, three dead ends — no new judge rule shipped

Given Result 2's root cause, the obvious next step is a per-finding rule instead
of a per-program one. Three were checked against the actual code and data before
writing anything into `local_judge.rs`. Each failed for a different, concrete
reason, and the third surfaced a genuine bug elsewhere. No suppression rule and
no plumbing change shipped from this — changing the judge's signature only earns
its place once a rule needs the richer data; none of these three did.

**Idea 1 — cross-validate a finding against the mapper's own per-instruction
flag.** `InstructionNode` already carries `has_signer_check` / `has_owner_check`
/ `has_cpi_program_id_check` per instruction
([lib.rs:79-81](../core/crates/ares-mapper/src/lib.rs:79)), and
`finding.location.function` is already populated with the matching instruction
name for `SignerAuthorization`, `OwnershipCheck`, and `ArbitraryCpi`
([scan.rs:698](../core/crates/ares-cli/src/commands/scan.rs:698),
[:736](../core/crates/ares-cli/src/commands/scan.rs:736),
[:752](../core/crates/ares-cli/src/commands/scan.rs:752)). A per-finding join
looked immediately possible.

*Dead on arrival:* `generate_initial_hypotheses` only ever generates each of
those three hypotheses when the *same* flag already reads "bad" — e.g.
`SignerAuthorization` requires `has_signer_check == Some(false)`
([scan.rs:691](../core/crates/ares-cli/src/commands/scan.rs:691)). By the time a
finding exists, the flag it would be cross-checked against can never say
"checked." This is not two independent opinions disagreeing; it's one opinion
checking itself. The same holds for `OwnershipCheck` and `ArbitraryCpi`.

**Idea 2 — the same cross-check for `--ast-scan`'s `missing-signer-check`,** a
genuinely separate detector (`ast_scanner.rs`) and, per Result 3, the single
biggest false-positive source (55 FPs) — a real disagreement is at least
possible there.

*Blocked, not disproven:* `AstFinding`
([ast_scanner.rs:42-49](../core/crates/ares-mapper/src/ast_scanner.rs:42)) carries
no function/instruction name, and `location.function` is left `None` for every
finding this path produces
([scan.rs:240](../core/crates/ares-cli/src/commands/scan.rs:240)). There is no
join key today. Adding one means editing `ast_scanner.rs`, ENG-3/ENG-4's
actively-developed file, not ENG-5's.

**Idea 3 — loosen the extended `UncheckedCast` rule's `is_large_dex` gate** so it
can act on the 5 `unsafe-type-cast` findings `--ast-scan` already produces
(Result 4). `is_large_dex` (`instructions.len() > 100`) never holds on a
single-file staged target, so the rule is unreachable regardless of corpus
content — loosening it looked like a safe, narrow, testable change.

*Rejected after reading the actual findings, not the rule.* None of the 11 raw
findings behind those 5 rows resemble the rule's own stated justification
("large DEX with custom fixed-point math wrappers" — Drift/Mango style). They're
small `solana-vuln-rust` training snippets: a fee-calculation cast, a
quantity/price multiplication, and one reading "Unchecked cast on tainted data
(InstructionData)" — a description naming exactly the shape of a real finding,
not obvious noise. Ground truth has no row for this category on any of these
targets, so "0 TP" means *unlabeled*, not *confirmed false*. Loosening the gate
would suppress these under a rationale that is factually false for this data —
moving a number by asserting something untrue about the code, the one thing
GOLDEN RULE 3 exists to prevent. Not done.

**What Idea 3 surfaced instead: a confirmed bug in `ast_scanner.rs`'s cast
detector**, unrelated to the local judge and not fixed here. `visit_expr`
([ast_scanner.rs:569](../core/crates/ares-mapper/src/ast_scanner.rs:569)) is
`syn`'s generic per-expression visitor: it fires once for *every* `Expr` node,
including every ancestor of a real cast, not only the `Expr::Cast` node itself.
`expr_str = quote::quote!(#node).to_string()`
([:570](../core/crates/ares-mapper/src/ast_scanner.rs:570)) stringifies whichever
node is currently being visited, so an outer expression that merely *contains* a
cast somewhere inside it also matches `expr_str.contains("as u64")`
([:694](../core/crates/ares-mapper/src/ast_scanner.rs:694)). The description then
shows `expr_str.chars().take(60)`
([:736](../core/crates/ares-mapper/src/ast_scanner.rs:736)) — the first 60
characters of that *outer* node, which is the ancestor's own start, not the cast.
That is exactly what the three `6bae2130540f` findings show: three different
60-character prefixes, each a bigger enclosing expression, none showing the
actual `as` keyword because it sits past character 60 in all three. Net effect:
one real cast can generate one misleadingly-labeled finding per ancestor node on
its path to the nearest enclosing statement or call — a duplication-and-mislabeling
bug, not a suppression opportunity for `local_judge.rs`. Flagged for whoever owns
`ast_scanner.rs`; not investigated further or fixed here.
