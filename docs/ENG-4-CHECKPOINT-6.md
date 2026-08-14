# ENG-4 — Checkpoint 6: the actual wiring into `scan.rs`

Stacking on top of Checkpoints 1–5. This is the real, senior-approved,
Tier 3 change — everything before this was preparation for this one.

## The design, and why each piece

**A new `--ast-scan` flag on `ares scan`, defaulting to `false`.** Every
other detector in this pipeline earned its default-on status with real
evidence: the hypothesis pipeline has a measured `EVAL-3` F1 of `0.3007`.
`ast_scanner` has never been measured against a real corpus at scale.
Checked this reasoning against real industry practice before committing
to it: Semgrep, CodeQL, and commercial SAST tools all ship new rules as
opt-in/experimental first, measure them, then promote — this isn't an
arbitrary caution, it's the standard the rest of this codebase (and the
security-tooling industry generally) already follows. Wiring in fully
(satisfying "all in one" architecturally) while defaulting off (following
the same rollout discipline every other detector here already went
through) are two separate decisions, not in tension with each other.

**Real production exposure, checked directly rather than assumed:**
`apps/auditor-api`'s worker — the actual, automatic, customer-facing
backend — exclusively calls the TS CLI (`npm run audit`). It never
touches `core/`'s Rust binary at all. This file, `scan.rs`, is not
currently in any automatic, customer-facing path — confirmed by grepping
the whole `apps/`/`services/`/`src/` tree for any caller. That doesn't
change the rollout discipline above, but it did change how much weight
the "default on vs off" question carries: real exposure today is
effectively zero either way.

**Insertion point:** right after the existing `cross_analysis` findings
loop, before fuzzing/PoC generation. Calls
`ares_mapper::ast_scanner::scan_directory_ast(program_path)` — the same,
already-validated `program_path` every other stage uses — and converts
each `AstFinding` into a real `ares_core::Finding` using the Checkpoint 4
bridge (`ast_category_to_core_category_str`) plus the exact same
`VulnerabilityCategory::from_str_checked(...).unwrap_or(InvariantViolation)`
pattern `cross_analysis`'s own findings already use.

**No separate confidence gate at the insertion point** — matches how
hypothesis and cross-analysis findings are already handled; all three
rely on the existing Phase-5 triager (`>= 0.70`) applied uniformly
afterward, not their own early filter.

**One call captures both `ENG-3` and `ENG-4`'s work.** `scan_directory_ast`
already aggregates every file's `analyze_file` output, which internally
includes `taint_engine`'s own findings (wired in back in `ENG-3`) — no
separate call needed for the taint engine specifically.

## A real mistake, caught before it went anywhere

While inserting the new code, an `str_replace` accidentally **deleted**
the existing `cross_findings` conversion loop entirely — included it in
the "old" text being replaced, but didn't carry it into the "new" text.
Caught by grepping for `ARES-CROSS` immediately after the edit and
finding nothing, restored it properly before doing anything else. Worth
disclosing plainly rather than glossing over: this is exactly the kind of
mistake a Tier 3 change can't afford, and it's why every edit to this
file was verified individually rather than trusted on the first pass.

## Traced through every downstream stage by hand, not just the entry point

A finding pushed at the insertion point still has to survive the
validator, local judge, and LLM judge before it ever reaches the triager.
Checked each directly against the real test case this checkpoint adds
(a raw `AccountInfo` handler with no signer check, confidence `0.70`):

- **Confidence boundary:** the triager's cutoff is `>= 0.70` (inclusive),
  and this finding's confidence is exactly `0.70` — both are the same `f64`
  literal parsed by the same compiler, so this is an exact match, not a
  floating-point risk.
- **`validator.rs`'s `check_signer`:** reads `finding.location.function`
  to correlate against a known instruction. This wiring doesn't populate
  `function` (see the disclosed limitation below), so the lookup misses
  and the check falls through to "not suppressed" — the finding survives,
  just without the benefit of that correlation.
- **`local_judge.rs`'s signer-authorization rule:** requires
  `patterns.is_anchor_heavy`, which is false for this native/raw test
  program — rule doesn't apply, finding survives.
- **LLM judge:** the existing tests in this same file already exercise
  this same step through the same `execute()` call, unconditionally —
  if it required real network/API access to pass reliably, those tests
  couldn't already be passing. Relying on that established precedent
  rather than re-verifying `LlmJudge`'s own fallback behavior from
  scratch.

## A real, disclosed limitation — not silently left out

**`location.function` is never populated** for AST-scanner-derived
findings in this wiring. `AstFinding` doesn't carry a separate,
structured function-name field the way it carries `file`/`line` —
handler names only exist interpolated into the description string,
which isn't something to parse back out reliably. This means these
findings don't get the benefit of the validator's function-level
correlation logic the way hypothesis findings do. Not a bug — the
finding still reaches the report — just a real scope boundary,
worth fixing properly in a follow-up (extending `AstFinding` with an
`Option<String>` function field) rather than rushed into this already
substantial change.

## Verified

- Confirmed directly (not assumed) that `apps/auditor-api` never touches
  the Rust binary, before treating that as part of the risk calculus
- Confirmed `ast_scanner` is `pub mod` and already reachable from
  `ares-cli` (via the existing `ares_mapper::MapperAgent` import), and
  that `ares-mapper` is already a declared dependency
- Found and fixed a real bug in my own edit (the deleted `cross_findings`
  loop) before it went anywhere
- Traced the finding's survival through every intermediate pipeline stage
  by hand — validator, local judge, LLM judge, triager — not just the
  insertion point
- Updated **all 3** real callers of `scan::execute` (`main.rs`, `agent.rs`,
  and 3 separate call sites in the integration test file), found by
  grepping the whole workspace rather than assuming `main.rs` was the
  only one
- Brace/paren balance checked individually across all 4 modified files:
  every one perfectly even
- 1 new integration test, exercising the real, complete `execute()` path
  end-to-end with `ast_scan: true`, checking the actual written JSON
  report for an `ARES-AST-*` finding ID — not a narrower unit test

**Not yet verified: `cargo test`, or an actual real-world scan run.**
This is the biggest change of the whole `ENG-4` task; it genuinely needs
real verification before going further, more than any prior checkpoint.

## To verify

```powershell
cd core
cargo test --package ares-cli ast_scan_true_makes_ast_scanner_findings_reach_the_real_report -- --nocapture
```

**Expected: 1 passed.** This is a real, complete `execute()` run (writes
actual files to a scratch directory, runs the whole pipeline including
the LLM judge step), so expect it to take longer than the `ares-mapper`
unit tests.

Also worth running the other 3 pre-existing tests in this same file, to
confirm the new parameter didn't disturb anything already passing:

```powershell
cargo test --package ares-cli --test scan_provenance_integration
```

**Expected: 4 passed** (3 pre-existing + this new one).
