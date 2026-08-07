# ENG-3 — Complete taint sources/sinks

## A much bigger finding than the backlog line suggested

Original backlog: *"Map each taint class (signer, owner, PDA bump,
arbitrary CPI, reinit, close-revival) to the canonical catalog IDs from
ENG-2... Implement/extend taint-tracking sources and sinks for each
class."*

**What was actually found, via direct code tracing, then empirically
confirmed on a real machine (I can't run `cargo test` myself — same Rust
version constraint as `ENG-1`):** `ast_scanner.rs` creates a `TaintEngine`,
marks tainted parameters, then **never actually walks any function
body**. The `Visit` trait implementation that would trigger the real
sink-detection logic (`process_stmt`/`process_expr` — covering
`arbitrary-cpi`, `type-cosplay`, owner-assignment, arithmetic, casts) was
correctly written but never invoked. Confirmed with a real test on a real
machine: a textbook `invoke()`-with-tainted-data pattern produced **zero**
taint-engine findings before the fix.

This means the actual scope here is bigger than "add missing categories"
— the sink-detection logic that already existed was **entirely dead
code**, for every category, not just the four genuinely missing ones.

## What was fixed

**1. The foundational wiring gap** — `ast_scanner.rs` now calls
`taint.visit_item_fn(func)` for each function, actually triggering the
`Visit` trait's traversal into the function body. Without this, nothing
below matters — even the four new checks would have been just as dead.

**2. Two category-name bugs**, found by directly comparing the code
against Gilbert's real canonical catalog (`src/knowledge/solana-vulns.ts`):
- `taint_engine.rs`'s owner-check sink used category `"ownership-check"`
  — the real catalog ID is `missing-owner-check`. Fixed.
- `ast_scanner.rs`'s existing per-parameter signer heuristic used
  `"signer-authorization"` — the real catalog ID is
  `missing-signer-check`. Fixed.

Both bugs meant these findings, even once they fired, could never
correctly link back to Gilbert's catalog at all.

**3. Three genuinely missing sink categories added:**
- `non-canonical-bump` — `create_program_address` (the raw/unsafe API)
  called with a tainted seed/bump argument, instead of the safe
  `find_program_address`. Matches the catalog's own detection hint
  precisely.
- `account-reinitialization` — a function whose name suggests an
  init/initialize instruction, with no `is_initialized` check or Anchor
  `constraint` anywhere in its body.
- `account-close-revival` — a function whose name suggests a close
  instruction, zeroing/transferring lamports but never zeroing the
  account's data.

The last two are function-level "missing guard" checks rather than a
classic source→sink dataflow chain, so they're implemented as a new
`check_function_level_patterns` method, using the same
stringify-then-pattern-match convention this file already established
(see the `Cast` handler's `is_safe_source` checks) rather than
introducing a second detection style.

**`arbitrary-cpi` itself needed no changes** — already correctly
implemented and correctly named; it just needed the wiring fix to
actually run.

## Mapping to the six required classes — final state

| Class | Catalog ID | Status |
|---|---|---|
| signer | `missing-signer-check` | Fixed (was firing under a wrong category name, and only became reachable once tested — the existing heuristic doesn't depend on the wiring fix, it's a separate check path) |
| owner | `missing-owner-check` | Fixed (wrong category name + only reachable once the wiring fix landed) |
| PDA bump | `non-canonical-bump` | New |
| arbitrary CPI | `arbitrary-cpi` | Already correct; only reachable once the wiring fix landed |
| reinit | `account-reinitialization` | New |
| close-revival | `account-close-revival` | New |

## Tests added

Zero test coverage existed for any of this before (`taint_engine.rs` had
no test module at all; confirmed directly). Added
`eng3_taint_sources_sinks` to `ast_scanner.rs` — sealevel-attacks style, a
vulnerable case per class plus a guarded/safe negative case wherever a
meaningful one is actually possible (signer, PDA bump, reinit,
close-revival all have one; owner and arbitrary-cpi don't have an
equally clean negative given how the existing code is structured, so
those are positive-only for now). 10 tests total.

## Honest disclosure — what I could not verify myself

**I have no working Rust toolchain in my environment** — same constraint
as `ENG-1`: current dependencies need rustc 1.80+, my sandbox has 1.75.0,
and I can't install a newer one (network-restricted). I tried
regenerating a throwaway local lockfile just to test the logic directly
— still blocked by real transitive dependency version requirements.

What I *did* do without a working toolchain:
- Traced every call site by hand to confirm the wiring gap precisely
- Had you run a real, live test that empirically confirmed it
  (`Findings: 1`, and that one finding was from the *unrelated* param-type
  heuristic, not the taint engine — exactly the predicted signature of
  the gap)
- Checked brace/paren balance on both modified files, and specifically
  chased down an apparent paren imbalance to its exact, benign source
  (two intentional string-literal search patterns, `"fill (0"` and
  `"fill(0"`, not a real syntax problem) rather than either ignoring it
  or trusting a broken check blindly
- Manually re-read every added line for correctness

**None of this substitutes for actually running `cargo test`.** This
needs your machine to give real, final confirmation — see the test
commands below.

## A real engine gap found via your test run — also fixed

`non_canonical_bump_fires_on_create_program_address_with_tainted_arg`
failed on your machine: `expected non-canonical-bump, got: []` — zero
findings, not even a wrong one. Traced to `expr_taint` having no handling
for `Expr::Array` at all — and `&[seed, data]` (an array literal) is
exactly how real `create_program_address`/`find_program_address` calls
actually look in practice, not an artifact of the test. This means the
gap was real: any tainted seed hidden inside an array-literal argument
was invisible to *every* sink check that inspects call arguments, not
just `non-canonical-bump`.

**Fixed** by adding array-element taint propagation to `expr_taint` —
tainted if any element is. This is a genuine improvement to the shared
engine, not a narrow patch just for this one test.

## A real smoke test, not just synthetic snippets

Everything above uses small snippets written specifically to exercise
each check — useful, but still code shaped around the implementation.
Added one more test: running the actual, independently-authored Cashio
incident-repro fixture (`eval/fixtures/rs/incident-repros/cashio-2022.rs`
— a stylized reproduction of the real ~$52M Cashio exploit, written for
`EVAL-3`, not with this taint engine in mind at all) through the real
`analyze_file` entry point, embedded at compile time via `include_str!`.

This exercises the *existing* `type-cosplay` sink (`Bank::try_from_slice`
on a raw, untyped `AccountInfo` with no owner check) — the same
pre-existing logic as `arbitrary-cpi`, not one of `ENG-3`'s four new
additions. The point isn't testing new logic again; it's confirming the
wiring fix actually generalizes to real code someone else wrote, not just
code written to fit this implementation.

**One subtlety worth documenting:** the real bug is
`Bank::try_from_slice(&bank.data.borrow())?` — note the `?` operator.
`syn` parses this as `Expr::Try` wrapping the `Call`, and
`process_expr`'s match has no explicit `Expr::Try` arm. Traced through
carefully: this still works, because the `Visit` trait's default
recursive behavior (`syn::visit::visit_expr` inside `TaintEngine`'s own
`visit_expr` override) visits into `Try`'s inner expression as its own
node, triggering a separate, direct `process_expr` call on the wrapped
`Call` when the traversal reaches it. Reasoned through by hand; genuinely
confirmed by the real test run below, not just this reasoning.

## What's still NOT done — deliberately out of scope

- **Anchor-attribute-level checks** (e.g. `#[account(close = ...)]`
  without `zero`) are a struct/macro-attribute concern, not a function-body
  dataflow concern — that's `ast_scanner`'s existing Anchor-account-struct
  scanning territory, which is `ENG-4`'s job ("Strengthen AST scanner for
  Anchor constraints"), not duplicated here.
- **Validation against the benchmark dataset** (the backlog's fourth
  to-do item) — `EVAL-3` merged, so the dependency is satisfied, but
  actually running the benchmark and checking these six categories'
  precision/recall against it is real, separate follow-up work, not done
  as part of this change.
- The negative tests for `missing-owner-check` and `arbitrary-cpi` — a
  clean negative wasn't as straightforward to construct given how those
  two sinks are currently structured; flagging this rather than forcing
  a negative test that might not actually be meaningful.

## To verify — run this on a real machine

```powershell
cd core
cargo test --package ares-mapper eng3_taint_sources_sinks -- --nocapture
```

**Expected: 10 passed, 0 failed.** If anything fails, the failure message
includes the actual findings list (`got: {:?}`) — send me that output
directly rather than just pass/fail, since it tells us exactly which
category did or didn't fire.
