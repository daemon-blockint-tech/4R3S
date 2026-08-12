# ENG-4 — Checkpoint 1: catalog category-name fixes

Per your senior's direction: the AST scanner should be wired into the real
scan pipeline, all-in-one with the platform auditor. Before doing that
architectural change, fixing the scanner's own detection-quality issues
first — wiring in a scanner with known bugs, then fixing the bugs
afterward, seemed backward.

## What this checkpoint covers

The task's own to-do says: *"Cross-reference detections against the
canonical catalog IDs from ENG-2."* Doing that literally surfaced 8 real
bugs — every one of these findings currently cannot correctly link back to
Gilbert's canonical catalog (`src/knowledge/solana-vulns.ts`), since the
category strings used don't exist there at all.

| Wrong string used | Real catalog ID | Occurrences |
|---|---|---|
| `"ownership-check"` | `missing-owner-check` (3 of 4) | lines 391, 578, 601 |
| `"ownership-check"` | `anchor-constraint-gap` (1 of 4 — see below) | line 295 |
| `"unchecked-cast"` | `unsafe-type-cast` | lines 589, 624, 674 |
| `"revival-attack"` | `account-close-revival` | line 717 |
| `"re-initialization"` | `account-reinitialization` | line 731 |

## Update — the broad-sweep test caught something the manual grep missed

Ran on a real machine: 1 of 2 tests passed, but the sweep test failed on a
category `"unchecked-cast"` finding whose description didn't match
anything in `ast_scanner.rs` at all. Traced it to **`taint_engine.rs`** —
a second file that also contributes findings to `analyze_file`'s output
(wired in during `ENG-3`), which I didn't check this round since the
initial grep only covered `ast_scanner.rs`.

Found 2 more occurrences there — and they needed **different** fixes, not
the same one:

- **Arithmetic sink** (`Add`/`Sub`/`Mul`/`Div`/`Rem`/`Shl`/`Shr` on tainted
  values) → corrected to `integer-overflow-underflow`, not
  `unsafe-type-cast` — the catalog's own description ("arithmetic
  operations... do not use checked math... allowing overflow/underflow")
  is a precise match, confirmed before fixing
- **Actual cast sink** (`expr as u64`-style, tainted, no safe wrapper) →
  correctly `unsafe-type-cast`, same as the `ast_scanner.rs` fixes

All 22 category strings across both files now verified against the real
catalog — 8 originally found by grep, 2 more found only by actually
running the test.

## Not a blanket fix — one real miscategorization caught by checking each individually

Initially applied a uniform substitution (`"ownership-check"` →
`missing-owner-check`), then reconsidered before finalizing: the catalog's
`anchor-constraint-gap` entry describes *"using UncheckedAccount without
[constraints]"* — almost word-for-word the exact pattern one of these four
findings detects (`is_unchecked && !is_signer && !has_owner &&
!has_constraint` in Anchor's `#[derive(Accounts)]` struct scanning).
Checked each of the 4 original occurrences' full context individually
before finalizing, rather than trust the blanket fix:

- **Line 295** (Anchor struct field, `UncheckedAccount` with zero
  validation) → corrected to `anchor-constraint-gap` — this is precisely
  what that catalog entry names
- **Line 391** (Solitaire raw `Info<'b>` standing in for a typed/verified
  account) → `missing-owner-check` — about verifying account *identity*,
  not a declarative Anchor constraint; Solitaire has no `#[account(...)]`
  macro system for `anchor-constraint-gap` to apply to anyway
- **Line 578** (oracle `_unchecked` function skipping owner validation) →
  `missing-owner-check` — the description explicitly says "owner
  validation," a precise match
- **Line 601** (generic `_unchecked(...)` catch-all, no more specific
  category fits) → `missing-owner-check` as the least-wrong available fit

## Tests added

- A direct test confirming the `UncheckedAccount` → `anchor-constraint-gap`
  fix specifically, and that the old, non-existent `"ownership-check"`
  string never appears
- A broad-sweep test exercising most of this file's detection paths at
  once (Anchor struct scanning, `arbitrary-cpi`, `type-cosplay`,
  `account-data-matching`, `account-close-revival`,
  `account-reinitialization`), asserting every category string produced
  exists in the real, authoritative catalog list — a regression guard
  against this exact class of bug recurring silently

## A minor, non-blocking overlap found along the way

The manual lamport-drain check in this file (`SolanaVisitor`, expression
level: `lamports.borrow_mut()... = 0`) and my own `ENG-3` function-level
check (`taint_engine.rs`'s `check_function_level_patterns`) can now both
independently fire `account-close-revival` on the same real code pattern.
Not a bug — just genuine, minor duplication between two independently
built detection paths for the same vulnerability class. Not fixed here;
de-duplicating findings is separate scope from a catalog-naming fix.

## Verified

- Brace/paren balance checked on both the original file (confirmed
  pre-existing, benign — a brace inside a string literal) and my specific
  additions (perfectly balanced, `15`/`15`)
- Manual, careful re-read of every changed line

**Not yet verified: `cargo test`.** Same constraint as `ENG-1`/`ENG-3` —
no working Rust toolchain in this sandbox. This genuinely needs a real run
on your machine before continuing to the larger constraint-modeling work.

## To verify

```powershell
cd core
cargo test --package ares-mapper eng4_catalog_category_fixes -- --nocapture
```

**Expected: 2 passed.** Also worth running the full crate's suite to check
for regressions from touching shared code:

```powershell
cargo test --package ares-mapper
```

**Expected: no regressions** — should still show all previously-passing
tests, plus these 2 new ones.
