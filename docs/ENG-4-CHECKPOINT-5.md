# ENG-4 — Checkpoint 5: closing the "test against real programs" gap

Stacking on top of Checkpoints 1–4. Prompted by a direct question worth
asking honestly: does everything so far actually satisfy the original
task? Checking rather than assuming surfaced a real, disclosed gap.

## The gap, found by checking rather than assuming

Every test across Checkpoints 1–4 is a hand-crafted, minimal synthetic
snippet. None run against a real, existing vulnerable program — a
genuine miss against the original task's own explicit fourth to-do:
*"Test against real Anchor programs with known issues."*

## Why this isn't a Cashio/Wormhole/Mango-style fixture

Checked `eval/fixtures/rs/incident-repros/` directly. A Wormhole
reproduction already exists there, and it's exactly the vulnerability
class `ENG-3`'s existing Solitaire check targets — but it's written in
plain native-Rust function style (`&AccountInfo` parameters), not
Solitaire's own `#[derive(FromAccounts)]` struct idiom. No existing
fixture in this repo uses Anchor's `#[derive(Accounts)]` style at all, so
there was nothing to point a `has_one`-gap test at directly.

More importantly: a missing `has_one` check isn't usually tied to one
specific, named, dollar-amount incident the way those three fixtures are.
It's a common vulnerability *class* — the same one Trail of Bits' own
Solana pitfalls post documents (already cited in the
`anchor-constraint-gap` catalog entry) and Neodyme's workshop teaches
directly. Fabricating a fake "real incident" attribution to match the
existing naming convention would have been dishonest in a way the other
fixtures aren't.

## The honest fix

Added `eval/fixtures/rs/pattern-examples/missing-has-one-vault-withdraw.rs`
— a new, separate directory (not `incident-repros/`, since this isn't
one), containing a realistic, *complete* Anchor program: a vault
withdraw instruction with the real `#[program]` module wrapper, proper
`use` statements, an error enum, and actual instruction logic — not a
2-line snippet. The vulnerability is real and exact: `authority` must
sign, but nothing ties that specific signer to *this vault's* authority,
so any account holder can drain any vault by naming their own key as
`authority`.

Added a smoke test running the real `analyze_file` entry point against
this fixture, confirming the `has_one` gap check (Checkpoint 2) fires
correctly on realistic, complete code — not just the minimal snippets
already covered.

## Verified

- Confirmed directly that no existing repo fixture uses
  `#[derive(Accounts)]` at all, before deciding a new fixture was needed
- Traced through the more complex surrounding code (the `#[program]` mod
  wrapper, `use` statement, error enum) by hand to confirm none of it
  interferes with the struct-level check, since real Anchor programs
  genuinely are structured with `Accounts` structs sitting outside the
  `#[program]` module, same as this fixture
- Brace/paren balance isolated against the exact Checkpoint 4 baseline
  (not a stale comparison point): perfectly even (`4`/`4`, `12`/`12`)
- 1 new test, using the real `analyze_file` entry point end-to-end, not a
  narrower internal function

**Not yet verified: `cargo test`.** Needs a real run, same as every
checkpoint.

## What's still ahead

The actual wiring into `scan.rs` — the real, senior-approved, Tier 3
change, still not started. This checkpoint only closes out the testing
gap in the original task's own to-do list.

## To verify

```powershell
cd core
cargo test --package ares-mapper eng4_smoke_test_realistic_fixture -- --nocapture
```

**Expected: 1 passed.**
