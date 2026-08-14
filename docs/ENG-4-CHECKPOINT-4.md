# ENG-4 — Checkpoint 4: the category-translation bridge

Stacking on top of Checkpoints 1–3. This is deliberately **not** the actual
wiring into `scan.rs` yet — that's the real Tier 3 change, saved for its
own separate, careful round. This checkpoint builds and verifies the
bridge that wiring will need, in isolation, before touching anything live.

## What investigating the wiring task actually surfaced

The real scan pipeline's `Finding` struct uses a Rust enum,
`ares_core::VulnerabilityCategory`, converted from a string via
`from_str_checked()`. This does **not** match the TS-side catalog
(`solana-vulns.ts`) that `ENG-2`/`ENG-3`/`ENG-4` all explicitly told us to
align `ast_scanner.rs`'s categories to. The old, "wrong" strings Checkpoint
1 fixed away from — `"ownership-check"`, `"unchecked-cast"`,
`"revival-attack"`, `"re-initialization"` — are exactly what this enum's
own string parser expects. The catalog-aligned strings Checkpoint 1 fixed
*to* aren't recognized by it at all.

Wiring `ast_scanner`'s findings in directly, the same way `cross_analysis`
already does, would have meant every one of Checkpoints 1–3's carefully
fixed categories silently collapsing into the generic `InvariantViolation`
bucket the moment they reached a real report.

## Genuinely good news, found along the way

`eval/mappings/ares-core-categories.json` already exists, already
documents this exact two-vocabulary split (*"21 Rust variants vs. 34
VULN_CATALOG ids"*), and — independently, without ever having seen this
file before writing Checkpoint 1 — that checkpoint's own fixes matched
this file's documented mappings exactly:
`ownership-check`→`missing-owner-check`, `unchecked-cast`→`unsafe-type-cast`,
`revival-attack`→`account-close-revival`,
`re-initialization`→`account-reinitialization`. Independent convergence on
the same answer is real evidence Checkpoint 1's reasoning was sound, not
just a coincidence to note in passing.

## The decision, per your direction: match existing, don't extend

Rather than add a new `ares_core` enum variant or modify `from_str_checked`
itself (confirmed technically safe to do — every match site on this enum
already has a wildcard fallback, checked directly across all 8 dependent
files — but still touches shared, foundational code), built a small,
local translation function in `ares-mapper` instead:
`ast_category_to_core_category_str()`. Zero changes to `ares-core`. Every
mapping either comes straight from the existing, authoritative mapping
file, or is disclosed plainly as my own coarse-stretch judgment call where
that file has no entry at all (`anchor-constraint-gap`,
`non-canonical-bump` — both categories this crate added after that file
was last written).

## A real bug caught before it shipped, and a real limitation disclosed rather than hidden

**Caught while writing this, not after:** my first draft collapsed
`integer-overflow-underflow` into `"unchecked-cast"`. Re-checked against
the actual `from_str_checked` source directly — `"arithmetic-overflow"`
is its own, separate, correctly-recognized string. Fixed before this ever
got tested, let alone shipped.

**A real, known limitation, stated plainly rather than left implicit:**
`from_str_checked` maps both `"re-initialization"` and `"revival-attack"`
to the *same* `AccountReloading` variant. `ENG-3` deliberately keeps
`account-reinitialization` and `account-close-revival` as two distinct
detection classes — different exploits, different remediation — and that
distinction survives all the way through this translation function. It's
lost one step later, in `ares_core`'s own enum, which is coarser here than
the catalog. This function can't fix that without either a new variant or
a change to `from_str_checked` — both deliberately avoided per your
direction to match what already exists rather than extend it. Worth
knowing about if this distinction ever matters for reporting, but not
something to silently paper over now.

## Verified

- Every mapping checked directly against the real `from_str_checked`
  source in `ares-core/src/lib.rs`, not just the JSON mapping file, since
  a JSON doc can itself drift from the code it describes
- Caught and fixed a real bug in my own first draft this way
  (`integer-overflow-underflow`)
- Brace/paren balance on this session's additions: perfectly even
  (`65`/`65`, `158`/`158`)
- 3 new tests: every catalog category this crate can actually produce
  translates to something the real Rust vocabulary recognizes (checked
  against a hand-mirrored copy of that recognized set, since
  `ares-mapper` doesn't depend on `ares-core`), the `arithmetic-overflow`
  fix specifically, and that an unknown category passes through
  unchanged rather than panicking

**Not yet verified: `cargo test`.** Needs a real run, same as every
checkpoint.

## What's still ahead — deliberately not done here

The actual wiring: calling `ast_scanner`'s `analyze_file`/`scan_directory_ast`
from `scan.rs`, converting its findings into real `ares_core::Finding`
values using this bridge, and deciding how they interleave with the
existing hypothesis/cross-analysis findings (including the known, minor
overlap between the manual lamport-drain check and `ENG-3`'s own
function-level check, noted back in Checkpoint 1). That's a separate,
bigger, Tier 3 change — this checkpoint only builds and verifies the one
piece it will need.

## To verify

```powershell
cd core
cargo test --package ares-mapper eng4_core_category_translation -- --nocapture
```

**Expected: 3 passed.**
