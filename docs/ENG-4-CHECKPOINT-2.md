# ENG-4 — Checkpoint 2: `has_one` authority-constraint gap

Stacking on top of Checkpoint 1 (category-name fixes), same branch.

## The actual gap

`AnchorAccountField` tracked `has_constraint` as a single, generic flag —
`has_one` OR `constraint` OR `owner` all collapsed into one boolean. This
meant a field with *any* unrelated constraint attribute would read as
"constrained," even if it were specifically missing the `has_one`
relationship check it actually needed.

The catalog's own `anchor-constraint-gap` detection hint says plainly:
*"Check for missing `has_one` on authority fields."* That's the literal
gap this checkpoint closes.

## Anchor semantics, worth being precise about

`has_one = authority` is declared on the account being *validated* (e.g.
a `vault` field gets `#[account(has_one = authority)]`, and Anchor checks
`vault.authority == authority.key()`), not on the authority field itself.
So "is this authority field properly guarded" isn't a per-field question
— it's a whole-struct one: does *any* field's `has_one` constraint
reference it by name?

## What's new

- `AnchorAccountField` gets a dedicated `has_one: bool`, split out from
  the generic `has_constraint` catch-all (which stays, for the existing
  `UncheckedAccount` check that already used it)
- A new, struct-level check: any field named `authority`, `admin`, or
  ending in `_authority`/`_admin` (Anchor's own conventional naming for
  this exact pattern) gets checked against the *whole struct's* combined
  attribute text for a `has_one` reference to it by name. If none exists,
  flags `anchor-constraint-gap` — Medium severity, 0.55 confidence
  (heuristic naming-based, not a hard guarantee, so pitched lower than the
  0.80 `UncheckedAccount` check)

## Verified

- Only one construction site for `AnchorAccountField` exists in the whole
  crate (checked directly) — adding a required field couldn't silently
  break compilation anywhere else
- `attr_to_string`'s `quote!`-based rendering only inserts spaces
  *between* separate tokens, never within a single identifier — confirmed
  this doesn't break the `"has_one"`/`"authority"` substring checks, since
  both are single, unsplittable tokens
- Brace/paren balance on this session's full diff: perfectly even
  (`40`/`40`, `102`/`102`)
- 4 new tests: fires on an unreferenced authority field, doesn't fire once
  a real `has_one` references it, doesn't fire when no authority-like
  field exists at all, and the `_authority`/`_admin` suffix convention is
  also recognised (not just the exact names `authority`/`admin`)

**Not yet verified: `cargo test`.** Same as every checkpoint — needs a
real run on your machine.

## To verify

```powershell
cd core
cargo test --package ares-mapper eng4_anchor_has_one_gap -- --nocapture
```

**Expected: 4 passed.**
