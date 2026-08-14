# ENG-4 — Checkpoint 3: `Mut<Info<'b>>` was completely invisible

Stacking on top of Checkpoints 1 and 2, same branch.

## The gap

`is_raw_solitaire_info` decides whether a Solitaire field is a raw,
unvalidated `AccountInfo` — the function feeding the exact finding
category already used for the real, documented Wormhole `VerifySignatures`
vulnerability (`instruction_acc: Info<'b>` bypassing secp256k1 signature
verification).

The check was: `trimmed.starts_with("Info<")`. A **mutable** raw account —
`Mut<Info<'b>>` — starts with `"Mut<"`, not `"Info<"`. This type was
**completely invisible** to the check, despite being at least as
dangerous as the already-detected immutable case: `Mut<>` only marks
writability, not validation, so a mutable, unvalidated account can be
*written to*, not just read, with zero checks either way.

## The fix

Strip one leading `Mut<...>` layer before the prefix check, falling back
to the original string when there's no such wrapper (so the already-working
bare `Info<'b>` case is completely unaffected). Verified the nesting
arithmetic precisely on the real double-bracket case
(`Mut<Info<'b>>` → strip `"Mut<"` → `"Info<'b>>"` → strip one trailing
`">"` → `"Info<'b>"`) before writing any test, including a triple-nested
const-generic case (`Mut<Data<'b, T, { CONST }>>`) to make sure the fix
doesn't accidentally sweep up Solitaire's own *validated* wrapper type.

## A real, compounding side effect — not just a new direct finding

`is_raw_info` also feeds the taint engine's own field-tainting (line
168-175: any Solitaire field with `is_raw_info = true` gets marked as an
untrusted source for dataflow tracking). Since `Mut<Info<'b>>` fields were
never recognized as raw at all, they were also never marked tainted —
meaning this fix improves the taint engine's own downstream analysis too,
not just this one direct check.

## Verified

- Traced the exact string manipulation on the real nested case in Python
  before trusting it in Rust
- Confirmed the pre-existing `Signer<`/`Sysvar<`/`Derive<` exclusion check
  (which runs *before* the new Mut-stripping logic, via `.contains()` on
  the whole string) already correctly handles `Mut<Signer<...>>` —
  nothing needed there, but added a regression test confirming my change
  doesn't disturb it
- Brace/paren balance across this session's full diff: perfectly even
  (`56`/`56`, `140`/`140`)
- 4 new tests: the newly-detected `Mut<Info<'b>>` case, a regression check
  that bare `Info<'b>` still fires unaffected, and two negative checks
  (`Mut<Data<...>>`, `Mut<Signer<...>>`) confirming real Solitaire
  validation wrappers are never misidentified

**Not yet verified: `cargo test`.** Needs a real run, same as every
checkpoint.

## To verify

```powershell
cd core
cargo test --package ares-mapper eng4_solitaire_mut_info_gap -- --nocapture
```

**Expected: 4 passed.**
