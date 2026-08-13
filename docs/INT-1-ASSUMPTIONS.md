# INT-1 — Consolidate final CLI: scan/ingest/report/poc/fuzz/validate

## Update — the Rust detection pipeline improved substantially after this
## was written; the framing below is now partially stale, corrected here
## rather than silently rewritten

When this doc was first written, `ORC2-F3`/`F6`/`F7` were open, documented
defects (measured **F1 of 0.0000**). Since then, `main` has moved — all
three are now fixed:

- `ORC2-F1` — a static scan can now run without requiring the fuzzer to be
  installed at all
- `ORC2-F3` — the CPI program-id check is now a real comparison, not a
  substring match defeated by a field literally named `program_id`
- `ORC2-F6` — **Rust itself now refuses an unreadable target as an error**,
  instead of exiting 0 with a fake "clean" report. This is the exact
  defect `validateAnchorPath` (below) exists to guard against — the guard
  is no longer the *only* protection, but it's not wrong to keep: it fails
  faster (no subprocess spawn at all) and gives one consistent error
  message across every Rust-backed subcommand here, not just `scan`.
- `ORC2-F7` — the hypothesis phase now actually reaches the report.
  Measured impact: **F1 went from 0.0000 to 0.3007** (`EVAL-3`).

**Still confirmed true, re-checked after all of the above landed:** the
`ast_scanner.rs`/`taint_engine.rs` code (fixed internally in `ENG-3`,
now merged) is a *different* detection mechanism from the
hypothesis-based one that just got fixed, and it is **still** called by
nothing outside its own module — re-verified by searching the whole
workspace again after these fixes. This is a real, separate,
still-unaddressed gap, not something this round of fixes touched.

## Scope, as actually found — my senior's brief was intentionally light on
## specifics here, so everything below is a documented assumption, not a
## confirmed instruction. Flag anything that should go differently.

Original backlog: *"Get the finalized CLI/REST/gRPC contract from Khashia's
ORC-2... Build a single CLI exposing scan, ingest, report, poc, fuzz,
validate as subcommands... Wire each subcommand to the appropriate
service via the contract."*

**What investigation actually revealed:** two genuinely separate systems
exist, not one CLI needing consolidation:

1. **The real, shipping TS audit pipeline** (root `src/`, `npm run audit`)
   — this is what `apps/auditor-api`'s worker actually calls in
   production. Its own CLI is one flat script (`parseArgs`, no
   subcommands at all).
2. **`core/`'s Rust `ares` binary** — already has its own clean
   `scan`/`report`/`fuzz`/`validate` subcommands. But per
   `docs/CORE-CONTRACT-FINDINGS.md` (written establishing `ORC-2`), the
   detection underneath has severe, documented, explicitly out-of-scope
   defects (`ORC2-F3`: a substring-matching check defeated by a field
   literally named `program_id`; `ORC2-F7`: hypotheses generated and then
   discarded — measured **F1 of 0.0000 across 159 targets** in `EVAL-2`).

**Assumption: don't reimplement either system — consolidate by
dispatching to whichever real one already backs each verb.** Two
commands (`scan`, `ingest`) wrap the existing, real TS scripts, the same
way `apps/auditor-api/worker.py` already spawns `npm run audit` rather
than importing its internals. Four commands (`report`, `poc`, `fuzz`,
`validate`) spawn `core/`'s real Rust binary, since `report`/`fuzz`/
`validate` already exist there with no TS-side equivalent at all, and
`poc` generation is `ares scan --poc true --fuzz false` per `ORC-2`'s own
documented recommended invocation.

## The mapping, and why each one landed where it did

| Command | Backs onto | Reasoning |
|---|---|---|
| `scan` | TS `npm run audit` | The real, shipping detection path |
| `ingest` | TS `npm run ingest:solsec` | Already exists standalone, direct wrap |
| `report` | Rust `ares report <scan-dir>` | TS's own `report`/`verify` graph nodes only run as internal pipeline steps today, not standalone — documented honestly rather than forcing an artificial split. Rust's `report` command is a real, standalone, already-working equivalent. |
| `poc` | Rust `ares scan --poc true --fuzz false` | No TS-side PoC generation exists at all; this is `ORC-2`'s own documented invocation pattern for exactly this |
| `fuzz` | Rust `ares fuzz <path>` | Genuinely Trident-specific; no TS equivalent, no reason to invent one |
| `validate` | Rust `ares validate <poc-path>` | Rust's own description is literally *"Validate a proof-of-concept in sandboxed environment"* — an exact match |

**`report`/`validate` are honest about a real limitation**: the TS
pipeline's own report/verify steps aren't separable from a full audit run
today. This CLI doesn't pretend otherwise — it routes those verbs to the
system that actually has them as standalone operations.

## The most important thing this CLI does — `ORC2-F6` protection

The contract's own most severe finding: **a nonexistent or wrong-shaped
path makes Rust's `ares scan` exit 0 with a fully-formed, "clean" report**
— indistinguishable from a real scan from the caller's side. Every
path-taking, Rust-backed subcommand here (`poc`, `fuzz`) validates the
path *itself* — exists, is a directory, has `Cargo.toml` + (`programs/`
or `src/`) — before ever invoking Rust. `report`/`validate` check their
own path arguments exist too, even though they don't need the full
Anchor-shape check (they take a scan-output directory / PoC file, not a
program to scan).

## A real, deliberate scoping cut — not implemented

**Did not attempt to fix `ORC2-F3`/`ORC2-F7`** (the actual detection
defects) as part of this task. That's a separate, substantial piece of
work belonging to whoever owns `ENG-1`/the Rust detection pipeline —
consolidating the *interface* to `scan`/`fuzz`/etc. is a genuinely
different problem from fixing what's underneath them, and conflating the
two here would blur exactly the kind of scope creep this whole project
has tried to avoid.

**Also not touched: the `ast_scanner.rs`/`taint_engine.rs` disconnection**
found during this investigation (the code fixed in `ENG-3` is not called
by the real `scan`/`benchmark` pipeline at all — confirmed by searching
the entire workspace for callers). Flagged directly in conversation;
`ENG-3` is still under review, so this is deliberately left for a later,
separate pass rather than folded in here.

## Verified

- `npm run typecheck` — clean
- Full test suite: **43 files, 415 tests passing**, zero regressions
- 9 new tests for `validateAnchorPath`/`ares_binary`/the dispatch table —
  using real temp directories via `mkdtempSync`, not mocked filesystem
  behavior
- **Real, live smoke tests of the actual CLI**, not just unit tests:
  - `--help` and unknown-command output
  - `poc`/`fuzz` against a genuinely nonexistent path → rejected before
    ever touching Rust
  - `fuzz` against a real, flat (non-Anchor) directory — the *exact*
    `ORC2-F6` trap — correctly rejected with a message citing the finding
  - `report`/`validate` against nonexistent paths → rejected with clear,
    specific messages

**Not verified: an actual successful run against a real Anchor project**,
since that requires the Rust binary to be built (`cargo build --release`
from `core/`) and this sandbox can't build it (same Rust-toolchain
constraint as `ENG-1`/`ENG-3`). The validation logic itself is fully
tested; the actual Rust subprocess invocation on a *valid* path is not.
Worth a real end-to-end run on a machine with the binary built.

## What's still NOT done — deliberately out of scope

- CLI help text is a static string, not generated from each subcommand's
  own arg definitions — fine for six fixed commands, would need
  revisiting if this grows
- No `--json` output mode for scripting/CI consumption — flag if that's
  wanted
- Doesn't attempt to unify `report`'s output format across the two
  systems (Rust's `report` has its own `--format` flag; TS has no
  equivalent at all)
