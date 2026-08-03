# ENG-1 — Pull ARES-v3 as core/: what was done, what was verified, what wasn't

## The blocker is resolved

The uploaded `ARES-v3-main.zip` is confirmed to be the actual codebase this
task meant, not a renamed 4R3S/ares-auditor:

- **F1 = 0.94** — stated directly in its own README, matching what was
  flagged as missing back when only 4R3S (138 tests, no ML eval surface)
  had been uploaded.
- **Exactly 54 test functions** — counted directly (`grep -rn "#\[test\]"`
  style, both `#[test]` and `#[tokio::test]`), not estimated.
- Genuine, separate Rust workspace (`Cargo.toml`, `Cargo.lock`, 7 crates) —
  confirmed there's no overlap with `ares-auditor`'s TypeScript codebase.

## What was actually done

Pulled the entire ARES-v3 repository, intact, into `ares-auditor/core/`:

```
ares-auditor/
  src/            (unchanged — the existing TS agent)
  core/           (new — full ARES-v3 import)
    crates/       (7 Rust crates)
    dataset/      (ground truth + benchmark fixtures)
    deny.toml     (license/vulnerability policy — see PLAT-2 connection below)
    Cargo.toml / Cargo.lock
    ... (docs, templates, changelog, etc. — everything, unpruned)
```

Copied as one complete, unmodified unit rather than cherry-picking files —
same principle as PLAT-3's `legacy-ares-v2/` preservation: don't guess at
what's "core" vs. "reference" and risk leaving out something a later task
needs.

### Path/config fixes required by the move

Checked for exactly what ENG-1's to-do asked for — breakage caused by the
move itself, not pre-existing issues:

- **Relative paths inside the Rust source are fine.** Tests use paths like
  `PathBuf::from("../../dataset")` and `include_str!("../../../../ares.toml.template")`.
  These resolve either at compile time (relative to the source file) or by
  Cargo at test-run time (relative to each crate's own manifest
  directory) — neither depends on where the *whole* workspace sits. Moving
  the entire tree as one intact unit preserves all of these correctly.

- **`.github/workflows/ci.yml` collided with ares-auditor's own `ci.yml`,
  and would have been silently inert anyway** — GitHub Actions only reads
  workflows from the repository root's `.github/workflows/`, not from a
  nested `core/.github/`. Moved both files up to the real root, renamed to
  `core-ci.yml` / `core-release.yml`, and added `defaults.run.working-directory: core`
  (plus fixed the artifact-path and `target/` references in the release
  workflow, which don't inherit that default) so they actually point at
  where `Cargo.toml` now lives. Also scoped `core-ci.yml`'s triggers to
  `paths: [ "core/**" ]` so unrelated TS-only commits don't spin up a Rust
  toolchain for nothing.

- **`.gitignore` needed no change.** Unlike `.github`, `.gitignore` files
  genuinely do cascade at whatever directory level they live in — `core/.gitignore`
  already has `target/` in it from ARES-v3's own repo, so `core/target/`
  is already correctly ignored without touching the root `.gitignore`.

- **ares-auditor's own TypeScript tooling is unaffected.** `tsconfig.json`
  scopes `include` to `src/**/*` only, and `lint` runs `eslint src`
  specifically — both already exclude `core/` by construction. Re-ran
  `npm ci` → `typecheck` → `lint` → `build` with `core/` now present to
  confirm this directly rather than just assuming it from the config.

- **Added a short section to the root `README.md`** noting `core/`'s
  existence and that it's not yet wired into the agent pipeline.

## What could NOT be verified — and why

**I cannot confirm "green build" in this sandbox environment**, and want
to be direct about that rather than imply it's been confirmed:

- The committed `Cargo.lock` is lockfile format v4, which requires a newer
  Cargo than what's installable here. This sandbox only has Rust 1.75.0
  available (via `apt`; `rustup`'s install domain isn't on this
  environment's network allowlist).
- Tried regenerating a fresh lockfile under 1.75 instead of the committed
  one. That pulled current crates.io releases of `clap_lex`, then
  (after pinning that back) `getrandom`, both now requiring Rust's
  `edition2024` feature, which 1.75 doesn't support. This kept cascading
  to the next dependency — confirmed it's a systemic "toolchain too old
  for today's crates.io" problem, not a one-off, so stopped chasing it
  rather than keep pinning indefinitely.
- **Restored the original `Cargo.lock` unmodified** rather than leave the
  repo in a partially-patched state.
- **What I did confirm:** running `cargo build --workspace` against
  `core/` post-move fails with the *exact same* lockfile-version error as
  running it against the original ARES-v3 repo pre-move — confirming the
  move itself introduced no new breakage, and the only blocker is this
  pre-existing sandbox/toolchain limitation.

GitHub's own CI (`dtolnay/rust-toolchain@stable`) always uses current
stable Rust, so this is very likely fine there — but that's an inference
on my part, not something I verified myself. Worth an actual CI run (or a
local build on a machine with a current Rust toolchain) before anyone
reports this as a confirmed green build.

## A license question worth flagging

ARES-v3 is **MIT**-licensed; `ares-auditor` is (per PLAT-1's assumption)
**Apache-2.0**. Including MIT-licensed code inside an Apache-2.0 project
is generally fine (MIT is permissive and compatible), but this is a real
detail for whoever owns the license decision to actually confirm — not
something I should silently wave through. Directly relevant to PLAT-2's
own "confirm any vendored code license constraints" ask.

## Direct connection to PLAT-2

`core/deny.toml` already exists, already configured with a permissive
license allow-list (`MIT, Apache-2.0, BSD-2/3-Clause, ISC, Unicode-DFS-2016,
Zlib, 0BSD`) plus vulnerability/unmaintained/yanked/unknown-registry
checks. The commit history shows a `cargo-deny` CI job existed and was
removed ("keep only security audit") — the config file was left behind,
unused. This is exactly what PLAT-2 originally asked for, on the actual
correct codebase this time. Re-wiring it back into `core-ci.yml` is a
natural, small follow-up — flagging it here rather than doing it
unprompted, since ENG-1's scope was the pull/build/tests, not PLAT-2's
gate.

## What's still NOT done

- Real verification of "green build" on a proper up-to-date Rust
  toolchain (see above).
- Any actual integration between `core/`'s detection engine and
  `src/`'s LangGraph agent pipeline — ENG-1 was the pull, not the wiring.
  That's presumably future work (possibly ENG-3/ENG-4's territory, or a
  new ticket).
- Confirming the MIT/Apache-2.0 license question with whoever owns that
  call.
- Nothing pushed to GitHub — same limitation as every other task so far.
- Re-wiring `deny.toml` into CI (flagged above as a natural PLAT-2
  follow-up, not done as part of this task).

## Verified before handing off

- 54 tests confirmed present via direct source count.
- F1 0.94 confirmed via ARES-v3's own README.
- Full copy verified structurally complete (6.9MB, matches source).
- Both new workflow files (`core-ci.yml`, `core-release.yml`) validated
  as syntactically correct YAML.
- Confirmed the move introduced no *new* build breakage (identical
  lockfile error before and after).
- Confirmed `ares-auditor`'s existing TS pipeline (`typecheck`/`lint`/`build`)
  is completely unaffected by `core/`'s presence.
