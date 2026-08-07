# CLAUDE.md — ARES monorepo

Guidance for Claude Code (and humans) working in this repository. Keep this file tight; it is loaded into context every session.

## What this repo is

`4R3S` is the **single monorepo** for the ARES platform. It ships **two products**:

- **ARES Auditor** — defensive, automated Solana security auditing. Lives in `core/`, `services/`, `packages/`, `apps/auditor-*`.
- **ARES-Sec** — offensive, authorized multi-agent framework. Lives in `apps/ares-sec/` as a separate app.

**The entire repo is Apache-2.0** (both products). There is no license firewall — the product boundary below is about safety and cleanliness, not licensing.

Authoritative specs are in `docs/`: `PRD.md` (what we build), `DEVELOPMENT_PLAN.md` (how/when), `BACKLOG.xlsx` (task IDs). When this file and a doc disagree on a rule, the PRD wins for scope, this file wins for repo mechanics.

## GOLDEN RULES (do not violate)

1. **Product & safety boundary.** The repo is **Apache-2.0** — no license firewall. ⚠️ **Known discrepancy, unresolved:** the root `LICENSE` is Apache-2.0 but `core/LICENSE` is **MIT**, and `core/Cargo.toml` sets `license = "MIT"` which all 7 crates inherit via `license.workspace = true`. Both are permissive so no copyleft rule is broken and `cargo deny` stays green, but the two licenses differ on patent grant (Apache-2.0 grants explicitly, MIT does not) — which is exactly what enterprise legal review asks about. Do not "fix" this by editing a license header; it is an ownership decision. Resolve it deliberately, then make this file and both LICENSE files agree. But keep the two products separate: offensive tooling in `apps/ares-sec/` must not be pulled into the defensive Auditor (`apps/auditor-*`), for **safety, liability, and product cleanliness** — not licensing. Shared reuse goes through permissive `packages/*`. Also keep third-party **strong-copyleft (GPL/AGPL)** dependencies out of any published artifact (LGPL and permissive are fine). **CI enforces both halves** in the `dependency audit` job: the copyleft half via `scripts/check-licenses.mjs` (npm) + `cargo deny check` (`core/deny.toml`, against `core/Cargo.toml`); the **product boundary** via `scripts/check-import-boundary.mjs` (`apps/auditor-*` must not import `apps/ares-sec`). If either fails, fix the code, don't weaken the check. Note: `apps/ares-sec/` now holds real offensive code (imported via SEC-1), so the boundary is live — keep the direction one-way.
2. **Determinism in the core.** `core/` (Rust engine) must have **no** LLM, no network, and no randomness in the detection path. Same input → identical output. LLMs live only in `apps/auditor-api` and `packages/orchestration`.
3. **No trust-me numbers.** Any metric that appears in a README, report, slide, or sale must be reproducible via `eval/` (`verify-claims`). If you can't re-derive it from committed data, don't publish it.
4. **Confirmation, not attack.** PoC/fork runs execute against the *target's own code* in a *sandboxed localnet/fork* to confirm findings. Never against live mainnet state in a mutating way. The code is `core/crates/ares-cli/src/poc.rs` (generates `solana-program-test` harnesses) and `core/crates/ares-cli/src/commands/confirm.rs` (fork-runs each PoC and writes `confirmed`/`refuted`/`inconclusive` verdicts to a *sibling* `.confirmed.json`, leaving the deterministic scan artifact byte-for-byte intact). Confirmation is a deliberate second pass, never part of `scan` — that is what keeps GOLDEN RULE 2 true. There are no `core/poc` or `core/fork-validator` directories; earlier revisions of this file named them and they never existed.
5. **Read the code.** The Auditor must load actual source (`.rs` + IDL) into analysis context. Never ship a "heuristic" that reasons only from a summary.

## Structure

Marked **[real]** where code exists today and **[planned]** where the directory
is still only a README. The distinction is load-bearing: a tree that lists
intended packages as if they existed is how an agent ends up "testing" an empty
workspace and reporting success.

```
src/          ***THE SHIPPING AUDITOR*** — TS agent, LangGraph pipeline        [real, npm]
              ├─ graph/ (nodes + proof chain) · knowledge/ · memory/ · retrieval/
              ├─ billing/ · llm/ · persistence/ · tools/ (semgrep, source, cua)
core/         Rust cargo workspace ROOT — deterministic engine (ENG-1)         [real, cargo]
              ├─ crates/ ares-cli · ares-core · ares-mapper · ares-trident
              │          ares-policy · ares-orchestrator · ares-report
              ├─ PoC generation: crates/ares-cli/src/poc.rs
              └─ fork confirmation: crates/ares-cli/src/commands/confirm.rs
              NOT yet wired into the src/ pipeline — that is ORC-2.
services/     detector & data services — risk · cve · family · evidence     [planned, README]
packages/     shared PERMISSIVE TS packages                                 [planned, README]
              The code these were to hold currently lives under src/
              (knowledge · billing · retrieval · memory). No migration yet.
apps/
  auditor-api/   agent plane — FastAPI + Arq worker            [real, own CI job]      [Py]
  auditor-web/   dashboard + landing                           [real, own CI workflow] [Next]
  ares-sec/      offensive framework — separate app            [partial: src/target/ missing] [TS]
eval/         scoring + benchmark harness (see "State of the tree" for what exists)
datasets/     sealevel-attacks · Neodyme workshop levels · incident reproductions
docs/         PRD.md · DEVELOPMENT_PLAN.md · BACKLOG.xlsx
```

## Tech stack

- **Rust** (stable) — `core/`. The cargo workspace root is `core/`, **not** the repo root; every cargo command needs `cd core` first.
- **TypeScript** — root `src/` on **npm** (this is the shipping auditor); `apps/auditor-web` and `apps/ares-sec` each have their own `package.json` and CI. `pnpm-workspace.yaml` globs `packages/*` and `apps/*`, but `packages/*` holds no packages — see Commands before reaching for pnpm.
- **Python** — `apps/auditor-api` (FastAPI + Arq, own CI job) and `eval/` (pytest).
- **Data:** Postgres, Supabase (pgvector), Neo4j — all optional; the engine runs without them.

## How work maps to tasks

Every change should reference a **backlog ID** (`ENG-2`, `KR-4`, `ORC-1`, …) from `docs/BACKLOG.xlsx`.
Branch: `feat/<ID>-short-desc`. Commit: `<ID>: <what changed>`. PR title starts with the ID.
Phases: **P0** = consolidation/licensing gate (do first) · **P1** = Auditor MVP · **P2** = Auditor enterprise · **P3** = ARES-Sec · **P4** = advanced detection.

## Definition of Done (every task)

- Tests green in CI; new logic has tests.
- License check passes (no GPL/AGPL third-party dependency in any published artifact).
- Determinism preserved for anything touching `core/`.
- Any metric produced is `verify-claims`-reproducible.
- Backlog `Status` updated.

## Commands

**What actually works today.** The shipping auditor is the TypeScript agent at
root `src/`, built with **npm** — not pnpm. `pnpm-workspace.yaml`
globs `packages/*` and `apps/*`, but `packages/*` are still README stubs (the
`src/*` migration hasn't happened), so the Auditor's real suites live under root
`src/` and run via `npm test` — **not** pnpm. (`apps/ares-sec` has its own
`package.json` + separate `npm` CI in `ares-sec-ci.yml`.) An agent that "passes"
by running `pnpm -r test` on the stubs would report success while testing nothing
real. CI is authoritative and uses `npm ci`.

```bash
# TS auditor (root src/) — this is the real build
npm ci
npm run typecheck && npm run lint && npm run build && npm test

npm run audit -- --program <ADDRESS>          # run an audit
npm run audit -- --source ./path/to/program   # source audit

# Rust engine (core/) — landed via ENG-1; the cargo workspace root is core/
(cd core && cargo build --workspace && cargo test --workspace)
# Careful: the CLI crate has three different names. Directory `crates/ares-cli/`,
# package `ares-v3` (what -p takes), binary `ares` (what target/release holds).
# `-p ares-cli` fails with "did not match any packages".
(cd core && cargo run -p ares-v3 -- scan <path>)     # deterministic source scan
(cd core && cargo run -p ares-v3 -- confirm <report.json>)  # fork-run PoCs (POC-2)

# Dependency gates (the `dependency audit` CI job runs these)
npm audit --audit-level=high
node scripts/check-licenses.mjs               # blocks GPL/AGPL npm deps
node scripts/check-import-boundary.mjs        # auditor apps must not import apps/ares-sec
(cd core && cargo deny check licenses bans sources)   # blocks GPL/AGPL crates (workspace is core/)

# Eval
pip install -r eval/requirements.txt          # needs Python >=3.10
python -m pytest eval -q
python eval/score_detections.py --truth <t.csv> --predictions <p.csv> --target-f1 0.94
python eval/check_published_claims.py         # README metrics must be re-derivable
```

**State of the tree (2026-08).** The Rust engine **landed (ENG-1)** — `core/` is a
real cargo workspace (7 crates; the CLI one is package `ares-v3` in
`crates/ares-cli/`, binary `ares`); `cd core && cargo test
--workspace` runs the engine's suite, green in CI via `core-ci.yml`. It is **not
yet wired into the TS agent pipeline** — that's ORC-2. `apps/ares-sec/` holds the
imported offensive framework, but the import is **incomplete** (its `src/target/`
source is missing), so `ares-sec-ci.yml` runs on ares-sec PRs + manual dispatch
only, **not on push to main**, until it's completed. Still stubs: `packages/*` and
`services/` — both hold a README and nothing else (the `src/*` migration is
pending). `apps/auditor-api` and `apps/auditor-web` are **no longer stubs**: the
API is a real FastAPI + Arq worker with its own pytest suite and CI job, and the
web app is a real Next dashboard with its own workflow. `eval/verify_claims.py`
does not exist — the harness is `score_detections.py` +
`check_published_claims.py` + the `verify-claims` CI job.

**The two gaps that decide whether this ships.** Both are about the *moat* —
findings you can prove — not about adding detectors:

1. **ORC-2: the proof engine is disconnected.** `core/` already has AST scanning
   (`ares-mapper/src/ast_scanner.rs`), PoC generation and fork-execution
   confirmation. Nothing in `src/` calls any of it. So the only mechanical
   evidence the shipping pipeline can offer is Semgrep, an on-chain RPC decode,
   and "the model cited a file we actually read" (`canBeConfirmed` in
   `graph/util.ts`). Executable proof exists in this repo and the product cannot
   reach it.
2. **Accuracy is unmeasured.** There is no `eval/predictions/ares-latest.csv`, so
   `verify-claims` reports ARES as UNSCORED and README lists precision/recall/F1
   as *not measured*. Note what this means for rule 3 below: it is not a missing
   nicety, it is the reason no accuracy claim may be made at all. Measuring the
   static layer is also what retired three rules — see README "Detection
   accuracy", where the committed 4-rule set emits 22 findings over 917 files of
   already-audited code with no confirmed true positive. Treat `source: "static"`
   as *cheap* evidence, not *strong* evidence.

## When unsure

- Scope question → `docs/PRD.md`.
- Sequencing / who owns what → `docs/DEVELOPMENT_PLAN.md`.
- "Can I import X from Y?" → importing `apps/ares-sec` into the Auditor is discouraged (safety/product hygiene, not licensing). Keep direction apps → packages → core.
- Prefer small, reviewable PRs tied to one backlog ID.
