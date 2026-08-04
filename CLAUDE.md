# CLAUDE.md — ARES monorepo

Guidance for Claude Code (and humans) working in this repository. Keep this file tight; it is loaded into context every session.

## What this repo is

`4R3S` is the **single monorepo** for the ARES platform. It ships **two products**:

- **ARES Auditor** — defensive, automated Solana security auditing. Lives in `core/`, `services/`, `packages/`, `apps/auditor-*`.
- **ARES-Sec** — offensive, authorized multi-agent framework. Lives in `apps/ares-sec/` as a separate app.

**The entire repo is Apache-2.0** (both products). There is no license firewall — the product boundary below is about safety and cleanliness, not licensing.

Authoritative specs are in `docs/`: `PRD.md` (what we build), `DEVELOPMENT_PLAN.md` (how/when), `BACKLOG.xlsx` (task IDs). When this file and a doc disagree on a rule, the PRD wins for scope, this file wins for repo mechanics.

## GOLDEN RULES (do not violate)

1. **Product & safety boundary.** The whole repo is **Apache-2.0** — no license firewall. But keep the two products separate: offensive tooling in `apps/ares-sec/` must not be pulled into the defensive Auditor (`apps/auditor-*`), for **safety, liability, and product cleanliness** — not licensing. Shared reuse goes through permissive `packages/*`. Also keep third-party **strong-copyleft (GPL/AGPL)** dependencies out of any published artifact (LGPL and permissive are fine). **CI enforces both halves** in the `dependency audit` job: the copyleft half via `scripts/check-licenses.mjs` (npm) + `cargo deny check` (`core/deny.toml`, against `core/Cargo.toml`); the **product boundary** via `scripts/check-import-boundary.mjs` (`apps/auditor-*` must not import `apps/ares-sec`). If either fails, fix the code, don't weaken the check. Note: `apps/ares-sec/` now holds real offensive code (imported via SEC-1), so the boundary is live — keep the direction one-way.
2. **Determinism in the core.** `core/` (Rust engine) must have **no** LLM, no network, and no randomness in the detection path. Same input → identical output. LLMs live only in `apps/auditor-api` and `packages/orchestration`.
3. **No trust-me numbers.** Any metric that appears in a README, report, slide, or sale must be reproducible via `eval/` (`verify-claims`). If you can't re-derive it from committed data, don't publish it.
4. **Confirmation, not attack.** PoC/fork runs (`core/poc`, `core/fork-validator`) execute against the *target's own code* in a *sandboxed localnet/fork* to confirm findings. Never against live mainnet state in a mutating way.
5. **Read the code.** The Auditor must load actual source (`.rs` + IDL) into analysis context. Never ship a "heuristic" that reasons only from a summary.

## Structure

```
core/         Rust cargo workspace ROOT — deterministic engine (ARES-v3, landed via ENG-1)
              ├─ crates/ ares-cli · ares-core · ares-mapper · ares-trident · ares-policy · ares-orchestrator · ares-report
services/     detector & data services (from ARES-AGENT) — risk · cve · family · evidence   [Rust/Py]
packages/     shared PERMISSIVE TS packages
              ├─ knowledge (canonical vuln catalog + memory + retrieval)
              ├─ report · orchestration · billing · config · ui (shared design system)
apps/
  auditor-api/   agent plane — LiteLLM · FastAPI · Arq worker · tracing (from ARES)          [Py]
  auditor-web/   dashboard + landing (from ares-v3-landing)                                   [Next]
  ares-sec/      offensive framework (from ares-sec) — separate app, Apache-2.0 like the rest  [TS]
eval/         verify-claims + benchmark harness
datasets/     sealevel-attacks · Neodyme workshop levels · incident reproductions
docs/         PRD.md · DEVELOPMENT_PLAN.md · BACKLOG.xlsx
```

## Tech stack

- **Rust** (stable) — `core/`, most of `services/`. Cargo workspace at root.
- **TypeScript** (pnpm + turbo) — `packages/*`, `apps/auditor-web`, `apps/ares-sec`.
- **Python** — `apps/auditor-api`, parts of `services/` (CVE, family, eval).
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
(cd core && cargo run -p ares-cli -- scan <path>)   # deterministic source scan

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
real cargo workspace (7 crates incl. `ares-cli`); `cd core && cargo test
--workspace` runs the engine's suite, green in CI via `core-ci.yml`. It is **not
yet wired into the TS agent pipeline** — that's ORC-2. `apps/ares-sec/` holds the
imported offensive framework, but the import is **incomplete** (its `src/target/`
source is missing), so `ares-sec-ci.yml` runs on ares-sec PRs + manual dispatch
only, **not on push to main**, until it's completed. Still stubs: `packages/*`
(the `src/*` migration is pending), `apps/auditor-api`, `apps/auditor-web`.
`eval/verify_claims.py` does not exist — the harness is `score_detections.py` +
`check_published_claims.py` + the `verify-claims` CI job.

## When unsure

- Scope question → `docs/PRD.md`.
- Sequencing / who owns what → `docs/DEVELOPMENT_PLAN.md`.
- "Can I import X from Y?" → importing `apps/ares-sec` into the Auditor is discouraged (safety/product hygiene, not licensing). Keep direction apps → packages → core.
- Prefer small, reviewable PRs tied to one backlog ID.
