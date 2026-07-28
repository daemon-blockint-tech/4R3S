# CLAUDE.md — ARES monorepo

Guidance for Claude Code (and humans) working in this repository. Keep this file tight; it is loaded into context every session.

## What this repo is

`4R3S` is the **single monorepo** for the ARES platform. It ships **two products**:

- **ARES Auditor** — defensive, automated Solana security auditing. Lives in `core/`, `services/`, `packages/`, `apps/auditor-*`.
- **ARES-Sec** — offensive, authorized multi-agent framework. Lives in `apps/ares-sec/` as a separate app.

**The entire repo is Apache-2.0** (both products). There is no license firewall — the product boundary below is about safety and cleanliness, not licensing.

Authoritative specs are in `docs/`: `PRD.md` (what we build), `DEVELOPMENT_PLAN.md` (how/when), `BACKLOG.xlsx` (task IDs). When this file and a doc disagree on a rule, the PRD wins for scope, this file wins for repo mechanics.

## GOLDEN RULES (do not violate)

1. **Product & safety boundary.** The whole repo is **Apache-2.0** — no license firewall. But keep the two products separate: offensive tooling in `apps/ares-sec/` must not be pulled into the defensive Auditor (`apps/auditor-*`), for **safety, liability, and product cleanliness** — not licensing. Shared reuse goes through permissive `packages/*`. Also keep third-party **strong-copyleft (GPL/AGPL)** dependencies out of any published artifact (LGPL and permissive are fine). CI checks both — if it fails, fix the dependency, don't weaken the check.
2. **Determinism in the core.** `core/` (Rust engine) must have **no** LLM, no network, and no randomness in the detection path. Same input → identical output. LLMs live only in `apps/auditor-api` and `packages/orchestration`.
3. **No trust-me numbers.** Any metric that appears in a README, report, slide, or sale must be reproducible via `eval/` (`verify-claims`). If you can't re-derive it from committed data, don't publish it.
4. **Confirmation, not attack.** PoC/fork runs (`core/poc`, `core/fork-validator`) execute against the *target's own code* in a *sandboxed localnet/fork* to confirm findings. Never against live mainnet state in a mutating way.
5. **Read the code.** The Auditor must load actual source (`.rs` + IDL) into analysis context. Never ship a "heuristic" that reasons only from a summary.

## Structure

```
core/         Rust cargo workspace — deterministic engine (from ARES-v3)
              ├─ mapper (regex→AST→taint→judge) · cli · poc · fork-validator · trident
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

```bash
# Rust core
cargo build --workspace && cargo test --workspace
cargo run -p ares-cli -- scan <path>          # deterministic source scan
cargo run -p ares-cli -- poc <finding>        # generate PoC harness
cargo deny check licenses                     # blocks incoming GPL/AGPL third-party crates

# TS / apps
pnpm install && pnpm -r build && pnpm -r test
pnpm --filter auditor-web dev

# Python
uv sync    # or: pip install -e apps/auditor-api

# Eval
python eval/verify_claims.py                  # re-derive all published metrics
```

## When unsure

- Scope question → `docs/PRD.md`.
- Sequencing / who owns what → `docs/DEVELOPMENT_PLAN.md`.
- "Can I import X from Y?" → importing `apps/ares-sec` into the Auditor is discouraged (safety/product hygiene, not licensing). Keep direction apps → packages → core.
- Prefer small, reviewable PRs tied to one backlog ID.
