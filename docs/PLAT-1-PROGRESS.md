# PLAT-1 — Monorepo skeleton (progress & handoff)

**Branch:** `feat/PLAT-1-monorepo-skeleton` · **Scope:** *structure only* — the skeleton is laid; the code migration is intentionally left for the team to continue.

## What this change does (structure only)
- Creates the monorepo skeleton per `CLAUDE.md`: `core/ services/ packages/ apps/{auditor-api,auditor-web,ares-sec} datasets/ docs/` (`eval/` already existed).
- Adds the **Rust workspace**: root `Cargo.toml` + a placeholder `core` crate (`ares-core`) so `cargo build --workspace` works. The deterministic engine is built **here, inside 4R3S** — no separate ARES-v3 repo to vendor.
- Adds forward-looking TS workspace markers: `pnpm-workspace.yaml`, `turbo.json`.
- Drops `CLAUDE.md` at the repo root (repo rules for contributors + Claude Code).
- Every new directory has a `README.md` stating its purpose and, for `packages/`, the exact `src/*` → `packages/*` migration map.

## What it deliberately does NOT do (left for devs)
- **No code moved yet.** The app still builds from root `src/` under npm — CI stays green. The `src/{knowledge,memory,retrieval,report,graph,llm,billing,config}` → `packages/*` moves are next (see `packages/README.md`).
- **No pnpm/turbo wiring of the real build** — markers only; CI still uses the root npm package.
- **No engine** — `core` is a scaffold; the real crates (mapper, cli, poc, fork-validator, trident) are **ENG-1**.
- **PLAT-2 CI copyleft gate** (license-checker / cargo-deny) not added here.

## Licensing note
The whole repo is **Apache-2.0** (root `LICENSE` already is; no `AGPL` strings remain). `apps/ares-sec` is Apache-2.0 too — kept apart from the Auditor by a **product/safety boundary**, not a license firewall. (This corrects the AGPL assumption in `PLAT-1-ASSUMPTIONS.md`.) Remaining license task (**PLAT-2**): add `"license": "Apache-2.0"` to `package.json` + each `Cargo.toml`, and add the third-party GPL/AGPL CI gate.

## Session context — what led here (28 Jul 2026)
1. Pulled `main`, mapped current state (SEC-5 + `eval/` harness already merged; billing fixes on `main`).
2. Reconciled the planning docs to **unified Apache-2.0** (removed the old AGPL/firewall framing).
3. Confirmed the Rust core is built **inside** 4R3S (no separate repo).
4. **Needs write/admin — not done here:** delete the orphan `master` branch; merge `claude/repo-overview-mct3wg` (secret-redaction at the log sink + outbound-request deadlines + knowledge-source failure surfacing). Whoever has write access should action these.

## Next for developers
- **Dev 1:** finish PLAT-1 (move `src/*` → `packages/*`, wire pnpm+turbo, keep build green) → PLAT-2 (license fields + copyleft CI gate) → ENG-1 (`core/` engine).
- **Dev 2:** `KR-1` (validate Crystalline memory), then `KR-4` / `ORC-1`.
- **Dev 3:** `EVAL-1/2` (the `eval/` scaffold exists — verify or refute F1 0.94).
