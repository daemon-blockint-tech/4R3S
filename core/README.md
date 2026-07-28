# core/ — ARES deterministic engine (Rust)

Built **inside** `4R3S` (there is no separate ARES-v3 repo). PLAT-1 lays the workspace; **ENG-1** brings the engine in.

**Planned crates:** `mapper` (regex→AST→taint→judge) · `cli` · `poc` · `fork-validator` · `trident`.

**Golden rule (CLAUDE.md #2):** deterministic — no LLM, no network, no randomness in the detection path. Same input → identical output. LLMs live only in `apps/auditor-api` and `packages/orchestration`.

Status: **scaffold** (`ares-core` placeholder crate so `cargo build --workspace` passes). Continue at ENG-1.
