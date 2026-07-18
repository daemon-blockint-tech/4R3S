# ARES-AGENT

[![CI](https://github.com/daemon-blockint-tech/4r3s/actions/workflows/ci.yml/badge.svg)](https://github.com/daemon-blockint-tech/4r3s/actions/workflows/ci.yml)

**Autonomous Solana program security auditor** built on LangGraph (JS), OpenRouter,
a five-level "Crystalline" cognitive memory layer, and a hybrid (Supabase +
Neo4j) knowledge base.

ARES runs an audit as a graph of phases. The analysis phase fans out to several
analyzers in parallel, and every audit both *reads from* and *writes back to* a
growing body of security knowledge.

## Architecture

```
        intake ──► recall ──┬──► analyzeOnchain   ──┐
        (LLM)      (hybrid)  ├──► analyzeStatic    ──┤
                            ├──► analyzeHeuristic  ──┼──► merge ──► remember ──► report
                            └──► analyzeCua (opt-in)─┘   (rank)     (persist)    (LLM)
```

| Phase        | What it does                                                                 |
| ------------ | ---------------------------------------------------------------------------- |
| **INTAKE**   | LLM parses the request into a structured target/depth/concerns summary.      |
| **RECALL**   | Hybrid retriever pulls relevant prior knowledge (see below).                 |
| **ANALYZE**  | Four analyzers run **in parallel** and append findings:                      |
|              | · `onchain` — loads the program via Solana/Helius RPC and reasons over it.   |
|              | · `static` — runs Semgrep over a source path (optional binary).              |
|              | · `heuristic` — LLM reasoning over intake + recalled memory.                 |
|              | · `cua` — **opt-in**: drives a real browser (Scrapybara Computer Use Agent)  |
|              |   to investigate explorers/repos/docs. See below.                            |
| **MERGE**    | Fan-in join: dedupes and severity-ranks the combined findings.               |
| **VERIFY**   | Skeptical critic pass: refines confidence/status, drops false-positives.     |
| **REMEMBER** | LLM decides what to persist; writes crystals + runs consolidation.           |
| **REPORT**   | Synthesizes a professional audit report (severity matrix, stable finding IDs, coverage). |

### Hybrid retrieval (RECALL)

Recall unions three sources and merges their scores, so a fragment surfaced by
several sources ranks higher:

1. **Crystalline** — in-process activation-based memory (working/episodic recall).
2. **Supabase** — `hybrid_search` RPC over pgvector + full-text (RRF) for
   candidate retrieval.
3. **Neo4j** — 1–2 hop graph expansion / relationship-aware reranking of those
   candidates.

Every source **degrades gracefully**: with Supabase/Neo4j/embeddings unset,
recall falls back to Crystalline-only and the agent still runs fully offline.

### CUA investigation analyzer (opt-in)

`analyzeCua` drives a real, Scrapybara-hosted browser to gather external
evidence about the audit target (block explorers, source repos, docs, prior
audit mentions), then turns the investigation transcript into findings.

- **Opt-in and off by default.** Enable with `CUA_ENABLED=true` or pass `--cua`
  for a single run. It only activates when **both** `OPENAI_API_KEY` and
  `SCRAPYBARA_API_KEY` are set — otherwise the node returns no findings
  immediately, exactly like `analyzeStatic`/`analyzeOnchain` do without their
  inputs, so the graph and test suite stay hermetic by default.
- **Uses OpenAI directly, not OpenRouter.** `@langchain/langgraph-cua` invokes
  OpenAI's `computer-use-preview` model itself (via `ChatOpenAI`, which reads
  `OPENAI_API_KEY` from the environment) — there's no way to route the
  browser-driving loop through OpenRouter. The rest of ARES is unaffected and
  stays on OpenRouter.
- **Read-only by design.** The system prompt
  (`cuaInvestigationSystemPrompt` in `src/llm/prompts.ts`) explicitly forbids
  authentication, form submission, and any other state-changing action — the
  agent may only navigate and read.

## Persistence

- **Checkpointer:** `PostgresSaver` persists per-thread graph state across runs.
- **Crystalline store:** `InMemoryStore` (session-scoped) — LangGraph JS has no
  Postgres store yet, so durable cross-audit knowledge lives in the Supabase +
  Neo4j knowledge base instead.

## Setup

```bash
cp .env.example .env      # fill in OPENROUTER_API_KEY (rest are optional)
npm install
npm run db:up             # starts Postgres + Neo4j via docker compose
npm run db:migrate        # creates checkpoint tables + Neo4j constraints
```

Supabase schema is applied separately (cloud or `supabase` CLI):

```bash
# apply db/supabase/0001_hybrid_search.sql via the Supabase SQL editor / CLI
```

Seed the knowledge base from the [solsec](https://github.com/sannykim/solsec)
corpus (requires Supabase and/or Neo4j credentials):

```bash
npm run ingest:solsec
```

## Run an audit

```bash
# On-chain program (uses Helius RPC when HELIUS_RPC_URL is set):
npm run audit -- --program <PROGRAM_ADDRESS>

# Local source with Semgrep static analysis:
npm run audit -- --source ./path/to/program

# Quick local run without Postgres:
npm run audit -- --program <ADDRESS> --ephemeral

# Opt into the CUA browser-investigation analyzer for this run
# (requires OPENAI_API_KEY + SCRAPYBARA_API_KEY):
npm run audit -- --program <ADDRESS> --cua
```

## Development

```bash
npm run typecheck   # tsc --noEmit
npm run lint        # eslint (flat config)
npm test            # vitest — hermetic; no external services required
npm run build       # emit to dist/
```

The test suite runs the full graph end-to-end with a fake LLM and an in-memory
store, exercising the parallel fan-out, the concat-reducer findings channel, and
Crystalline persistence — with Supabase/Neo4j unset to prove graceful fallback.

### Continuous integration

`.github/workflows/ci.yml` runs the four commands above (typecheck, lint, build,
test) on every push and pull request to `main`, across Node 20 and 22. Because
the suite is hermetic, CI needs no secrets or services. Dependency updates are
grouped into weekly Dependabot PRs (`.github/dependabot.yml`).

## Vulnerability knowledge & reporting

The analyzers work through a structured Solana vulnerability catalog
(`src/knowledge/solana-vulns.ts`) — access-control, CPI, PDA, arithmetic,
lifecycle, oracle, DeFi (slippage/front-running), availability (DoS),
governance (upgrade authority), Token-2022 extensions, and business-logic
classes — grounded in the [Sealevel Attacks](https://github.com/coral-xyz/sealevel-attacks),
[Neodyme's common pitfalls](https://neodyme.io/en/blog/solana_common_pitfalls/),
and the [solsec](https://github.com/sannykim/solsec) corpus. Every finding is
tagged with a catalog id and the set of evaluated classes is tracked as
`coverage`.

Findings are rated on an impact × likelihood severity matrix
(`src/knowledge/severity.ts`), and the REPORT phase emits a professional
assessment — executive summary with a deterministic severity table, scope &
methodology, stable finding IDs (`ARES-001`…), per-finding
description/impact/recommendation, and a coverage section — in the style of
firms like OtterSec, Neodyme, and Zellic.

## Security

See [`SECURITY.md`](SECURITY.md) for the vulnerability-reporting process,
ARES's read-only runtime posture, and the status of tracked dependency
advisories.

## Configuration

All variables are documented in `.env.example`. Only `OPENROUTER_API_KEY` is
required; Solana defaults to mainnet-beta, Postgres to the docker-compose
values, and Supabase/Neo4j/embeddings/Helius are optional enhancements.

## Extending

- **New analyzers:** add a node under `src/graph/nodes/`, wire it into the
  ANALYZE fan-out in `src/graph/build-graph.ts`, and append `Finding`s.
- **New tools:** add under `src/tools/`. Remote tools can be surfaced via the
  Model Context Protocol (MCP) with the same load/run/normalize shape.
- **New knowledge sources:** implement the `Retriever` interface
  (`src/retrieval/types.ts`) and add it to `createHybridRetriever`.
