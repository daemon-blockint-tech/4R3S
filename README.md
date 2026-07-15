# ARES-AGENT

**Autonomous Solana program security auditor** built on LangGraph (JS), OpenRouter,
a five-level "Crystalline" cognitive memory layer, and a hybrid (Supabase +
Neo4j) knowledge base.

ARES runs an audit as a graph of phases. The analysis phase fans out to several
analyzers in parallel, and every audit both *reads from* and *writes back to* a
growing body of security knowledge.

## Architecture

```
        intake ──► recall ──┬──► analyzeOnchain  ──┐
        (LLM)      (hybrid)  ├──► analyzeStatic   ──┼──► merge ──► remember ──► report
                            └──► analyzeHeuristic ─┘   (rank)     (persist)    (LLM)
```

| Phase        | What it does                                                                 |
| ------------ | ---------------------------------------------------------------------------- |
| **INTAKE**   | LLM parses the request into a structured target/depth/concerns summary.      |
| **RECALL**   | Hybrid retriever pulls relevant prior knowledge (see below).                 |
| **ANALYZE**  | Three analyzers run **in parallel** and append findings:                     |
|              | · `onchain` — loads the program via Solana/Helius RPC and reasons over it.   |
|              | · `static` — runs Semgrep over a source path (optional binary).              |
|              | · `heuristic` — LLM reasoning over intake + recalled memory.                 |
| **MERGE**    | Fan-in join: dedupes and severity-ranks the combined findings.               |
| **REMEMBER** | LLM decides what to persist; writes crystals + runs consolidation.           |
| **REPORT**   | LLM synthesizes the final markdown audit report.                             |

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
