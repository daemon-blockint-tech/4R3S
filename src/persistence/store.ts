/**
 * Store factory for the Crystalline memory layer.
 *
 * NOTE: as of LangGraph JS 1.x, `@langchain/langgraph-checkpoint-postgres`
 * ships only a `PostgresSaver` (checkpointer) — there is no Postgres-backed
 * `BaseStore`. So Crystalline memory uses the in-process `InMemoryStore`, which
 * is session-scoped: it does not survive a process restart.
 *
 * Durable, cross-audit knowledge is instead persisted to the hybrid knowledge
 * base (Supabase + Neo4j) during the REMEMBER phase and via the ingestion
 * script. Crystalline therefore acts as fast working/episodic memory within a
 * run, while the KB holds long-term semantic/procedural knowledge.
 *
 * `createStore` is the single seam to swap in a persistent BaseStore later
 * without touching callers.
 */
import { InMemoryStore, type BaseStore } from "@langchain/langgraph";

import { logger } from "../config/logger.js";

/** Build the BaseStore that `CrystallineStore` wraps. */
export function createStore(): BaseStore {
  logger.debug({ component: "store" }, "Using in-memory Crystalline store");
  return new InMemoryStore();
}
