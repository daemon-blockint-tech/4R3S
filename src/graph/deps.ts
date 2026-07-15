/**
 * Graph dependencies.
 *
 * Nodes are built as closures over this object so the graph can be assembled
 * with real backends in production and with fakes (mock chat model, in-memory
 * store) in tests. Keeps node logic free of module-level singletons.
 */
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";

import type { CrystallineStore } from "../memory/crystalline-store.js";
import type { HybridRetriever } from "../retrieval/index.js";

export interface GraphDeps {
  /** Chat model used across all LLM-backed phases. */
  chat: BaseChatModel;
  /** Working/episodic memory. */
  crystalline: CrystallineStore;
  /** RECALL substrate (Crystalline + Supabase + Neo4j). */
  retriever: HybridRetriever;
}
