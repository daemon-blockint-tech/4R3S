/**
 * Retrieval factory — assembles the active retriever set from configured
 * backends. Crystalline is always present; Supabase and Neo4j join only when
 * their credentials are set (otherwise recall is Crystalline-only).
 */
import type { CrystallineStore } from "../memory/crystalline-store.js";
import { logger } from "../config/logger.js";
import { hasSupabase } from "../persistence/supabase.js";
import { hasNeo4j } from "../persistence/neo4j.js";
import { CrystallineRetriever } from "./crystalline-retriever.js";
import { SupabaseRetriever } from "./supabase-retriever.js";
import { Neo4jRetriever } from "./neo4j-retriever.js";
import { HybridRetriever } from "./hybrid-retriever.js";

export * from "./types.js";
export { HybridRetriever } from "./hybrid-retriever.js";
export { embed, embedBatch, hasEmbeddings } from "./embeddings.js";

/** Build the hybrid retriever backed by the given Crystalline store. */
export function createHybridRetriever(store: CrystallineStore): HybridRetriever {
  const crystalline = new CrystallineRetriever(store);
  const supabase = hasSupabase() ? new SupabaseRetriever() : undefined;
  const neo4j = hasNeo4j() ? new Neo4jRetriever() : undefined;

  logger.info(
    {
      component: "retrieval",
      sources: ["crystalline", supabase && "supabase", neo4j && "neo4j"].filter(
        Boolean,
      ),
    },
    "Hybrid retriever assembled",
  );

  return new HybridRetriever(crystalline, supabase, neo4j);
}
