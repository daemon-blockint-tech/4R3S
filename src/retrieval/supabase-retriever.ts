/**
 * Supabase retriever — candidate retrieval via the `hybrid_search` RPC
 * (pgvector similarity fused with full-text `tsvector` ranking, RRF).
 *
 * See `db/supabase/0001_hybrid_search.sql` for the function definition. Returns
 * chunk fragments carrying `doc_id` / `chunk_id` / `entity_id` in metadata so
 * the Neo4j stage can expand them by graph relationships.
 */
import type { ScoredCrystal } from "../memory/types.js";
import { logger } from "../config/logger.js";
import { getSupabase } from "../persistence/supabase.js";
import { synthCrystal } from "./util.js";
import type { HybridQuery, Retriever } from "./types.js";

interface HybridSearchRow {
  chunk_id: string;
  doc_id: string;
  entity_id: string | null;
  content: string;
  score: number | null;
}

export class SupabaseRetriever implements Retriever {
  readonly name = "supabase";

  async retrieve(query: HybridQuery): Promise<ScoredCrystal[]> {
    const supabase = getSupabase();
    if (!supabase) return [];

    try {
      const { data, error } = await supabase.rpc("hybrid_search", {
        query_text: query.text,
        query_embedding: query.embedding ?? null,
        match_count: query.limit ?? 20,
      });
      if (error) {
        logger.warn(
          { component: "supabase-retriever", err: error.message },
          "hybrid_search RPC failed; skipping Supabase source",
        );
        return [];
      }

      const rows = (data ?? []) as HybridSearchRow[];
      return rows.map((row) => ({
        crystal: synthCrystal({
          id: row.chunk_id,
          content: row.content,
          metadata: {
            source: "supabase",
            doc_id: row.doc_id,
            chunk_id: row.chunk_id,
            entity_id: row.entity_id ?? undefined,
          },
        }),
        score: row.score ?? 0,
      }));
    } catch (err) {
      logger.warn(
        { component: "supabase-retriever", err: String(err) },
        "Supabase retrieval errored; skipping source",
      );
      return [];
    }
  }
}
