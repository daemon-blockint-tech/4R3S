/**
 * Supabase retriever — candidate retrieval via the `hybrid_search` RPC
 * (pgvector similarity fused with full-text `tsvector` ranking, RRF).
 *
 * See `db/supabase/0001_hybrid_search.sql` for the function definition. Returns
 * chunk fragments carrying `doc_id` / `chunk_id` / `entity_id` in metadata so
 * the Neo4j stage can expand them by graph relationships.
 */
import { logger } from "../config/logger.js";
import {
  describePostgrestError,
  logPostgrestError,
} from "../persistence/supabase-error.js";
import { getSupabase } from "../persistence/supabase.js";
import { synthCrystal } from "./util.js";
import type { HybridQuery, RetrievalResult, Retriever } from "./types.js";

interface HybridSearchRow {
  chunk_id: string;
  doc_id: string;
  entity_id: string | null;
  content: string;
  score: number | null;
}

export class SupabaseRetriever implements Retriever {
  readonly name = "supabase";

  async retrieve(query: HybridQuery): Promise<RetrievalResult> {
    const supabase = getSupabase();
    if (!supabase) return { fragments: [] };

    try {
      const { data, error } = await supabase.rpc("hybrid_search", {
        query_text: query.text,
        query_embedding: query.embedding ?? null,
        match_count: query.limit ?? 20,
      });
      if (error) {
        logPostgrestError(
          "supabase-retriever",
          error,
          "hybrid_search RPC failed; skipping Supabase source",
        );
        return {
          fragments: [],
          error: `hybrid_search RPC failed: ${describePostgrestError(error)}`,
        };
      }

      const rows = (data ?? []) as HybridSearchRow[];
      const fragments = rows.map((row) => ({
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
      return { fragments };
    } catch (err) {
      logger.warn(
        { component: "supabase-retriever", err: String(err) },
        "Supabase retrieval errored; skipping source",
      );
      return { fragments: [], error: String(err) };
    }
  }
}
