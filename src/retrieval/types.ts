/**
 * Retrieval layer types.
 *
 * A `Retriever` is any knowledge source that, given a query, returns scored
 * memory fragments in the common `ScoredCrystal` shape. The hybrid retriever
 * composes several of these (Crystalline, Supabase, Neo4j) into one ranked set.
 */
import type { ScoredCrystal } from "../memory/types.js";

/** A retrieval query shared across all sources. */
export interface HybridQuery {
  /** Free-text query (from the intake summary / audit target). */
  text: string;
  /** Optional dense embedding of `text`, when an embedder is configured. */
  embedding?: number[];
  /** Optional coarse tag filter. */
  tags?: string[];
  /** Max results to return. */
  limit?: number;
}

/** A named knowledge source. */
export interface Retriever {
  /** Stable identifier used in logs and result provenance. */
  readonly name: string;
  /** Return scored fragments for the query. Must never throw — degrade to []. */
  retrieve(query: HybridQuery): Promise<ScoredCrystal[]>;
}
