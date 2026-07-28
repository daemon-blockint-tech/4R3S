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

/**
 * What a source returned for a query.
 *
 * A configured source that errors returns no fragments, which is
 * indistinguishable from a source that simply had nothing to offer — so the
 * failure is carried here rather than only logged. RECALL surfaces it in the
 * report: an audit that ran without its knowledge base is a narrower audit.
 */
export interface RetrievalResult {
  fragments: ScoredCrystal[];
  /** Set only when the source was configured and failed. */
  error?: string;
}

/** A named knowledge source. */
export interface Retriever {
  /** Stable identifier used in logs and result provenance. */
  readonly name: string;
  /**
   * Return scored fragments for the query. Must never throw: report a failure
   * as `error` with no fragments so the caller can tell it apart from silence.
   */
  retrieve(query: HybridQuery): Promise<RetrievalResult>;
}
