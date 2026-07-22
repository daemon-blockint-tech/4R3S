/**
 * Hybrid retriever — the RECALL substrate.
 *
 * Pipeline (per the augment-Crystalline design):
 *   1. In parallel: Crystalline activation recall, Supabase candidate search,
 *      and a standalone Neo4j lexical match (so the graph contributes candidates
 *      on its own, not only as an expansion of Supabase hits).
 *   2. Map Supabase candidates to chunk ids and expand them in Neo4j (1–2 hops)
 *      for relationship-aware enrichment.
 *   3. Merge all sources: normalize each source's scores, weight them, and sum
 *      per fragment id — a fragment surfaced by multiple sources (e.g. a chunk
 *      that is both semantically similar AND graph-adjacent) ranks higher.
 *
 * Any source that is unconfigured or errors contributes nothing; with only
 * Crystalline present this reduces to plain activation recall.
 */
import type { ScoredCrystal } from "../memory/types.js";
import { logger } from "../config/logger.js";
import type { CrystallineRetriever } from "./crystalline-retriever.js";
import type { SupabaseRetriever } from "./supabase-retriever.js";
import type { Neo4jRetriever } from "./neo4j-retriever.js";
import type { HybridQuery, Retriever } from "./types.js";

/** Per-source weights applied after normalization. */
const WEIGHTS = {
  crystalline: 0.9,
  supabase: 1.0,
  neo4j: 0.6,
} as const;

export class HybridRetriever implements Retriever {
  readonly name = "hybrid";

  constructor(
    private readonly crystalline: CrystallineRetriever,
    private readonly supabase?: SupabaseRetriever,
    private readonly neo4j?: Neo4jRetriever,
  ) {}

  async retrieve(query: HybridQuery): Promise<ScoredCrystal[]> {
    const limit = query.limit ?? 8;

    // Stage 1: Crystalline recall, Supabase candidates, and a standalone Neo4j
    // lexical match — all in parallel.
    const [crystalResults, supabaseResults, graphMatches] = await Promise.all([
      this.crystalline.retrieve(query),
      this.supabase?.retrieve({ ...query, limit: (limit ?? 8) * 3 }) ??
        Promise.resolve([]),
      this.neo4j?.retrieve({ ...query, limit: (limit ?? 8) * 3 }) ??
        Promise.resolve([]),
    ]);

    // Stage 2: expand Supabase candidates via Neo4j graph topology.
    const seedChunkIds = supabaseResults
      .map((r) => r.crystal.metadata.chunk_id)
      .filter((id): id is string => typeof id === "string");
    const graphExpansion = this.neo4j
      ? await this.neo4j.expand(seedChunkIds, limit * 3)
      : [];

    // The graph contributes both its standalone matches and the expansion of
    // Supabase seeds; both share the Neo4j weight bucket.
    const graphResults = [...graphMatches, ...graphExpansion];

    // Stage 3: weighted merge across sources.
    const merged = this.merge([
      { weight: WEIGHTS.crystalline, results: crystalResults },
      { weight: WEIGHTS.supabase, results: supabaseResults },
      { weight: WEIGHTS.neo4j, results: graphResults },
    ]);

    logger.debug(
      {
        component: "hybrid-retriever",
        crystalline: crystalResults.length,
        supabase: supabaseResults.length,
        neo4jMatch: graphMatches.length,
        neo4jExpand: graphExpansion.length,
        merged: merged.length,
      },
      "Hybrid recall complete",
    );

    return merged.slice(0, limit);
  }

  /**
   * Normalize each source's scores to [0,1], apply the source weight, and sum
   * per fragment id. Keeps the highest-content variant of each fragment.
   */
  private merge(
    sources: Array<{ weight: number; results: ScoredCrystal[] }>,
  ): ScoredCrystal[] {
    const acc = new Map<string, ScoredCrystal>();

    for (const { weight, results } of sources) {
      if (results.length === 0) continue;
      const max = Math.max(...results.map((r) => r.score), 1e-9);
      for (const r of results) {
        const contribution = (r.score / max) * weight;
        const existing = acc.get(r.crystal.id);
        if (existing) {
          existing.score += contribution;
        } else {
          acc.set(r.crystal.id, { crystal: r.crystal, score: contribution });
        }
      }
    }

    return [...acc.values()].sort((a, b) => b.score - a.score);
  }
}
