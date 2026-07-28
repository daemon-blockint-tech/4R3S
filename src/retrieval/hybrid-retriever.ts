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
 * Crystalline present this reduces to plain activation recall. The difference
 * between those two cases matters, though — an unconfigured source is the
 * documented default, a configured one that errored means the audit ran with
 * less prior knowledge than intended — so `retrieveWithStatus` reports each
 * source's outcome for RECALL to carry into the report.
 */
import type { ScoredCrystal } from "../memory/types.js";
import { logger } from "../config/logger.js";
import type { CrystallineRetriever } from "./crystalline-retriever.js";
import type { SupabaseRetriever } from "./supabase-retriever.js";
import type { Neo4jRetriever } from "./neo4j-retriever.js";
import type { HybridQuery, RetrievalResult, Retriever } from "./types.js";

/** How one knowledge source fared during a recall. */
export interface SourceStatus {
  source: "crystalline" | "supabase" | "neo4j";
  /** `skipped` means the source is not configured — the documented default. */
  outcome: "ok" | "skipped" | "failed";
  fragments: number;
  detail?: string;
}

/** Fragments plus the per-source outcomes that produced them. */
export interface HybridRecall {
  fragments: ScoredCrystal[];
  sources: SourceStatus[];
}

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

  /** `Retriever` contract: fragments only. Use `retrieveWithStatus` for outcomes. */
  async retrieve(query: HybridQuery): Promise<RetrievalResult> {
    const { fragments } = await this.retrieveWithStatus(query);
    return { fragments };
  }

  /** Recall, with each source's outcome reported alongside the fragments. */
  async retrieveWithStatus(query: HybridQuery): Promise<HybridRecall> {
    const limit = query.limit ?? 8;

    // Stage 1: Crystalline recall, Supabase candidates, and a standalone Neo4j
    // lexical match — all in parallel.
    const [crystalResult, supabaseResult, graphResult] = await Promise.all([
      this.crystalline.retrieve(query),
      this.supabase?.retrieve({ ...query, limit: limit * 3 }),
      this.neo4j?.retrieve({ ...query, limit: limit * 3 }),
    ]);

    // Stage 2: expand Supabase candidates via Neo4j graph topology.
    const seedChunkIds = (supabaseResult?.fragments ?? [])
      .map((r) => r.crystal.metadata.chunk_id)
      .filter((id): id is string => typeof id === "string");
    const expansion = this.neo4j
      ? await this.neo4j.expand(seedChunkIds, limit * 3)
      : undefined;

    // The graph contributes both its standalone matches and the expansion of
    // Supabase seeds; both share the Neo4j weight bucket.
    const graphFragments = [
      ...(graphResult?.fragments ?? []),
      ...(expansion?.fragments ?? []),
    ];

    // Stage 3: weighted merge across sources.
    const fragments = this.merge([
      { weight: WEIGHTS.crystalline, results: crystalResult.fragments },
      { weight: WEIGHTS.supabase, results: supabaseResult?.fragments ?? [] },
      { weight: WEIGHTS.neo4j, results: graphFragments },
    ]).slice(0, limit);

    const sources: SourceStatus[] = [
      status("crystalline", this.crystalline !== undefined, crystalResult),
      status("supabase", this.supabase !== undefined, supabaseResult),
      status("neo4j", this.neo4j !== undefined, {
        fragments: graphFragments,
        // Either query failing means the graph did not contribute what it could.
        error: graphResult?.error ?? expansion?.error,
      }),
    ];

    logger.debug(
      {
        component: "hybrid-retriever",
        merged: fragments.length,
        sources: sources.map((s) => `${s.source}:${s.outcome}`),
      },
      "Hybrid recall complete",
    );

    return { fragments, sources };
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

/** Classify one source's result. An unconfigured source is skipped, not failed. */
function status(
  source: SourceStatus["source"],
  configured: boolean,
  result: RetrievalResult | undefined,
): SourceStatus {
  if (!configured || !result) {
    return { source, outcome: "skipped", fragments: 0, detail: "not configured" };
  }
  if (result.error) {
    return {
      source,
      outcome: "failed",
      fragments: result.fragments.length,
      detail: result.error,
    };
  }
  return { source, outcome: "ok", fragments: result.fragments.length };
}
