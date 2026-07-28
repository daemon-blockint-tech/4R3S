/**
 * Neo4j retriever — knowledge-graph expansion and relationship-aware reranking.
 *
 * Two roles:
 *   - `retrieve(query)`: standalone lexical match over Chunk/Entity nodes, so
 *     the graph can contribute candidates on its own.
 *   - `expand(seedChunkIds)`: given candidate chunk ids (typically from the
 *     Supabase stage), traverse 1–2 hops to surface related chunks/entities and
 *     score them by graph proximity.
 *
 * See `db/neo4j/schema.cypher` for the node/relationship model. All methods
 * degrade to `[]` when Neo4j is not configured or a query fails.
 */
import neo4j from "neo4j-driver";

import type { ScoredCrystal } from "../memory/types.js";
import { logger } from "../config/logger.js";
import { withNeo4jSession } from "../persistence/neo4j.js";
import { synthCrystal } from "./util.js";
import type { HybridQuery, RetrievalResult, Retriever } from "./types.js";

interface GraphRow {
  id: string;
  content: string;
  entityId: string | null;
  proximity: number;
}

/** Lucene syntax characters that would otherwise be parsed as operators. */
const LUCENE_SPECIAL = /[+\-&|!(){}[\]^"~*?:\\/]/g;

/**
 * Turn a natural-language query into a safe Lucene OR query.
 *
 * The full-text index speaks Lucene, so an unescaped `:` or `-` from a program
 * address or a file path is a syntax error, not a search term — and a raw
 * sentence would be ANDed into nothing. Terms are escaped, short noise words
 * dropped, and the rest ORed so any overlap ranks. Returns "" when nothing
 * usable survives, which the caller treats as "no fragments" rather than
 * sending a query that matches everything.
 */
export function toLuceneQuery(text: string, maxTerms = 24): string {
  return (text ?? "")
    .split(/\s+/)
    .map((t) => t.replace(LUCENE_SPECIAL, "").trim())
    .filter((t) => t.length > 2)
    .slice(0, maxTerms)
    .join(" OR ");
}

export class Neo4jRetriever implements Retriever {
  readonly name = "neo4j";

  async retrieve(query: HybridQuery): Promise<RetrievalResult> {
    // neo4j.int(): the driver packs a plain JS number as a PackStream Float, and
    // Cypher's LIMIT wants an integer. Passing 8 sends `LIMIT 8.0`.
    const limit = neo4j.int(query.limit ?? 20);

    // `CONTAINS` required a single chunk to contain the *entire* query string
    // verbatim. The query is `intake.summary` — a whole sentence, and when
    // INTAKE has no summary, the raw request — so no seeded corpus chunk ever
    // matched, and the source reported `ok` with zero fragments on every run:
    // "answered and had nothing" was indistinguishable from "never worked".
    // The full-text index this needs has existed unused in
    // db/neo4j/schema.cypher since the schema was written.
    const terms = toLuceneQuery(query.text);
    if (!terms) return { fragments: [] };

    const { rows, error } = await this.run(
      `
      CALL db.index.fulltext.queryNodes('chunk_content', $terms)
      YIELD node AS c, score
      OPTIONAL MATCH (c)-[:MENTIONS]->(e:Entity)
      RETURN c.chunk_id AS id, c.content AS content,
             e.entity_id AS entityId, score AS proximity
      ORDER BY proximity DESC
      LIMIT $limit
      `,
      { terms, limit },
    );
    return { fragments: this.toScored(rows, "neo4j-search"), error };
  }

  /**
   * Expand a set of seed chunk ids by graph relationships. Neighbors closer in
   * the graph (fewer hops) score higher.
   */
  async expand(seedChunkIds: string[], limit = 20): Promise<RetrievalResult> {
    if (seedChunkIds.length === 0) return { fragments: [] };
    const limitInt = neo4j.int(limit);
    const { rows, error } = await this.run(
      `
      MATCH (seed:Chunk) WHERE seed.chunk_id IN $ids
      MATCH path = (seed)-[*1..2]-(n:Chunk)
      WHERE n.chunk_id IS NOT NULL AND NOT n.chunk_id IN $ids
      WITH n, min(length(path)) AS hops
      OPTIONAL MATCH (n)-[:MENTIONS]->(e:Entity)
      RETURN n.chunk_id AS id, n.content AS content,
             e.entity_id AS entityId, 1.0 / (1 + hops) AS proximity
      ORDER BY proximity DESC
      LIMIT $limit
      `,
      { ids: seedChunkIds, limit: limitInt },
    );
    return { fragments: this.toScored(rows, "neo4j-expand"), error };
  }

  private async run(
    cypher: string,
    params: Record<string, unknown>,
  ): Promise<{ rows: GraphRow[]; error?: string }> {
    try {
      const result = await withNeo4jSession(async (session) => {
        const res = await session.run(cypher, params);
        return res.records.map((r) => ({
          id: String(r.get("id")),
          content: String(r.get("content") ?? ""),
          entityId: r.get("entityId") ? String(r.get("entityId")) : null,
          proximity: Number(r.get("proximity") ?? 0),
        }));
      });
      return { rows: result ?? [] };
    } catch (err) {
      logger.warn(
        { component: "neo4j-retriever", err: String(err) },
        "Neo4j query failed; skipping graph source",
      );
      return { rows: [], error: String(err) };
    }
  }

  private toScored(rows: GraphRow[], source: string): ScoredCrystal[] {
    return rows.map((row) => ({
      crystal: synthCrystal({
        id: row.id,
        content: row.content,
        metadata: {
          source,
          chunk_id: row.id,
          entity_id: row.entityId ?? undefined,
        },
      }),
      score: row.proximity,
    }));
  }
}
