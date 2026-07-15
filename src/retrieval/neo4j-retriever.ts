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
import type { ScoredCrystal } from "../memory/types.js";
import { logger } from "../config/logger.js";
import { withNeo4jSession } from "../persistence/neo4j.js";
import { synthCrystal } from "./util.js";
import type { HybridQuery, Retriever } from "./types.js";

interface GraphRow {
  id: string;
  content: string;
  entityId: string | null;
  proximity: number;
}

export class Neo4jRetriever implements Retriever {
  readonly name = "neo4j";

  async retrieve(query: HybridQuery): Promise<ScoredCrystal[]> {
    const limit = query.limit ?? 20;
    const rows = await this.run(
      `
      MATCH (c:Chunk)
      WHERE toLower(c.content) CONTAINS toLower($text)
      OPTIONAL MATCH (c)-[:MENTIONS]->(e:Entity)
      RETURN c.chunk_id AS id, c.content AS content,
             e.entity_id AS entityId, 1.0 AS proximity
      LIMIT $limit
      `,
      { text: query.text, limit },
    );
    return this.toScored(rows, "neo4j-search");
  }

  /**
   * Expand a set of seed chunk ids by graph relationships. Neighbors closer in
   * the graph (fewer hops) score higher.
   */
  async expand(seedChunkIds: string[], limit = 20): Promise<ScoredCrystal[]> {
    if (seedChunkIds.length === 0) return [];
    const rows = await this.run(
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
      { ids: seedChunkIds, limit },
    );
    return this.toScored(rows, "neo4j-expand");
  }

  private async run(
    cypher: string,
    params: Record<string, unknown>,
  ): Promise<GraphRow[]> {
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
      return result ?? [];
    } catch (err) {
      logger.warn(
        { component: "neo4j-retriever", err: String(err) },
        "Neo4j query failed; skipping graph source",
      );
      return [];
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
