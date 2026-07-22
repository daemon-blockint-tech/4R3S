/**
 * Runtime knowledge-base writeback.
 *
 * The REMEMBER phase decides which findings are worth keeping for future
 * audits. Crystalline stores them in-process, but that store is session-scoped
 * (`persistence/store.ts`) and evaporates when the process exits. This writer
 * persists the same fragments to the durable hybrid knowledge base — Supabase
 * (pgvector + full-text) and/or Neo4j (graph) — using the exact id scheme and
 * table/node shapes the ingestion script uses (`scripts/ingest-solsec.ts`), so
 * recalled runtime memory joins the seeded corpus and survives restarts.
 *
 * Every write degrades gracefully: unconfigured backends are skipped and any
 * backend error is logged, never thrown — memory writeback must not break an
 * audit. When neither backend is configured, `enabled` is false and `persist`
 * is a no-op, exactly like recall's Crystalline-only fallback.
 */
import { createHash } from "node:crypto";

import { logger } from "../config/logger.js";
import type { KnowledgeLevel } from "../memory/types.js";
import { getSupabase, hasSupabase } from "./supabase.js";
import { hasNeo4j, withNeo4jSession } from "./neo4j.js";

/** A memory fragment to persist durably. */
export interface KnowledgeFragment {
  content: string;
  level: KnowledgeLevel;
  tags: string[];
  embedding?: number[];
  /** Free-form context (e.g. `{ target, source }`) — `target` groups the doc. */
  metadata?: Record<string, unknown>;
}

/** Ids assigned to a persisted fragment (join keys across Supabase + Neo4j). */
export interface PersistedFragment {
  docId: string;
  chunkId: string;
}

/** A durable sink for runtime memory fragments. */
export interface KnowledgeWriter {
  /** True when at least one backend (Supabase or Neo4j) is configured. */
  readonly enabled: boolean;
  /** Persist one fragment. Never throws; returns ids, or undefined if skipped. */
  persist(fragment: KnowledgeFragment): Promise<PersistedFragment | undefined>;
}

function sha(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, 32);
}

/** Stable slug ids for tag-derived entities, mirroring the ingest script. */
function tagEntities(tags: string[]): Array<{ id: string; name: string }> {
  return [...new Set(tags.map((t) => t.trim()).filter(Boolean))].map((name) => ({
    id: sha(name.toLowerCase()),
    name,
  }));
}

/** Writes runtime memory to Supabase and/or Neo4j when configured. */
export class HybridKnowledgeWriter implements KnowledgeWriter {
  get enabled(): boolean {
    return hasSupabase() || hasNeo4j();
  }

  async persist(
    fragment: KnowledgeFragment,
  ): Promise<PersistedFragment | undefined> {
    const content = fragment.content.trim();
    if (!content) return undefined;

    // Group all runtime memory for a target under one synthetic document; key
    // the chunk by content hash so repeated writes upsert instead of duplicate.
    const target = String(fragment.metadata?.target ?? "runtime-memory");
    const docId = sha(`runtime-memory:${target}`);
    const chunkId = sha(`${docId}:${content}`);

    let wroteAnything = false;
    if (hasSupabase()) {
      wroteAnything = (await this.writeSupabase(fragment, { docId, chunkId, target, content })) || wroteAnything;
    }
    if (hasNeo4j()) {
      wroteAnything = (await this.writeNeo4j(fragment, { docId, chunkId, target, content })) || wroteAnything;
    }

    if (!wroteAnything) return undefined;
    logger.debug(
      { component: "knowledge-writer", docId, chunkId, level: fragment.level },
      "Runtime memory persisted to knowledge base",
    );
    return { docId, chunkId };
  }

  private async writeSupabase(
    fragment: KnowledgeFragment,
    ids: { docId: string; chunkId: string; target: string; content: string },
  ): Promise<boolean> {
    const supabase = getSupabase();
    if (!supabase) return false;
    try {
      const { error: docErr } = await supabase.from("documents").upsert(
        {
          doc_id: ids.docId,
          title: `runtime memory: ${ids.target}`,
          path: `runtime/${ids.docId}`,
        },
        { onConflict: "doc_id" },
      );
      if (docErr) throw new Error(`documents upsert: ${docErr.message}`);

      const { error: chunkErr } = await supabase.from("chunks").upsert(
        {
          chunk_id: ids.chunkId,
          doc_id: ids.docId,
          content: ids.content,
          chunk_index: 0,
          embedding: fragment.embedding ?? null,
        },
        { onConflict: "chunk_id" },
      );
      if (chunkErr) throw new Error(`chunks upsert: ${chunkErr.message}`);
      return true;
    } catch (err) {
      logger.warn(
        { component: "knowledge-writer", backend: "supabase", err: String(err) },
        "Supabase writeback failed (non-fatal)",
      );
      return false;
    }
  }

  private async writeNeo4j(
    fragment: KnowledgeFragment,
    ids: { docId: string; chunkId: string; target: string; content: string },
  ): Promise<boolean> {
    try {
      const entities = tagEntities(fragment.tags);
      await withNeo4jSession(async (session) => {
        await session.run(
          `MERGE (doc:Document { doc_id: $doc_id })
             SET doc.title = $title, doc.path = $path
           MERGE (ch:Chunk { chunk_id: $chunk_id })
             SET ch.content = $content, ch.chunk_index = 0, ch.level = $level
           MERGE (doc)-[:HAS_CHUNK]->(ch)
           WITH ch
           UNWIND $entities AS ent
             MERGE (e:Entity { entity_id: ent.id })
               SET e.name = ent.name
             MERGE (ch)-[:MENTIONS]->(e)`,
          {
            doc_id: ids.docId,
            title: `runtime memory: ${ids.target}`,
            path: `runtime/${ids.docId}`,
            chunk_id: ids.chunkId,
            content: ids.content,
            level: fragment.level,
            entities,
          },
        );
      });
      return true;
    } catch (err) {
      logger.warn(
        { component: "knowledge-writer", backend: "neo4j", err: String(err) },
        "Neo4j writeback failed (non-fatal)",
      );
      return false;
    }
  }
}

/** No-op writer used when durable writeback isn't wired (e.g. in tests). */
export class NullKnowledgeWriter implements KnowledgeWriter {
  readonly enabled = false;
  async persist(): Promise<undefined> {
    return undefined;
  }
}

/** Build the writer for the current environment. */
export function createKnowledgeWriter(): KnowledgeWriter {
  const writer = new HybridKnowledgeWriter();
  logger.info(
    {
      component: "knowledge-writer",
      supabase: hasSupabase(),
      neo4j: hasNeo4j(),
      enabled: writer.enabled,
    },
    writer.enabled
      ? "Runtime knowledge writeback enabled"
      : "Runtime knowledge writeback disabled (no Supabase/Neo4j) — Crystalline only",
  );
  return writer;
}
