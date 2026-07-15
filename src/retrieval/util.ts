/**
 * Retrieval helpers shared by the non-Crystalline sources.
 *
 * Supabase and Neo4j return documents/chunks/entities that aren't native
 * Crystals. `synthCrystal` wraps them in the `Crystal` shape (defaulting the
 * cognitive fields) so every retriever speaks one common result type.
 */
import type { Crystal, KnowledgeLevel } from "../memory/types.js";

export function synthCrystal(init: {
  id: string;
  content: string;
  level?: KnowledgeLevel;
  embedding?: number[];
  metadata?: Record<string, unknown>;
  tags?: string[];
}): Crystal {
  const now = Date.now();
  return {
    id: init.id,
    level: init.level ?? "semantic",
    content: init.content,
    embedding: init.embedding,
    // Synthetic KB fragments are treated as fully "warm" for this recall.
    activation: 1,
    lastActivated: now,
    createdAt: now,
    accessCount: 0,
    links: [],
    metadata: init.metadata ?? {},
    tags: init.tags ?? [],
  };
}
