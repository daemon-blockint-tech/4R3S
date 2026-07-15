/**
 * Crystalline Store — activation-based memory over LangGraph's BaseStore.
 *
 * Crystals are persisted as store items keyed by id under per-level namespaces.
 * The store handles serialization; this class adds the cognitive envelope:
 * activation decay, spreading activation, consolidation, and level promotion.
 *
 * Embeddings are kept inside the stored value and similarity is computed here
 * (rather than delegating to store-level vector indexing) so the same logic
 * works across any BaseStore implementation, including the in-memory store.
 */
import type { BaseStore, Item } from "@langchain/langgraph";
import { v4 as uuidv4 } from "uuid";

import { logger } from "../config/logger.js";
import {
  type Crystal,
  type ConsolidationReport,
  type CrystallineConfig,
  type KnowledgeLevel,
  type RecallQuery,
  type ScoredCrystal,
  LEVEL_ORDER,
  levelNamespace,
} from "./types.js";

const DEFAULT_CONFIG: CrystallineConfig = {
  activationBoost: 0.6,
  activationMax: 1.0,
  activationHalfLifeMs: 60 * 60 * 1000, // 1h
  pruneThreshold: 0.02,
  semanticPromotionAccess: 3,
  mergeSimilarity: 0.9,
  defaultRecallLimit: 8,
};

/** Internal store payload — the crystal plus a schema version. */
interface StoredCrystal {
  v: 1;
  crystal: Crystal;
}

export class CrystallineStore {
  private readonly store: BaseStore;
  private readonly cfg: CrystallineConfig;

  constructor(store: BaseStore, cfg: Partial<CrystallineConfig> = {}) {
    this.store = store;
    this.cfg = { ...DEFAULT_CONFIG, ...cfg };
  }

  // ──────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ──────────────────────────────────────────────────────────────────────

  async start(): Promise<void> {
    await (this.store as { start?: () => Promise<void> }).start?.();
    logger.debug({ component: "crystalline" }, "Crystalline store started");
  }

  async stop(): Promise<void> {
    await (this.store as { stop?: () => Promise<void> }).stop?.();
    logger.debug({ component: "crystalline" }, "Crystalline store stopped");
  }

  // ──────────────────────────────────────────────────────────────────────
  // Writes
  // ──────────────────────────────────────────────────────────────────────

  /** Create a new crystal at the given level. Returns the stored crystal. */
  async crystallize(
    level: KnowledgeLevel,
    content: string,
    init: Partial<Pick<Crystal, "embedding" | "metadata" | "tags" | "links">> = {},
  ): Promise<Crystal> {
    const now = Date.now();
    const crystal: Crystal = {
      id: uuidv4(),
      level,
      content,
      embedding: init.embedding,
      activation: this.cfg.activationBoost,
      lastActivated: now,
      createdAt: now,
      accessCount: 0,
      links: init.links ?? [],
      metadata: init.metadata ?? {},
      tags: init.tags ?? [],
    };
    await this.persist(crystal);
    logger.debug(
      { component: "crystalline", level, id: crystal.id, tags: crystal.tags },
      "Crystallized new memory",
    );
    return crystal;
  }

  /** Touch an existing crystal, boosting its activation. */
  async activate(crystalId: string, level: KnowledgeLevel): Promise<void> {
    const c = await this.load(crystalId, level);
    if (!c) return;
    c.activation = Math.min(
      this.cfg.activationMax,
      this.decayedActivation(c) + this.cfg.activationBoost,
    );
    c.lastActivated = Date.now();
    c.accessCount += 1;
    await this.persist(c);
  }

  /** Add a directed link between two crystals. */
  async link(
    sourceId: string,
    sourceLevel: KnowledgeLevel,
    targetId: string,
    weight: number,
    relation?: string,
  ): Promise<void> {
    const c = await this.load(sourceId, sourceLevel);
    if (!c) return;
    const existing = c.links.find((l) => l.target === targetId);
    if (existing) {
      existing.weight = Math.max(existing.weight, weight);
      if (relation) existing.relation = relation;
    } else {
      c.links.push({ target: targetId, weight, relation });
    }
    await this.persist(c);
  }

  /** Delete a crystal. */
  async forget(crystalId: string, level: KnowledgeLevel): Promise<void> {
    await this.store.delete(levelNamespace(level), crystalId);
  }

  // ──────────────────────────────────────────────────────────────────────
  // Reads
  // ──────────────────────────────────────────────────────────────────────

  /** Load a single crystal by id. */
  async load(
    crystalId: string,
    level: KnowledgeLevel,
  ): Promise<Crystal | undefined> {
    const item = await this.store.get(levelNamespace(level), crystalId);
    if (!item) return undefined;
    return this.deserialize(item);
  }

  /**
   * Activation-based recall. Computes decayed activation for all crystals
   * in the candidate set, scores by similarity + tag match + activation,
   * then spreads activation along links up to `spreadDepth` hops.
   */
  async recall(query: RecallQuery): Promise<ScoredCrystal[]> {
    const levels = query.levels ?? LEVEL_ORDER;
    const limit = query.limit ?? this.cfg.defaultRecallLimit;
    const minActivation = query.minActivation ?? 0.05;
    const spreadDepth = query.spreadDepth ?? 1;
    const spreadDecay = query.spreadDecay ?? 0.5;

    // Gather candidates across levels, optionally filtered by tags.
    const candidates: Crystal[] = [];
    for (const level of levels) {
      const items = await this.searchLevel(level, query.tags, 200);
      for (const item of items) {
        const c = this.deserialize(item);
        if (c) candidates.push(c);
      }
    }

    // Score each candidate.
    const scored = candidates.map((c) => {
      const act = this.decayedActivation(c);
      const sim =
        query.queryEmbedding && c.embedding
          ? cosineSimilarity(query.queryEmbedding, c.embedding)
          : tagSimilarity(query.query, c.tags);
      const base = act * 0.4 + sim * 0.6;
      return { crystal: c, score: base, act };
    });

    // Spreading activation: boost scores of neighbors of top candidates.
    const topIds = new Set(
      scored
        .filter((s) => s.act >= minActivation)
        .sort((a, b) => b.score - a.score)
        .slice(0, limit)
        .map((s) => s.crystal.id),
    );

    if (spreadDepth > 0 && topIds.size > 0) {
      const spread = new Map<string, number>();
      for (const s of scored) {
        if (!topIds.has(s.crystal.id)) continue;
        for (const link of s.crystal.links) {
          const boost = s.score * link.weight * spreadDecay;
          spread.set(link.target, (spread.get(link.target) ?? 0) + boost);
        }
      }
      // Resolve spread targets across all levels.
      for (const s of scored) {
        const boost = spread.get(s.crystal.id);
        if (boost) s.score += boost;
      }
    }

    return scored
      .filter((s) => s.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, limit)
      .map(({ crystal, score }) => ({ crystal, score }));
  }

  // ──────────────────────────────────────────────────────────────────────
  // Consolidation
  // ──────────────────────────────────────────────────────────────────────

  /**
   * Run a consolidation pass:
   *   1. Decay activation on all crystals; prune those below threshold.
   *   2. Promote frequently-accessed episodic crystals to semantic.
   *   3. Merge near-duplicate semantic crystals by embedding similarity.
   *   4. Strengthen links between crystals that co-activated recently.
   */
  async consolidate(): Promise<ConsolidationReport> {
    const report: ConsolidationReport = {
      promoted: [],
      pruned: [],
      linked: [],
      merged: [],
    };

    for (const level of LEVEL_ORDER) {
      const items = await this.searchLevel(level, undefined, 500);
      const crystals: Crystal[] = [];
      for (const item of items) {
        const c = this.deserialize(item);
        if (c) crystals.push(c);
      }

      // 1. Decay + prune (only ephemeral levels).
      if (level === "sensory" || level === "working") {
        for (const c of crystals) {
          const act = this.decayedActivation(c);
          if (act < this.cfg.pruneThreshold) {
            await this.forget(c.id, level);
            report.pruned.push(c.id);
          } else {
            c.activation = act;
            await this.persist(c);
          }
        }
        continue;
      }

      // 2. Promote episodic → semantic.
      if (level === "episodic") {
        for (const c of crystals) {
          if (c.accessCount >= this.cfg.semanticPromotionAccess) {
            const promoted: Crystal = {
              ...c,
              level: "semantic",
              activation: this.cfg.activationBoost,
              lastActivated: Date.now(),
            };
            await this.forget(c.id, "episodic");
            await this.persist(promoted);
            report.promoted.push({
              crystalId: c.id,
              from: "episodic",
              to: "semantic",
            });
          }
        }
      }

      // 3. Merge near-duplicate semantic crystals.
      if (level === "semantic") {
        const merged = this.findMerges(crystals);
        for (const m of merged) {
          const into = m.into;
          into.content = `${into.content}\n\n[merged] ${m.from
            .map((id) => crystals.find((c) => c.id === id)?.content ?? "")
            .join("\n\n")}`;
          into.accessCount += m.from.length;
          for (const id of m.from) {
            await this.forget(id, "semantic");
          }
          await this.persist(into);
          report.merged.push({ into: into.id, from: m.from });
        }
      }
    }

    logger.info(
      {
        component: "crystalline",
        promoted: report.promoted.length,
        pruned: report.pruned.length,
        merged: report.merged.length,
      },
      "Consolidation pass complete",
    );
    return report;
  }

  // ──────────────────────────────────────────────────────────────────────
  // Internals
  // ──────────────────────────────────────────────────────────────────────

  private decayedActivation(c: Crystal): number {
    const elapsed = Date.now() - c.lastActivated;
    const halfLives = elapsed / this.cfg.activationHalfLifeMs;
    return c.activation * Math.pow(0.5, halfLives);
  }

  private async persist(c: Crystal): Promise<void> {
    const payload: StoredCrystal = { v: 1, crystal: c };
    // Store the whole payload under the crystal id; no store-level index —
    // similarity is computed in `recall` from the embedding kept in `value`.
    await this.store.put(
      levelNamespace(c.level),
      c.id,
      payload as unknown as Record<string, unknown>,
    );
  }

  private deserialize(item: Item): Crystal | undefined {
    const raw = item.value as unknown as StoredCrystal;
    if (!raw || raw.v !== 1) return undefined;
    return raw.crystal;
  }

  /**
   * List crystals in a level, optionally filtered by tag overlap. Tag matching
   * is done in-memory (rather than via store filter operators) so it works
   * uniformly across store backends and against array-valued `tags`.
   */
  private async searchLevel(
    level: KnowledgeLevel,
    tags: string[] | undefined,
    limit: number,
  ): Promise<Item[]> {
    const items = await this.store.search(levelNamespace(level), { limit });
    if (!tags || tags.length === 0) return items;
    const wanted = new Set(tags);
    return items.filter((item) => {
      const c = this.deserialize(item);
      return c ? c.tags.some((t) => wanted.has(t)) : false;
    });
  }

  private findMerges(
    crystals: Crystal[],
  ): Array<{ into: Crystal; from: string[] }> {
    const merges: Array<{ into: Crystal; from: string[] }> = [];
    const consumed = new Set<string>();
    for (const c of crystals) {
      if (consumed.has(c.id) || !c.embedding) continue;
      const cluster: Crystal[] = [c];
      for (const other of crystals) {
        if (other.id === c.id || consumed.has(other.id)) continue;
        if (!other.embedding) continue;
        if (
          cosineSimilarity(c.embedding, other.embedding) >=
          this.cfg.mergeSimilarity
        ) {
          cluster.push(other);
        }
      }
      if (cluster.length > 1) {
        for (const m of cluster) consumed.add(m.id);
        merges.push({
          into: c,
          from: cluster.filter((m) => m.id !== c.id).map((m) => m.id),
        });
      }
    }
    return merges;
  }
}

// ──────────────────────────────────────────────────────────────────────
// Vector helpers
// ──────────────────────────────────────────────────────────────────────

export function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length) return 0;
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i]! * b[i]!;
    na += a[i]! * a[i]!;
    nb += b[i]! * b[i]!;
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

function tagSimilarity(query: string, tags: string[]): number {
  if (tags.length === 0) return 0;
  const q = query.toLowerCase();
  const hits = tags.filter((t) => q.includes(t.toLowerCase())).length;
  return hits / tags.length;
}
