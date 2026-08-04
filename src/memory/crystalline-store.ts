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

import { log } from "../config/logger.js";
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
    await this.store.start?.();
    log.debug("Crystalline store started", { component: "crystalline" });
  }

  async stop(): Promise<void> {
    await this.store.stop?.();
    log.debug("Crystalline store stopped", { component: "crystalline" });
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
    log.debug("Crystallized new memory", {
      component: "crystalline",
      level,
      id: crystal.id,
      tags: crystal.tags,
    });
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
    const raw = await this.store.get(levelNamespace(level), crystalId);
    if (!raw) return undefined;
    return this.deserialize(raw);
  }

  /**
   * Similarity-based recall (KR-1 fall-back from activation scoring).
   *
   * Scores candidates by embedding similarity, falling back to tag overlap
   * when no comparable embedding exists. Previously this also weighted in
   * decayed activation and spread the result along `links`. Both are removed:
   * `link()` has no caller anywhere in this codebase, so every crystal ships
   * with `links: []` and spreading never contributed a nonzero boost; and
   * decay is keyed off wall-clock time (`Date.now() - lastActivated`), which
   * made two recall() calls milliseconds apart score differently even over
   * identical data — the same non-reproducibility eval/ exists to catch.
   * See docs/KR-1-FINDINGS.md for the evidence (crystalline-inertness.test.ts).
   *
   * `minActivation`, `spreadDepth`, and `spreadDecay` on RecallQuery are
   * accepted but unused, kept for call-site compatibility rather than forcing
   * an unrelated signature change in this pass.
   */
  async recall(query: RecallQuery): Promise<ScoredCrystal[]> {
    const levels = query.levels ?? LEVEL_ORDER;
    const limit = query.limit ?? this.cfg.defaultRecallLimit;

    // Gather candidates across levels, optionally filtered by tags.
    const candidates: Crystal[] = [];
    for (const level of levels) {
      const items = await this.searchLevel(level, query.tags, 200);
      for (const item of items) {
        const c = this.deserialize(item);
        if (c) candidates.push(c);
      }
    }

    // Score each candidate. A crystal whose vector has a different dimension
    // than the query was embedded by a different model and is not comparable;
    // it falls back to tag scoring rather than being silently scored at zero.
    let dimMismatches = 0;
    const scored = candidates.map((c) => {
      const comparable =
        query.queryEmbedding &&
        c.embedding &&
        query.queryEmbedding.length === c.embedding.length;
      if (query.queryEmbedding && c.embedding && !comparable) dimMismatches += 1;
      const sim = comparable
        ? cosineSimilarity(query.queryEmbedding!, c.embedding!)
        : tagSimilarity(query.query, c.tags);
      return { crystal: c, score: sim };
    });

    if (dimMismatches > 0) {
      log.warn(
        {
          component: "crystalline",
          mismatched: dimMismatches,
          candidates: candidates.length,
          queryDim: query.queryEmbedding?.length,
        },
        "Stored embeddings have a different dimension than the query; semantic " +
          "scoring fell back to tags for those crystals. Re-ingest after an " +
          "EMBEDDINGS_MODEL change.",
      );
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

    log.info("Consolidation pass complete", {
      component: "crystalline",
      promoted: report.promoted.length,
      pruned: report.pruned.length,
      merged: report.merged.length,
    });
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
        // Incomparable vectors must not merge two unrelated crystals.
        if (other.embedding.length !== c.embedding.length) continue;
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

/**
 * Cosine similarity of two equal-length vectors.
 *
 * Throws on a length mismatch rather than returning 0. Returning 0 made a
 * configuration error — vectors written under a different EMBEDDINGS_MODEL —
 * indistinguishable from "genuinely unrelated", so changing the model silently
 * scored every stored crystal at zero while recall still reported success.
 * Callers are expected to check dimensions and degrade explicitly.
 */
export function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length) {
    throw new Error(
      `cosineSimilarity: dimension mismatch (${a.length} vs ${b.length}) — ` +
        "stored vectors were probably written under a different embedding model",
    );
  }
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
