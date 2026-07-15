/**
 * Crystalline retriever — adapts the existing activation-based CrystallineStore
 * to the common `Retriever` interface. No new retrieval logic; it simply maps a
 * `HybridQuery` onto `CrystallineStore.recall`.
 */
import type { CrystallineStore } from "../memory/crystalline-store.js";
import type { ScoredCrystal } from "../memory/types.js";
import { logger } from "../config/logger.js";
import type { HybridQuery, Retriever } from "./types.js";

export class CrystallineRetriever implements Retriever {
  readonly name = "crystalline";
  private readonly store: CrystallineStore;

  constructor(store: CrystallineStore) {
    this.store = store;
  }

  async retrieve(query: HybridQuery): Promise<ScoredCrystal[]> {
    try {
      return await this.store.recall({
        query: query.text,
        queryEmbedding: query.embedding,
        tags: query.tags,
        limit: query.limit,
      });
    } catch (err) {
      logger.warn(
        { component: "crystalline-retriever", err: String(err) },
        "Crystalline recall failed; returning no fragments",
      );
      return [];
    }
  }
}
