/**
 * Crystalline Memory Layer — Core Types
 *
 * A five-level knowledge architecture with activation-based retrieval and
 * cross-level consolidation. Each memory unit is a "Crystal": a discrete
 * knowledge fragment with an activation level that decays over time and
 * associative links to related crystals.
 *
 * Levels (Purdue-inspired cognitive hierarchy, lowest → highest):
 *   1. SENSORY     — raw, ephemeral inputs (tool outputs, code excerpts, findings)
 *   2. WORKING     — current audit context, the active scratchpad
 *   3. EPISODIC    — specific audit sessions ("the time we audited program X")
 *   4. SEMANTIC    — generalized vulnerability patterns and domain knowledge
 *   5. PROCEDURAL  — reusable audit workflows, heuristics, playbooks
 *
 * Crystals flow upward through consolidation and are retrieved by spreading
 * activation: a recalled crystal primes its neighbors, mirroring human
 * associative recall.
 */

/** The five knowledge strata of the Crystalline memory. */
export type KnowledgeLevel =
  | "sensory"
  | "working"
  | "episodic"
  | "semantic"
  | "procedural";

/** Ordered levels, lowest to highest. Used by consolidation promotion. */
export const LEVEL_ORDER: KnowledgeLevel[] = [
  "sensory",
  "working",
  "episodic",
  "semantic",
  "procedural",
];

/** Namespace prefix under which all ARES crystals live in the backing store. */
export const ARES_NAMESPACE_ROOT = "ares";

/** Per-level namespace path within the store. */
export function levelNamespace(level: KnowledgeLevel): string[] {
  return [ARES_NAMESPACE_ROOT, level];
}

/**
 * A directed associative link between two crystals.
 * `weight` modulates how much activation spreads along the edge.
 */
export interface CrystalLink {
  /** Target crystal id. */
  target: string;
  /** Edge strength in (0, 1]. Higher = stronger association. */
  weight: number;
  /** Optional relation label, e.g. "causes", "similar-to", "fixes". */
  relation?: string;
}

/**
 * A single unit of crystallized knowledge.
 *
 * The `value` field is the store-facing payload; activation, links, and
 * metadata form the cognitive envelope that drives retrieval and
 * consolidation.
 */
export interface Crystal {
  /** Stable id, also used as the store key. */
  id: string;
  /** Knowledge stratum this crystal belongs to. */
  level: KnowledgeLevel;
  /** Human/LLM-readable content (finding text, pattern description, etc.). */
  content: string;
  /** Optional dense vector for similarity search. */
  embedding?: number[];
  /** Current activation potential in [0, 1]. Decays with time since lastActivated. */
  activation: number;
  /** Epoch ms of last activation boost. */
  lastActivated: number;
  /** Epoch ms of creation. */
  createdAt: number;
  /** Number of times this crystal has been recalled. */
  accessCount: number;
  /** Associative edges to other crystals. */
  links: CrystalLink[];
  /** Free-form structured metadata (severity, cwe, program, etc.). */
  metadata: Record<string, unknown>;
  /** Topic tags for coarse-grained filtering. */
  tags: string[];
}

/** A crystal plus its computed retrieval score at query time. */
export interface ScoredCrystal {
  crystal: Crystal;
  /** Final retrieval score = activation + similarity + link spread. */
  score: number;
}

/** Query parameters for activation-based retrieval. */
export interface RecallQuery {
  /** Text query; used for tag matching and (if embeddings exist) similarity. */
  query: string;
  /** Optional query embedding aligned with crystal embeddings. */
  queryEmbedding?: number[];
  /** Restrict to these levels. Default: all levels. */
  levels?: KnowledgeLevel[];
  /** Restrict to crystals with any of these tags. */
  tags?: string[];
  /** Minimum activation threshold to be returned. Default 0.05. */
  minActivation?: number;
  /** Maximum number of crystals to return. Default 8. */
  limit?: number;
  /** How many hops of spreading activation to perform. Default 1. */
  spreadDepth?: number;
  /** Decay factor applied per hop of spread. Default 0.5. */
  spreadDecay?: number;
}

/** Result of a consolidation pass. */
export interface ConsolidationReport {
  /** Crystals promoted to a higher level. */
  promoted: Array<{ crystalId: string; from: KnowledgeLevel; to: KnowledgeLevel }>;
  /** Crystals whose activation decayed below the prune threshold and were dropped. */
  pruned: string[];
  /** New or strengthened links formed between crystals. */
  linked: Array<{ source: string; target: string; relation: string }>;
  /** Crystals merged into a single generalized semantic crystal. */
  merged: Array<{ into: string; from: string[] }>;
}

/** Tunable parameters for the Crystalline store. */
export interface CrystallineConfig {
  /** Activation added to a crystal when it is touched. Default 0.6. */
  activationBoost: number;
  /** Activation ceiling. Default 1.0. */
  activationMax: number;
  /** Half-life of activation in ms. Default 1 hour. */
  activationHalfLifeMs: number;
  /** Activation below which a sensory/working crystal is pruned. Default 0.02. */
  pruneThreshold: number;
  /** Access count at/above which an episodic crystal is promoted to semantic. Default 3. */
  semanticPromotionAccess: number;
  /** Cosine similarity at/above which two crystals are considered for merging. Default 0.9. */
  mergeSimilarity: number;
  /** Default recall limit. Default 8. */
  defaultRecallLimit: number;
}
