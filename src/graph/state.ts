/**
 * ARES audit graph state.
 *
 * Channels flow through the phases INTAKE → RECALL → [parallel ANALYZE] →
 * MERGE → REMEMBER → REPORT. `findings` uses a concat reducer so the parallel
 * analyzer nodes can append concurrently in one superstep without clobbering
 * each other; most other channels are last-value.
 */
import { Annotation } from "@langchain/langgraph";

import type { ScoredCrystal, KnowledgeLevel } from "../memory/types.js";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "high" | "medium" | "low";

/** Severity ordering for ranking (higher = more severe). */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/** A single audit finding produced by an analyzer. */
export interface Finding {
  /** Vulnerability class, e.g. "signer-missing", "owner-check-bypass". */
  vulnClass: string;
  /** Instruction / account / file:line the finding concerns. */
  location: string;
  severity: Severity;
  /** Concrete evidence (tool output, code excerpt) supporting the finding. */
  evidence: string;
  /** Proposed remediation. */
  remediation: string;
  /** Which analyzer produced it. */
  source: "onchain" | "static" | "heuristic" | "cua";
  /** Catalog vulnerability id (from VULN_CATALOG), or "other". */
  category: string;
  /** True when the finding is pattern-based without code-level evidence. */
  speculative: boolean;
  /** Confidence level: high (tool/code evidence), medium (partial), low (speculative). */
  confidence: Confidence;
}

/** Structured output of the INTAKE phase. */
export interface IntakeSummary {
  target: string;
  depth: string;
  concerns: string[];
  summary: string;
}

/** A memory fragment the REMEMBER phase decided to persist. */
export interface MemoryWrite {
  level: KnowledgeLevel;
  content: string;
  tags?: string[];
  metadata?: Record<string, unknown>;
}

export const AresStateAnnotation = Annotation.Root({
  /** Raw audit request text. */
  request: Annotation<string>(),
  /** Concrete on-chain target, if the audit is for a deployed program. */
  programAddress: Annotation<string | undefined>(),
  /** Concrete source path, if the audit is for local source. */
  sourcePath: Annotation<string | undefined>(),
  /** Structured intake summary (LLM-parsed). */
  intake: Annotation<IntakeSummary | undefined>(),
  /** Memory fragments recalled by the hybrid retriever. */
  recalled: Annotation<ScoredCrystal[]>({
    reducer: (_prev, next) => next,
    default: () => [],
  }),
  /** Findings — appended by each analyzer in the parallel ANALYZE superstep. */
  findings: Annotation<Finding[]>({
    reducer: (prev, next) => prev.concat(next),
    default: () => [],
  }),
  /** Deduped + severity-ranked findings produced by the MERGE node. */
  mergedFindings: Annotation<Finding[]>({
    reducer: (_prev, next) => next,
    default: () => [],
  }),
  /** What REMEMBER chose to persist. */
  memoryWrites: Annotation<MemoryWrite[]>({
    reducer: (_prev, next) => next,
    default: () => [],
  }),
  /** Final synthesized report. */
  report: Annotation<string>({
    reducer: (_prev, next) => next,
    default: () => "",
  }),
  /** LLM-call counter, summed across nodes; bounds runaway loops. */
  iterations: Annotation<number>({
    reducer: (prev, next) => prev + next,
    default: () => 0,
  }),
  /** Vulnerability classes evaluated across analyzers (catalog ids). */
  coverage: Annotation<string[]>({
    reducer: (prev, next) => [...new Set([...prev, ...next])],
    default: () => [],
  }),
});

export type AresState = typeof AresStateAnnotation.State;
export type AresStateUpdate = typeof AresStateAnnotation.Update;
