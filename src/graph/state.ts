/**
 * ARES audit graph state.
 *
 * Channels flow through the phases INTAKE → RECALL → [parallel ANALYZE] →
 * MERGE → VERIFY → REMEMBER → REPORT. `findings` uses a concat reducer so the
 * parallel analyzer nodes can append concurrently in one superstep without
 * clobbering each other; most other channels are last-value.
 */
import { Annotation } from "@langchain/langgraph";

import type { ScoredCrystal, KnowledgeLevel } from "../memory/types.js";
import type { LoadedSource } from "../tools/source.js";
import type { AnalyzerName } from "../knowledge/finding.js";
import type { Finding } from "../knowledge/finding.js";

/**
 * Finding vocabulary lives in `knowledge/finding.ts` — it is domain language,
 * not graph state. Re-exported here so callers that think in graph terms (and
 * every existing import) keep working.
 */
export type {
  Severity,
  Confidence,
  FindingStatus,
  Finding,
  AnalyzerName,
} from "../knowledge/finding.js";
export { SEVERITY_RANK } from "../knowledge/finding.js";

/**
 * How an analyzer's run ended. The distinction that matters for an audit is
 * between "looked and found nothing" and "never got to look":
 *
 *  - `ok`       — ran against real input and completed. Silence here is evidence.
 *  - `skipped`  — deliberately not applicable (no target of its kind, opt-in off).
 *                 Expected, not a defect, but its ground was never covered.
 *  - `degraded` — ran with a missing capability or unusable output, so it may
 *                 have missed issues it would otherwise catch.
 *  - `failed`   — attempted and errored. Silence here means nothing at all.
 */
export type AnalyzerOutcome = "ok" | "skipped" | "degraded" | "failed";

/** One analyzer's outcome, surfaced in the report so silence can be read correctly. */
export interface AnalyzerReport {
  analyzer: AnalyzerName;
  outcome: AnalyzerOutcome;
  /** Why, in one line. Shown verbatim in the report's limitations table. */
  detail?: string;
}

/** How one knowledge source fared during RECALL. */
export interface RetrievalReport {
  source: string;
  /** `skipped` means unconfigured — the documented default, not a defect. */
  outcome: "ok" | "skipped" | "failed";
  fragments: number;
  detail?: string;
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
  /**
   * Program source loaded from `sourcePath`, shared by every analyzer in the
   * parallel superstep. Without this the LLM analyzers reason from a summary
   * and must invent the `location` and `evidence` they report.
   */
  source: Annotation<LoadedSource | undefined>({
    reducer: (_prev, next) => next,
    default: () => undefined,
  }),
  /** Memory fragments recalled by the hybrid retriever. */
  recalled: Annotation<ScoredCrystal[]>({
    reducer: (_prev, next) => next,
    default: () => [],
  }),
  /**
   * Per-source outcome of RECALL. A configured knowledge source that errored
   * returns no fragments, exactly like one that had nothing to say — REPORT
   * needs this to tell the reader which of the two happened.
   */
  retrieval: Annotation<RetrievalReport[]>({
    reducer: (_prev, next) => next,
    default: () => [],
  }),
  /** Findings — appended by each analyzer in the parallel ANALYZE superstep. */
  findings: Annotation<Finding[]>({
    reducer: (prev, next) => prev.concat(next),
    default: () => [],
  }),
  /**
   * One entry per analyzer, appended in the same parallel superstep as
   * `findings`. Lets REPORT state which analyzers actually ran, so an empty
   * findings list can be told apart from an analyzer that never executed.
   */
  analyzers: Annotation<AnalyzerReport[]>({
    reducer: (prev, next) => prev.concat(next),
    default: () => [],
  }),
  /** Deduped + severity-ranked findings produced by the MERGE node. */
  mergedFindings: Annotation<Finding[]>({
    reducer: (_prev, next) => next,
    default: () => [],
  }),
  /**
   * Findings that survived the VERIFY critic pass, with confidence/status
   * refined and clear false-positives dropped. REMEMBER and REPORT consume this.
   */
  verifiedFindings: Annotation<Finding[]>({
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
