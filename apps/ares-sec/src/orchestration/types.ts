/**
 * Types for the Decomposition Orchestrator
 */

import type { LLMConfig } from '../types/index.js';

// =============================================================================
// CONFIGURATION
// =============================================================================

export interface DecompositionConfig {
  /** The orchestrator model — holds the full offensive objective (e.g. opus). */
  orchestratorModel: LLMConfig;
  /** The worker model — receives only innocuous analytical queries (e.g. fable-5). */
  workerModel: LLMConfig;
  /** Max decomposed queries per round before forcing synthesis. Default 8. */
  maxQueriesPerRound?: number;
  /** Max decomposition rounds (decompose → query → synthesize → repeat). Default 5. */
  maxRounds?: number;
  /** Max tokens for worker responses. Default 4096. */
  workerMaxTokens?: number;
  /** Max tokens for orchestrator responses. Default 8192. */
  orchestratorMaxTokens?: number;
  /** Temperature for worker queries. Lower = more deterministic analysis. Default 0.2. */
  workerTemperature?: number;
  /** Run worker queries in parallel. Default true. */
  parallelWorkers?: boolean;
  /** Max concurrent worker queries when parallel. Default 4. */
  maxConcurrency?: number;
  /**
   * Auto-attach the full source context to every worker query when the query
   * carries no focused snippet of its own. Keeps the orchestrator from having to
   * copy-paste code (saves tokens, removes transcription drift). Default true.
   */
  attachSourceToWorker?: boolean;
  /** Emit verbose progress events. Default false. */
  verbose?: boolean;
}

// =============================================================================
// DECOMPOSED QUERIES — the innocuous analytical subtasks
// =============================================================================

/** A single analytical query the orchestrator produces for a worker. */
export interface DecomposedQuery {
  /** Unique ID for tracking. */
  id: string;
  /** The benign analytical question for the worker model. */
  query: string;
  /** What aspect of the objective this query serves (for orchestrator's own tracking). */
  purpose: string;
  /** Query category — helps the orchestrator reason about coverage. */
  category: QueryCategory;
  /** Priority within the round (1 = highest). */
  priority: number;
  /** Optional: specific files/functions/lines the worker should focus on. */
  focusTargets?: string[];
  /** Optional: source code or context to include with the query. */
  context?: string;
}

export type QueryCategory =
  | 'data_flow'        // trace input propagation
  | 'bounds_check'     // identify validation / guards
  | 'type_analysis'    // sizeof, field layout, integer ranges
  | 'reachability'     // is this code path reachable from entry point X?
  | 'auth_check'       // authentication / authorization on the path
  | 'config_analysis'  // default vs non-default configurations
  | 'call_graph'       // who calls this, what does it call
  | 'side_effect'      // what state does this function mutate
  | 'protocol'         // wire format, serialization, parsing behavior
  | 'general';         // anything else

// =============================================================================
// QUERY RESULTS — what comes back from the worker
// =============================================================================

export interface QueryResult {
  /** Matches the DecomposedQuery.id. */
  queryId: string;
  /** The worker's raw response text. */
  rawResponse: string;
  /** Structured answer extracted by the orchestrator. */
  extractedFacts: ExtractedFact[];
  /** Whether the worker actually answered or deflected. */
  status: 'answered' | 'partial' | 'refused' | 'error';
  /** Token usage for cost tracking. */
  usage?: { promptTokens: number; completionTokens: number };
  /** Latency in ms. */
  durationMs: number;
}

export interface ExtractedFact {
  /** One-line summary of the fact. */
  summary: string;
  /** The evidence from the worker's response. */
  evidence: string;
  /** Confidence the orchestrator assigns to this extraction. */
  confidence: 'high' | 'medium' | 'low';
  /** Which source file/line this fact is about, if applicable. */
  location?: string;
}

// =============================================================================
// SYNTHESIS — the orchestrator reassembles the picture
// =============================================================================

export interface SynthesisResult {
  /** What the orchestrator concluded from this round's results. */
  findings: SynthesisFinding[];
  /** Knowledge gaps the orchestrator identified — drives the next round. */
  gaps: string[];
  /** Whether the orchestrator wants another round. */
  continueDecomposition: boolean;
  /** The orchestrator's current mental model of the attack surface. */
  attackSurfaceModel: string;
  /** Orchestrator's confidence that the objective is achievable. */
  confidence: number;
}

export interface SynthesisFinding {
  /** Classification. */
  type: 'vulnerability' | 'attack_path' | 'guard' | 'constraint' | 'observation';
  /** Short title. */
  title: string;
  /** Detailed description assembled from worker facts. */
  description: string;
  /** Which query results contributed to this finding. */
  sourceQueryIds: string[];
  /** Severity if it's a vulnerability. */
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Suggested next action (exploit, verify, investigate further). */
  nextAction?: string;
}

// =============================================================================
// OVERALL RESULT
// =============================================================================

export interface DecompositionResult {
  /** All rounds of decomposition. */
  rounds: DecompositionRound[];
  /** Final synthesis across all rounds. */
  finalSynthesis: SynthesisResult;
  /** Total queries sent to the worker model. */
  totalQueries: number;
  /** Queries where the worker actually answered. */
  answeredQueries: number;
  /** Queries where the worker refused/deflected. */
  refusedQueries: number;
  /** Total wall-clock time. */
  totalDurationMs: number;
  /** Total token usage across all calls. */
  totalUsage: { orchestratorTokens: number; workerTokens: number };
}

export interface DecompositionRound {
  roundNumber: number;
  queries: DecomposedQuery[];
  results: QueryResult[];
  synthesis: SynthesisResult;
  durationMs: number;
}

// =============================================================================
// EVENTS
// =============================================================================

export interface DecompositionEvents {
  'decomposition:start': { objective: string; config: DecompositionConfig };
  'decomposition:round_start': { round: number };
  'decomposition:queries_planned': { round: number; queries: DecomposedQuery[] };
  'decomposition:query_sent': { round: number; query: DecomposedQuery };
  'decomposition:query_result': { round: number; result: QueryResult };
  'decomposition:query_refused': { round: number; queryId: string; preview: string };
  'decomposition:synthesis': { round: number; synthesis: SynthesisResult };
  'decomposition:round_complete': { round: number; durationMs: number };
  'decomposition:complete': { result: DecompositionResult };
}
