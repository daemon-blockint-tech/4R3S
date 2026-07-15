/**
 * Audit graph assembly.
 *
 * INTAKE → RECALL → { analyzeOnchain, analyzeStatic, analyzeHeuristic, analyzeCua }
 * → MERGE → VERIFY → REMEMBER → REPORT. The analyzer nodes form a parallel
 * superstep: RECALL fans out to all of them, and MERGE (fan-in) runs only after
 * all complete. VERIFY is a critic pass that refines confidence/status and drops
 * false-positives. `analyzeCua` is opt-in and returns no findings unless CUA is
 * enabled and configured (see `src/tools/cua.ts`).
 */
import { StateGraph, START, END } from "@langchain/langgraph";
import type { BaseCheckpointSaver, BaseStore } from "@langchain/langgraph";

import { AresStateAnnotation } from "./state.js";
import type { GraphDeps } from "./deps.js";
import { makeIntakeNode } from "./nodes/intake.js";
import { makeRecallNode } from "./nodes/recall.js";
import { makeAnalyzeOnchainNode } from "./nodes/analyze-onchain.js";
import { makeAnalyzeStaticNode } from "./nodes/analyze-static.js";
import { makeAnalyzeHeuristicNode } from "./nodes/analyze-heuristic.js";
import { makeAnalyzeCuaNode } from "./nodes/analyze-cua.js";
import { makeMergeNode } from "./nodes/merge.js";
import { makeVerifyNode } from "./nodes/verify.js";
import { makeRememberNode } from "./nodes/remember.js";
import { makeReportNode } from "./nodes/report.js";

export interface BuildGraphOptions {
  deps: GraphDeps;
  checkpointer?: BaseCheckpointSaver;
  store?: BaseStore;
}

/** Build and compile the ARES audit graph. */
export function buildAuditGraph({
  deps,
  checkpointer,
  store,
}: BuildGraphOptions) {
  // Node ids are suffixed "Phase" to avoid colliding with state channel names
  // (LangGraph forbids a node id equal to a channel id, e.g. `intake`/`report`).
  const graph = new StateGraph(AresStateAnnotation)
    .addNode("intakePhase", makeIntakeNode(deps))
    .addNode("recallPhase", makeRecallNode(deps))
    .addNode("analyzeOnchain", makeAnalyzeOnchainNode(deps))
    .addNode("analyzeStatic", makeAnalyzeStaticNode())
    .addNode("analyzeHeuristic", makeAnalyzeHeuristicNode(deps))
    .addNode("analyzeCua", makeAnalyzeCuaNode(deps))
    .addNode("mergePhase", makeMergeNode())
    .addNode("verifyPhase", makeVerifyNode(deps))
    .addNode("rememberPhase", makeRememberNode(deps))
    .addNode("reportPhase", makeReportNode(deps))
    .addEdge(START, "intakePhase")
    .addEdge("intakePhase", "recallPhase")
    // Fan-out: parallel ANALYZE superstep.
    .addEdge("recallPhase", "analyzeOnchain")
    .addEdge("recallPhase", "analyzeStatic")
    .addEdge("recallPhase", "analyzeHeuristic")
    .addEdge("recallPhase", "analyzeCua")
    // Fan-in: merge waits for all analyzers.
    .addEdge("analyzeOnchain", "mergePhase")
    .addEdge("analyzeStatic", "mergePhase")
    .addEdge("analyzeHeuristic", "mergePhase")
    .addEdge("analyzeCua", "mergePhase")
    // Critic pass, then persist + report from the verified set.
    .addEdge("mergePhase", "verifyPhase")
    .addEdge("verifyPhase", "rememberPhase")
    .addEdge("rememberPhase", "reportPhase")
    .addEdge("reportPhase", END);

  return graph.compile({ checkpointer, store });
}
