/**
 * Audit graph assembly.
 *
 * INTAKE → RECALL → { analyzeOnchain, analyzeStatic, analyzeHeuristic } → MERGE
 * → REMEMBER → REPORT. The three analyzer nodes form a parallel superstep: RECALL
 * fans out to all three, and MERGE (fan-in) runs only after all three complete.
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
import { makeMergeNode } from "./nodes/merge.js";
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
    .addNode("mergePhase", makeMergeNode())
    .addNode("rememberPhase", makeRememberNode(deps))
    .addNode("reportPhase", makeReportNode(deps))
    .addEdge(START, "intakePhase")
    .addEdge("intakePhase", "recallPhase")
    // Fan-out: parallel ANALYZE superstep.
    .addEdge("recallPhase", "analyzeOnchain")
    .addEdge("recallPhase", "analyzeStatic")
    .addEdge("recallPhase", "analyzeHeuristic")
    // Fan-in: merge waits for all three analyzers.
    .addEdge("analyzeOnchain", "mergePhase")
    .addEdge("analyzeStatic", "mergePhase")
    .addEdge("analyzeHeuristic", "mergePhase")
    .addEdge("mergePhase", "rememberPhase")
    .addEdge("rememberPhase", "reportPhase")
    .addEdge("reportPhase", END);

  return graph.compile({ checkpointer, store });
}
