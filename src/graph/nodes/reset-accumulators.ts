/**
 * RESET-ACCUMULATORS node — the graph's entry point. Clears the three
 * accumulating channels so a fresh audit never inherits values from a previous
 * one. It does not touch any other channel; the last-value channels are
 * rewritten unconditionally by their own phase on every run.
 *
 * Why this exists: the checkpointer keys graph state by `thread_id`. Invoking
 * the graph again on a thread whose previous run reached END starts a new run
 * from START but keeps the stored channel values, so `findings` (concat),
 * `coverage` (union) and `iterations` (sum) carry the previous audit forward
 * and its findings get reported against the new target. An accumulating reducer
 * cannot be cleared by returning an empty update — concat of `[]` is a no-op —
 * so the reset writes through LangGraph's `Overwrite` sentinel, which bypasses
 * the reducer.
 *
 * Resuming an interrupted run is deliberately unaffected: a resumed run picks
 * up at its pending tasks, so this node — already completed — does not re-run
 * and the partial findings survive. Both properties are covered in
 * `build-graph.test.ts` ("state isolation across runs").
 */
import { Overwrite } from "@langchain/langgraph";

import { logger } from "../../config/logger.js";
import type { AresState, AresStateUpdate } from "../state.js";

export function makeResetAccumulatorsNode() {
  return async function resetAccumulators(
    state: AresState,
  ): Promise<AresStateUpdate> {
    if (state.findings.length > 0 || state.iterations > 0) {
      logger.info(
        {
          component: "node.reset-accumulators",
          staleFindings: state.findings.length,
          staleCoverage: state.coverage.length,
          staleIterations: state.iterations,
        },
        "Clearing state carried over from a previous audit on this thread",
      );
    }

    return {
      findings: new Overwrite([]),
      coverage: new Overwrite([]),
      iterations: new Overwrite(0),
    };
  };
}
