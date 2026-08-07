/**
 * RESET-ACCUMULATORS node — the graph's entry point. Clears the channels that
 * would otherwise carry a previous audit on this thread into a new one.
 *
 * This used to clear the accumulating channels only, on the reasoning that "the
 * last-value channels are rewritten unconditionally by their own phase on every
 * run". That is true of a run that REACHES those phases, and only of that run.
 * A run that throws before MERGE — a rotated API key, a rate limit, a dropped
 * connection — never reaches them, so `mergedFindings` and `verifiedFindings`
 * still hold the last COMPLETED audit's results.
 *
 * Why this exists: the checkpointer keys graph state by `thread_id`. Invoking
 * the graph again on a thread whose previous run reached END starts a new run
 * from START but keeps the stored channel values, so `findings` (concat),
 * `analyzers` (concat), `coverage` (union) and `iterations` (sum) carry the
 * previous audit forward and its findings get reported against the new target. An accumulating reducer
 * cannot be cleared by returning an empty update — concat of `[]` is a no-op —
 * so the reset writes through LangGraph's `Overwrite` sentinel, which bypasses
 * the reducer.
 *
 * That is not a hygiene problem, because `reportParkedRun` in `index.ts` reads
 * exactly those two channels to decide what a parked run has to show, and prints
 * a full report from them — severity table, finding ids, `Status: confirmed`.
 * The failure: audit a target, fix the bugs, re-audit, and have the second run
 * park early. The operator is handed a confirmed-severity report describing bugs
 * that were fixed before the run began, under a message saying this run parked
 * with N findings checkpointed.
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
      analyzers: new Overwrite([]),
      coverage: new Overwrite([]),
      iterations: new Overwrite(0),
      // Last-value channels, so a plain assignment clears them — no `Overwrite`
      // sentinel needed, that is only required to bypass an accumulating reducer.
      // These are here because a run can end WITHOUT reaching the phase that
      // writes them, and `reportParkedRun` reads both.
      mergedFindings: [],
      verifiedFindings: [],
    };
  };
}
