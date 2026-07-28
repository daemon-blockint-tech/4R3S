/**
 * LOAD-SOURCE node — read the target's program source before the analyzers run.
 *
 * Runs between RECALL and the parallel ANALYZE superstep, deliberately *not*
 * inside it: the analyzers are siblings in one superstep and cannot observe each
 * other's writes, so the only way every analyzer can see the source (and can
 * know whether there is any) is to load it first.
 *
 * It deliberately writes only `sourceFiles` and does not report on the
 * `analyzers` channel. It is not an analyzer, and the two analyzers whose
 * reliability actually depends on it already carry the signal: `analyzeStatic`
 * reports `failed`/`degraded` when the scanner could not read the path, and
 * `analyzeHeuristic` reports that it ran black-box. Emitting a second `static`
 * row here would duplicate that in the report's status table. REPORT states the
 * source position outright from `sourceFiles`.
 */
import { logger } from "../../config/logger.js";
import { loadSource } from "../../tools/source.js";
import type { AresState, AresStateUpdate } from "../state.js";

export function makeLoadSourceNode() {
  return async function loadSourceNode(
    state: AresState,
  ): Promise<AresStateUpdate> {
    if (!state.sourcePath) {
      return { sourceFiles: [] };
    }

    const result = await loadSource(state.sourcePath);

    if (result.files.length === 0) {
      logger.warn(
        { component: "node.load-source", path: state.sourcePath, note: result.note },
        "Source path supplied but no source could be read",
      );
      return { sourceFiles: [] };
    }

    logger.info(
      {
        component: "node.load-source",
        files: result.files.length,
        truncated: result.truncated,
      },
      "Source loaded for analysis",
    );

    return { sourceFiles: result.files };
  };
}
