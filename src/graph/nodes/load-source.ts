/**
 * LOAD-SOURCE node — read the target's actual `.rs` and IDL files into state.
 *
 * Runs between INTAKE and RECALL so every analyzer in the parallel superstep
 * shares one read. This is the node that makes a citation checkable: without
 * it the LLM analyzers are asked for a `location` and `evidence` describing
 * code they were never shown, and the only honest thing to do with such a
 * finding is to treat it as speculation.
 *
 * A failure here is not fatal. The audit continues black-box, and the analyzers
 * downgrade their findings accordingly — but it is recorded, because a report
 * that silently reasoned without source reads exactly like one that did.
 */
import { logger } from "../../config/logger.js";
import { loadSource } from "../../tools/source.js";
import type { AresState, AresStateUpdate } from "../state.js";

export function makeLoadSourceNode() {
  return async function loadSourceNode(
    state: AresState,
  ): Promise<AresStateUpdate> {
    const source = await loadSource(state.sourcePath);

    if (!source.available) {
      logger.info(
        {
          component: "node.load-source",
          reason: source.reason,
          note: source.note,
        },
        "No source loaded; analyzers run black-box",
      );
    } else if (source.truncated) {
      logger.warn(
        {
          component: "node.load-source",
          loaded: source.files.length,
          discovered: source.discovered.length,
        },
        "Source budget exhausted; only part of the tree was read",
      );
    }

    return { source };
  };
}
