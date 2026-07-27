/**
 * RECALL node — pull relevant prior knowledge via the hybrid retriever
 * (Crystalline + Supabase + Neo4j), embedding the intake for semantic search
 * when embeddings are configured.
 *
 * Recalled Crystalline fragments are then *activated*: activation is boosted and
 * the access count incremented. Without this the cognitive layer is inert —
 * `accessCount` never leaves zero, so the episodic→semantic promotion in
 * `consolidate()` can never fire and activation can only ever decay. Fragments
 * synthesized from Supabase/Neo4j are skipped: they have no crystal in the store
 * to update.
 */
import { logger } from "../../config/logger.js";
import { embed } from "../../retrieval/embeddings.js";
import type { ScoredCrystal } from "../../memory/types.js";
import type { GraphDeps } from "../deps.js";
import type { AresState, AresStateUpdate } from "../state.js";

/**
 * Boost activation for the fragments this audit actually used. Best-effort:
 * nothing downstream reads the result, and memory bookkeeping must not abort an
 * audit, so failures are logged rather than thrown.
 */
async function activateRecalled(
  deps: GraphDeps,
  recalled: ScoredCrystal[],
): Promise<number> {
  const native = recalled.filter((s) => !s.crystal.metadata.synthetic);
  if (native.length === 0) return 0;

  const results = await Promise.allSettled(
    native.map((s) => deps.crystalline.activate(s.crystal.id, s.crystal.level)),
  );
  const failed = results.filter((r) => r.status === "rejected").length;
  if (failed > 0) {
    logger.warn(
      { component: "node.recall", failed },
      "Some recalled crystals could not be activated (non-fatal)",
    );
  }
  return native.length - failed;
}

export function makeRecallNode(deps: GraphDeps) {
  return async function recall(state: AresState): Promise<AresStateUpdate> {
    const queryText =
      state.intake?.summary ?? state.request ?? state.programAddress ?? "";
    const tags = state.intake?.concerns;

    const embedding = await embed(queryText);
    const recalled = await deps.retriever.retrieve({
      text: queryText,
      embedding,
      tags,
      limit: 8,
    });

    const activated = await activateRecalled(deps, recalled);

    logger.info(
      { component: "node.recall", recalled: recalled.length, activated },
      "Recall complete",
    );
    return { recalled };
  };
}
