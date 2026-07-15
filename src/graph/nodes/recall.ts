/**
 * RECALL node — pull relevant prior knowledge via the hybrid retriever
 * (Crystalline + Supabase + Neo4j), embedding the intake for semantic search
 * when embeddings are configured.
 */
import { logger } from "../../config/logger.js";
import { embed } from "../../retrieval/embeddings.js";
import type { GraphDeps } from "../deps.js";
import type { AresState, AresStateUpdate } from "../state.js";

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

    logger.info(
      { component: "node.recall", recalled: recalled.length },
      "Recall complete",
    );
    return { recalled };
  };
}
