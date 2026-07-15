/**
 * INTAKE node — parse the audit request into a structured summary.
 */
import { intakeSystemPrompt } from "../../llm/prompts.js";
import { logger } from "../../config/logger.js";
import type { GraphDeps } from "../deps.js";
import type { AresState, AresStateUpdate, IntakeSummary } from "../state.js";
import { chatJson } from "../util.js";

export function makeIntakeNode(deps: GraphDeps) {
  return async function intake(state: AresState): Promise<AresStateUpdate> {
    const target = state.programAddress ?? state.sourcePath ?? state.request;
    const fallback: IntakeSummary = {
      target,
      depth: "standard",
      concerns: [],
      summary: state.request,
    };

    const human = [
      `Audit request: ${state.request}`,
      state.programAddress ? `Program address: ${state.programAddress}` : "",
      state.sourcePath ? `Source path: ${state.sourcePath}` : "",
      "",
      "Return ONLY a JSON object with keys: target, depth, concerns (string[]), summary.",
    ]
      .filter(Boolean)
      .join("\n");

    const intake = await chatJson<IntakeSummary>(
      deps.chat,
      intakeSystemPrompt(),
      human,
      fallback,
    );

    logger.info({ component: "node.intake", target: intake.target }, "Intake complete");
    return { intake, iterations: 1 };
  };
}
