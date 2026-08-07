/**
 * INTAKE node — parse the audit request into a structured summary.
 */
import { intakeSystemPrompt } from "../../llm/prompts.js";
import { logger } from "../../config/logger.js";
import type { GraphDeps } from "../deps.js";
import type { AresState, AresStateUpdate, IntakeSummary } from "../state.js";
import { chatJson } from "../util.js";

/**
 * chatJson guarantees valid JSON, not a valid shape: a scalar or wrong-typed
 * `concerns` would crash `state.intake.concerns.join` downstream. Anything
 * that fails this check is treated as if the model returned nothing.
 */
function isIntakeSummary(raw: unknown): raw is IntakeSummary {
  if (!raw || typeof raw !== "object") return false;
  const o = raw as Record<string, unknown>;
  return (
    typeof o.target === "string" &&
    typeof o.depth === "string" &&
    typeof o.summary === "string" &&
    Array.isArray(o.concerns) &&
    o.concerns.every((c) => typeof c === "string")
  );
}

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

    const raw = await chatJson<unknown>(
      deps.chat,
      intakeSystemPrompt(),
      human,
      fallback,
    );
    const intake = isIntakeSummary(raw) ? raw : fallback;
    if (intake === fallback && raw !== fallback) {
      logger.warn(
        { component: "node.intake" },
        "LLM intake JSON had an unexpected shape; using fallback",
      );
    }

    logger.info({ component: "node.intake", target: intake.target }, "Intake complete");
    return { intake, iterations: 1 };
  };
}
