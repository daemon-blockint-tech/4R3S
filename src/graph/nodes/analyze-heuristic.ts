/**
 * ANALYZE (heuristic) node — pure LLM reasoning over the intake summary and
 * recalled memory, independent of the on-chain/static tool outputs (which are
 * produced by sibling nodes in the same superstep). Contributes findings with
 * source "heuristic".
 */
import { analyzeSystemPrompt } from "../../llm/prompts.js";
import { logger } from "../../config/logger.js";
import type { GraphDeps } from "../deps.js";
import type { AresState, AresStateUpdate, Finding } from "../state.js";
import { chatJson, coerceFindings, extractChecked } from "../util.js";

export function makeAnalyzeHeuristicNode(deps: GraphDeps) {
  return async function analyzeHeuristic(
    state: AresState,
  ): Promise<AresStateUpdate> {
    const memory = state.recalled
      .slice(0, 8)
      .map((s, i) => `#${i + 1} (${s.crystal.level}): ${s.crystal.content}`)
      .join("\n");

    const human = [
      state.intake
        ? `Intake summary: ${state.intake.summary}`
        : `Request: ${state.request}`,
      state.intake?.concerns?.length
        ? `Concerns: ${state.intake.concerns.join(", ")}`
        : "",
      "",
      "Recalled memory fragments (prior audit knowledge):",
      memory || "(none)",
      "",
      "Reason about likely vulnerability classes for this target. Return a JSON",
      "object: { findings: [...], checked: [...] }. Each finding: { category,",
      "vulnClass, location, severity, evidence, remediation }. List every checklist",
      "class you evaluated in checked. Mark speculative items as info/low severity",
      "and say so in evidence. Return { findings: [], checked: [...] } if you have",
      "no basis to hypothesize.",
    ]
      .filter(Boolean)
      .join("\n");

    const raw = await chatJson<unknown>(
      deps.chat,
      analyzeSystemPrompt(),
      human,
      [],
    );
    const findings: Finding[] = coerceFindings(raw, "heuristic");
    const coverage = extractChecked(raw);

    logger.info(
      { component: "node.analyze-heuristic", findings: findings.length, coverage: coverage.length },
      "Heuristic analysis complete",
    );
    return { findings, coverage, iterations: 1 };
  };
}
