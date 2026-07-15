/**
 * ANALYZE (cua) node — drives a real browser (Scrapybara Computer Use Agent)
 * to investigate the target externally (explorers, source repos, docs), then
 * coerces the investigation transcript into findings. Part of the parallel
 * ANALYZE superstep. Contributes findings with source "cua".
 *
 * Opt-in: returns no findings immediately when CUA isn't enabled/configured
 * (see `hasCua` in `src/tools/cua.ts`), so the graph and test suite stay
 * hermetic by default.
 */
import { analyzeSystemPrompt } from "../../llm/prompts.js";
import { logger } from "../../config/logger.js";
import { hasCua, runCuaInvestigation } from "../../tools/cua.js";
import type { GraphDeps } from "../deps.js";
import type { AresState, AresStateUpdate, Finding } from "../state.js";
import { chatJson, coerceFindings, extractChecked } from "../util.js";

export function makeAnalyzeCuaNode(deps: GraphDeps) {
  return async function analyzeCua(state: AresState): Promise<AresStateUpdate> {
    if (!hasCua()) {
      return { findings: [] };
    }

    const target = state.intake?.target ?? state.programAddress ?? state.request;
    const objective = [
      `Investigate this Solana audit target: ${target}`,
      state.intake?.summary ? `Context: ${state.intake.summary}` : "",
      "Look it up on Solana block explorers, find its source repository if",
      "public, and check for prior audits or known community-reported issues.",
    ]
      .filter(Boolean)
      .join("\n");

    const investigation = await runCuaInvestigation(objective);
    if (!investigation.available) {
      logger.info(
        { component: "node.analyze-cua", note: investigation.note },
        "CUA analysis skipped",
      );
      return { findings: [] };
    }

    const human = [
      "Browser investigation transcript (tool output):",
      investigation.transcript,
      "",
      state.intake ? `Intake: ${state.intake.summary}` : "",
      "",
      "Based ONLY on this transcript, return a JSON object: { findings: [...], checked: [...] }.",
      "Each finding: { category, vulnClass, location, severity, evidence, remediation }.",
      "List every checklist class you evaluated in checked, even if no issue was found.",
      "If the transcript shows no security-relevant signal, return { findings: [], checked: [...] }.",
    ]
      .filter(Boolean)
      .join("\n");

    const raw = await chatJson<unknown>(
      deps.chat,
      analyzeSystemPrompt(),
      human,
      [],
    );
    const findings: Finding[] = coerceFindings(raw, "cua");
    const coverage = extractChecked(raw);

    logger.info(
      { component: "node.analyze-cua", findings: findings.length, coverage: coverage.length },
      "CUA analysis complete",
    );
    return { findings, coverage, iterations: 1 };
  };
}
