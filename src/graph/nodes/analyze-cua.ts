/**
 * ANALYZE (cua) node — drives a real browser (Scrapybara Computer Use Agent)
 * to investigate the target externally (explorers, source repos, docs), then
 * coerces the investigation transcript into findings. Part of the parallel
 * ANALYZE superstep. Contributes findings with source "cua".
 *
 * Opt-in: returns no findings immediately when CUA isn't enabled/configured
 * (see `hasCua` in `src/tools/cua.ts`), so the graph and test suite stay
 * hermetic by default. Reports its outcome on the `analyzers` channel so being
 * switched off reads as "not applicable" while a browser session that errored
 * out reads as a failure.
 */
import { analyzeSystemPrompt } from "../../llm/prompts.js";
import { logger } from "../../config/logger.js";
import { hasCua, runCuaInvestigation } from "../../tools/cua.js";
import type { GraphDeps } from "../deps.js";
import type {
  AnalyzerOutcome,
  AnalyzerReport,
  AresState,
  AresStateUpdate,
  Finding,
} from "../state.js";
import { chatJsonResult, coerceFindings, extractChecked } from "../util.js";

/** Build this node's entry for the `analyzers` channel. */
function status(outcome: AnalyzerOutcome, detail?: string): AnalyzerReport[] {
  return [{ analyzer: "cua", outcome, detail }];
}

export function makeAnalyzeCuaNode(deps: GraphDeps) {
  return async function analyzeCua(state: AresState): Promise<AresStateUpdate> {
    if (!hasCua()) {
      return {
        findings: [],
        analyzers: status("skipped", "CUA not enabled (opt-in)"),
      };
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
      logger.warn(
        { component: "node.analyze-cua", note: investigation.note },
        "CUA investigation did not complete",
      );
      return {
        findings: [],
        analyzers: status("failed", investigation.note),
      };
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

    const { value: raw, parsed } = await chatJsonResult<unknown>(
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
    return {
      findings,
      coverage,
      iterations: 1,
      analyzers: parsed
        ? status("ok")
        : status(
            "degraded",
            "model response was not valid JSON; no findings extracted",
          ),
    };
  };
}
