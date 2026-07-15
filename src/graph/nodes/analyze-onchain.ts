/**
 * ANALYZE (on-chain) node — load the target program from chain and reason about
 * its security posture from the tool evidence. Part of the parallel ANALYZE
 * superstep. Contributes findings with source "onchain".
 */
import { analyzeSystemPrompt } from "../../llm/prompts.js";
import { logger } from "../../config/logger.js";
import { loadProgram } from "../../tools/solana.js";
import { isKnownProgram, getKnownProgram } from "../../knowledge/known-programs.js";
import type { GraphDeps } from "../deps.js";
import type { AresState, AresStateUpdate, Finding } from "../state.js";
import { chatJson, coerceFindings, extractChecked, downgradeSpeculative } from "../util.js";

export function makeAnalyzeOnchainNode(deps: GraphDeps) {
  return async function analyzeOnchain(
    state: AresState,
  ): Promise<AresStateUpdate> {
    if (!state.programAddress) {
      return { findings: [] };
    }

    const program = await loadProgram(state.programAddress);
    if (!program.exists) {
      logger.info(
        { component: "node.analyze-onchain", address: state.programAddress },
        "Program not found on chain; no on-chain findings",
      );
      return {
        findings: [],
        iterations: 0,
      };
    }

    const human = [
      "On-chain program metadata (tool output):",
      JSON.stringify(program, null, 2),
      "",
      state.intake ? `Intake: ${state.intake.summary}` : "",
      "",
      "Based ONLY on this evidence, return a JSON object: { findings: [...], checked: [...] }.",
      "Each finding: { category, vulnClass, location, severity, evidence, remediation }.",
      "List every checklist class you evaluated in checked, even if no issue was found.",
      "If the evidence shows no security-relevant signal, return { findings: [], checked: [...] }.",
    ]
      .filter(Boolean)
      .join("\n");

    const raw = await chatJson<unknown>(
      deps.chat,
      analyzeSystemPrompt(),
      human,
      [],
    );
    let findings: Finding[] = coerceFindings(raw, "onchain");
    const coverage = extractChecked(raw);

    // Downgrade on-chain findings for known canonical programs.
    if (state.programAddress && isKnownProgram(state.programAddress)) {
      findings = downgradeSpeculative(findings);
      logger.info(
        { component: "node.analyze-onchain", reason: `known program (${getKnownProgram(state.programAddress)?.name})`, downgraded: findings.length },
        "Findings downgraded to speculative",
      );
    }

    logger.info(
      { component: "node.analyze-onchain", findings: findings.length, coverage: coverage.length, speculative: findings.filter((f) => f.speculative).length },
      "On-chain analysis complete",
    );
    return { findings, coverage, iterations: 1 };
  };
}
