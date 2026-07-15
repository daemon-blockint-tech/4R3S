/**
 * ANALYZE (on-chain) node — load the target program from chain and reason about
 * its security posture from the tool evidence. Part of the parallel ANALYZE
 * superstep. Contributes findings with source "onchain".
 */
import { analyzeSystemPrompt } from "../../llm/prompts.js";
import { logger } from "../../config/logger.js";
import { loadProgram } from "../../tools/solana.js";
import type { GraphDeps } from "../deps.js";
import type { AresState, AresStateUpdate, Finding } from "../state.js";
import { chatJson, coerceFindings } from "../util.js";

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
      "Based ONLY on this evidence, return a JSON array of findings. Each finding:",
      "{ vulnClass, location, severity (info|low|medium|high|critical), evidence, remediation }.",
      "If the evidence shows no security-relevant signal, return [].",
    ]
      .filter(Boolean)
      .join("\n");

    const raw = await chatJson<unknown>(
      deps.chat,
      analyzeSystemPrompt(),
      human,
      [],
    );
    const findings: Finding[] = coerceFindings(raw, "onchain");

    logger.info(
      { component: "node.analyze-onchain", findings: findings.length },
      "On-chain analysis complete",
    );
    return { findings, iterations: 1 };
  };
}
