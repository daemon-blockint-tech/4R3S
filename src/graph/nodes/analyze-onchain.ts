/**
 * ANALYZE (on-chain) node — load the target program from chain and reason about
 * its security posture from the tool evidence. Part of the parallel ANALYZE
 * superstep. Contributes findings with source "onchain".
 *
 * Reports its outcome on the `analyzers` channel so REPORT can tell a clean
 * on-chain review apart from one that never happened: an RPC error and a
 * genuinely absent program both end with zero findings here, and only one of
 * those means the report carries real on-chain assurance.
 */
import { analyzeSystemPrompt } from "../../llm/prompts.js";
import { logger } from "../../config/logger.js";
import { loadProgram } from "../../tools/solana.js";
import { isKnownProgram, getKnownProgram } from "../../knowledge/known-programs.js";
import type { GraphDeps } from "../deps.js";
import type {
  AnalyzerOutcome,
  AnalyzerReport,
  AresState,
  AresStateUpdate,
  Finding,
} from "../state.js";
import {
  chatJsonResult,
  coerceFindings,
  extractChecked,
  downgradeSpeculative,
} from "../util.js";

/** Build this node's entry for the `analyzers` channel. */
function status(outcome: AnalyzerOutcome, detail?: string): AnalyzerReport[] {
  return [{ analyzer: "onchain", outcome, detail }];
}

export function makeAnalyzeOnchainNode(deps: GraphDeps) {
  return async function analyzeOnchain(
    state: AresState,
  ): Promise<AresStateUpdate> {
    if (!state.programAddress) {
      return {
        findings: [],
        analyzers: status("skipped", "no program address supplied"),
      };
    }

    const program = await loadProgram(state.programAddress);

    // An RPC error (or an unparseable address) is not a clean result — the chain
    // was never actually read, so silence here means nothing.
    if (program.error) {
      logger.warn(
        {
          component: "node.analyze-onchain",
          address: state.programAddress,
          err: program.error,
        },
        "On-chain analysis could not read the program",
      );
      return {
        findings: [],
        iterations: 0,
        analyzers: status("failed", `could not read program: ${program.error}`),
      };
    }

    if (!program.exists) {
      logger.info(
        { component: "node.analyze-onchain", address: state.programAddress },
        "Program not found on chain; no on-chain findings",
      );
      return {
        findings: [],
        iterations: 0,
        analyzers: status(
          "degraded",
          "program account not found on chain — nothing to analyze",
        ),
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

    const { value: raw, parsed } = await chatJsonResult<unknown>(
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
