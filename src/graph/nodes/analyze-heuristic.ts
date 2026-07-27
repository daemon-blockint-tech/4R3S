/**
 * ANALYZE (heuristic) node — pure LLM reasoning over the intake summary and
 * recalled memory, independent of the on-chain/static tool outputs (which are
 * produced by sibling nodes in the same superstep). Contributes findings with
 * source "heuristic".
 *
 * Reports its outcome on the `analyzers` channel: this node's only failure mode
 * is a response that doesn't parse, which yields zero findings and would
 * otherwise be indistinguishable from "nothing to flag".
 */
import { analyzeSystemPrompt } from "../../llm/prompts.js";
import { logger } from "../../config/logger.js";
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
  return [{ analyzer: "heuristic", outcome, detail }];
}

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

    const { value: raw, parsed } = await chatJsonResult<unknown>(
      deps.chat,
      analyzeSystemPrompt(),
      human,
      [],
    );
    let findings: Finding[] = coerceFindings(raw, "heuristic");
    const coverage = extractChecked(raw);

    // Downgrade heuristic findings to speculative when:
    //   1. No source code available (black-box audit), OR
    //   2. Target is a known canonical program (noise from pattern-matching).
    const target = state.programAddress ?? state.intake?.target ?? "";
    const known = target ? isKnownProgram(target) : false;
    const noSource = !state.sourcePath;
    if (known || noSource) {
      const reason = known
        ? `known program (${getKnownProgram(target)?.name})`
        : "no source code (black-box)";
      findings = downgradeSpeculative(findings);
      logger.info(
        { component: "node.analyze-heuristic", reason, downgraded: findings.length },
        "Findings downgraded to speculative",
      );
    }

    logger.info(
      { component: "node.analyze-heuristic", findings: findings.length, coverage: coverage.length, speculative: findings.filter((f) => f.speculative).length },
      "Heuristic analysis complete",
    );
    return {
      findings,
      coverage,
      iterations: 1,
      analyzers: parsed
        ? status(
            "ok",
            noSource ? "black-box: findings downgraded to speculative" : undefined,
          )
        : status(
            "degraded",
            "model response was not valid JSON; no findings extracted",
          ),
    };
  };
}
