/**
 * ANALYZE (static) node — run Semgrep over the source path and map results to
 * findings. Deterministic (no LLM call): Semgrep results map directly to
 * findings with source "static". Degrades to no findings when Semgrep or the
 * source path is unavailable.
 */
import { logger } from "../../config/logger.js";
import { runSemgrep, type SemgrepFinding } from "../../tools/semgrep.js";
import type { AresState, AresStateUpdate, Finding, Severity } from "../state.js";

/** Map Semgrep severities onto the audit severity scale. */
function mapSeverity(semgrep: string): Severity {
  switch (semgrep.toUpperCase()) {
    case "ERROR":
      return "high";
    case "WARNING":
      return "medium";
    default:
      return "low";
  }
}

function toFinding(f: SemgrepFinding): Finding {
  return {
    vulnClass: f.ruleId,
    location: `${f.path}:${f.line}`,
    severity: mapSeverity(f.severity),
    evidence: f.message,
    remediation: "Review the flagged code against the Semgrep rule guidance.",
    source: "static",
  };
}

export function makeAnalyzeStaticNode() {
  return async function analyzeStatic(
    state: AresState,
  ): Promise<AresStateUpdate> {
    const result = await runSemgrep(state.sourcePath);
    if (!result.available) {
      logger.info(
        { component: "node.analyze-static", note: result.note },
        "Static analysis skipped",
      );
      return { findings: [] };
    }

    const findings = result.findings.map(toFinding);
    logger.info(
      { component: "node.analyze-static", findings: findings.length },
      "Static analysis complete",
    );
    return { findings };
  };
}
