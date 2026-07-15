/**
 * ANALYZE (static) node — run Semgrep over the source path and map results to
 * findings. Deterministic (no LLM call): Semgrep results map directly to
 * findings with source "static". Degrades to no findings when Semgrep or the
 * source path is unavailable.
 */
import { logger } from "../../config/logger.js";
import { runSemgrep, type SemgrepFinding } from "../../tools/semgrep.js";
import type { AresState, AresStateUpdate, Finding, Severity } from "../state.js";
import { VULN_IDS } from "../../knowledge/solana-vulns.js";

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

/** Best-effort map a Semgrep ruleId to a catalog vulnerability id. */
function mapCategory(ruleId: string): string {
  const lower = ruleId.toLowerCase();
  for (const id of VULN_IDS) {
    if (lower.includes(id) || id.includes(lower)) {
      return id;
    }
  }
  // Heuristic substring matches for common rule naming patterns.
  if (lower.includes("overflow") || lower.includes("underflow")) return "integer-overflow-underflow";
  if (lower.includes("signer")) return "missing-signer-check";
  if (lower.includes("owner")) return "missing-owner-check";
  if (lower.includes("cpi")) return "arbitrary-cpi";
  if (lower.includes("reinit")) return "account-reinitialization";
  if (lower.includes("pda") || lower.includes("seed")) return "pda-seed-collision";
  if (lower.includes("close")) return "account-close-revival";
  if (lower.includes("sysvar")) return "sysvar-spoofing";
  return "other";
}

function toFinding(f: SemgrepFinding): Finding {
  return {
    vulnClass: f.ruleId,
    location: `${f.path}:${f.line}`,
    severity: mapSeverity(f.severity),
    evidence: f.message,
    remediation: "Review the flagged code against the Semgrep rule guidance.",
    source: "static",
    category: mapCategory(f.ruleId),
    speculative: false,
    confidence: "high",
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
    const coverage = [...new Set(findings.map((f) => f.category))].filter((id) => id !== "other");
    logger.info(
      { component: "node.analyze-static", findings: findings.length, coverage: coverage.length },
      "Static analysis complete",
    );
    return { findings, coverage };
  };
}
