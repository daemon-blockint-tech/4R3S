/**
 * ANALYZE (static) node — run Semgrep over the source path and map results to
 * findings. Deterministic (no LLM call): Semgrep results map directly to
 * findings with source "static". Degrades to no findings when Semgrep or the
 * source path is unavailable.
 */
import { logger } from "../../config/logger.js";
import {
  runSemgrep,
  type SemgrepFinding,
  type SemgrepSkipReason,
} from "../../tools/semgrep.js";
import type {
  AnalyzerOutcome,
  AnalyzerReport,
  AresState,
  AresStateUpdate,
  Finding,
  Severity,
} from "../state.js";
import { VULN_IDS } from "../../knowledge/solana-vulns.js";
import { asData } from "../util.js";

/** Build this node's entry for the `analyzers` channel. */
function status(outcome: AnalyzerOutcome, detail?: string): AnalyzerReport[] {
  return [{ analyzer: "static", outcome, detail }];
}

/**
 * Map a Semgrep skip reason onto an analyzer outcome.
 *
 * `no-source` is the only benign case — nothing was asked of the scanner. Every
 * other reason means source analysis was expected but did not happen: a missing
 * path is an outright failure, while a missing binary or unusable output leaves
 * the scan degraded.
 *
 * `scan-error` and `scan-timeout` are named explicitly rather than left to the
 * `default`, which is `degraded` and too weak for them: a scanner that exited
 * non-zero, reported rule errors, or was killed on its deadline did not inspect
 * the source at all, so its silence carries no assurance whatsoever.
 */
function outcomeFor(reason: SemgrepSkipReason | undefined): AnalyzerOutcome {
  switch (reason) {
    case "no-source":
      return "skipped";
    case "path-missing":
    case "spawn-error":
    case "scan-error":
    case "scan-timeout":
      return "failed";
    default:
      return "degraded";
  }
}

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

/**
 * `path` comes from the audited repository and `message` from a Semgrep rule
 * that may interpolate matched source, so both are attacker-reachable text on
 * its way to the VERIFY prompt — a directory named to read like an instruction
 * is enough. See `asData` in graph/util.ts.
 */
function toFinding(f: SemgrepFinding): Finding {
  return {
    vulnClass: asData(f.ruleId),
    location: asData(`${f.path}:${f.line}`),
    severity: mapSeverity(f.severity),
    evidence: asData(f.message, 2000),
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
    if (!result.available || result.reason) {
      const outcome = outcomeFor(result.reason);
      logger.info(
        {
          component: "node.analyze-static",
          note: result.note,
          reason: result.reason,
          outcome,
        },
        "Static analysis did not produce results",
      );
      return {
        findings: [],
        analyzers: status(outcome, result.note),
      };
    }

    const findings = result.findings.map(toFinding);
    const coverage = [...new Set(findings.map((f) => f.category))].filter((id) => id !== "other");
    logger.info(
      { component: "node.analyze-static", findings: findings.length, coverage: coverage.length },
      "Static analysis complete",
    );
    return { findings, coverage, analyzers: status("ok") };
  };
}
