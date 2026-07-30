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
 *
 * `no-files-scanned` joins them: a scan that opened zero files did not look, so
 * reporting it as `ok` published an unscanned program as a clean audit.
 */
function outcomeFor(reason: SemgrepSkipReason | undefined): AnalyzerOutcome {
  switch (reason) {
    case "no-source":
      return "skipped";
    case "path-missing":
    case "spawn-error":
    case "scan-error":
    case "scan-timeout":
    case "no-files-scanned":
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

/**
 * Best-effort map a Semgrep ruleId to a catalog vulnerability id.
 *
 * Gated on the finding being about Rust. The keyword chain below assigns a
 * *specific* Solana class from a single generic word, and a scan covers whatever
 * is under the source path — JS, Python, YAML, Dockerfiles — so rule ids from
 * unrelated languages reached it. Measured against 1594 rule ids from the live
 * registry, exactly one collided:
 * `python.lang.security.deserialization.pickle.avoid-cPickle` contains "cpi" and
 * was labelled `arbitrary-cpi`. One is not many, but the label is then pushed
 * into `coverage` as a class considered, and the fix costs a line.
 *
 * Note the `id.includes(lower)` direction of the exact-match loop is dead: rule
 * ids are fully-qualified dotted paths and can never be a substring of a short
 * kebab-case catalog id. Kept for the `lower.includes(id)` direction, which does
 * fire for a committed Solana ruleset naming its rules after catalog ids.
 */
function mapCategory(ruleId: string, path: string): string {
  const lower = ruleId.toLowerCase();
  const isRust = lower.startsWith("rust.") || path.toLowerCase().endsWith(".rs");
  if (!isRust) return "other";

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
    category: mapCategory(f.ruleId, f.path),
    speculative: false,
    // A tool hit is real evidence, but "high" was hardcoded regardless of how
    // the rule was matched. A finding whose class we could not identify is not
    // one we should assert confidently — VERIFY reads this, and `applyVerdicts`
    // lets a non-speculative static finding be stamped `confirmed`.
    confidence: mapCategory(f.ruleId, f.path) === "other" ? "medium" : "high",
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
      {
        component: "node.analyze-static",
        findings: findings.length,
        coverage: coverage.length,
        partial: result.partial,
      },
      "Static analysis complete",
    );
    // A scan that completed but could not parse every file found real issues in
    // the files it did read, so the findings stand — but the classes it never
    // reached are unexamined, and `ok` would claim otherwise.
    return {
      findings,
      coverage,
      analyzers: result.partial ? status("degraded", result.partial) : status("ok"),
    };
  };
}
