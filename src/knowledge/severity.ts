/**
 * Severity classification — the impact × likelihood methodology that
 * professional Solana auditors (OtterSec, Neodyme, Zellic, Trail of Bits, Sec3)
 * use to rate findings, plus report-formatting helpers.
 *
 * A finding's severity is derived from two axes:
 *   - Impact:     how bad is it if exploited (fund loss, DoS, info leak).
 *   - Likelihood: how easy / probable is exploitation in practice.
 *
 * The REPORT phase uses this to present a consistent severity scale, a
 * deterministic finding-count summary, and stable finding identifiers, rather
 * than letting the model invent its own scheme each run.
 */
import type { Finding, Severity } from "../graph/state.js";
import { SEVERITY_RANK } from "../graph/state.js";

export type Impact = "high" | "medium" | "low";
export type Likelihood = "high" | "medium" | "low";

/**
 * Impact × Likelihood → Severity matrix. This is the de-facto industry matrix:
 * only high-impact & high-likelihood is Critical; low-impact & low-likelihood is
 * Informational; everything else grades in between.
 *
 *                       Likelihood
 *                 high      medium    low
 *   Impact high   critical  high      medium
 *          medium high      medium    low
 *          low    medium    low       info
 */
const SEVERITY_MATRIX: Record<Impact, Record<Likelihood, Severity>> = {
  high: { high: "critical", medium: "high", low: "medium" },
  medium: { high: "high", medium: "medium", low: "low" },
  low: { high: "medium", medium: "low", low: "info" },
};

/** Derive a finding severity from the impact/likelihood axes. */
export function severityFromMatrix(
  impact: Impact,
  likelihood: Likelihood,
): Severity {
  return SEVERITY_MATRIX[impact][likelihood];
}

/** One-line definition of each severity level, for report methodology sections. */
export const SEVERITY_DEFINITIONS: Record<Severity, string> = {
  critical:
    "Directly exploitable to steal or freeze funds, or fully compromise the protocol. Fix before deployment.",
  high: "Serious risk to funds or protocol integrity under realistic conditions. Fix before deployment.",
  medium:
    "Exploitable only under specific preconditions, or with limited impact. Should be fixed.",
  low: "Minor issue with little or no direct risk to funds. Fix when convenient.",
  info: "Best-practice, code-quality, or hardening note with no direct security impact.",
};

/** Severity levels ordered most-severe first. */
export const SEVERITY_ORDER: Severity[] = (
  Object.keys(SEVERITY_RANK) as Severity[]
).sort((a, b) => SEVERITY_RANK[b] - SEVERITY_RANK[a]);

/** Count findings by severity (all levels present, zero-filled). */
export function severityDistribution(
  findings: Pick<Finding, "severity">[],
): Record<Severity, number> {
  const dist: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) dist[f.severity] += 1;
  return dist;
}

/**
 * Stable, human-readable finding identifier: `ARES-001`, `ARES-002`, … The
 * index is zero-based; ids are 1-based and zero-padded to 3 digits.
 */
export function formatFindingId(index: number, prefix = "ARES"): string {
  return `${prefix}-${String(index + 1).padStart(3, "0")}`;
}

/**
 * Render the severity distribution as a compact markdown table. Deterministic —
 * computed from the findings, not the LLM — so the report's headline counts are
 * always accurate.
 */
export function severitySummaryTable(
  dist: Record<Severity, number>,
): string {
  const total = SEVERITY_ORDER.reduce((n, s) => n + dist[s], 0);
  const rows = SEVERITY_ORDER.map(
    (s) => `| ${capitalize(s)} | ${dist[s]} |`,
  ).join("\n");
  return [
    "| Severity | Count |",
    "| --- | --- |",
    rows,
    `| **Total** | **${total}** |`,
  ].join("\n");
}

/**
 * The severity-classification block injected into the REPORT system prompt so
 * the model rates and describes findings on a consistent, industry-standard
 * scale.
 */
export function formatSeverityMethodology(): string {
  const defs = SEVERITY_ORDER.map(
    (s) => `- **${capitalize(s)}** — ${SEVERITY_DEFINITIONS[s]}`,
  ).join("\n");
  return [
    "Severity is assessed as a function of Impact (fund loss / DoS / data exposure) and",
    "Likelihood (how easily it can be triggered), per the standard auditor matrix:",
    "Critical = high impact & high likelihood; Informational = low impact & low likelihood.",
    "",
    defs,
  ].join("\n");
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
