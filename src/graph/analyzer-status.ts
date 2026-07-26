/**
 * Analyzer status reporting.
 *
 * An audit report is only trustworthy if the reader can tell "we looked and
 * found nothing" apart from "we never looked". Every analyzer degrades
 * gracefully — an RPC error, a missing Semgrep binary, or unparseable model
 * output all end with zero findings — so without this the two cases render
 * identically as a clean report.
 *
 * These helpers are deterministic and computed in code, not delegated to the
 * model: the banner is prepended to the finished report so it cannot be dropped,
 * and the table is handed to REPORT for its methodology section.
 */
import type { AnalyzerName, AnalyzerOutcome, AnalyzerReport } from "./state.js";

/** Analyzer order used in the report, independent of superstep completion order. */
const ANALYZER_ORDER: AnalyzerName[] = ["onchain", "static", "heuristic", "cua"];

/** Outcomes that mean an absence of findings carries no assurance. */
const UNTRUSTWORTHY_SILENCE: AnalyzerOutcome[] = ["degraded", "failed"];

const OUTCOME_LABEL: Record<AnalyzerOutcome, string> = {
  ok: "ran",
  skipped: "not applicable",
  degraded: "degraded",
  failed: "failed",
};

/** Sort reports into a stable, human-readable order. */
export function orderAnalyzers(reports: readonly AnalyzerReport[]): AnalyzerReport[] {
  return [...reports].sort(
    (a, b) =>
      ANALYZER_ORDER.indexOf(a.analyzer) - ANALYZER_ORDER.indexOf(b.analyzer),
  );
}

/** Analyzers whose silence must not be read as a clean result. */
export function unreliableAnalyzers(
  reports: readonly AnalyzerReport[],
): AnalyzerReport[] {
  return orderAnalyzers(reports).filter((r) =>
    UNTRUSTWORTHY_SILENCE.includes(r.outcome),
  );
}

/**
 * Markdown table of analyzer outcomes for the report's Scope & Methodology
 * section. Rendered here so the counts and wording can't drift per run.
 */
export function analyzerStatusTable(reports: readonly AnalyzerReport[]): string {
  const rows = orderAnalyzers(reports).map(
    (r) =>
      `| ${r.analyzer} | ${OUTCOME_LABEL[r.outcome]} | ${r.detail ?? "—"} |`,
  );
  return [
    "| Analyzer | Status | Detail |",
    "| -------- | ------ | ------ |",
    ...(rows.length ? rows : ["| — | no analyzers reported | — |"]),
  ].join("\n");
}

/**
 * Blockquote warning for a report whose coverage is incomplete, or `undefined`
 * when every analyzer either ran or was legitimately not applicable.
 *
 * `skipped` analyzers are named too: an audit that never had source code to
 * analyze is a narrower audit, and the reader should know that even though
 * nothing malfunctioned.
 */
export function assuranceBanner(
  reports: readonly AnalyzerReport[],
): string | undefined {
  const unreliable = unreliableAnalyzers(reports);
  if (unreliable.length === 0) return undefined;

  const total = reports.length;
  const detail = unreliable
    .map((r) => `${r.analyzer} ${r.outcome}${r.detail ? ` (${r.detail})` : ""}`)
    .join("; ")
    .trim();

  return [
    `> **Incomplete assessment — ${unreliable.length} of ${total} analyzers did not run reliably.**`,
    `> ${detail}.`,
    "> Absence of findings in the affected areas is not evidence that none exist.",
  ].join("\n");
}

/**
 * Prepend the assurance banner to a finished report. Applied after synthesis so
 * the warning is guaranteed to be present rather than left to the model.
 */
export function withAssuranceBanner(
  report: string,
  reports: readonly AnalyzerReport[],
): string {
  const banner = assuranceBanner(reports);
  if (!banner) return report;
  return `${banner}\n\n${report}`;
}
