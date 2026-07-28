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
 *
 * An analyzer that reported nothing at all counts as unreliable too. Otherwise
 * the absence of a report — a checkpoint written before this channel existed, or
 * a future node that forgets to emit one — would render as a clean assessment,
 * which is exactly the failure this module exists to prevent.
 */
import type {
  AnalyzerName,
  AnalyzerOutcome,
  AnalyzerReport,
  RetrievalReport,
} from "./state.js";

/**
 * Every analyzer expected to report, in the order the report lists them
 * (independent of superstep completion order). Any analyzer absent from a run's
 * reports is treated as an unknown, not as a pass.
 */
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

/** Analyzers that ran badly: silence from these carries no assurance. */
export function unreliableAnalyzers(
  reports: readonly AnalyzerReport[],
): AnalyzerReport[] {
  return orderAnalyzers(reports).filter((r) =>
    UNTRUSTWORTHY_SILENCE.includes(r.outcome),
  );
}

/**
 * Analyzers that produced no report at all. Their coverage is unknown, which is
 * not the same as covered — so they are surfaced alongside the failures.
 */
export function missingAnalyzers(
  reports: readonly AnalyzerReport[],
): AnalyzerName[] {
  const reported = new Set(reports.map((r) => r.analyzer));
  return ANALYZER_ORDER.filter((name) => !reported.has(name));
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
  // List analyzers that never reported, rather than omitting them silently.
  const missingRows = missingAnalyzers(reports).map(
    (name) => `| ${name} | no result reported | coverage unknown |`,
  );
  return [
    "| Analyzer | Status | Detail |",
    "| -------- | ------ | ------ |",
    ...rows,
    ...missingRows,
  ].join("\n");
}

/** Knowledge sources that were configured but did not answer. */
export function failedSources(
  retrieval: readonly RetrievalReport[],
): RetrievalReport[] {
  return retrieval.filter((r) => r.outcome === "failed");
}

/** Markdown table of knowledge-source outcomes for the methodology section. */
export function retrievalStatusTable(
  retrieval: readonly RetrievalReport[],
): string {
  const label: Record<RetrievalReport["outcome"], string> = {
    ok: "answered",
    skipped: "not configured",
    failed: "failed",
  };
  const rows = retrieval.map(
    (r) =>
      `| ${r.source} | ${label[r.outcome]} | ${r.fragments} | ${r.detail ?? "—"} |`,
  );
  return [
    "| Knowledge source | Status | Fragments | Detail |",
    "| ---------------- | ------ | --------- | ------ |",
    ...(rows.length ? rows : ["| — | no sources reported | 0 | — |"]),
  ].join("\n");
}

/**
 * Blockquote warning for a report whose coverage is incomplete, or `undefined`
 * when every expected analyzer either ran or was legitimately not applicable.
 *
 * `skipped` does not trigger it: an analyzer with nothing of its kind to inspect
 * did not malfunction, and its absence is already stated in the status table.
 * `degraded`, `failed` and "never reported" all do.
 */
export function assuranceBanner(
  reports: readonly AnalyzerReport[],
  retrieval: readonly RetrievalReport[] = [],
  droppedFalsePositives = 0,
): string | undefined {
  const unreliable = unreliableAnalyzers(reports);
  const missing = missingAnalyzers(reports);
  const sources = failedSources(retrieval);
  const affected = unreliable.length + missing.length;
  if (affected === 0 && sources.length === 0 && droppedFalsePositives <= 0) {
    return undefined;
  }

  const detail = [
    ...unreliable.map(
      (r) => `${r.analyzer} ${r.outcome}${r.detail ? ` (${r.detail})` : ""}`,
    ),
    ...missing.map((name) => `${name} reported no result`),
  ]
    .join("; ")
    .trim();

  const lines: string[] = [];
  if (affected > 0) {
    lines.push(
      `> **Incomplete assessment — ${affected} of ${ANALYZER_ORDER.length} analyzers did not run reliably.**`,
      `> ${detail}.`,
    );
  } else if (sources.length > 0) {
    lines.push("> **Incomplete assessment — the knowledge base was not fully consulted.**");
  } else {
    lines.push("> **Findings were removed during verification.**");
  }

  // A configured knowledge source that errored means the analyzers reasoned
  // with less prior knowledge than this deployment is set up to provide.
  if (sources.length > 0) {
    const sourceDetail = sources
      .map((r) => `${r.source}${r.detail ? ` (${r.detail})` : ""}`)
      .join("; ");
    lines.push(
      `> Knowledge sources unavailable: ${sourceDetail}. Prior audit knowledge` +
        " that would normally inform this review was missing.",
    );
  }

  // The critic is the only stage that deletes findings, and a deleted finding
  // appears nowhere else in the report. Stating the count in code keeps that
  // visible even when the model omits the parenthetical it was handed.
  if (droppedFalsePositives > 0) {
    lines.push(
      `> ${droppedFalsePositives} draft finding(s) were discarded as false positives by the` +
        " verification pass and do not appear below. Verification judges a finding against" +
        " its own stated evidence, so a high count relative to the findings shown means the" +
        " result is unsettled rather than clean.",
    );
  }

  lines.push(
    "> Absence of findings in the affected areas is not evidence that none exist.",
  );
  return lines.join("\n");
}

/**
 * Prepend the assurance banner to a finished report. Applied after synthesis so
 * the warning is guaranteed to be present rather than left to the model.
 */
export function withAssuranceBanner(
  report: string,
  reports: readonly AnalyzerReport[],
  retrieval: readonly RetrievalReport[] = [],
  droppedFalsePositives = 0,
): string {
  const banner = assuranceBanner(reports, retrieval, droppedFalsePositives);
  if (!banner) return report;
  return `${banner}\n\n${report}`;
}
