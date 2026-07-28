/**
 * REPORT node — synthesize the verified findings into a final markdown report.
 *
 * Two things are computed here rather than delegated to the model: the severity
 * table / finding ids, and the analyzer-coverage warning. The warning is
 * prepended to the finished text (`withAssuranceBanner`), so a run where an
 * analyzer failed can never render as a clean assessment even if the model
 * ignores the instruction.
 */
import { reportSystemPrompt } from "../../llm/prompts.js";
import { logger } from "../../config/logger.js";
import { VULN_CATALOG } from "../../knowledge/solana-vulns.js";
import {
  formatFindingId,
  severityDistribution,
  severitySummaryTable,
} from "../../knowledge/severity.js";
import type { GraphDeps } from "../deps.js";
import type { AresState, AresStateUpdate, Finding } from "../state.js";
import {
  analyzerStatusTable,
  failedSources,
  retrievalStatusTable,
  unreliableAnalyzers,
  withAssuranceBanner,
} from "../analyzer-status.js";
import { chatText } from "../util.js";

/**
 * A report assembled without the model, for when prose synthesis fails.
 *
 * Deliberately plain: it reproduces the tables and the finding list that were
 * already computed deterministically, and says outright that the narrative is
 * missing. A terse report a reader can act on beats exiting with nothing after
 * every analyzer has run and been paid for.
 */
export function fallbackReport(input: {
  target: string;
  summaryTable: string;
  statusTable: string;
  sourceTable: string;
  findings: Finding[];
  coverage: string[];
  error: string;
}): string {
  const details = input.findings.length
    ? input.findings
        .map((f, i) =>
          [
            `### ${formatFindingId(i)} — ${f.vulnClass}  [${f.severity}]`,
            `- **Status:** ${f.status ?? "suspected"}  **Confidence:** ${f.confidence}` +
              `  **Source:** ${f.source}  **Category:** ${f.category}`,
            `- **Location:** ${f.location || "(not specified)"}`,
            `- **Evidence:** ${f.evidence || "(none)"}`,
            `- **Recommendation:** ${f.remediation || "(none)"}`,
          ].join("\n"),
        )
        .join("\n\n")
    : "No findings survived verification within the evaluated scope.";

  return [
    `# Security Assessment: ${input.target}`,
    "",
    "## Executive Summary",
    "",
    "> **This report was generated without narrative synthesis.** The language model" +
      " call that writes the prose sections failed, so what follows is the raw" +
      " deterministic output of the audit: the findings, their severities, and the" +
      " coverage tables. The analysis itself completed; only the write-up did not.",
    "",
    `Synthesis error: ${input.error}`,
    "",
    input.summaryTable,
    "",
    "## Scope & Methodology",
    "",
    "Analyzer status:",
    "",
    input.statusTable,
    "",
    "Knowledge sources consulted:",
    "",
    input.sourceTable,
    "",
    "## Detailed Findings",
    "",
    details,
    "",
    "## Coverage",
    "",
    `Checked ${input.coverage.length} of ${VULN_CATALOG.length} vulnerability classes.` +
      (input.coverage.length ? ` Classes: ${input.coverage.join(", ")}.` : ""),
    "",
    "## Disclaimer",
    "",
    "This is an automated assessment, not a substitute for a manual audit; absence of" +
      " findings is not a guarantee of safety.",
  ].join("\n");
}

export function makeReportNode(deps: GraphDeps) {
  return async function report(state: AresState): Promise<AresStateUpdate> {
    // VERIFY always runs before REPORT and fails safe (keeps all findings on
    // LLM error), so verifiedFindings is authoritative — an empty set genuinely
    // means every draft finding was rejected as a false-positive.
    const findings = state.verifiedFindings;
    const droppedFalsePositives = Math.max(
      0,
      state.mergedFindings.length - state.verifiedFindings.length,
    );

    // Assign stable, deterministic finding IDs (ARES-001…) and compute the
    // severity distribution here rather than trusting the LLM to count.
    const dist = severityDistribution(findings);
    const summaryTable = severitySummaryTable(dist);

    // Analyzer coverage: which analyzers ran, and whose silence can't be trusted.
    const statusTable = analyzerStatusTable(state.analyzers);
    const unreliable = unreliableAnalyzers(state.analyzers);
    // Knowledge sources: a configured one that errored means the analyzers
    // reasoned with less prior knowledge than this deployment provides.
    const sourceTable = retrievalStatusTable(state.retrieval);
    const brokenSources = failedSources(state.retrieval);

    const human = [
      state.intake ? `Target: ${state.intake.target}` : `Request: ${state.request}`,
      state.intake ? `Summary: ${state.intake.summary}` : "",
      "",
      "Severity summary table (reproduce verbatim in the Executive Summary):",
      summaryTable,
      "",
      "Analyzer status (reproduce this table verbatim in Scope & Methodology):",
      statusTable,
      "",
      "Knowledge sources consulted (reproduce verbatim in Scope & Methodology):",
      sourceTable,
      "",
      brokenSources.length
        ? "IMPORTANT: the knowledge sources marked failed above were configured " +
          "but did not answer, so prior audit knowledge that would normally " +
          "inform this review was unavailable. State this in Scope & Methodology."
        : "",
      "",
      unreliable.length
        ? "IMPORTANT: the analyzers listed above as failed or degraded did not " +
          "produce reliable results. Say so explicitly in Scope & Methodology " +
          "and state that the absence of findings in those areas is not " +
          "evidence that none exist. Do not describe the target as clean."
        : "",
      "",
      `Findings (${findings.length}), most severe first` +
        (droppedFalsePositives > 0
          ? ` (${droppedFalsePositives} dropped as false-positive in verification):`
          : ":"),
      findings.length
        ? findings
            .map(
              (f, i) =>
                `${formatFindingId(i)} [${f.severity}] ${f.vulnClass} [${f.category}] @ ${f.location} (${f.source})` +
                `${f.speculative ? " [SPECULATIVE]" : ""} [confidence: ${f.confidence}]` +
                `${f.status ? ` [status: ${f.status}]` : ""}\n` +
                `   evidence: ${f.evidence}\n   remediation: ${f.remediation}`,
            )
            .join("\n")
        : "(no findings)",
      "",
      // What was actually read is as material as what was found: a reader
      // cannot weigh "no findings" without knowing whether any code was opened.
      state.source?.available
        ? `Source read: ${state.source.files.length} of ${state.source.discovered.length} discovered file(s)` +
          (state.source.truncated
            ? " — TRUNCATED at the context budget. State in Scope & Methodology that the unread files were not examined."
            : ".")
        : "Source read: NONE — this was a black-box review. State plainly in Scope & Methodology that no program source was analyzed and that findings are pattern-based hypotheses, not observations.",
      "",
      `Coverage: checked ${state.coverage.length} of ${VULN_CATALOG.length} vulnerability classes.`,
      state.coverage.length
        ? `Checked classes: ${state.coverage.join(", ")}`
        : "(no coverage reported)",
      "",
      "Write the final audit report in the required markdown structure, using the exact finding IDs above.",
    ]
      .filter(Boolean)
      .join("\n");

    // Not caught here, for the same reason as VERIFY: a throw parks the run at
    // this node with every finding checkpointed, so resuming costs one call
    // rather than a whole re-audit. `fallbackReport` is exported for the CLI,
    // which is where a failed synthesis must still yield something readable.
    const synthesized = await chatText(deps.chat, reportSystemPrompt(), human);

    // Guarantee the warning rather than trusting the model to include it.
    const reportText = withAssuranceBanner(
      synthesized,
      state.analyzers,
      state.retrieval,
      droppedFalsePositives,
    );

    logger.info(
      {
        component: "node.report",
        length: reportText.length,
        findings: findings.length,
        severity: dist,
        analyzers: state.analyzers.map((a) => `${a.analyzer}:${a.outcome}`),
        unreliableAnalyzers: unreliable.length,
        failedSources: brokenSources.map((s) => s.source),
      },
      "Report synthesized",
    );
    return { report: reportText, iterations: 1 };
  };
}
