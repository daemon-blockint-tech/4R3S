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
import type { AresState, AresStateUpdate } from "../state.js";
import {
  analyzerStatusTable,
  failedSources,
  retrievalStatusTable,
  unreliableAnalyzers,
  withAssuranceBanner,
} from "../analyzer-status.js";
import { chatText } from "../util.js";

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

    // Whether the auditor actually read the program. A report that reviews code
    // nobody loaded must say so in Scope & Methodology rather than leaving the
    // reader to assume a source review happened because a path was passed.
    const sourceSummary = state.sourceFiles.length
      ? `Source reviewed: ${state.sourceFiles.length} file(s) were read and placed in analysis context` +
        `${state.sourceFiles.some((f) => f.truncated) ? " (some were truncated to fit, so the review of those files is partial)" : ""}.`
      : state.sourcePath
        ? "IMPORTANT: a source path was supplied but NO source code could be read." +
          " State plainly in Scope & Methodology that no code was reviewed and that" +
          " any findings are unverified inference, not code review."
        : "No source path was supplied: this is a black-box review and no program" +
          " code was read. Say so in Scope & Methodology.";

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
      // Self-reported, and must be labelled as such. `coverage` is the union of
      // whatever each analyzer put in its `checked` array — for the three LLM
      // analyzers that is the model's own claim, validated only for catalog
      // membership, so a black-box run can assert all of them. Printing it as
      // "checked N of M" read as a measured figure. It is not one.
      `Coverage (analyzer-asserted, not independently measured): the analyzers` +
        ` reported considering ${state.coverage.length} of ${VULN_CATALOG.length}` +
        ` vulnerability classes.`,
      state.coverage.length
        ? `Classes the analyzers claim to have considered: ${state.coverage.join(", ")}`
        : "(no coverage reported)",
      "IMPORTANT: describe coverage as self-reported by the analyzers. Do not" +
        " present it as a measured or verified figure, and do not infer that a" +
        " listed class was soundly checked.",
      sourceSummary,
      "",
      "Write the final audit report in the required markdown structure, using the exact finding IDs above.",
    ]
      .filter(Boolean)
      .join("\n");

    const synthesized = await chatText(deps.chat, reportSystemPrompt(), human);
    // Guarantee the warning rather than trusting the model to include it.
    const reportText = withAssuranceBanner(
      synthesized,
      state.analyzers,
      state.retrieval,
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
