/**
 * REPORT node — synthesize the verified findings into a final markdown report.
 */
import { reportSystemPrompt } from "../../llm/prompts.js";
import { logger } from "../../config/logger.js";
import { VULN_CATALOG } from "../../knowledge/solana-vulns.js";
import type { GraphDeps } from "../deps.js";
import type { AresState, AresStateUpdate } from "../state.js";
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

    const human = [
      state.intake ? `Target: ${state.intake.target}` : `Request: ${state.request}`,
      state.intake ? `Summary: ${state.intake.summary}` : "",
      "",
      `Findings (${findings.length}), most severe first` +
        (droppedFalsePositives > 0
          ? ` (${droppedFalsePositives} dropped as false-positive in verification):`
          : ":"),
      findings.length
        ? findings
            .map(
              (f, i) =>
                `${i + 1}. [${f.severity}] ${f.vulnClass} [${f.category}] @ ${f.location} (${f.source})` +
                `${f.speculative ? " [SPECULATIVE]" : ""} [confidence: ${f.confidence}]` +
                `${f.status ? ` [status: ${f.status}]` : ""}\n` +
                `   evidence: ${f.evidence}\n   remediation: ${f.remediation}`,
            )
            .join("\n")
        : "(no findings)",
      "",
      `Coverage: checked ${state.coverage.length} of ${VULN_CATALOG.length} vulnerability classes.`,
      state.coverage.length
        ? `Checked classes: ${state.coverage.join(", ")}`
        : "(no coverage reported)",
      "",
      "Write the final audit report in the required markdown structure.",
    ]
      .filter(Boolean)
      .join("\n");

    const reportText = await chatText(deps.chat, reportSystemPrompt(), human);

    logger.info(
      { component: "node.report", length: reportText.length },
      "Report synthesized",
    );
    return { report: reportText, iterations: 1 };
  };
}
