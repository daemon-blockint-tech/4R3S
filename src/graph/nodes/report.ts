/**
 * REPORT node — synthesize the merged findings into a final markdown report.
 */
import { reportSystemPrompt } from "../../llm/prompts.js";
import { logger } from "../../config/logger.js";
import type { GraphDeps } from "../deps.js";
import type { AresState, AresStateUpdate } from "../state.js";
import { chatText } from "../util.js";

export function makeReportNode(deps: GraphDeps) {
  return async function report(state: AresState): Promise<AresStateUpdate> {
    const findings = state.mergedFindings;

    const human = [
      state.intake ? `Target: ${state.intake.target}` : `Request: ${state.request}`,
      state.intake ? `Summary: ${state.intake.summary}` : "",
      "",
      `Findings (${findings.length}), most severe first:`,
      findings.length
        ? findings
            .map(
              (f, i) =>
                `${i + 1}. [${f.severity}] ${f.vulnClass} @ ${f.location} (${f.source})\n` +
                `   evidence: ${f.evidence}\n   remediation: ${f.remediation}`,
            )
            .join("\n")
        : "(no findings)",
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
