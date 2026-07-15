/**
 * VERIFY node — the critic pass. Runs between MERGE and REMEMBER. Reviews the
 * merged findings against their own evidence/source in one batched LLM call,
 * refines each finding's `confidence` and `status`, and drops those judged
 * clear false-positives (targeting unsupported `heuristic` speculation).
 *
 * Fail-safe: if the LLM returns nothing usable, all merged findings pass
 * through marked `suspected` (nothing is silently dropped).
 */
import { verifySystemPrompt } from "../../llm/prompts.js";
import { logger } from "../../config/logger.js";
import type { GraphDeps } from "../deps.js";
import type { AresState, AresStateUpdate } from "../state.js";
import { chatJson, coerceVerdicts, applyVerdicts } from "../util.js";

export function makeVerifyNode(deps: GraphDeps) {
  return async function verify(state: AresState): Promise<AresStateUpdate> {
    const findings = state.mergedFindings;
    if (findings.length === 0) {
      return { verifiedFindings: [] };
    }

    const human = [
      state.intake ? `Target: ${state.intake.target}` : `Request: ${state.request}`,
      "",
      "Draft findings to review (index. [severity] category (source) — evidence):",
      findings
        .map(
          (f, i) =>
            `${i}. [${f.severity}] ${f.category} (${f.source})` +
            `${f.speculative ? " [speculative]" : ""}\n` +
            `   vulnClass: ${f.vulnClass} @ ${f.location}\n` +
            `   evidence: ${f.evidence || "(none)"}`,
        )
        .join("\n"),
      "",
      `Return one verdict per finding, referencing each index (0..${findings.length - 1}).`,
    ]
      .filter(Boolean)
      .join("\n");

    const raw = await chatJson<unknown>(deps.chat, verifySystemPrompt(), human, []);
    const verdicts = coerceVerdicts(raw, findings.length);
    const { kept, dropped } = applyVerdicts(findings, verdicts);

    logger.info(
      {
        component: "node.verify",
        reviewed: findings.length,
        kept: kept.length,
        droppedFalsePositives: dropped,
        confirmed: kept.filter((f) => f.status === "confirmed").length,
      },
      "Verification pass complete",
    );
    return { verifiedFindings: kept, iterations: 1 };
  };
}
