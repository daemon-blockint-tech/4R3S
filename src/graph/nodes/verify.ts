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
import {
  chatJson,
  coerceVerdicts,
  applyVerdicts,
  asData,
  fenceUntrusted,
} from "../util.js";

export function makeVerifyNode(deps: GraphDeps) {
  return async function verify(state: AresState): Promise<AresStateUpdate> {
    const findings = state.mergedFindings;
    if (findings.length === 0) {
      return { verifiedFindings: [] };
    }

    // Finding text originates in the audited repository (Semgrep paths and rule
    // messages) and on web pages (the CUA transcript). VERIFY is the only node
    // that deletes findings, so that text is in a position to argue for its own
    // dismissal. Fields are stripped by `asData` upstream; the fence is what
    // tells the model where instructions stop and evidence begins. Shared with
    // `analyze-cua`, which fences the same class of text on the way in.
    const human = [
      state.intake ? `Target: ${asData(state.intake.target)}` : `Request: ${asData(state.request)}`,
      "",
      "Draft findings to review (index. [severity] category (source) — evidence):",
      fenceUntrusted(
        findings
          .map(
            (f, i) =>
              `${i}. [${f.severity}] ${f.category} (${f.source})` +
              `${f.speculative ? " [speculative]" : ""}\n` +
              `   vulnClass: ${f.vulnClass} @ ${f.location}\n` +
              `   evidence: ${f.evidence || "(none)"}`,
          )
          .join("\n"),
      ),
      "",
      `Return one verdict per finding, referencing each index (0..${findings.length - 1}).`,
    ]
      .filter(Boolean)
      .join("\n");

    // A thrown error is deliberately NOT caught here. The checkpointer parks the
    // run at this node with the analyzers' findings already persisted, so the
    // audit is resumable on the same thread id without re-running them — see
    // "keeps the partial findings of an interrupted run when it is resumed" in
    // build-graph.test.ts. Swallowing the throw would trade that for a silently
    // unverified report. The CLI is what must not exit empty-handed; see index.ts.
    const raw = await chatJson<unknown>(deps.chat, verifySystemPrompt(), human, []);
    const verdicts = coerceVerdicts(raw, findings.length);
    const { kept, dropped, clamped } = applyVerdicts(findings, verdicts, state.source);

    logger.info(
      {
        component: "node.verify",
        reviewed: findings.length,
        kept: kept.length,
        droppedFalsePositives: dropped,
        confirmed: kept.filter((f) => f.status === "confirmed").length,
        // Findings the critic called `confirmed` without an artifact to check
        // against; demoted to `suspected`. A high number here means the model
        // is over-confirming, which is worth seeing.
        clampedToSuspected: clamped,
      },
      "Verification pass complete",
    );
    return { verifiedFindings: kept, iterations: 1 };
  };
}
