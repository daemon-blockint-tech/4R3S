/**
 * VERIFY node — the critic pass. Runs between MERGE and REMEMBER. Reviews the
 * merged findings against their own evidence/source in batched LLM calls,
 * refines each finding's `confidence` and `status`, and drops those judged
 * clear false-positives (targeting unsupported `heuristic` speculation).
 *
 * Fail-safe: if the LLM returns nothing usable, all merged findings pass
 * through marked `suspected` (nothing is silently dropped).
 */
import { verifySystemPrompt } from "../../llm/prompts.js";
import { logger } from "../../config/logger.js";
import type { GraphDeps } from "../deps.js";
import type { AresState, AresStateUpdate, Finding } from "../state.js";
import {
  chatJson,
  coerceVerdicts,
  applyVerdicts,
  asData,
  fenceUntrusted,
  stripFenceMarkers,
  FENCE_MAX,
  type Verdict,
} from "../util.js";

/** One finding as the critic sees it, numbered by its position in its batch. */
function render(f: Finding, index: number): string {
  return (
    `${index}. [${f.severity}] ${f.category} (${f.source})` +
    `${f.speculative ? " [speculative]" : ""}\n` +
    `   vulnClass: ${f.vulnClass} @ ${f.location}\n` +
    `   evidence: ${f.evidence || "(none)"}`
  );
}

function renderBlock(batch: Finding[]): string {
  return batch.map(render).join("\n");
}

/**
 * Split findings into batches whose rendered block fits the fence budget whole.
 *
 * One block used to be rendered for every finding and then truncated by the
 * fence, while the instruction line still asked for a verdict per finding and
 * `coerceVerdicts` still accepted every index below the total. Verdicts were
 * therefore applied to findings the critic was never shown — wrong in both
 * directions, since such a verdict could delete a real finding or promote an
 * unseen one to `confirmed`, which REMEMBER then writes to durable memory.
 * Twenty findings with ~1.2k of evidence each overflowed; with `EVIDENCE_MAX`
 * at 2000 it takes about eight, i.e. an ordinary audit.
 *
 * Batching rather than truncating, because a finding dropped from review can
 * never be confirmed and so never reaches durable memory — silently narrowing
 * the proof chain to whatever fits one prompt. The cost is one extra LLM call
 * per batch.
 *
 * Measured on the *stripped* text: `fenceUntrusted` rewrites smuggled markers
 * into something longer than the shortest marker it replaces, so a batch sized
 * on raw length can still lose its tail to a payload that asks it to.
 */
function batchToBudget(findings: Finding[]): Finding[][] {
  const batches: Finding[][] = [];
  let current: Finding[] = [];
  for (const f of findings) {
    const candidate = [...current, f];
    // ponytail: re-renders the batch per finding — O(n²) over a list of tens of
    // findings whose fields `asData` already bounds. Pack incrementally if a
    // report ever runs to thousands.
    if (
      current.length > 0 &&
      stripFenceMarkers(renderBlock(candidate)).length > FENCE_MAX
    ) {
      batches.push(current);
      current = [f];
    } else {
      current = candidate;
    }
  }
  if (current.length > 0) batches.push(current);
  return batches;
}

export function makeVerifyNode(deps: GraphDeps) {
  return async function verify(state: AresState): Promise<AresStateUpdate> {
    const findings = state.mergedFindings;
    if (findings.length === 0) {
      return { verifiedFindings: [] };
    }

    const batches = batchToBudget(findings);
    const verdicts: Verdict[] = [];
    let offset = 0;

    for (const batch of batches) {
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
        fenceUntrusted(renderBlock(batch)),
        "",
        // The batch's own range, so a verdict can never address a finding that
        // was not rendered above it.
        `Return one verdict per finding, referencing each index (0..${batch.length - 1}).`,
      ]
        // `.filter(Boolean)` here dropped the two `""` entries above, because an
        // empty string is falsy — collapsing the three sections into one run of
        // lines with no separator between the instruction, the fenced data, and
        // the range. The fence markers still delimited the untrusted block, so
        // nothing was mis-parsed, but the blank lines were written deliberately
        // and were silently absent. There is no conditional entry left to
        // filter: the first element is a ternary that always yields a string.
        .join("\n");

      // A thrown error is deliberately NOT caught here. The checkpointer parks the
      // run at this node with the analyzers' findings already persisted, so the
      // audit is resumable on the same thread id without re-running them — see
      // "keeps the partial findings of an interrupted run when it is resumed" in
      // build-graph.test.ts. Swallowing the throw would trade that for a silently
      // unverified report. The CLI is what must not exit empty-handed; see index.ts.
      const raw = await chatJson<unknown>(deps.chat, verifySystemPrompt(), human, []);
      // Indices are per-batch on the way out and global on the way in.
      for (const v of coerceVerdicts(raw, batch.length)) {
        verdicts.push({ ...v, index: v.index + offset });
      }
      offset += batch.length;
    }

    const { kept, dropped, clamped, refusedDeletion } = applyVerdicts(
      findings,
      verdicts,
      state.source,
    );

    logger.info(
      {
        component: "node.verify",
        reviewed: findings.length,
        batches: batches.length,
        kept: kept.length,
        droppedFalsePositives: dropped,
        confirmed: kept.filter((f) => f.status === "confirmed").length,
        // Findings the critic called `confirmed` without an artifact to check
        // against; demoted to `suspected`. A high number here means the model
        // is over-confirming, which is worth seeing.
        clampedToSuspected: clamped,
        // The other half of the same signal: deletions the critic asked for on
        // findings decoded from bytes, which it has nothing to refute with.
        refusedDeletions: refusedDeletion,
      },
      "Verification pass complete",
    );
    return { verifiedFindings: kept, iterations: batches.length };
  };
}
