/**
 * MERGE node — the fan-in join. Dedupes the findings appended by the three
 * parallel analyzers (keyed by vulnClass + location, keeping the most severe /
 * best-evidenced variant) and ranks them by severity. Writes the result to
 * `mergedFindings` (the raw `findings` channel is append-only).
 */
import { logger } from "../../config/logger.js";
import type { AresState, AresStateUpdate, Finding } from "../state.js";
import { SEVERITY_RANK } from "../state.js";

/**
 * Identity for dedup purposes.
 *
 * Two problems with keying on `vulnClass + location` alone. Both fields are
 * free text from the model, and `coerceFindings` defaults them to `"unknown"`
 * and `""` — so any response that omitted them collapsed *every* finding onto
 * the single key `unknown::`, and all but one were discarded. MERGE is the only
 * node that deletes a finding without saying so: REPORT derives its dropped
 * count as `mergedFindings.length - verifiedFindings.length`, which cannot see
 * a loss that happened before VERIFY.
 *
 * So: an unlocated finding is never deduped (it has no identity to compare),
 * and `category` — the one field validated against the catalog — joins the key
 * so two genuinely different classes at one location stay separate.
 */
function key(f: Finding, index: number): string {
  // Per-finding sentinel, so an unlocated finding only ever matches itself.
  // Contains no "::", so it can never collide with a real key below.
  if (!f.location.trim()) return `unlocated#${index}`;
  return `${f.category}::${f.vulnClass.toLowerCase()}::${f.location.toLowerCase()}`;
}

export function makeMergeNode() {
  return async function merge(state: AresState): Promise<AresStateUpdate> {
    const byKey = new Map<string, Finding>();
    state.findings.forEach((f, index) => {
      const k = key(f, index);
      const existing = byKey.get(k);
      if (
        !existing ||
        SEVERITY_RANK[f.severity] > SEVERITY_RANK[existing.severity] ||
        (SEVERITY_RANK[f.severity] === SEVERITY_RANK[existing.severity] &&
          f.evidence.length > existing.evidence.length)
      ) {
        byKey.set(k, f);
      }
    });

    const mergedFindings = [...byKey.values()].sort(
      (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity],
    );

    // Deduping discards a finding that no later phase can account for, so say so
    // at warn level rather than leaving it implicit in two info counters.
    const deduped = state.findings.length - mergedFindings.length;
    if (deduped > 0) {
      logger.warn(
        { component: "node.merge", deduped, raw: state.findings.length },
        "Findings discarded as duplicates during merge",
      );
    }

    logger.info(
      {
        component: "node.merge",
        raw: state.findings.length,
        merged: mergedFindings.length,
      },
      "Findings merged",
    );
    return { mergedFindings };
  };
}
