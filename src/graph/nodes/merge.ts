/**
 * MERGE node — the fan-in join. Dedupes the findings appended by the three
 * parallel analyzers (keyed by vulnClass + location, keeping the most severe /
 * best-evidenced variant) and ranks them by severity. Writes the result to
 * `mergedFindings` (the raw `findings` channel is append-only).
 */
import { logger } from "../../config/logger.js";
import type { AresState, AresStateUpdate, Finding } from "../state.js";
import { SEVERITY_RANK } from "../state.js";

function key(f: Finding): string {
  return `${f.vulnClass.toLowerCase()}::${f.location.toLowerCase()}`;
}

export function makeMergeNode() {
  return async function merge(state: AresState): Promise<AresStateUpdate> {
    const byKey = new Map<string, Finding>();
    for (const f of state.findings) {
      const k = key(f);
      const existing = byKey.get(k);
      if (
        !existing ||
        SEVERITY_RANK[f.severity] > SEVERITY_RANK[existing.severity] ||
        (SEVERITY_RANK[f.severity] === SEVERITY_RANK[existing.severity] &&
          f.evidence.length > existing.evidence.length)
      ) {
        byKey.set(k, f);
      }
    }

    const mergedFindings = [...byKey.values()].sort(
      (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity],
    );

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
