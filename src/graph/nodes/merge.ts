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
 * Dedupe key for a finding.
 *
 * Two rules, both learned from the previous key (`vulnClass + location`):
 *
 *  - A finding with no location cannot be shown to be the same issue as any
 *    other, so it gets a unique key and never merges. `coerceFindings` defaults
 *    a missing `location` to "", and nothing obliges a model to supply one, so
 *    the old key collapsed every unlocated finding of a given class onto one
 *    entry and discarded the rest with no log line and no counter.
 *  - When a finding carries a real catalog `category`, that is a better identity
 *    than the model's free-text `vulnClass`: two analyzers describing the same
 *    bug at the same line in different words are the duplicate this join exists
 *    to collapse. `vulnClass` is the fallback for uncategorized findings.
 */
function key(f: Finding, index: number): string {
  const location = f.location.trim().toLowerCase();
  if (!location) return `__unlocated__::${index}`;
  const identity =
    f.category && f.category !== "other"
      ? f.category
      : f.vulnClass.trim().toLowerCase();
  return `${identity}::${location}`;
}

export function makeMergeNode() {
  return async function merge(state: AresState): Promise<AresStateUpdate> {
    const byKey = new Map<string, Finding>();
    state.findings.forEach((f, i) => {
      const k = key(f, i);
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

    logger.info(
      {
        component: "node.merge",
        raw: state.findings.length,
        merged: mergedFindings.length,
        // A dedupe that collapses more than it should is a silent finding loss,
        // so the count it removed is worth seeing in the log.
        collapsed: state.findings.length - mergedFindings.length,
        unlocated: state.findings.filter((f) => !f.location.trim()).length,
      },
      "Findings merged",
    );
    return { mergedFindings };
  };
}
