import { describe, it, expect } from "vitest";

import { makeMergeNode } from "./merge.js";
import { coerceFindings } from "../util.js";
import type { AresState, Finding } from "../state.js";

const merge = makeMergeNode();

/** Run MERGE over a bare findings list; other channels are irrelevant to it. */
async function run(findings: Finding[]): Promise<Finding[]> {
  const out = await merge({ findings } as unknown as AresState);
  return (out as { mergedFindings: Finding[] }).mergedFindings;
}

describe("MERGE dedup", () => {
  it("does not collapse distinct findings that share the default empty location", async () => {
    // The regression. `coerceFindings` defaults vulnClass to "unknown" and
    // location to "", so any model response omitting them produced the single
    // key "unknown::" and all but one finding was silently discarded. Nothing
    // downstream could see the loss: REPORT derives its dropped count as
    // mergedFindings.length - verifiedFindings.length, which is computed after
    // MERGE has already thrown them away.
    const findings = coerceFindings(
      [
        { category: "missing-signer-check", evidence: "no signer check" },
        { category: "arbitrary-cpi", evidence: "unchecked cpi target" },
        { category: "account-close-revival", evidence: "close without zeroing" },
      ],
      "heuristic",
    );
    expect(findings.every((f) => f.location === "")).toBe(true);

    const merged = await run(findings);
    expect(merged).toHaveLength(3);
    expect(new Set(merged.map((f) => f.category)).size).toBe(3);
  });

  it("still dedups a genuine duplicate at the same location", async () => {
    const findings = coerceFindings(
      [
        {
          vulnClass: "missing signer",
          location: "src/lib.rs:42",
          category: "missing-signer-check",
          severity: "medium",
          evidence: "short",
        },
        {
          vulnClass: "Missing Signer",
          location: "SRC/LIB.RS:42",
          category: "missing-signer-check",
          severity: "high",
          evidence: "a much longer and better evidenced description",
        },
      ],
      "heuristic",
    );

    const merged = await run(findings);
    expect(merged).toHaveLength(1);
    // The more severe variant wins.
    expect(merged[0]!.severity).toBe("high");
  });

  it("keeps two different vulnerability classes reported at one location", async () => {
    const findings = coerceFindings(
      [
        {
          vulnClass: "missing signer",
          location: "src/lib.rs:42",
          category: "missing-signer-check",
          severity: "high",
        },
        {
          vulnClass: "arbitrary cpi",
          location: "src/lib.rs:42",
          category: "arbitrary-cpi",
          severity: "high",
        },
      ],
      "heuristic",
    );

    const merged = await run(findings);
    expect(merged).toHaveLength(2);
  });

  it("ranks the result by severity, most severe first", async () => {
    const findings = coerceFindings(
      [
        { vulnClass: "a", location: "f:1", severity: "low" },
        { vulnClass: "b", location: "f:2", severity: "critical" },
        { vulnClass: "c", location: "f:3", severity: "medium" },
      ],
      "heuristic",
    );

    const merged = await run(findings);
    expect(merged.map((f) => f.severity)).toEqual(["critical", "medium", "low"]);
  });

  it("returns an empty list unchanged", async () => {
    expect(await run([])).toEqual([]);
  });
});
