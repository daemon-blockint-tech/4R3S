import { describe, it, expect } from "vitest";

import { makeMergeNode } from "./merge.js";
import { coerceFindings } from "../util.js";
import type { AresState } from "../state.js";

const merge = makeMergeNode();

async function mergeOf(raw: unknown[]): Promise<AresState["mergedFindings"]> {
  const findings = coerceFindings({ findings: raw }, "heuristic");
  const out = await merge({ findings } as AresState);
  return out.mergedFindings ?? [];
}

describe("merge dedupe", () => {
  it("keeps distinct findings that the model left unlocated", async () => {
    // `coerceFindings` defaults a missing `location` to "", and nothing obliges
    // a model to supply one. Keying on vulnClass+location therefore collapsed
    // every unlocated finding of a class onto one entry and discarded the rest
    // with no log line and no counter — two separate overflow sites became one.
    const merged = await mergeOf([
      {
        vulnClass: "integer-overflow",
        severity: "high",
        evidence: "unchecked add in deposit()",
        category: "integer-overflow-underflow",
      },
      {
        vulnClass: "integer-overflow",
        severity: "high",
        evidence: "unchecked sub in withdraw()",
        category: "integer-overflow-underflow",
      },
    ]);

    expect(merged).toHaveLength(2);
    expect(merged.map((f) => f.evidence).sort()).toEqual([
      "unchecked add in deposit()",
      "unchecked sub in withdraw()",
    ]);
  });

  it("still collapses the same issue reported at the same location", async () => {
    const merged = await mergeOf([
      {
        vulnClass: "integer-overflow",
        location: "src/lib.rs:12",
        severity: "medium",
        evidence: "short",
        category: "integer-overflow-underflow",
      },
      {
        vulnClass: "integer-overflow",
        location: "src/lib.rs:12",
        severity: "high",
        evidence: "a much longer and better-evidenced description",
        category: "integer-overflow-underflow",
      },
    ]);

    expect(merged).toHaveLength(1);
    // The more severe variant wins.
    expect(merged[0]!.severity).toBe("high");
  });

  it("collapses two analyzers describing one issue in different words", async () => {
    // A real catalog category is a better identity than free-text vulnClass:
    // this is the cross-analyzer duplicate the fan-in join exists to remove.
    const merged = await mergeOf([
      {
        vulnClass: "narrowing cast",
        location: "src/lib.rs:2",
        severity: "medium",
        evidence: "as u64",
        category: "unsafe-type-cast",
      },
      {
        vulnClass: "unchecked numeric truncation",
        location: "src/lib.rs:2",
        severity: "medium",
        evidence: "truncating cast on an amount",
        category: "unsafe-type-cast",
      },
    ]);

    expect(merged).toHaveLength(1);
  });

  it("keeps genuinely different classes at the same location", async () => {
    const merged = await mergeOf([
      {
        vulnClass: "a",
        location: "src/lib.rs:2",
        severity: "high",
        evidence: "x",
        category: "unsafe-type-cast",
      },
      {
        vulnClass: "b",
        location: "src/lib.rs:2",
        severity: "high",
        evidence: "y",
        category: "arbitrary-cpi",
      },
    ]);

    expect(merged).toHaveLength(2);
  });
});
