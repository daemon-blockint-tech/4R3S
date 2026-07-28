import { describe, it, expect, vi, beforeEach } from "vitest";

import type { SemgrepResult } from "../../tools/semgrep.js";
import type { AresState, AnalyzerReport } from "../state.js";

const runSemgrep = vi.fn<() => Promise<SemgrepResult>>();
vi.mock("../../tools/semgrep.js", () => ({ runSemgrep: () => runSemgrep() }));

const { makeAnalyzeStaticNode } = await import("./analyze-static.js");
const { assuranceBanner, unreliableAnalyzers } = await import(
  "../analyzer-status.js"
);

const node = makeAnalyzeStaticNode();

async function outcomeOf(result: SemgrepResult): Promise<AnalyzerReport> {
  runSemgrep.mockResolvedValue(result);
  const out = await node({ sourcePath: "/some/path" } as unknown as AresState);
  return (out as { analyzers: AnalyzerReport[] }).analyzers[0]!;
}

beforeEach(() => runSemgrep.mockReset());

describe("analyzeStatic outcome mapping", () => {
  it("reports `failed` when the scan errored, so the assurance banner fires", async () => {
    // The whole point: a scan that did not complete must not read as evidence
    // of a clean program. `ok` and `skipped` deliberately raise no banner, so
    // anything short of `failed`/`degraded` here would hide a broken scan.
    const report = await outcomeOf({
      available: false,
      findings: [],
      note: "semgrep exited 2",
      reason: "scan-error",
    });
    expect(report.outcome).toBe("failed");

    const banner = assuranceBanner([report], []);
    expect(banner).toBeDefined();
    expect(banner).toMatch(/not evidence that none exist/i);
  });

  it("reports `failed` when the scan was killed on its deadline", async () => {
    const report = await outcomeOf({
      available: false,
      findings: [],
      note: "semgrep exceeded 120000ms and was killed",
      reason: "scan-timeout",
    });
    expect(report.outcome).toBe("failed");
    expect(assuranceBanner([report], [])).toBeDefined();
  });

  it("reports `degraded` when semgrep is simply not installed", async () => {
    const report = await outcomeOf({
      available: false,
      findings: [],
      note: "semgrep not installed",
      reason: "not-installed",
    });
    expect(report.outcome).toBe("degraded");
  });

  it("reports `ok` only for a scan that genuinely completed", async () => {
    const report = await outcomeOf({ available: true, findings: [] });
    expect(report.outcome).toBe("ok");
    // `ok` contributes nothing to the banner — which is safe only because a
    // failed scan can no longer reach this branch. (The banner itself also
    // flags analyzers that never reported, so it is asserted on the one
    // analyzer under test rather than on a partial set.)
    expect(unreliableAnalyzers([report])).toEqual([]);
  });
});
