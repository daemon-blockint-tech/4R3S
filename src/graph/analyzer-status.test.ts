import { describe, it, expect } from "vitest";

import {
  analyzerStatusTable,
  assuranceBanner,
  orderAnalyzers,
  unreliableAnalyzers,
  withAssuranceBanner,
} from "./analyzer-status.js";
import type { AnalyzerReport } from "./state.js";

const ok: AnalyzerReport[] = [
  { analyzer: "onchain", outcome: "ok" },
  { analyzer: "static", outcome: "skipped", detail: "no source path provided" },
  { analyzer: "heuristic", outcome: "ok" },
  { analyzer: "cua", outcome: "skipped", detail: "CUA not enabled (opt-in)" },
];

const rpcFailed: AnalyzerReport[] = [
  {
    analyzer: "onchain",
    outcome: "failed",
    detail: "could not read program: Error: fetch failed",
  },
  { analyzer: "static", outcome: "skipped", detail: "no source path provided" },
  { analyzer: "heuristic", outcome: "ok" },
  { analyzer: "cua", outcome: "skipped" },
];

describe("orderAnalyzers", () => {
  it("renders in a fixed order regardless of superstep completion order", () => {
    const shuffled: AnalyzerReport[] = [
      { analyzer: "cua", outcome: "skipped" },
      { analyzer: "heuristic", outcome: "ok" },
      { analyzer: "onchain", outcome: "ok" },
      { analyzer: "static", outcome: "ok" },
    ];
    expect(orderAnalyzers(shuffled).map((r) => r.analyzer)).toEqual([
      "onchain",
      "static",
      "heuristic",
      "cua",
    ]);
  });
});

describe("unreliableAnalyzers", () => {
  it("counts failed and degraded, but not skipped or ok", () => {
    expect(unreliableAnalyzers(ok)).toEqual([]);
    expect(unreliableAnalyzers(rpcFailed).map((r) => r.analyzer)).toEqual([
      "onchain",
    ]);
    const degraded: AnalyzerReport[] = [
      { analyzer: "static", outcome: "degraded", detail: "semgrep not installed" },
      { analyzer: "heuristic", outcome: "ok" },
    ];
    expect(unreliableAnalyzers(degraded).map((r) => r.analyzer)).toEqual(["static"]);
  });
});

describe("assuranceBanner", () => {
  it("is absent when every analyzer either ran or was not applicable", () => {
    expect(assuranceBanner(ok)).toBeUndefined();
  });

  it("names the analyzer, its outcome and the reason when one failed", () => {
    const banner = assuranceBanner(rpcFailed);
    expect(banner).toBeDefined();
    expect(banner).toContain("1 of 4 analyzers did not run reliably");
    expect(banner).toContain("onchain failed");
    expect(banner).toContain("fetch failed");
    expect(banner).toContain("not evidence that none exist");
  });

  it("reports every unreliable analyzer, not just the first", () => {
    const banner = assuranceBanner([
      { analyzer: "onchain", outcome: "failed", detail: "rpc down" },
      { analyzer: "static", outcome: "degraded", detail: "semgrep not installed" },
    ]);
    expect(banner).toContain("2 of 2");
    expect(banner).toContain("onchain failed");
    expect(banner).toContain("static degraded");
  });
});

describe("withAssuranceBanner", () => {
  it("leaves a fully-covered report untouched", () => {
    expect(withAssuranceBanner("# Report", ok)).toBe("# Report");
  });

  it("prepends the warning above the report body", () => {
    const out = withAssuranceBanner("# Report", rpcFailed);
    expect(out.startsWith("> **Incomplete assessment")).toBe(true);
    expect(out).toContain("# Report");
    // The warning has to come first — a reader must not have to scroll for it.
    expect(out.indexOf("Incomplete assessment")).toBeLessThan(out.indexOf("# Report"));
  });
});

describe("analyzerStatusTable", () => {
  it("lists every analyzer with its status and detail", () => {
    const table = analyzerStatusTable(rpcFailed);
    expect(table).toContain("| Analyzer | Status | Detail |");
    expect(table).toContain("| onchain | failed | could not read program");
    expect(table).toContain("| static | not applicable | no source path provided |");
    expect(table).toContain("| heuristic | ran | — |");
  });

  it("degrades to a placeholder row rather than an empty table", () => {
    expect(analyzerStatusTable([])).toContain("no analyzers reported");
  });
});
