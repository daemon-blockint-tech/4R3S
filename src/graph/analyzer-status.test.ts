import { describe, it, expect } from "vitest";

import {
  analyzerStatusTable,
  assuranceBanner,
  failedSources,
  missingAnalyzers,
  orderAnalyzers,
  retrievalStatusTable,
  unreliableAnalyzers,
  withAssuranceBanner,
} from "./analyzer-status.js";
import type { AnalyzerReport, RetrievalReport } from "./state.js";

const sourcesOk: RetrievalReport[] = [
  { source: "crystalline", outcome: "ok", fragments: 3 },
  { source: "supabase", outcome: "skipped", fragments: 0, detail: "not configured" },
  { source: "neo4j", outcome: "skipped", fragments: 0, detail: "not configured" },
];

const sourceDown: RetrievalReport[] = [
  { source: "crystalline", outcome: "ok", fragments: 3 },
  { source: "supabase", outcome: "failed", fragments: 0, detail: "rpc exploded" },
  { source: "neo4j", outcome: "skipped", fragments: 0, detail: "not configured" },
];

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
      { analyzer: "heuristic", outcome: "ok" },
      { analyzer: "cua", outcome: "skipped" },
    ]);
    expect(banner).toContain("2 of 4");
    expect(banner).toContain("onchain failed");
    expect(banner).toContain("static degraded");
  });

  it("warns when an analyzer reported nothing at all", () => {
    // A checkpoint written before the `analyzers` channel existed, or a node
    // that forgets to report, must not render as full coverage.
    const banner = assuranceBanner([
      { analyzer: "onchain", outcome: "ok" },
      { analyzer: "static", outcome: "ok" },
      { analyzer: "heuristic", outcome: "ok" },
    ]);
    expect(banner).toContain("1 of 4");
    expect(banner).toContain("cua reported no result");
  });

  it("warns loudly when no analyzer reported at all", () => {
    const banner = assuranceBanner([]);
    expect(banner).toBeDefined();
    expect(banner).toContain("4 of 4");
    expect(banner).toContain("onchain reported no result");
  });
});

describe("knowledge sources", () => {
  it("counts only configured sources that errored as failed", () => {
    // Unconfigured is the documented default mode, not a fault.
    expect(failedSources(sourcesOk)).toEqual([]);
    expect(failedSources(sourceDown).map((r) => r.source)).toEqual(["supabase"]);
  });

  it("renders each source with its fragment count", () => {
    const table = retrievalStatusTable(sourceDown);
    expect(table).toContain("| Knowledge source | Status | Fragments | Detail |");
    expect(table).toContain("| crystalline | answered | 3 | — |");
    expect(table).toContain("| supabase | failed | 0 | rpc exploded |");
    expect(table).toContain("| neo4j | not configured | 0 | not configured |");
  });

  it("warns when a configured source did not answer, even with healthy analyzers", () => {
    // Every analyzer ran, so without this the report would read as complete
    // while the knowledge base that should have informed it was down.
    const banner = assuranceBanner(ok, sourceDown);
    expect(banner).toBeDefined();
    expect(banner).toContain("knowledge base was not fully consulted");
    expect(banner).toContain("supabase (rpc exploded)");
    expect(banner).toContain("Prior audit knowledge");
  });

  it("stays silent when sources are merely unconfigured", () => {
    expect(assuranceBanner(ok, sourcesOk)).toBeUndefined();
  });

  it("reports analyzer and source problems together", () => {
    const banner = assuranceBanner(rpcFailed, sourceDown)!;
    expect(banner).toContain("1 of 4 analyzers");
    expect(banner).toContain("Knowledge sources unavailable: supabase");
  });
});

describe("missingAnalyzers", () => {
  it("names the expected analyzers that produced no report", () => {
    expect(missingAnalyzers(ok)).toEqual([]);
    expect(missingAnalyzers([{ analyzer: "heuristic", outcome: "ok" }])).toEqual([
      "onchain",
      "static",
      "cua",
    ]);
    expect(missingAnalyzers([])).toEqual([
      "onchain",
      "static",
      "heuristic",
      "cua",
    ]);
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

  it("lists analyzers that never reported instead of omitting them", () => {
    const table = analyzerStatusTable([{ analyzer: "heuristic", outcome: "ok" }]);
    expect(table).toContain("| heuristic | ran | — |");
    expect(table).toContain("| onchain | no result reported | coverage unknown |");
    expect(table).toContain("| cua | no result reported | coverage unknown |");
  });

  it("renders a full unknown-coverage table when nothing reported", () => {
    const table = analyzerStatusTable([]);
    for (const name of ["onchain", "static", "heuristic", "cua"]) {
      expect(table).toContain(`| ${name} | no result reported | coverage unknown |`);
    }
  });
});
