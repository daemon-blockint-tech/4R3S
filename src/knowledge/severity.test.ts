import { describe, it, expect } from "vitest";

import {
  severityFromMatrix,
  severityDistribution,
  severitySummaryTable,
  formatFindingId,
  formatSeverityMethodology,
  SEVERITY_ORDER,
  SEVERITY_DEFINITIONS,
} from "./severity.js";
import type { Finding, Severity } from "../graph/state.js";

describe("severityFromMatrix", () => {
  it("maps the corners of the impact × likelihood matrix", () => {
    expect(severityFromMatrix("high", "high")).toBe("critical");
    expect(severityFromMatrix("low", "low")).toBe("info");
    expect(severityFromMatrix("high", "low")).toBe("medium");
    expect(severityFromMatrix("low", "high")).toBe("medium");
  });

  it("only high impact + high likelihood is critical", () => {
    const impacts = ["high", "medium", "low"] as const;
    const likelihoods = ["high", "medium", "low"] as const;
    const criticals = impacts.flatMap((i) =>
      likelihoods.filter((l) => severityFromMatrix(i, l) === "critical").map((l) => [i, l]),
    );
    expect(criticals).toEqual([["high", "high"]]);
  });

  it("never returns an out-of-scale value", () => {
    const valid = new Set<Severity>(SEVERITY_ORDER);
    for (const i of ["high", "medium", "low"] as const) {
      for (const l of ["high", "medium", "low"] as const) {
        expect(valid.has(severityFromMatrix(i, l))).toBe(true);
      }
    }
  });
});

describe("SEVERITY_ORDER", () => {
  it("is ordered most-severe first and covers every level", () => {
    expect(SEVERITY_ORDER).toEqual(["critical", "high", "medium", "low", "info"]);
    for (const s of SEVERITY_ORDER) {
      expect(SEVERITY_DEFINITIONS[s]).toBeTruthy();
    }
  });
});

function f(severity: Severity): Finding {
  return {
    vulnClass: "x",
    location: "ix:1",
    severity,
    evidence: "e",
    remediation: "r",
    source: "heuristic",
    category: "other",
    speculative: false,
    confidence: "medium",
  };
}

describe("severityDistribution", () => {
  it("counts each severity, zero-filling absent levels", () => {
    const dist = severityDistribution([f("high"), f("high"), f("low")]);
    expect(dist).toEqual({ critical: 0, high: 2, medium: 0, low: 1, info: 0 });
  });

  it("returns all-zero for no findings", () => {
    expect(severityDistribution([])).toEqual({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    });
  });
});

describe("severitySummaryTable", () => {
  it("renders a markdown table whose total matches the counts", () => {
    const dist = severityDistribution([f("critical"), f("high"), f("high")]);
    const table = severitySummaryTable(dist);
    expect(table).toContain("| Severity | Count |");
    expect(table).toContain("| Critical | 1 |");
    expect(table).toContain("| High | 2 |");
    expect(table).toContain("| **Total** | **3** |");
  });
});

describe("formatFindingId", () => {
  it("produces stable, zero-padded, 1-based ids", () => {
    expect(formatFindingId(0)).toBe("ARES-001");
    expect(formatFindingId(9)).toBe("ARES-010");
    expect(formatFindingId(122)).toBe("ARES-123");
  });

  it("honors a custom prefix", () => {
    expect(formatFindingId(0, "SEC")).toBe("SEC-001");
  });
});

describe("formatSeverityMethodology", () => {
  it("mentions impact, likelihood, and every severity level", () => {
    const text = formatSeverityMethodology().toLowerCase();
    expect(text).toContain("impact");
    expect(text).toContain("likelihood");
    for (const s of SEVERITY_ORDER) {
      expect(text).toContain(s);
    }
  });
});
