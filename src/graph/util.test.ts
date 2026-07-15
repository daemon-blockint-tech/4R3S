import { describe, it, expect } from "vitest";

import { coerceFindings, extractChecked, downgradeSpeculative, messageText } from "./util.js";

describe("coerceFindings", () => {
  it("normalizes valid findings and forces the source", () => {
    const raw = [
      {
        vulnClass: "arithmetic-overflow",
        location: "ix:1",
        severity: "HIGH",
        evidence: "e",
        remediation: "r",
        category: "integer-overflow-underflow",
        speculative: true,
        confidence: "low",
      },
    ];
    const out = coerceFindings(raw, "onchain");
    expect(out).toHaveLength(1);
    expect(out[0]!.source).toBe("onchain");
    expect(out[0]!.severity).toBe("high");
    expect(out[0]!.vulnClass).toBe("arithmetic-overflow");
    expect(out[0]!.category).toBe("integer-overflow-underflow");
    expect(out[0]!.speculative).toBe(true);
    expect(out[0]!.confidence).toBe("low");
  });

  it("defaults invalid severity to info and fills missing fields", () => {
    const out = coerceFindings([{ vulnClass: "x", severity: "bogus" }], "heuristic");
    expect(out[0]!.severity).toBe("info");
    expect(out[0]!.location).toBe("");
    expect(out[0]!.remediation).toBe("");
    expect(out[0]!.category).toBe("other");
    expect(out[0]!.speculative).toBe(false);
    expect(out[0]!.confidence).toBe("medium");
  });

  it("accepts object-with-findings form and coerces category", () => {
    const raw = {
      findings: [
        {
          vulnClass: "missing signer",
          location: "ix:withdraw",
          severity: "high",
          evidence: "no is_signer check",
          remediation: "add Signer constraint",
          category: "missing-signer-check",
          speculative: false,
          confidence: "high",
        },
      ],
      checked: ["missing-signer-check", "bogus-id", "integer-overflow-underflow"],
    };
    const out = coerceFindings(raw, "heuristic");
    expect(out).toHaveLength(1);
    expect(out[0]!.category).toBe("missing-signer-check");
    expect(out[0]!.vulnClass).toBe("missing signer");
    expect(out[0]!.confidence).toBe("high");
  });

  it("defaults invalid category to other", () => {
    const raw = {
      findings: [
        {
          vulnClass: "weird-bug",
          location: "ix:1",
          severity: "low",
          evidence: "e",
          remediation: "r",
          category: "nonexistent-vuln-id",
        },
      ],
      checked: [],
    };
    const out = coerceFindings(raw, "static");
    expect(out).toHaveLength(1);
    expect(out[0]!.category).toBe("other");
  });

  it("downgradeSpeculative tags findings as speculative with low confidence and info severity", () => {
    const findings = coerceFindings(
      [{ vulnClass: "x", severity: "high", category: "missing-signer-check" }],
      "heuristic",
    );
    const downgraded = downgradeSpeculative(findings);
    expect(downgraded[0]!.speculative).toBe(true);
    expect(downgraded[0]!.confidence).toBe("low");
    expect(downgraded[0]!.severity).toBe("info");
  });

  it("returns [] for non-array / malformed input", () => {
    expect(coerceFindings(null, "static")).toEqual([]);
    expect(coerceFindings("nope", "static")).toEqual([]);
    expect(coerceFindings([null, 3, "x"], "static")).toEqual([]);
  });
});

describe("extractChecked", () => {
  it("filters to valid catalog ids", () => {
    const raw = {
      findings: [],
      checked: ["missing-signer-check", "bogus-id", "integer-overflow-underflow", 42, null],
    };
    const out = extractChecked(raw);
    expect(out).toEqual(["missing-signer-check", "integer-overflow-underflow"]);
  });

  it("returns [] when no checked field", () => {
    expect(extractChecked({ findings: [] })).toEqual([]);
    expect(extractChecked(null)).toEqual([]);
    expect(extractChecked("nope")).toEqual([]);
  });
});

describe("messageText", () => {
  it("passes strings through", () => {
    expect(messageText("hello")).toBe("hello");
  });
  it("joins array content parts", () => {
    expect(messageText([{ text: "a" }, "b", { text: "c" }])).toBe("abc");
  });
});
