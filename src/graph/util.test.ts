import { describe, it, expect } from "vitest";

import { coerceFindings, messageText } from "./util.js";

describe("coerceFindings", () => {
  it("normalizes valid findings and forces the source", () => {
    const raw = [
      {
        vulnClass: "arithmetic-overflow",
        location: "ix:1",
        severity: "HIGH",
        evidence: "e",
        remediation: "r",
      },
    ];
    const out = coerceFindings(raw, "onchain");
    expect(out).toHaveLength(1);
    expect(out[0]!.source).toBe("onchain");
    expect(out[0]!.severity).toBe("high");
    expect(out[0]!.vulnClass).toBe("arithmetic-overflow");
  });

  it("defaults invalid severity to info and fills missing fields", () => {
    const out = coerceFindings([{ vulnClass: "x", severity: "bogus" }], "heuristic");
    expect(out[0]!.severity).toBe("info");
    expect(out[0]!.location).toBe("");
    expect(out[0]!.remediation).toBe("");
  });

  it("returns [] for non-array / malformed input", () => {
    expect(coerceFindings(null, "static")).toEqual([]);
    expect(coerceFindings("nope", "static")).toEqual([]);
    expect(coerceFindings([null, 3, "x"], "static")).toEqual([]);
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
