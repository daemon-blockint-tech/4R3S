import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, it, expect } from "vitest";

import {
  VULN_CATALOG,
  VULN_IDS,
  getVuln,
  isVulnId,
  formatChecklistForPrompt,
} from "./solana-vulns.js";
import { SEVERITY_RANK } from "./finding.js";

const VALID_SEVERITIES = new Set(Object.keys(SEVERITY_RANK));

describe("VULN_CATALOG integrity", () => {
  it("has unique ids", () => {
    const ids = VULN_CATALOG.map((v) => v.id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });

  it("every entry has non-empty required fields", () => {
    for (const entry of VULN_CATALOG) {
      expect(entry.id).toBeTruthy();
      expect(entry.title).toBeTruthy();
      expect(entry.category).toBeTruthy();
      expect(entry.description).toBeTruthy();
      expect(entry.detectionHints).toBeTruthy();
      expect(entry.remediation).toBeTruthy();
      expect(entry.references.length).toBeGreaterThanOrEqual(0);
    }
  });

  it("every defaultSeverity is a valid Severity", () => {
    for (const entry of VULN_CATALOG) {
      expect(VALID_SEVERITIES.has(entry.defaultSeverity)).toBe(true);
    }
  });

  it("VULN_IDS matches catalog ids", () => {
    expect(VULN_IDS.size).toBe(VULN_CATALOG.length);
    for (const entry of VULN_CATALOG) {
      expect(VULN_IDS.has(entry.id)).toBe(true);
    }
  });

  it("has at least 20 entries", () => {
    expect(VULN_CATALOG.length).toBeGreaterThanOrEqual(20);
  });
});

describe("getVuln", () => {
  it("returns the entry for a valid id", () => {
    const entry = getVuln("integer-overflow-underflow");
    expect(entry).toBeDefined();
    expect(entry!.id).toBe("integer-overflow-underflow");
  });

  it("returns undefined for an invalid id", () => {
    expect(getVuln("nonexistent-vuln")).toBeUndefined();
  });
});

describe("isVulnId", () => {
  it("returns true for valid ids", () => {
    expect(isVulnId("missing-signer-check")).toBe(true);
    expect(isVulnId("arbitrary-cpi")).toBe(true);
  });

  it("returns false for invalid ids", () => {
    expect(isVulnId("nope")).toBe(false);
    expect(isVulnId("")).toBe(false);
  });
});

describe("formatChecklistForPrompt", () => {
  it("contains every catalog id", () => {
    const checklist = formatChecklistForPrompt();
    for (const entry of VULN_CATALOG) {
      expect(checklist).toContain(entry.id);
    }
  });

  it("is a numbered list", () => {
    const checklist = formatChecklistForPrompt();
    const lines = checklist.split("\n");
    expect(lines.length).toBe(VULN_CATALOG.length);
    expect(lines[0]).toMatch(/^1\./);
  });
});

describe("rules/solana.yml ↔ catalog contract", () => {
  // The Semgrep ruleset names every rule after a catalog id so analyze-static's
  // mapCategory hits the exact-match branch; a typo'd id silently falls through
  // to the fuzzy fallback and mislabels the finding's class. This enforces the
  // invariant the ruleset header only asserts in a comment.
  const rulesetPath = fileURLToPath(
    new URL("../../rules/solana.yml", import.meta.url),
  );
  const ruleIds = [
    ...readFileSync(rulesetPath, "utf8").matchAll(/^\s*-\s*id:\s*(\S+)\s*$/gm),
  ].map((m) => m[1]);

  it("parsed at least the committed rules", () => {
    // Guards against a broken path or regex passing vacuously — the failure the
    // ruleset itself was written to prevent.
    expect(ruleIds).toContain("unsafe-type-cast");
    expect(ruleIds.length).toBeGreaterThanOrEqual(7);
  });

  it("every rule id is a catalog id", () => {
    for (const id of ruleIds) {
      expect(isVulnId(id), `rule "${id}" is not a VULN_CATALOG id`).toBe(true);
    }
  });
});
