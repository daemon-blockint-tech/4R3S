import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runSemgrep, classifyScan } from "./semgrep.js";

describe("runSemgrep", () => {
  it("reports unavailable when no source path is given", async () => {
    const res = await runSemgrep(undefined);
    expect(res.available).toBe(false);
    expect(res.findings).toEqual([]);
    expect(res.note).toMatch(/no source path/i);
  });

  it("reports unavailable when the source path does not exist", async () => {
    const res = await runSemgrep("/definitely/not/here/xyz");
    expect(res.available).toBe(false);
    expect(res.note).toMatch(/not found/i);
  });

  // Removed: a test that ran `runSemgrep(dir)` with the default `--config auto`.
  // It asserted only that the result had an `available` property — true whether
  // Semgrep worked, was missing, or crashed — and on a machine that has Semgrep
  // installed it shelled out for real and fetched its ruleset from the registry,
  // which exceeded 60s here. That non-determinism is itself a finding (the
  // "deterministic, no LLM" static analyzer depends on a network fetch at scan
  // time); a test suite documented as hermetic must not depend on it. The case
  // below covers the same ground deterministically.

  it("reports a scan that could not run as unavailable, not as clean", async () => {
    // A config path that does not exist makes a real semgrep exit non-zero
    // immediately (no network needed). Where semgrep is absent we get
    // `not-installed`. Both are failures; what must never happen is
    // `available: true` with no reason, which reads downstream as a clean scan.
    const dir = mkdtempSync(join(tmpdir(), "ares-semgrep-bad-"));
    try {
      const res = await runSemgrep(dir, "/nonexistent/ruleset/xyz.yml");
      expect(res.available).toBe(false);
      expect(res.reason).toBeDefined();
      expect(["scan-error", "not-installed", "spawn-error"]).toContain(res.reason);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);
});

/**
 * The regression this block exists for: every failure case below used to
 * collapse to `{ available: true, findings: [] }`, which `analyze-static`
 * reports as `ok` — defined in state.ts as "ran against real input; silence
 * here is evidence". A crashed scan therefore rendered as a clean audit with no
 * assurance banner.
 */
describe("classifyScan", () => {
  const hit = JSON.stringify({
    results: [
      {
        check_id: "rust.lang.security.foo",
        path: "src/lib.rs",
        start: { line: 42 },
        extra: { message: "bad", severity: "ERROR" },
      },
    ],
  });

  it("treats exit 0 with no findings as a genuine clean scan", () => {
    const res = classifyScan(0, JSON.stringify({ results: [] }));
    expect(res).toEqual({ available: true, findings: [] });
    expect(res.reason).toBeUndefined();
  });

  it("treats exit 1 with findings as success (semgrep signals hits with 1)", () => {
    const res = classifyScan(1, hit);
    expect(res.available).toBe(true);
    expect(res.reason).toBeUndefined();
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0]).toMatchObject({ path: "src/lib.rs", line: 42 });
  });

  it("treats a non-zero exit as a failed scan, not a clean one", () => {
    const res = classifyScan(2, "", "invalid rule syntax");
    expect(res.available).toBe(false);
    expect(res.reason).toBe("scan-error");
    expect(res.note).toContain("invalid rule syntax");
  });

  it("treats an empty stdout with a bad exit code as a failed scan", () => {
    // The exact original defect: empty output resolved as available+clean.
    const res = classifyScan(7, "");
    expect(res.available).toBe(false);
    expect(res.reason).toBe("scan-error");
  });

  it("treats a killed process (null exit code) as a failed scan", () => {
    const res = classifyScan(null, "");
    expect(res.available).toBe(false);
    expect(res.reason).toBe("scan-error");
  });

  it("honours semgrep's `errors` array even when it exits 0", () => {
    const res = classifyScan(
      0,
      JSON.stringify({ results: [], errors: [{ message: "rule failed to parse" }] }),
    );
    expect(res.available).toBe(false);
    expect(res.reason).toBe("scan-error");
    expect(res.note).toContain("rule failed to parse");
  });

  it("does not fail a scan for an empty errors array", () => {
    const res = classifyScan(0, JSON.stringify({ results: [], errors: [] }));
    expect(res.available).toBe(true);
    expect(res.reason).toBeUndefined();
  });

  it("still reports unparseable output as unparseable", () => {
    const res = classifyScan(0, "not json at all");
    expect(res.reason).toBe("unparseable");
  });

  it("keeps a truly empty stdout on a success exit as clean", () => {
    expect(classifyScan(0, "   ")).toEqual({ available: true, findings: [] });
  });
});
