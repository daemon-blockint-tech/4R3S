import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runSemgrep } from "./semgrep.js";

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

  it("degrades gracefully when semgrep is not installed on a real path", async () => {
    // The path exists, so it gets past the access() check and tries to spawn
    // semgrep. In CI/hermetic envs semgrep isn't installed → available:false,
    // never a throw. If it happens to be installed, we still get a valid shape.
    const dir = mkdtempSync(join(tmpdir(), "ares-semgrep-"));
    try {
      const res = await runSemgrep(dir);
      expect(res).toHaveProperty("available");
      expect(Array.isArray(res.findings)).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
