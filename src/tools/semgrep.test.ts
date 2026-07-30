import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runSemgrep } from "./semgrep.js";
import { makeAnalyzeStaticNode } from "../graph/nodes/analyze-static.js";
import type { AresState } from "../graph/state.js";

/**
 * Build a throwaway `semgrep` on PATH that behaves however the test needs, plus
 * a source dir to point the scan at. Hermetic — no real semgrep required.
 */
function shimSemgrep(script: string): { src: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "ares-semgrep-shim-"));
  const bin = join(dir, "bin");
  const src = join(dir, "src");
  mkdirSync(bin, { recursive: true });
  mkdirSync(src, { recursive: true });
  writeFileSync(join(src, "a.rs"), "fn main(){}\n");
  writeFileSync(join(bin, "semgrep"), script);
  chmodSync(join(bin, "semgrep"), 0o755);
  process.env.PATH = bin;
  // vitest.config.ts points SEMGREP_BIN at a name that does not exist so the
  // rest of the suite never spawns a real scanner; these tests want theirs.
  process.env.SEMGREP_BIN = "semgrep";
  return { src, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

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
    // the scanner. SEMGREP_BIN is set to a name that does not exist (see
    // vitest.config.ts), so this deterministically exercises the not-installed
    // path instead of depending on the host having semgrep.
    const dir = mkdtempSync(join(tmpdir(), "ares-semgrep-"));
    try {
      const res = await runSemgrep(dir);
      expect(res).toHaveProperty("available");
      expect(Array.isArray(res.findings)).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    // Generous deadline on purpose: where semgrep IS installed this spawns it for
    // real, and a cold start with rule parsing runs to several seconds. The 5s
    // default made this red on developer machines and green in hermetic CI.
  }, 20_000);
});

/**
 * A scan that did not complete produces the same empty findings array as a scan
 * that found nothing, and only the second one is evidence. These pin the
 * distinction end to end: `runSemgrep` must set a `reason`, and analyze-static
 * must turn that into a `failed` outcome so the report's assurance banner fires.
 */
describe("a scan that did not complete is not a clean result", () => {
  const realPath = process.env.PATH;
  const realBin = process.env.SEMGREP_BIN;
  afterEach(() => {
    process.env.PATH = realPath;
    if (realBin === undefined) delete process.env.SEMGREP_BIN;
    else process.env.SEMGREP_BIN = realBin;
  });

  it("reports scan-error when semgrep exits non-zero", async () => {
    // Exactly what a registry fetch with no egress looks like: noise on stderr,
    // nothing on stdout, non-zero exit.
    const { src, cleanup } = shimSemgrep(
      '#!/bin/sh\necho "[ERROR] failed to download config" >&2\nexit 2\n',
    );
    try {
      const res = await runSemgrep(src);
      expect(res.available).toBe(false);
      expect(res.reason).toBe("scan-error");
      expect(res.note).toMatch(/failed to download config/);
    } finally {
      cleanup();
    }
  }, 20_000);

  it("reports scan-error when semgrep exits 0 but reports rule errors", async () => {
    // A rule that fails to parse yields results:[] alongside errors:[...] on a
    // successful exit — the shape that silently read as "scanned, found nothing".
    const { src, cleanup } = shimSemgrep(
      '#!/bin/sh\necho \'{"results":[],"errors":[{"message":"Rule parse error in rule x"}]}\'\nexit 0\n',
    );
    try {
      const res = await runSemgrep(src);
      expect(res.available).toBe(false);
      expect(res.reason).toBe("scan-error");
      expect(res.note).toMatch(/Rule parse error/);
    } finally {
      cleanup();
    }
  }, 20_000);

  it("surfaces a failed scan as a failed analyzer, not 'ok'", async () => {
    const { src, cleanup } = shimSemgrep('#!/bin/sh\necho "boom" >&2\nexit 2\n');
    try {
      const update = await makeAnalyzeStaticNode()({ sourcePath: src } as AresState);
      expect(update.analyzers?.[0]?.outcome).toBe("failed");
      expect(update.findings).toEqual([]);
    } finally {
      cleanup();
    }
  }, 20_000);

  it("still reports success when semgrep genuinely finds nothing", async () => {
    const { src, cleanup } = shimSemgrep('#!/bin/sh\necho \'{"results":[],"errors":[]}\'\nexit 0\n');
    try {
      const update = await makeAnalyzeStaticNode()({ sourcePath: src } as AresState);
      expect(update.analyzers?.[0]?.outcome).toBe("ok");
    } finally {
      cleanup();
    }
  }, 20_000);
});

describe("scan-coverage regressions", () => {
  const realPath = process.env.PATH;

  afterEach(() => {
    process.env.PATH = realPath;
    // Restore the absent-binary default from vitest.config.ts so the rest of
    // the suite stays hermetic on hosts that do have semgrep.
    process.env.SEMGREP_BIN = "ares-semgrep-absent-in-tests";
  });

  it("treats a scan that opened no files as failed, never ok", async () => {
    // Semgrep applies .gitignore by default, so an audited repo that ignores its
    // own source path yielded scanned:0 with no error — which rendered as `ok`,
    // and `ok` means "silence here is evidence". That published a clean audit of
    // a program nobody scanned, and the audited party controls .gitignore.
    const { src, cleanup } = shimSemgrep(
      `#!/bin/sh\necho '{"results":[],"errors":[],"paths":{"scanned":[]}}'\n`,
    );
    try {
      const res = await runSemgrep(src);
      expect(res.available).toBe(false);
      expect(res.reason).toBe("no-files-scanned");

      const out = await makeAnalyzeStaticNode()({ sourcePath: src } as AresState);
      expect(out.analyzers?.[0]?.outcome).toBe("failed");
      expect(out.findings).toEqual([]);
    } finally {
      cleanup();
    }
  });

  it("keeps findings when a warn-level parse error accompanies a completed scan", async () => {
    // One warn-level PartialParsing on 1 of 173 real programs discarded all 110
    // findings from the other 172. Warnings degrade coverage; they do not void
    // the scan.
    const json = JSON.stringify({
      results: [
        {
          check_id: "rules.sysvar-spoofing",
          path: "a.rs",
          start: { line: 3 },
          extra: { message: "spoofable sysvar", severity: "ERROR" },
        },
      ],
      errors: [{ level: "warn", type: "PartialParsing", message: "could not parse b.rs" }],
      paths: { scanned: ["a.rs", "b.rs"] },
    });
    // `echo` is a shell builtin; the shim puts only its own dir on PATH, so an
    // external binary like `cat` would not resolve and the scan would look
    // empty for the wrong reason.
    const { src, cleanup } = shimSemgrep(`#!/bin/sh\necho '${json}'\n`);
    try {
      const res = await runSemgrep(src);
      expect(res.available).toBe(true);
      expect(res.findings).toHaveLength(1);
      expect(res.partial).toMatch(/coverage is incomplete/i);

      const out = await makeAnalyzeStaticNode()({ sourcePath: src } as AresState);
      // Findings survive, but the analyzer must not claim full coverage.
      expect(out.findings).toHaveLength(1);
      expect(out.analyzers?.[0]?.outcome).toBe("degraded");
    } finally {
      cleanup();
    }
  });

  it("still fails the scan on an error-level entry", async () => {
    const json = JSON.stringify({
      results: [],
      errors: [{ level: "error", type: "RuleParseError", message: "bad rule" }],
      paths: { scanned: ["a.rs"] },
    });
    const { src, cleanup } = shimSemgrep(`#!/bin/sh\necho '${json}'\n`);
    try {
      const res = await runSemgrep(src);
      expect(res.available).toBe(false);
      // Specifically scan-error, not the `unparseable` an empty stdout yields —
      // otherwise this passes on a shim that never printed anything.
      expect(res.reason).toBe("scan-error");
    } finally {
      cleanup();
    }
  });
});
