import { describe, it, expect, afterEach, vi } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventEmitter } from "node:events";

/**
 * The previous version of this file faked `semgrep` as a real, spawnable
 * file on PATH — a POSIX shell script, chmod +x'd. That can never work on
 * Windows: there's no shebang support, and creating a genuinely
 * OS-launchable stand-in without shell:true turns out to be a real,
 * inherent limitation there (a .cmd/.bat file needs cmd.exe as an
 * interpreter, which spawn() without shell:true cannot invoke — confirmed
 * directly, the same finding as BIZ-1's npm.cmd issue).
 *
 * Mocking `spawn` itself at the module level sidesteps the OS entirely —
 * `runSemgrep` never actually launches a real process in these tests, on
 * any platform, so there's no OS-level executable-format question to
 * solve at all. `mockSpawnBehavior` is configured per test via
 * `vi.hoisted()`, which is vitest's supported way to share mutable state
 * with a hoisted `vi.mock()` factory.
 */
const { mockSpawnBehavior, setMockSpawnBehavior } = vi.hoisted(() => {
  let behavior: {
    stdout?: string;
    stderr?: string;
    exitCode: number | null;
    spawnError?: NodeJS.ErrnoException;
  } | null = null;
  return {
    mockSpawnBehavior: () => behavior,
    setMockSpawnBehavior: (b: typeof behavior) => {
      behavior = b;
    },
  };
});

vi.mock("node:child_process", () => ({
  spawn: () => {
    const child = new EventEmitter() as EventEmitter & {
      stdout: EventEmitter;
      stderr: EventEmitter;
      kill: (signal?: string) => void;
    };
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = () => {};

    const behavior = mockSpawnBehavior();
    // Defer to a later tick — production code attaches its .on() listeners
    // immediately after calling spawn(); emitting synchronously here would
    // fire before those listeners exist and be silently missed, same as a
    // real child process never emits synchronously either.
    queueMicrotask(() => {
      if (!behavior) {
        // Default: simulate semgrep genuinely not being on PATH, the same
        // ENOENT-shaped error a real missing binary produces.
        const err = new Error("spawn semgrep ENOENT") as NodeJS.ErrnoException;
        err.code = "ENOENT";
        child.emit("error", err);
        return;
      }
      if (behavior.spawnError) {
        child.emit("error", behavior.spawnError);
        return;
      }
      if (behavior.stdout) child.stdout.emit("data", Buffer.from(behavior.stdout));
      if (behavior.stderr) child.stderr.emit("data", Buffer.from(behavior.stderr));
      child.emit("close", behavior.exitCode);
    });

    return child;
  },
}));

import { runSemgrep } from "./semgrep.js";
import { makeAnalyzeStaticNode } from "../graph/nodes/analyze-static.js";
import type { AresState } from "../graph/state.js";

/** A real directory to point the scan at — runSemgrep's own access() check
 * still needs a genuinely existing path before it ever reaches spawn(). */
function realSourceDir(): { src: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "ares-semgrep-shim-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "src", "a.rs"), "fn main(){}\n");
  return { src: dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

describe("runSemgrep", () => {
  afterEach(() => setMockSpawnBehavior(null));

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
    // No behavior configured — the mock's default simulates ENOENT, the
    // same as a real host without semgrep installed.
    const { src, cleanup } = realSourceDir();
    try {
      const res = await runSemgrep(src);
      expect(res).toHaveProperty("available");
      expect(Array.isArray(res.findings)).toBe(true);
    } finally {
      cleanup();
    }
  });
});

/**
 * A scan that did not complete produces the same empty findings array as a scan
 * that found nothing, and only the second one is evidence. These pin the
 * distinction end to end: `runSemgrep` must set a `reason`, and analyze-static
 * must turn that into a `failed` outcome so the report's assurance banner fires.
 */
describe("a scan that did not complete is not a clean result", () => {
  afterEach(() => setMockSpawnBehavior(null));

  it("reports scan-error when semgrep exits non-zero", async () => {
    // Exactly what a registry fetch with no egress looks like: noise on stderr,
    // nothing on stdout, non-zero exit.
    setMockSpawnBehavior({ stderr: "[ERROR] failed to download config\n", exitCode: 2 });
    const { src, cleanup } = realSourceDir();
    try {
      const res = await runSemgrep(src);
      expect(res.available).toBe(false);
      expect(res.reason).toBe("scan-error");
      expect(res.note).toMatch(/failed to download config/);
    } finally {
      cleanup();
    }
  });

  it("reports scan-error when semgrep exits 0 but reports rule errors", async () => {
    // A rule that fails to parse yields results:[] alongside errors:[...] on a
    // successful exit — the shape that silently read as "scanned, found nothing".
    setMockSpawnBehavior({
      stdout: '{"results":[],"errors":[{"message":"Rule parse error in rule x"}]}\n',
      exitCode: 0,
    });
    const { src, cleanup } = realSourceDir();
    try {
      const res = await runSemgrep(src);
      expect(res.available).toBe(false);
      expect(res.reason).toBe("scan-error");
      expect(res.note).toMatch(/Rule parse error/);
    } finally {
      cleanup();
    }
  });

  it("surfaces a failed scan as a failed analyzer, not 'ok'", async () => {
    setMockSpawnBehavior({ stderr: "boom\n", exitCode: 2 });
    const { src, cleanup } = realSourceDir();
    try {
      const update = await makeAnalyzeStaticNode()({ sourcePath: src } as AresState);
      expect(update.analyzers?.[0]?.outcome).toBe("failed");
      expect(update.findings).toEqual([]);
    } finally {
      cleanup();
    }
  });

  it("still reports success when semgrep genuinely finds nothing", async () => {
    setMockSpawnBehavior({ stdout: '{"results":[],"errors":[]}\n', exitCode: 0 });
    const { src, cleanup } = realSourceDir();
    try {
      const update = await makeAnalyzeStaticNode()({ sourcePath: src } as AresState);
      expect(update.analyzers?.[0]?.outcome).toBe("ok");
    } finally {
      cleanup();
    }
  });
});

describe("scan-coverage regressions", () => {
  afterEach(() => setMockSpawnBehavior(null));

  it("treats a scan that opened no files as failed, never ok", async () => {
    // Semgrep applies .gitignore by default, so an audited repo that ignores its
    // own source path yielded scanned:0 with no error — which rendered as `ok`,
    // and `ok` means "silence here is evidence". That published a clean audit of
    // a program nobody scanned, and the audited party controls .gitignore.
    setMockSpawnBehavior({
      stdout: '{"results":[],"errors":[],"paths":{"scanned":[]}}\n',
      exitCode: 0,
    });
    const { src, cleanup } = realSourceDir();
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
    setMockSpawnBehavior({ stdout: `${json}\n`, exitCode: 0 });
    const { src, cleanup } = realSourceDir();
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
    setMockSpawnBehavior({ stdout: `${json}\n`, exitCode: 0 });
    const { src, cleanup } = realSourceDir();
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
