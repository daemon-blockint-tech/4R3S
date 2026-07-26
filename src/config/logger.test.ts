import { describe, it, expect, vi, afterEach } from "vitest";

import { logger } from "./logger.js";

function capture(run: () => void): { out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  const so = vi.spyOn(process.stdout, "write").mockImplementation((c) => {
    out.push(String(c));
    return true;
  });
  const se = vi.spyOn(process.stderr, "write").mockImplementation((c) => {
    err.push(String(c));
    return true;
  });
  try {
    run();
  } finally {
    so.mockRestore();
    se.mockRestore();
  }
  return { out, err };
}

afterEach(() => vi.restoreAllMocks());

describe("logger stream discipline", () => {
  it("writes every level to stderr and nothing to stdout", () => {
    // stdout carries the audit report; a log line there corrupts a piped report.
    const { out, err } = capture(() => {
      logger.error("boom");
      logger.warn("careful");
      logger.info("progress");
    });

    expect(out).toEqual([]);
    // ARES_LOG_LEVEL is "error" under vitest, so only the error line is emitted.
    expect(err.length).toBeGreaterThanOrEqual(1);
    expect(err.join("")).toContain("boom");
  });

  it("emits one JSON line per record, with level, message and metadata", () => {
    const { err } = capture(() => {
      logger.error({ component: "test", findings: 3 }, "audit complete");
    });

    const parsed = JSON.parse(err[0]!.trim());
    expect(parsed.level).toBe("error");
    expect(parsed.msg).toBe("audit complete");
    expect(parsed.component).toBe("test");
    expect(parsed.findings).toBe(3);
    expect(typeof parsed.t).toBe("string");
    expect(err[0]!.endsWith("\n")).toBe(true);
  });

  it("accepts the message-first call style too", () => {
    const { err } = capture(() => {
      logger.error("message first", { component: "test" });
    });
    const parsed = JSON.parse(err[0]!.trim());
    expect(parsed.msg).toBe("message first");
    expect(parsed.component).toBe("test");
  });
});
