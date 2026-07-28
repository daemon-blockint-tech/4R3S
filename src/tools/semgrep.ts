/**
 * Semgrep static-analysis tool.
 *
 * Runs `semgrep --json` over a source path and normalizes the results. Semgrep
 * is an optional local binary: if it isn't installed, or no source path was
 * provided, the tool reports `available: false` and returns no findings rather
 * than failing the audit.
 */
import { spawn } from "node:child_process";
import { access } from "node:fs/promises";

import { env } from "../config/env.js";
import { logger } from "../config/logger.js";

/** Cap on buffered stdout. A scan producing more than this is not usable anyway. */
const MAX_OUTPUT_BYTES = 32 * 1024 * 1024;

export interface SemgrepFinding {
  ruleId: string;
  path: string;
  line: number;
  severity: string;
  message: string;
}

/**
 * Why Semgrep produced nothing. Machine-readable so callers can distinguish an
 * audit that legitimately had no source path from one where the scan could not
 * run — matching on the human-readable `note` would be fragile.
 */
export type SemgrepSkipReason =
  | "no-source"
  | "path-missing"
  | "not-installed"
  | "unparseable"
  | "spawn-error"
  /** Non-zero exit, or errors reported in Semgrep's own JSON `errors` array. */
  | "scan-error"
  /** Killed after exceeding its deadline. */
  | "scan-timeout";

export interface SemgrepResult {
  available: boolean;
  findings: SemgrepFinding[];
  note?: string;
  reason?: SemgrepSkipReason;
}

interface SemgrepJson {
  results: Array<{
    check_id: string;
    path: string;
    start: { line: number };
    extra: { message: string; severity: string };
  }>;
  /**
   * Rule-parse and target errors. Semgrep reports a scan that did not complete
   * here as well as via the exit code; ignoring it made a broken scan look
   * exactly like a clean one.
   */
  errors?: Array<{ message?: string; type?: string }>;
}

/**
 * Semgrep's success codes: 0 = ran, no findings; 1 = ran, findings present.
 * Anything else means the scan did not complete.
 */
function ranToCompletion(code: number | null): boolean {
  return code === 0 || code === 1;
}

/**
 * Decide what a finished Semgrep process actually told us.
 *
 * Extracted from the `close` handler so the failure paths are testable without
 * spawning anything: the defect this replaces was that *all* of them collapsed
 * to `{ available: true, findings: [] }`, which `analyze-static` reports as
 * `ok` — "silence here is evidence" — so a crashed scan rendered as a clean
 * audit with no assurance banner. Exit code, Semgrep's own `errors` array, and
 * stderr are all consulted now.
 */
export function classifyScan(
  code: number | null,
  raw: string,
  stderr = "",
): SemgrepResult {
  const detail = stderr.trim().slice(0, 400);

  if (!ranToCompletion(code)) {
    return {
      available: false,
      findings: [],
      note: `semgrep exited ${code ?? "null"}${detail ? `: ${detail}` : ""}`,
      reason: "scan-error",
    };
  }

  const body = raw.trim();
  if (!body) return { available: true, findings: [] };

  let parsed: SemgrepJson;
  try {
    parsed = JSON.parse(body) as SemgrepJson;
  } catch {
    return {
      available: true,
      findings: [],
      note: "unparseable output",
      reason: "unparseable",
    };
  }

  // Semgrep can exit 0 while reporting rule or target errors here.
  const errors = parsed.errors ?? [];
  if (errors.length > 0) {
    return {
      available: false,
      findings: [],
      note: `semgrep reported ${errors.length} scan error(s): ${
        errors[0]?.message ?? errors[0]?.type ?? "unknown"
      }`,
      reason: "scan-error",
    };
  }

  return {
    available: true,
    findings: (parsed.results ?? []).map((r) => ({
      ruleId: r.check_id,
      path: r.path,
      line: r.start?.line ?? 0,
      severity: r.extra?.severity ?? "INFO",
      message: r.extra?.message ?? "",
    })),
  };
}

/** Run Semgrep over `sourcePath`. Never throws. */
export async function runSemgrep(
  sourcePath: string | undefined,
  config = "auto",
): Promise<SemgrepResult> {
  if (!sourcePath) {
    return {
      available: false,
      findings: [],
      note: "no source path provided",
      reason: "no-source",
    };
  }
  try {
    await access(sourcePath);
  } catch {
    return {
      available: false,
      findings: [],
      note: `source path not found: ${sourcePath}`,
      reason: "path-missing",
    };
  }

  return new Promise<SemgrepResult>((resolve) => {
    const chunks: Buffer[] = [];
    const errChunks: Buffer[] = [];
    let bytes = 0;
    let overflowed = false;
    let settled = false;

    // The deadline and the close handler race each other; whichever lands first
    // wins and the timer is always cleared so the process can exit.
    const finish = (result: SemgrepResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    let child;
    try {
      child = spawn(
        "semgrep",
        ["--json", "--quiet", "--config", config, sourcePath],
        // stderr is piped, not ignored: it carries the reason a scan failed,
        // which is exactly the detail the report needs to stay honest.
        { stdio: ["ignore", "pipe", "pipe"] },
      );
    } catch {
      resolve({
        available: false,
        findings: [],
        note: "semgrep not installed",
        reason: "not-installed",
      });
      return;
    }

    // Without a deadline a wedged scan never settles, the parallel ANALYZE
    // superstep never fans in, and the audit hangs with no log line after
    // RECALL. Every other outbound call in this codebase is already bounded.
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      logger.warn(
        { component: "semgrep", timeoutMs: env.SEMGREP_TIMEOUT_MS },
        "Semgrep exceeded its deadline and was killed",
      );
      finish({
        available: false,
        findings: [],
        note: `semgrep exceeded ${env.SEMGREP_TIMEOUT_MS}ms and was killed`,
        reason: "scan-timeout",
      });
    }, env.SEMGREP_TIMEOUT_MS);
    timer.unref?.();

    child.on("error", (err: NodeJS.ErrnoException) => {
      const notInstalled = err.code === "ENOENT";
      const note = notInstalled ? "semgrep not installed" : String(err);
      logger.warn({ component: "semgrep", note }, "Semgrep unavailable");
      finish({
        available: false,
        findings: [],
        note,
        reason: notInstalled ? "not-installed" : "spawn-error",
      });
    });

    child.stdout.on("data", (d: Buffer) => {
      bytes += d.length;
      if (bytes > MAX_OUTPUT_BYTES) {
        overflowed = true;
        child.kill("SIGKILL");
        return;
      }
      chunks.push(d);
    });
    child.stderr.on("data", (d: Buffer) => {
      if (errChunks.length < 32) errChunks.push(d);
    });

    child.on("close", (code: number | null) => {
      if (overflowed) {
        finish({
          available: false,
          findings: [],
          note: `semgrep output exceeded ${MAX_OUTPUT_BYTES} bytes`,
          reason: "scan-error",
        });
        return;
      }

      const stderr = Buffer.concat(errChunks).toString("utf8");
      const result = classifyScan(
        code,
        Buffer.concat(chunks).toString("utf8"),
        stderr,
      );
      if (result.reason) {
        logger.warn(
          { component: "semgrep", code, reason: result.reason, note: result.note },
          "Semgrep scan did not complete cleanly",
        );
      }
      finish(result);
    });
  });
}
