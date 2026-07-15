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

import { logger } from "../config/logger.js";

export interface SemgrepFinding {
  ruleId: string;
  path: string;
  line: number;
  severity: string;
  message: string;
}

export interface SemgrepResult {
  available: boolean;
  findings: SemgrepFinding[];
  note?: string;
}

interface SemgrepJson {
  results: Array<{
    check_id: string;
    path: string;
    start: { line: number };
    extra: { message: string; severity: string };
  }>;
}

/** Run Semgrep over `sourcePath`. Never throws. */
export async function runSemgrep(
  sourcePath: string | undefined,
  config = "auto",
): Promise<SemgrepResult> {
  if (!sourcePath) {
    return { available: false, findings: [], note: "no source path provided" };
  }
  try {
    await access(sourcePath);
  } catch {
    return {
      available: false,
      findings: [],
      note: `source path not found: ${sourcePath}`,
    };
  }

  return new Promise<SemgrepResult>((resolve) => {
    const chunks: Buffer[] = [];
    let child;
    try {
      child = spawn(
        "semgrep",
        ["--json", "--quiet", "--config", config, sourcePath],
        { stdio: ["ignore", "pipe", "ignore"] },
      );
    } catch {
      resolve({ available: false, findings: [], note: "semgrep not installed" });
      return;
    }

    child.on("error", (err: NodeJS.ErrnoException) => {
      const note =
        err.code === "ENOENT" ? "semgrep not installed" : String(err);
      logger.warn({ component: "semgrep", note }, "Semgrep unavailable");
      resolve({ available: false, findings: [], note });
    });

    child.stdout.on("data", (d: Buffer) => chunks.push(d));

    child.on("close", () => {
      const raw = Buffer.concat(chunks).toString("utf8").trim();
      if (!raw) {
        resolve({ available: true, findings: [] });
        return;
      }
      try {
        const parsed = JSON.parse(raw) as SemgrepJson;
        const findings = (parsed.results ?? []).map((r) => ({
          ruleId: r.check_id,
          path: r.path,
          line: r.start?.line ?? 0,
          severity: r.extra?.severity ?? "INFO",
          message: r.extra?.message ?? "",
        }));
        resolve({ available: true, findings });
      } catch (err) {
        logger.warn(
          { component: "semgrep", err: String(err) },
          "Failed to parse Semgrep output",
        );
        resolve({ available: true, findings: [], note: "unparseable output" });
      }
    });
  });
}
