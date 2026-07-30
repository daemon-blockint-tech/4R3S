/**
 * Semgrep static-analysis tool.
 *
 * Runs `semgrep --json` over a source path and normalizes the results. Semgrep
 * is an optional local binary: if it isn't installed, or no source path was
 * provided, the tool reports `available: false` and returns no findings rather
 * than failing the audit.
 *
 * The distinction this module exists to preserve is between "scanned, found
 * nothing" and "never scanned". Those produce the same empty findings array, and
 * only the first one means anything. Every path that did not complete a scan
 * therefore sets a machine-readable `reason`, which analyze-static maps onto a
 * `failed`/`degraded` analyzer outcome so the report can say so.
 */
import { spawn } from "node:child_process";
import { access } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { env } from "../config/env.js";
import { logger } from "../config/logger.js";

/**
 * The committed ruleset, resolved relative to this module so it works from
 * `src/` under tsx and from `dist/` after a build (both are one directory deep).
 * Pinned rather than `--config auto`, which fetches from the Semgrep registry
 * over the network on every scan.
 */
const DEFAULT_CONFIG = fileURLToPath(new URL("../../rules/solana.yml", import.meta.url));

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
  /** Non-zero exit, or an error-level entry in the JSON `errors` array. */
  | "scan-error"
  /** Killed after SEMGREP_TIMEOUT_MS. */
  | "scan-timeout"
  /** The scan ran but covered no files, so its silence says nothing. */
  | "no-files-scanned";

export interface SemgrepResult {
  available: boolean;
  findings: SemgrepFinding[];
  note?: string;
  reason?: SemgrepSkipReason;
  /**
   * Set when the scan completed and its findings are usable, but coverage was
   * incomplete — currently a warn-level parse failure on some files. Distinct
   * from `reason`: the findings are real and must still be reported, while the
   * analyzer degrades so the report says coverage was partial.
   */
  partial?: string;
}

interface SemgrepJson {
  results: Array<{
    check_id: string;
    path: string;
    start: { line: number };
    extra: { message: string; severity: string };
  }>;
  /**
   * Rule-parse and target errors. `level` matters: semgrep emits warn-level
   * entries (e.g. PartialParsing on one file) alongside a scan that otherwise
   * completed and found real issues.
   */
  errors?: Array<{ message?: string; type?: unknown; level?: string }>;
  /** Files semgrep actually opened. Empty means it inspected nothing. */
  paths?: { scanned?: string[] };
}

/**
 * Semgrep's success codes: 0 = ran, no findings; 1 = ran, findings present.
 * Anything else means the scan did not complete.
 */
function ranToCompletion(code: number | null): boolean {
  return code === 0 || code === 1;
}

/** Run Semgrep over `sourcePath`. Never throws. */
export async function runSemgrep(
  sourcePath: string | undefined,
  config = DEFAULT_CONFIG,
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
    let settled = false;
    /** Resolve once — the deadline and the close handler race each other. */
    const finish = (result: SemgrepResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    // Read at call time, not from the frozen `env` snapshot, so a test can make
    // the binary deterministically absent. The suite must not depend on whether
    // semgrep happens to be installed on the machine running it: with a real one
    // present, several test files spawn it in parallel and contend for seconds.
    const bin = process.env.SEMGREP_BIN ?? "semgrep";
    let child;
    try {
      child = spawn(
        bin,
        [
          "--json",
          "--quiet",
          // Rules come from a committed file, so there is no reason to phone
          // home; SECURITY.md promises no outbound calls in the offline config.
          "--metrics=off",
          // Semgrep applies .gitignore semantics by default, so a target whose
          // source path the audited repository ignores is silently skipped: the
          // scan examines zero files and reports no findings, which this
          // analyzer used to render as `ok` — a clean audit of code nobody
          // scanned. The audited party controls that file.
          "--no-git-ignore",
          "--config",
          config,
          sourcePath,
        ],
        // stderr is piped, not ignored: it carries the reason a scan failed,
        // which is the detail the report needs in order to be honest.
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

    // Without this a hung scan never settles, the parallel ANALYZE superstep
    // never fans in, and the audit hangs with no log line after RECALL.
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

    child.stdout.on("data", (d: Buffer) => chunks.push(d));
    child.stderr?.on("data", (d: Buffer) => errChunks.push(d));

    child.on("close", (code: number | null) => {
      const raw = Buffer.concat(chunks).toString("utf8").trim();
      const stderr = Buffer.concat(errChunks).toString("utf8").trim();
      /** First line of stderr — enough to say why, short enough for a table. */
      const detail = stderr.split("\n").find((l) => l.trim())?.slice(0, 200);

      // A scan that did not run to completion produced no findings *because it
      // did not look*. Reporting that as an empty-but-successful result is what
      // let a broken scanner render as a clean audit.
      if (!ranToCompletion(code)) {
        logger.warn(
          { component: "semgrep", code, detail },
          "Semgrep exited non-zero; static analysis did not complete",
        );
        finish({
          available: false,
          findings: [],
          note: `semgrep exited ${code}${detail ? `: ${detail}` : ""}`,
          reason: "scan-error",
        });
        return;
      }

      if (!raw) {
        logger.warn(
          { component: "semgrep", code, detail },
          "Semgrep exited cleanly but produced no output",
        );
        finish({
          available: false,
          findings: [],
          note: "semgrep produced no output",
          reason: "unparseable",
        });
        return;
      }

      try {
        const parsed = JSON.parse(raw) as SemgrepJson;

        // A rule that failed to parse yields `results: []` alongside a populated
        // `errors[]`. Silently dropping that reports "scanned, found nothing"
        // for rules that never ran.
        //
        // Level is load-bearing. Treating every entry as fatal discards a whole
        // scan over one warn-level PartialParsing on one file: measured against
        // 173 real programs, a single warn threw away all 110 findings from the
        // other 172. Only error-level entries mean the scan did not complete.
        const errors = parsed.errors ?? [];
        const fatal = errors.filter((e) => (e.level ?? "error") === "error");
        if (fatal.length > 0) {
          const first = fatal[0]?.message ?? String(fatal[0]?.type ?? "unknown error");
          logger.warn(
            { component: "semgrep", errors: fatal.length, first },
            "Semgrep reported rule/target errors",
          );
          finish({
            available: false,
            findings: [],
            note: `semgrep reported ${fatal.length} error(s): ${String(first).slice(0, 200)}`,
            reason: "scan-error",
          });
          return;
        }

        // Zero files opened is not "scanned and found nothing" — it is "did not
        // look". The dominant cause was .gitignore filtering (now disabled
        // above); a path holding no scannable source reaches here too. Either
        // way the analyzer must not claim its silence is evidence.
        // Only when the field is present and empty. An absent `paths` means the
        // scanner did not tell us what it opened, which is not the same as
        // telling us it opened nothing — inventing a failure there would fail
        // every genuinely clean scan from a build that omits the field.
        const scanned = parsed.paths?.scanned;
        if (scanned && scanned.length === 0) {
          logger.warn(
            { component: "semgrep", path: sourcePath },
            "Semgrep scanned no files; its silence carries no assurance",
          );
          finish({
            available: false,
            findings: [],
            note: `semgrep scanned 0 files under ${sourcePath}`,
            reason: "no-files-scanned",
          });
          return;
        }

        const findings = (parsed.results ?? []).map((r) => ({
          ruleId: r.check_id,
          path: r.path,
          line: r.start?.line ?? 0,
          severity: r.extra?.severity ?? "INFO",
          message: r.extra?.message ?? "",
        }));
        const partial =
          errors.length > 0
            ? `${errors.length} file(s) could not be fully parsed; coverage is incomplete`
            : undefined;
        if (partial) {
          logger.warn(
            { component: "semgrep", warnings: errors.length, scanned: scanned?.length },
            "Semgrep completed with parse warnings; findings kept, coverage partial",
          );
        }
        finish({ available: true, findings, partial });
      } catch (err) {
        logger.warn(
          { component: "semgrep", err: String(err) },
          "Failed to parse Semgrep output",
        );
        finish({
          available: false,
          findings: [],
          note: "unparseable output",
          reason: "unparseable",
        });
      }
    });
  });
}
