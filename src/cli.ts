#!/usr/bin/env node
/**
 * INT-1 — consolidated CLI: scan / ingest / report / poc / fuzz / validate.
 *
 * Two genuinely different systems exist in this repo (see
 * docs/INT-1-ASSUMPTIONS.md for the full reasoning):
 *   - the real, shipping TS audit pipeline (root src/, "npm run audit")
 *   - core/'s Rust `ares` binary — its own scan/report/fuzz/validate
 *     subcommands. docs/CORE-CONTRACT-FINDINGS.md documented several real
 *     defects here (ORC2-F1/F3/F6/F7) — all now fixed upstream as of this
 *     writing, including a real F1 improvement from 0.0000 to 0.3007
 *     (EVAL-3). validateAnchorPath below still exists as a fast, consistent
 *     client-side guard (ORC2-F6 is fixed in Rust itself now too — this is
 *     defense in depth, not the only protection).
 *
 * This file does not reimplement either. `scan`/`ingest` spawn the real,
 * already-working TS scripts, the same way apps/auditor-api/worker.py
 * already spawns `npm run audit` rather than importing its internals.
 * `report`/`poc`/`fuzz`/`validate` spawn core/'s real `ares` binary,
 * following docs/ORC-2-CORE-CALL-CONTRACT.md's documented invocation
 * shape.
 */
import { existsSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const REPO_ROOT = fileURLToPath(new URL("..", import.meta.url));
const CORE_DIR = path.join(REPO_ROOT, "core");

export function ares_binary(): string {
  // Windows only ever installs it as .exe; same class of gotcha as
  // BIZ-1's npm/npm.cmd finding — an exact, un-resolved name silently
  // fails to spawn there. cargo puts the built binary at core/target/…
  const exe = process.platform === "win32" ? "ares.exe" : "ares";
  return path.join(CORE_DIR, "target", "release", exe);
}

/** Fast, consistent client-side guard for the same thing ORC2-F6 covers —
 * Rust's own `ares scan` now correctly refuses an unreadable target as an
 * error (fixed upstream), so this is defense in depth, not the only
 * protection: it fails before ever spawning a subprocess, and gives one
 * consistent message across every Rust-backed subcommand here. */
export function validateAnchorPath(targetPath: string): string | null {
  if (!existsSync(targetPath)) {
    return `Path does not exist: ${targetPath}`;
  }
  if (!statSync(targetPath).isDirectory()) {
    return `Not a directory: ${targetPath}`;
  }
  const hasCargoToml = existsSync(path.join(targetPath, "Cargo.toml"));
  const hasAnchorShape =
    existsSync(path.join(targetPath, "programs")) || existsSync(path.join(targetPath, "src"));
  if (!hasCargoToml || !hasAnchorShape) {
    return (
      `${targetPath} does not look like an Anchor project (needs Cargo.toml ` +
      `+ programs/ or src/). Rust's own scan now also refuses this as an error ` +
      `(see docs/CORE-CONTRACT-FINDINGS.md ORC2-F6, fixed upstream) — this check ` +
      `just catches it faster, before spawning a subprocess at all.`
    );
  }
  return null;
}

type SpawnResult = { code: number };

function spawnAndWait(
  cmd: string,
  args: string[],
  opts: { cwd?: string; needsShell?: boolean } = {},
): Promise<SpawnResult> {
  return new Promise((resolve, reject) => {
    const proc = spawn(cmd, args, {
      cwd: opts.cwd ?? REPO_ROOT,
      stdio: "inherit",
      // Only npm needs this on Windows (resolves to npm.cmd, which spawn()
      // can't launch without a shell). core/'s ares binary is a real .exe —
      // applying shell:true there too would be unnecessary, and a real risk:
      // shell:true means args get concatenated into a command line, and any
      // path containing a space (common on Windows — "C:\Users\John Doe\...")
      // needs correct quoting to survive that unless the shell is skipped
      // entirely, which a real .exe never needs in the first place.
      shell: (opts.needsShell ?? false) && process.platform === "win32",
    });
    proc.on("error", reject);
    proc.on("exit", (code) => resolve({ code: code ?? 1 }));
  });
}

async function cmdScan(args: string[]): Promise<number> {
  const { code } = await spawnAndWait("npm", ["run", "audit", "--", ...args], {
    needsShell: true,
  });
  return code;
}

async function cmdIngest(args: string[]): Promise<number> {
  const { code } = await spawnAndWait("npm", ["run", "ingest:solsec", "--", ...args], {
    needsShell: true,
  });
  return code;
}

async function cmdReport(args: string[]): Promise<number> {
  const [scanOutputDir, ...rest] = args;
  if (!scanOutputDir) {
    console.error("Usage: ares-cli report <scan-output-dir> [--format markdown|pdf|json|html|github-issue] [--output <file>]");
    return 1;
  }
  if (!existsSync(scanOutputDir)) {
    console.error(`Scan output directory does not exist: ${scanOutputDir}`);
    return 1;
  }
  const { code } = await spawnAndWait(ares_binary(), ["report", scanOutputDir, ...rest], {
    cwd: CORE_DIR,
  });
  return code;
}

async function cmdPoc(args: string[]): Promise<number> {
  const [targetPath, ...rest] = args;
  if (!targetPath) {
    console.error("Usage: ares-cli poc <anchor-project-path> [--output <dir>] [--max-duration <secs>]");
    return 1;
  }
  const validationError = validateAnchorPath(targetPath);
  if (validationError) {
    console.error(validationError);
    return 1;
  }
  // Per docs/ORC-2-CORE-CALL-CONTRACT.md's own recommended invocation for
  // PoC generation specifically: --poc true, --fuzz false (fuzzing is a
  // separate, heavier operation this CLI exposes as its own `fuzz` command).
  const { code } = await spawnAndWait(
    ares_binary(),
    ["scan", targetPath, "--poc", "true", "--fuzz", "false", ...rest],
    { cwd: CORE_DIR },
  );
  return code;
}

async function cmdFuzz(args: string[]): Promise<number> {
  const [targetPath, ...rest] = args;
  if (!targetPath) {
    console.error("Usage: ares-cli fuzz <path> [--iterations <n>] [--test <name>] [--deterministic]");
    return 1;
  }
  const validationError = validateAnchorPath(targetPath);
  if (validationError) {
    console.error(validationError);
    return 1;
  }
  const { code } = await spawnAndWait(ares_binary(), ["fuzz", targetPath, ...rest], {
    cwd: CORE_DIR,
  });
  return code;
}

async function cmdValidate(args: string[]): Promise<number> {
  const [pocPath, ...rest] = args;
  if (!pocPath) {
    console.error("Usage: ares-cli validate <poc-path> [--fork-mainnet] [--fork-slot <n>] [--rpc-url <url>]");
    return 1;
  }
  if (!existsSync(pocPath)) {
    console.error(`PoC path does not exist: ${pocPath}`);
    return 1;
  }
  const { code } = await spawnAndWait(ares_binary(), ["validate", pocPath, ...rest], {
    cwd: CORE_DIR,
  });
  return code;
}

export const COMMANDS: Record<string, (args: string[]) => Promise<number>> = {
  scan: cmdScan,
  ingest: cmdIngest,
  report: cmdReport,
  poc: cmdPoc,
  fuzz: cmdFuzz,
  validate: cmdValidate,
};

function printHelp(): void {
  console.log(`ares-cli — consolidated ARES interface (INT-1)

Usage: ares-cli <command> [args...]

Commands:
  scan <path>              Run the real TS audit pipeline against a target
                            (wraps: npm run audit -- --source <path>)
  ingest                   Ingest the solsec corpus into the knowledge base
                            (wraps: npm run ingest:solsec)
  report <scan-output-dir> Format an existing Rust core/ scan's output
                            [--format markdown|pdf|json|html|github-issue] [--output <file>]
  poc <anchor-path>        Generate PoC tests via Rust core/ (--poc true, --fuzz false)
  fuzz <anchor-path>       Run a Trident fuzz campaign via Rust core/
                            [--iterations <n>] [--test <name>] [--deterministic]
  validate <poc-path>      Validate a PoC in a sandboxed fork via Rust core/
                            [--fork-mainnet] [--fork-slot <n>] [--rpc-url <url>]

Note: report/poc/fuzz/validate spawn core/'s Rust "ares" binary, which
must be built first (cargo build --release, from core/). See
docs/INT-1-ASSUMPTIONS.md for why these two systems are separate rather
than unified into one implementation.`);
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === "--help" || command === "-h") {
    printHelp();
    process.exitCode = command ? 0 : 1;
    return;
  }
  const handler = COMMANDS[command];
  if (!handler) {
    console.error(`Unknown command: ${command}\n`);
    printHelp();
    process.exitCode = 1;
    return;
  }
  process.exitCode = await handler(rest);
}

// Only run when this is the actual entry point — not when a test file
// imports validateAnchorPath/ares_binary/COMMANDS for testing.
//
// Comparing via a raw `file://${process.argv[1]}` string breaks on Windows:
// process.argv[1] there is a native path with backslashes and no leading
// slash (C:\Users\...\cli.ts), so the concatenation produces
// file://C:\Users\...\cli.ts — never equal to the real import.meta.url
// (file:///C:/Users/.../cli.ts). main() would silently never run when the
// CLI is invoked directly on Windows: no error, no output, just a no-op
// exit. Comparing through fileURLToPath instead means both sides are in
// the same, real, native path format before the comparison happens.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
  });
}
