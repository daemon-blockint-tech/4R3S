/**
 * Program source loader.
 *
 * CLAUDE.md GOLDEN RULE 5 requires the Auditor to load actual source (`.rs` +
 * IDL) into analysis context and forbids a "heuristic" that reasons only from a
 * summary. Nothing did: `sourcePath` reached Semgrep as a CLI argument, the
 * intake prompt as a path *string*, and `analyze-heuristic` as a boolean. No
 * analyzer had ever seen a line of the program it was auditing.
 *
 * This reads the tree so they can. It is deliberately bounded rather than
 * complete — a model context is finite, and a half-read tree that says so is
 * worth more than a full one that blows the window. Callers get `truncated` and
 * act on it; `loadSource` reports `degraded` when it fires.
 */
import { readFile, readdir, stat } from "node:fs/promises";
import { extname, join, relative } from "node:path";

import { logger } from "../config/logger.js";

/** One source file, trimmed to fit. */
export interface SourceFile {
  /** Path relative to the audit root — stable across machines. */
  path: string;
  content: string;
  /** True when `content` is a prefix of the real file. */
  truncated: boolean;
}

export interface SourceLoad {
  files: SourceFile[];
  /** True when files or bytes were dropped: analysis is partial. */
  truncated: boolean;
  /** Why nothing (or not everything) was loaded. */
  note?: string;
}

/** Directories that never contain program source worth auditing. */
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "target",
  "dist",
  "build",
  ".next",
  "test-ledger",
  "__pycache__",
  ".venv",
]);

const MAX_FILES = 60;
const MAX_FILE_BYTES = 96 * 1024;
const MAX_TOTAL_BYTES = 900 * 1024;
/** Depth guard: also stops a symlink cycle from walking forever. */
const MAX_DEPTH = 12;

/** Rust source, plus Anchor IDL / Cargo manifests for program identity. */
function isInteresting(name: string): boolean {
  const ext = extname(name).toLowerCase();
  if (ext === ".rs") return true;
  if (name === "Cargo.toml" || name === "Anchor.toml") return true;
  // Anchor emits its IDL as JSON; a program's IDL is the account/instruction
  // shape an auditor needs when the Rust is unavailable or partial.
  return ext === ".json" && /idl/i.test(name);
}

/**
 * Rank files so the bounded budget is spent on the code that matters. Anchor
 * puts instruction handlers and `#[derive(Accounts)]` structs in `lib.rs`,
 * `instructions/` and `state/`; tests and benches are noise for an audit.
 */
function priority(path: string): number {
  const p = path.toLowerCase();
  if (/(^|\/)(tests?|benches)\//.test(p)) return 4;
  if (p.endsWith("cargo.toml") || p.endsWith("anchor.toml")) return 3;
  if (/idl/i.test(p)) return 2;
  if (/(^|\/)lib\.rs$/.test(p) || /instructions?\//.test(p) || /state\//.test(p)) return 0;
  return 1;
}

async function walk(
  root: string,
  dir: string,
  depth: number,
  out: string[],
): Promise<void> {
  if (depth > MAX_DEPTH || out.length > MAX_FILES * 8) return;
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return; // unreadable directory is not fatal to an audit
  }
  // Sorted so the same tree always yields the same file order.
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name) || entry.name.startsWith(".")) continue;
      await walk(root, full, depth + 1, out);
    } else if (entry.isFile() && isInteresting(entry.name)) {
      out.push(relative(root, full) || entry.name);
    }
  }
}

/**
 * Load program source under `sourcePath`. Never throws — a source tree that
 * cannot be read degrades the audit, it does not abort it.
 */
export async function loadSource(
  sourcePath: string | undefined,
): Promise<SourceLoad> {
  if (!sourcePath) {
    return { files: [], truncated: false, note: "no source path provided" };
  }

  let info;
  try {
    info = await stat(sourcePath);
  } catch {
    return {
      files: [],
      truncated: false,
      note: `source path not found: ${sourcePath}`,
    };
  }

  const root = info.isDirectory() ? sourcePath : join(sourcePath, "..");
  const candidates: string[] = [];
  if (info.isDirectory()) {
    await walk(root, sourcePath, 0, candidates);
  } else {
    candidates.push(relative(root, sourcePath));
  }

  if (candidates.length === 0) {
    return {
      files: [],
      truncated: false,
      note: `no .rs or IDL files found under ${sourcePath}`,
    };
  }

  candidates.sort((a, b) => priority(a) - priority(b) || a.localeCompare(b));
  const selected = candidates.slice(0, MAX_FILES);

  const files: SourceFile[] = [];
  let total = 0;
  let truncated = selected.length < candidates.length;

  for (const rel of selected) {
    if (total >= MAX_TOTAL_BYTES) {
      truncated = true;
      break;
    }
    let raw: string;
    try {
      raw = await readFile(join(root, rel), "utf8");
    } catch {
      truncated = true;
      continue;
    }
    const budget = Math.min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - total);
    const fileTruncated = raw.length > budget;
    const content = fileTruncated ? raw.slice(0, budget) : raw;
    total += content.length;
    if (fileTruncated) truncated = true;
    files.push({ path: rel, content, truncated: fileTruncated });
  }

  logger.info(
    {
      component: "source",
      files: files.length,
      candidates: candidates.length,
      bytes: total,
      truncated,
    },
    "Program source loaded",
  );

  return {
    files,
    truncated,
    note: truncated
      ? `loaded ${files.length} of ${candidates.length} files (${total} bytes); analysis is partial`
      : undefined,
  };
}

/** Render loaded files for a prompt, fenced and labelled by path. */
export function formatSourceForPrompt(files: SourceFile[]): string {
  if (files.length === 0) return "";
  return files
    .map(
      (f) =>
        `--- ${f.path}${f.truncated ? " (truncated)" : ""} ---\n${f.content}`,
    )
    .join("\n\n");
}
