/**
 * Source loader.
 *
 * The auditor's analyzers reasoned from an intake summary and account metadata
 * and never read a line of the program they were auditing, so every `location`
 * and `evidence` string an LLM analyzer produced was necessarily invented. This
 * loads the actual `.rs` sources and Anchor IDL so there is something real to
 * cite, and so a citation can be checked against a file that exists.
 *
 * Follows the tool idiom in this directory: never throws, and reports a
 * machine-readable reason when it produced nothing, so the caller can tell
 * "no source to read" apart from "could not read the source".
 */
import { readFile, readdir, stat } from "node:fs/promises";
import { basename, join, relative, extname, sep } from "node:path";

import { env } from "../config/env.js";
import { logger } from "../config/logger.js";

/** One loaded file. `path` is relative to the audit root, so it is citable. */
export interface SourceFile {
  path: string;
  lines: number;
  content: string;
}

export type SourceSkipReason =
  | "no-source"
  | "path-missing"
  | "unreadable"
  | "no-rust-files";

export interface LoadedSource {
  available: boolean;
  /** Files actually loaded, in priority order. */
  files: SourceFile[];
  /** Every Rust/IDL path discovered, whether or not its body fit the budget. */
  discovered: string[];
  /** True when the budget cut the file list short. */
  truncated: boolean;
  note?: string;
  reason?: SourceSkipReason;
}

/** Directories that never contain auditable program source. */
const SKIP_DIRS = new Set([
  "node_modules",
  "target",
  ".git",
  "dist",
  "build",
  ".next",
  "coverage",
]);

/**
 * Ranking for the context budget. An Anchor program's security surface is
 * concentrated in its instruction handlers and account structs, so those are
 * loaded before helpers and tests — when the budget truncates, it should drop
 * the least interesting files rather than whatever sorted last.
 */
function priority(path: string): number {
  const p = path.toLowerCase();
  if (p.endsWith(".json")) return 0; // IDL: small and highly structural
  if (p.includes(`${sep}instructions${sep}`) || p.endsWith("lib.rs")) return 1;
  if (p.endsWith("state.rs") || p.endsWith("account.rs") || p.endsWith("accounts.rs")) return 2;
  if (p.includes(`${sep}tests${sep}`) || p.includes("test")) return 5;
  return 3;
}

/** Recursively collect candidate files. Never throws. */
async function walk(root: string, dir: string, out: string[]): Promise<void> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    let info;
    try {
      info = await stat(full);
    } catch {
      continue;
    }
    if (info.isDirectory()) {
      await walk(root, full, out);
      continue;
    }
    const ext = extname(entry);
    // `.json` only when it looks like an Anchor IDL — a program's package.json
    // or a lockfile is noise that would eat the budget.
    if (ext === ".rs" || (ext === ".json" && /idl/i.test(full))) {
      out.push(relative(root, full));
    }
  }
}

/** Load a single `.rs` or Anchor IDL file named directly as the source path. */
async function loadSingleFile(
  filePath: string,
  budgetChars: number,
): Promise<LoadedSource> {
  const ext = extname(filePath);
  const isIdl = ext === ".json" && /idl/i.test(filePath);
  if (ext !== ".rs" && !isIdl) {
    return {
      available: false,
      files: [],
      discovered: [],
      truncated: false,
      note: `not a Rust or IDL source file: ${filePath}`,
      reason: "no-rust-files",
    };
  }
  let content: string;
  try {
    content = await readFile(filePath, "utf8");
  } catch {
    return {
      available: false,
      files: [],
      discovered: [],
      truncated: false,
      note: `could not read ${filePath}`,
      reason: "unreadable",
    };
  }
  const rel = basename(filePath);
  const truncated = content.length > budgetChars;
  if (truncated) content = content.slice(0, budgetChars);
  return {
    available: true,
    files: [{ path: rel, lines: content.split("\n").length, content }],
    discovered: [rel],
    truncated,
  };
}

/**
 * Load auditable source under `sourcePath`.
 *
 * Bounded by `ARES_SOURCE_BUDGET_CHARS`: a real Anchor workspace is far larger
 * than any usable context window, so the budget is a hard constraint rather
 * than a tuning knob. `truncated` and `discovered` let the report state plainly
 * how much of the tree was actually read — silence about a truncated read would
 * be the same lie as silence about a failed analyzer.
 */
export async function loadSource(
  sourcePath: string | undefined,
  budgetChars = env.ARES_SOURCE_BUDGET_CHARS,
): Promise<LoadedSource> {
  if (!sourcePath) {
    return {
      available: false,
      files: [],
      discovered: [],
      truncated: false,
      note: "no source path provided",
      reason: "no-source",
    };
  }

  let rootStat;
  try {
    rootStat = await stat(sourcePath);
  } catch {
    return {
      available: false,
      files: [],
      discovered: [],
      truncated: false,
      note: `source path not found: ${sourcePath}`,
      reason: "path-missing",
    };
  }

  // A single file named directly, not a tree: `--source program.rs` and the
  // eval corpus (one `.rs` per target) both land here. walk() readdir's its
  // argument, so a file path would discover nothing and the audit would
  // silently drop to black-box — the exact failure the source loader exists to
  // prevent.
  if (rootStat.isFile()) {
    return loadSingleFile(sourcePath, budgetChars);
  }

  const discovered: string[] = [];
  await walk(sourcePath, sourcePath, discovered);

  if (discovered.length === 0) {
    return {
      available: false,
      files: [],
      discovered: [],
      truncated: false,
      note: `no .rs or IDL files under ${sourcePath}`,
      reason: "no-rust-files",
    };
  }

  const ordered = [...discovered].sort(
    (a, b) => priority(a) - priority(b) || a.localeCompare(b),
  );

  const files: SourceFile[] = [];
  let used = 0;
  let truncated = false;
  for (const rel of ordered) {
    if (used >= budgetChars) {
      truncated = true;
      break;
    }
    let content: string;
    try {
      content = await readFile(join(sourcePath, rel), "utf8");
    } catch {
      continue;
    }
    // A single oversized file is clipped rather than skipped: the head of a
    // handler file is still the most security-relevant part of it.
    const remaining = budgetChars - used;
    if (content.length > remaining) {
      content = content.slice(0, remaining);
      truncated = true;
    }
    used += content.length;
    files.push({ path: rel, lines: content.split("\n").length, content });
  }

  if (files.length === 0) {
    return {
      available: false,
      files: [],
      discovered,
      truncated: false,
      note: "source files were discovered but none could be read",
      reason: "unreadable",
    };
  }

  logger.info(
    {
      component: "source",
      discovered: discovered.length,
      loaded: files.length,
      chars: used,
      truncated,
    },
    "Source loaded",
  );

  return { available: true, files, discovered, truncated };
}

/** Render loaded files for a prompt, with line numbers so citations can be exact. */
export function formatSourceForPrompt(source: LoadedSource): string {
  return source.files
    .map((f) => {
      const numbered = f.content
        .split("\n")
        .map((line, i) => `${String(i + 1).padStart(4)} | ${line}`)
        .join("\n");
      return `--- ${f.path} ---\n${numbered}`;
    })
    .join("\n\n");
}

/**
 * True when `location` cites a file that was actually loaded.
 *
 * Locations arrive as `path:line` or bare `path`, and a model may cite a path
 * relative to a different root, so the comparison is suffix-based rather than
 * exact. Anything that matches nothing was not read by this run and therefore
 * cannot have been observed.
 */
export function citesLoadedFile(location: string, source: LoadedSource): boolean {
  if (!location) return false;
  const cited = location.split(":")[0]?.trim().replace(/^\.\//, "");
  if (!cited) return false;
  return source.files.some(
    (f) => f.path === cited || f.path.endsWith(`${sep}${cited}`) || cited.endsWith(f.path),
  );
}
