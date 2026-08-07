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
import { readFile, readdir, lstat, stat } from "node:fs/promises";
import { basename, dirname, join, relative, extname, sep } from "node:path";

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
  /**
   * Entries the walk could not read at all — a `readdir`/`lstat` that threw.
   *
   * `discovered` is what the walk *found*, so a directory it could not open is
   * absent from both sides of `files.length of discovered.length` and the report
   * shows full coverage of a subset it never learned the size of. Counting them
   * is what separates "there was nothing there" from "we could not look".
   *
   * A count, not paths: the report is not a place to render strings from a tree
   * the audited party controls. The paths go to the log channel.
   */
  unreadable: number;
  /**
   * Symlinks deliberately not followed. Correct policy — a link could point at
   * `~/.ssh` — but the file still went unexamined, and a target whose source
   * sits behind one gets an audit of nothing. Kept separate from `unreadable`
   * because this is our decision, not an unknown.
   */
  skippedLinks: number;
  note?: string;
  reason?: SourceSkipReason;
}

/** Directories that never contain auditable program source. */
/**
 * Exported so the Semgrep invocation can exclude the same directories.
 *
 * Two walkers over one tree that disagree about which directories count are two
 * world models: a hit under `target/` becomes a `static` finding — which
 * `canBeConfirmed` promotes to `confirmed` unconditionally — about generated
 * code the loader never read and `citesLoadedFile` would have rejected.
 * Deriving both from this one definition makes them agree by construction.
 */
export const SKIP_DIRS = new Set([
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

/**
 * True when a `.json` path looks like an Anchor IDL rather than npm metadata.
 *
 * Judged on the file's own name and on its directory being exactly `idl/` —
 * never on the rest of the path. `/idl/i` used to be tested against the joined
 * path, which carries the directories *above* the audit root: those belong to
 * whoever launched the run, not to the audited tree, so a root under
 * `~/audits/solidly-fork` (or `candidly`, `idle`, `/tmp/idl-audit`) made every
 * `.json` in the tree qualify. `.json` ranks priority 0, so a package-lock.json
 * then sorted ahead of every `.rs` file and could consume the whole budget on
 * its own — a run that read no program source while reporting `available:
 * true`, which is precisely what stops `analyze-heuristic` from downgrading its
 * findings to speculative, and a finding citing `package-lock.json:9` satisfies
 * `citesLoadedFile`, the mechanical evidence `canBeConfirmed` accepts.
 *
 * The directory clause is an equality, not a substring: Anchor emits
 * `target/idl/vault.json`, and matching `idl-tools/` or `solidly-fork/` too
 * would put the same class of noise back.
 */
function looksLikeIdl(path: string): boolean {
  return (
    /idl/i.test(basename(path)) || basename(dirname(path)).toLowerCase() === "idl"
  );
}

/** What a walk could not examine, alongside what it found. */
interface WalkGaps {
  unreadable: number;
  skippedLinks: number;
}

/** Recursively collect candidate files. Never throws. */
async function walk(
  root: string,
  dir: string,
  out: string[],
  gaps: WalkGaps,
): Promise<void> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch (err) {
    // An unopenable directory is invisible on both sides of the coverage ratio
    // the report prints, so silence here reads as "nothing to see".
    gaps.unreadable += 1;
    logger.warn(
      { component: "source", dir, err: String(err) },
      "Directory could not be read; its contents are not in the audit",
    );
    return;
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    let info;
    try {
      // lstat, not stat: never follow a symlink. An audited repo could link
      // to ~/.env or any file outside its tree and have secrets pulled into
      // the prompt with the source.
      info = await lstat(full);
    } catch (err) {
      gaps.unreadable += 1;
      logger.warn(
        { component: "source", path: full, err: String(err) },
        "Entry could not be stat'd; not in the audit",
      );
      continue;
    }
    if (info.isSymbolicLink()) {
      gaps.skippedLinks += 1;
      continue;
    }
    if (info.isDirectory()) {
      await walk(root, full, out, gaps);
      continue;
    }
    const ext = extname(entry);
    const rel = relative(root, full);
    // `.json` only when it looks like an Anchor IDL — a program's package.json
    // or a lockfile is noise that would eat the budget. See `looksLikeIdl` for
    // why the test never sees the path above the audit root.
    if (ext === ".rs" || (ext === ".json" && looksLikeIdl(rel))) {
      out.push(rel);
    }
  }
}

/** Load a single `.rs` or Anchor IDL file named directly as the source path. */
async function loadSingleFile(
  filePath: string,
  budgetChars: number,
): Promise<LoadedSource> {
  const ext = extname(filePath);
  // Same rule as the tree walk, and for the same reason: `/idl/i` over the
  // whole path accepted `~/idle/proj/package.json` as an IDL, and that lockfile
  // became the run's entire `available: true` source with no budget pressure
  // needed. `target/` is in SKIP_DIRS, so naming the file is the only route to
  // the IDL Anchor actually emits — hence `idl/` as a directory still counts.
  const isIdl = ext === ".json" && looksLikeIdl(filePath);
  if (ext !== ".rs" && !isIdl) {
    return {
      available: false,
      files: [],
      discovered: [],
      truncated: false,
      unreadable: 0,
      skippedLinks: 0,
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
      unreadable: 0,
      skippedLinks: 0,
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
    // A single named file: no directory was walked, so nothing went unexamined.
    unreadable: 0,
    skippedLinks: 0,
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
      unreadable: 0,
      skippedLinks: 0,
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
      unreadable: 0,
      skippedLinks: 0,
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
  const gaps: WalkGaps = { unreadable: 0, skippedLinks: 0 };
  await walk(sourcePath, sourcePath, discovered, gaps);

  if (discovered.length === 0) {
    return {
      available: false,
      files: [],
      discovered: [],
      truncated: false,
      unreadable: 0,
      skippedLinks: 0,
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
      unreadable: 0,
      skippedLinks: 0,
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
      unreadable: gaps.unreadable,
      skippedLinks: gaps.skippedLinks,
    },
    "Source loaded",
  );

  return {
    available: true,
    files,
    discovered,
    truncated,
    unreadable: gaps.unreadable,
    skippedLinks: gaps.skippedLinks,
  };
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
  // Both suffix directions must land on a path separator. Without that boundary
  // on the second one, `endsWith` compares raw characters and a file that was
  // never read matches a file that was: cited `my_vault.rs` "confirms" against a
  // loaded `vault.rs`, and cited `xlib.rs` against `lib.rs`. That is the exact
  // failure this function exists to catch — `canBeConfirmed` in graph/util.ts
  // treats a passing citation as the mechanical evidence that lets an
  // LLM-authored finding be labelled `confirmed`, and REMEMBER then persists
  // only confirmed findings into durable memory that later audits recall as
  // prior knowledge. An unbounded suffix match is therefore the path by which a
  // hallucinated filename becomes a fact the system believes about itself.
  //
  // Citing a *longer* path than was loaded stays legal on purpose: the loader
  // stores paths relative to the audit root, so a model that cites
  // `programs/vault/src/lib.rs` for a loaded `src/lib.rs` is describing the same
  // file from a different root. The separator is what distinguishes that from a
  // different file whose name merely ends the same way.
  const matched = source.files.find((f) => pathsMatch(cited, f.path));
  if (!matched) return false;

  // The path is only half the citation, and this half was lost when LAT-1 and
  // LAT-2 were merged: both rewrote this function's tail, the merge kept one
  // side, and the line check went with the other.
  //
  // Everything after the first `:` used to be discarded, so `lib.rs:840` passed
  // against a file this run holds 300 lines of — and `lines` is counted from the
  // *truncated* content, which is exactly the text the model was shown. A line
  // beyond that is a line nothing in this run ever read: the same claim the path
  // check exists to refuse, one field over.
  //
  // A missing or non-numeric line stays legal: on-chain findings cite a bare
  // address and set no line, and models emit `file.rs:fn_name`. Only a line that
  // is present AND numeric is held to the file's extent.
  const citedLine = location.split(":")[1]?.trim();
  if (citedLine === undefined || citedLine === "") return true;
  const lineNumber = Number(citedLine);
  if (!Number.isFinite(lineNumber)) return true;
  return Number.isInteger(lineNumber) && lineNumber >= 1 && lineNumber <= matched.lines;
}

/**
 * True when two paths name the same file, allowing either to be rooted deeper.
 *
 * Both suffix directions must land on a path separator. Without that boundary
 * `endsWith` compares raw characters and a file that was never read matches one
 * that was: `my_vault.rs` against a loaded `vault.rs`, `xlib.rs` against
 * `lib.rs`. Citing a *longer* path stays legal on purpose — the loader stores
 * paths relative to the audit root, so `programs/vault/src/lib.rs` and a loaded
 * `src/lib.rs` are the same file seen from different roots.
 *
 * Exported so the Semgrep reconciliation in `analyze-static` compares its
 * scanned set against loaded files by this same rule rather than reimplementing
 * it — one definition, so the boundary cannot regress in only one of them.
 */
export function pathsMatch(a: string, b: string): boolean {
  return a === b || a.endsWith(`${sep}${b}`) || b.endsWith(`${sep}${a}`);
}

