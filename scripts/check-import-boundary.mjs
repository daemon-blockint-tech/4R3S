#!/usr/bin/env node
/**
 * GOLDEN RULE 1's product/safety-boundary half: offensive tooling in
 * apps/ares-sec/ must never be imported into the defensive Auditor.
 *
 * CLAUDE.md flagged this as deferred: "apps/ares-sec/ and apps/auditor-*
 * are still README stubs, so there are no imports to check — add an
 * import-direction check when real code lands there." Real code landed
 * via SEC-1 — this is that check.
 *
 * Scans every Auditor-side location that actually exists today (not just
 * apps/auditor-*, which is CLAUDE.md's shorthand — the real Auditor side
 * currently also includes root src/, core/, services/, packages/, since
 * the src/ -> packages/* migration isn't finished yet) for any import
 * reaching into apps/ares-sec.
 *
 * WHAT TO MATCH, AND WHY IT IS NOT JUST THE STRING "ares-sec". Two spellings
 * reach that code and only one of them contains "ares-sec":
 *
 *   - a relative path — `from "../../ares-sec/src/agent"` — which does;
 *   - the package name, which is `ares`, not `ares-sec`
 *     (apps/ares-sec/package.json declares `"name": "ares"`). A dependency
 *     entry `"ares": "file:../ares-sec"` plus `from "ares"` links the whole
 *     offensive framework into the Auditor without the substring "ares-sec"
 *     ever appearing in a .ts file. The declaration that makes it resolve
 *     lives in package.json, and a tsconfig `paths` alias can hide the path
 *     spelling too — neither is a code file, so both are scanned here.
 *
 * So the code scan works on *module specifiers*, not on raw lines: a specifier
 * of exactly `ares` (or a deep import `ares/...`) is a violation on its own.
 * Matching a bare /\bares\b/ per line is not an option — the repo is called
 * ARES and the token is in a third of its identifiers, and a gate that noisy
 * gets muted rather than obeyed, which is how two detectors here already died.
 */
import { readFileSync, readdirSync, existsSync } from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const AUDITOR_DIRS = ["src", "core", "services", "packages", "apps/auditor-api", "apps/auditor-web"];
// The root package IS the shipping Auditor (`ares-agent`, root src/), so its own
// manifests are Auditor-side even though they sit outside AUDITOR_DIRS. A root
// dependency on the offensive package would otherwise be declared where nothing looks.
const AUDITOR_ROOT_FILES = ["package.json", "package-lock.json", "tsconfig.json"];
const SKIP_DIRS = new Set(["node_modules", "target", "dist", ".git", "__pycache__"]);
const CODE_EXT = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".rs"]);
const MANIFEST_EXT = new Set([".json"]);

const OFFENSIVE_DIR = "ares-sec"; // the directory, for path spellings
const OFFENSIVE_PKG = "ares"; // apps/ares-sec/package.json "name"
const DEP_FIELDS = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];

// `from "x"`, `import "x"`, `import("x")`, `require("x")`, `export … from "x"`.
// Deliberately specifier-scoped: the quoted string is the only place a module
// name can appear, so `const ares = …` and `aresSecrets` cannot trip it.
const SPECIFIER_RE = /\b(?:from|import|require)\s*\(?\s*["']([^"']+)["']/g;

function isForbiddenSpecifier(spec) {
  return spec === OFFENSIVE_PKG || spec.startsWith(`${OFFENSIVE_PKG}/`) || spec.includes(OFFENSIVE_DIR);
}

function walk(dir, out) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // directory doesn't exist (e.g. services/ is still a stub) — nothing to scan
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, out);
    } else {
      const ext = path.extname(entry.name);
      if (CODE_EXT.has(ext) || MANIFEST_EXT.has(ext)) out.push(full);
    }
  }
}

function scanFile(file, content) {
  const found = [];
  const lines = content.split("\n");

  for (const [i, line] of lines.entries()) {
    if (line.includes(OFFENSIVE_DIR)) {
      found.push({ line: i + 1, text: line.trim(), why: `path into apps/${OFFENSIVE_DIR}` });
      continue; // one report per line is enough; the specifier scan would only echo it
    }
    if (!CODE_EXT.has(path.extname(file))) continue;
    for (const match of line.matchAll(SPECIFIER_RE)) {
      if (isForbiddenSpecifier(match[1])) {
        found.push({ line: i + 1, text: line.trim(), why: `imports the offensive package "${match[1]}"` });
      }
    }
  }

  // `"ares": "workspace:*"` names no path, so the substring scan above cannot
  // see it — yet it is the entry that makes `from "ares"` resolve.
  if (path.basename(file) === "package.json") {
    let manifest = null;
    try {
      manifest = JSON.parse(content);
    } catch {
      // A manifest that doesn't parse is the build's problem, not this gate's.
    }
    for (const field of DEP_FIELDS) {
      const range = manifest?.[field]?.[OFFENSIVE_PKG];
      if (range === undefined) continue;
      const at = lines.findIndex((l) => l.includes(`"${OFFENSIVE_PKG}"`));
      if (found.some((f) => f.line === at + 1)) continue; // `"ares": "file:../ares-sec"` already reported by path
      found.push({
        line: at + 1,
        text: `"${OFFENSIVE_PKG}": ${JSON.stringify(range)}`,
        why: `${field} on the offensive package`,
      });
    }
  }

  return found;
}

const violations = [];
let scanned = 0;

const files = [];
for (const dir of AUDITOR_DIRS) walk(path.join(ROOT, dir), files);
for (const name of AUDITOR_ROOT_FILES) {
  const full = path.join(ROOT, name);
  if (existsSync(full)) files.push(full);
}

for (const file of files) {
  scanned += 1;
  for (const hit of scanFile(file, readFileSync(file, "utf8"))) {
    violations.push({ file: path.relative(ROOT, file), ...hit });
  }
}

if (violations.length > 0) {
  console.error(`\n✗ Import-boundary check failed — ${violations.length} reference(s) to apps/ares-sec in the Auditor tree:\n`);
  for (const v of violations) console.error(`  ${v.file}:${v.line}: ${v.text}\n      ^ ${v.why}`);
  console.error("\nOffensive tooling (apps/ares-sec, npm name \"ares\") must not be imported into the Auditor. See CLAUDE.md GOLDEN RULE 1.");
  process.exit(1);
}

console.log(
  `✓ Import-boundary check passed — ${scanned} Auditor-side file(s) scanned, no path into apps/${OFFENSIVE_DIR} and no dependency on "${OFFENSIVE_PKG}".`,
);
