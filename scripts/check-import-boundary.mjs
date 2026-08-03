#!/usr/bin/env node
/**
 * GOLDEN RULE 1's product/safety-boundary half: offensive tooling in
 * apps/ares-sec/ must never be imported into the defensive Auditor side.
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
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const AUDITOR_DIRS = ["src", "core", "services", "packages", "apps/auditor-api", "apps/auditor-web"];
const FORBIDDEN = /ares-sec/;
const SKIP_DIRS = new Set(["node_modules", "target", "dist", ".git", "__pycache__"]);
const CODE_EXT = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".rs"]);

function walk(dir, out) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // directory doesn't exist (e.g. apps/auditor-api is still a stub) — nothing to scan
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, out);
    } else if (CODE_EXT.has(path.extname(entry.name))) {
      out.push(full);
    }
  }
}

const violations = [];
let scanned = 0;

for (const dir of AUDITOR_DIRS) {
  const files = [];
  walk(path.join(ROOT, dir), files);
  for (const file of files) {
    scanned += 1;
    const content = readFileSync(file, "utf8");
    for (const [i, line] of content.split("\n").entries()) {
      if (FORBIDDEN.test(line)) {
        violations.push({ file: path.relative(ROOT, file), line: i + 1, text: line.trim() });
      }
    }
  }
}

if (violations.length > 0) {
  console.error(`\n✗ Import-boundary check failed — ${violations.length} reference(s) to ares-sec found in the Auditor tree:\n`);
  for (const v of violations) console.error(`  ${v.file}:${v.line}: ${v.text}`);
  console.error("\nOffensive tooling (apps/ares-sec) must not be imported into the Auditor. See CLAUDE.md GOLDEN RULE 1.");
  process.exit(1);
}

console.log(`✓ Import-boundary check passed — ${scanned} Auditor-side file(s) scanned, no reference to ares-sec.`);
