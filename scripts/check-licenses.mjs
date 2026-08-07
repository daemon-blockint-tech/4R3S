#!/usr/bin/env node
/**
 * Enforce GOLDEN RULE 1's dependency half: no strong-copyleft third-party
 * package in a published artifact.
 *
 * CLAUDE.md has asserted "CI checks both" since it was written, while no job
 * checked either and no `deny.toml` existed. This is the npm side; `deny.toml`
 * covers cargo.
 *
 * Scope is deliberately narrow, matching the rule's own wording — "keep
 * third-party **strong-copyleft (GPL/AGPL)** dependencies out of any published
 * artifact (LGPL and permissive are fine)":
 *
 *   - GPL-* and AGPL-* fail.
 *   - LGPL-* passes. It is a substring of "GPL", which is exactly the trap a
 *     naive grep falls into, so it is excluded explicitly and tested below.
 *   - MPL/EPL/CDDL pass. They are weak copyleft, and the rule does not ban them.
 *   - The root package is skipped: it is `"private": true` and marked
 *     UNLICENSED, which is not a third-party dependency.
 *   - UNKNOWN is reported but does not fail. A package that simply omits the
 *     field is not evidence of copyleft, and failing on it would make the gate
 *     noisy enough to get switched off — which is how the last one died.
 */
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";

const BANNED = /(?<!L)GPL-|^AGPL/i;

function licensesOf(entry) {
  const raw = entry.licenses ?? "UNKNOWN";
  return Array.isArray(raw) ? raw : [String(raw)];
}

// Pinned devDependency, executed from node_modules. Never `npx -y`: that
// resolves and downloads whatever the registry serves at check time, so the
// gate itself would be an unpinned network fetch.
const bin = createRequire(import.meta.url).resolve(
  "license-checker-rseidelsohn/bin/license-checker-rseidelsohn.js",
);

const json = execFileSync(
  process.execPath,
  [bin, "--json", "--production"],
  { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 },
);

const packages = JSON.parse(json);
const violations = [];
const unknown = [];

for (const [name, entry] of Object.entries(packages)) {
  // The root package itself is not a third-party dependency.
  if (name.startsWith("ares-agent@")) continue;
  for (const license of licensesOf(entry)) {
    if (BANNED.test(license)) violations.push(`${name}  ${license}`);
    else if (/UNKNOWN/i.test(license)) unknown.push(`${name}  ${license}`);
  }
}

if (unknown.length > 0) {
  console.log(`note: ${unknown.length} package(s) declare no license:`);
  for (const u of unknown) console.log(`  ${u}`);
}

if (violations.length > 0) {
  console.error(
    `\nGOLDEN RULE 1: ${violations.length} strong-copyleft dependency/dependencies found:`,
  );
  for (const v of violations) console.error(`  ${v}`);
  console.error("\nFix the dependency. Do not weaken this check.");
  process.exit(1);
}

console.log(
  `license check passed: ${Object.keys(packages).length} packages, no GPL/AGPL.`,
);
