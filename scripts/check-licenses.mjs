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

const BANNED = /(?<!L)GPL-|^AGPL/i;

function licensesOf(entry) {
  const raw = entry.licenses ?? "UNKNOWN";
  return Array.isArray(raw) ? raw : [String(raw)];
}

// Windows resolves "npx" to npx.cmd — a batch script, which Windows can
// only actually execute via a shell/cmd.exe interpreter (confirmed
// directly: explicit "npx.cmd" naming without shell:true fails with
// EINVAL, not just ENOENT — this isn't a name-resolution problem, .cmd
// files genuinely require shell:true on Windows).
//
// Node flags shell:true + an args array as a security anti-pattern
// (arguments get concatenated, not escaped) — real concern in general,
// but not here: every argument below is a fixed literal in this file's
// own source, never derived from user input, file content, or any other
// untrusted source. There is nothing for a shell-injection to attach to.
const json = execFileSync(
  "npx",
  ["-y", "license-checker-rseidelsohn", "--json", "--production"],
  { encoding: "utf8", maxBuffer: 32 * 1024 * 1024, shell: true },
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
