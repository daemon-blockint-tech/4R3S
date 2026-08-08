#!/usr/bin/env node
/**
 * Enforce GOLDEN RULE 1's dependency half: no strong-copyleft third-party
 * package in a published artifact.
 *
 * CLAUDE.md has asserted "CI checks both" since it was written, while no job
 * checked either and no `deny.toml` existed. This is the npm side; `deny.toml`
 * covers cargo.
 *
 * Which licenses fail is deliberately narrow, matching the rule's own wording —
 * "keep third-party **strong-copyleft (GPL/AGPL)** dependencies out of any
 * published artifact (LGPL and permissive are fine)":
 *
 *   - The GPL and AGPL family fails, however it is spelled — see BANNED.
 *   - LGPL-* passes. It is a substring of "GPL", which is exactly the trap a
 *     naive grep falls into, so it is excluded explicitly and tested below.
 *   - MPL/EPL/CDDL pass. They are weak copyleft, and the rule does not ban them.
 *   - Each tree's own root package is skipped: it is first-party, not a
 *     third-party dependency.
 *   - UNKNOWN is reported but does not fail. A package that simply omits the
 *     field is not evidence of copyleft, and failing on it would make the gate
 *     noisy enough to get switched off — which is how the last one died. But a
 *     package that DID declare something license-checker could not parse is not
 *     unknown at all, so its own declaration is re-read first; see npmPackages.
 *
 * WHICH TREES, and why it is no longer just the root. This used to invoke
 * license-checker with no `--start`, so it walked only the tree rooted at
 * process.cwd() — the root npm package, 149 packages. That was correct when it
 * was written ("apps/ares-sec/ and apps/auditor-* are README stubs with no
 * imports to check") and silently stopped being correct when apps/auditor-web
 * became a deployed Next dashboard with 50+ production dependencies of its own
 * and 700+ transitively. The pass line names a package count, so a CI log that
 * excluded a whole published artifact still read as positive evidence the repo
 * was GPL-free.
 *
 * So every npm/pnpm package in the repo is discovered and walked, and a tree
 * whose dependencies are not installed FAILS instead of being skipped: a tree
 * nobody walked cannot be reported clean, which was the whole defect. pnpm gets
 * its own `pnpm licenses list` rather than license-checker `--start`, because
 * license-checker only sees the direct dependencies pnpm symlinks at the top of
 * node_modules (55 of 716 for auditor-web) — the transitive tail, where a GPL
 * dependency actually arrives unnoticed, lives in the virtual store.
 */
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";

const ROOT = process.cwd();

/**
 * Match the GPL/AGPL *family*, not one punctuation of it.
 *
 * The previous `/(?<!L)GPL-|^AGPL/` required a literal hyphen after GPL, so it
 * recognised canonical SPDX ids and nothing else — `GPL`, `GPLv2`, `GPLv3`,
 * `GNU GPL` and `GNU General Public License v3.0` all tested false and shipped.
 * Nothing normalises those away before they get here: license-checker passes a
 * legacy `licenses: [{type: …}]` array through VERBATIM, and `pnpm licenses
 * list` reports whatever the package declared, which is the 700+-package
 * auditor-web tree.
 *
 * `\b` is the LGPL carve-out, which the rule requires (LGPL and permissive are
 * fine; only strong copyleft is banned). There is no word boundary between the
 * L and the GPL in "LGPL", so "LGPL-2.1" does not match — while "MIT OR
 * GPL-2.0" still does. The second alternative catches the prose spelling, with
 * the same carve-out for Lesser/Library (LGPL 2.0's original name).
 */
const BANNED = /\bA?GPL|(?<!LESSER )(?<!LIBRARY )GENERAL PUBLIC LICEN[SC]E/i;

function toArray(raw) {
  if (raw === undefined || raw === null) return ["UNKNOWN"];
  return Array.isArray(raw) ? raw.map(String) : [String(raw)];
}

/**
 * What a package's own package.json declares, in every shape npm has used:
 * `license: "MIT"`, `license: {type}`, `licenses: [{type}]`, `licenses: ["MIT"]`.
 */
function declaredLicenses(dir) {
  let pkg;
  try {
    pkg = JSON.parse(readFileSync(path.join(dir, "package.json"), "utf8"));
  } catch {
    return []; // unreadable or absent — nothing to add beyond what the walker said
  }
  const one = (v) => (typeof v === "string" ? v : typeof v?.type === "string" ? v.type : null);
  const raw = pkg.license ?? pkg.licenses;
  return (Array.isArray(raw) ? raw.map(one) : [one(raw)]).filter(Boolean);
}

/** Root package + every apps/* that is an npm or pnpm package. */
function discoverTrees() {
  const dirs = ["."];
  let apps = [];
  try {
    apps = readdirSync(path.join(ROOT, "apps"), { withFileTypes: true });
  } catch {
    // no apps/ — root-only repo
  }
  for (const entry of apps) {
    if (!entry.isDirectory()) continue;
    if (existsSync(path.join(ROOT, "apps", entry.name, "package.json"))) dirs.push(`apps/${entry.name}`);
  }

  return dirs.map((dir) => {
    const abs = path.join(ROOT, dir);
    const pkg = JSON.parse(readFileSync(path.join(abs, "package.json"), "utf8"));
    // Detected from the lockfile rather than configured, so a new app is covered
    // the day it lands instead of the day someone remembers to add it here.
    const manager = existsSync(path.join(abs, "pnpm-lock.yaml")) ? "pnpm" : "npm";
    return { dir, abs, manager, self: `${pkg.name}@${pkg.version}` };
  });
}

function npmPackages(tree) {
  // Resolved from node_modules, NOT `npx -y`. `npx -y` downloads whatever the
  // registry serves at check time, which would make the licence gate itself an
  // unpinned network fetch — a supply-chain hole in the check that exists to
  // close supply-chain holes. The package is a pinned devDependency.
  const bin = createRequire(import.meta.url).resolve(
    "license-checker-rseidelsohn/bin/license-checker-rseidelsohn.js",
  );
  const json = execFileSync(
    process.execPath,
    [bin, "--json", "--production", "--start", tree.abs],
    { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
  );
  return Object.entries(JSON.parse(json)).map(([id, entry]) => {
    const licenses = toArray(entry.licenses);
    // license-checker resolves anything that is not a parseable SPDX expression
    // to UNKNOWN — "GPLv3" and "GNU GPL" included — and UNKNOWN is deliberately
    // non-fatal above. So on this path a legacy spelling is not merely unmatched
    // by BANNED, it never reaches BANNED at all: read what the package itself
    // declared before trusting the walker's UNKNOWN.
    if (entry.path && licenses.some((l) => /UNKNOWN/i.test(l))) licenses.push(...declaredLicenses(entry.path));
    return { id, licenses };
  });
}

function pnpmPackages(tree) {
  // Keyed by license, not by package: { "MIT": [{ name, versions, license }], … }
  const json = execFileSync("pnpm", ["licenses", "list", "--prod", "--json"], {
    cwd: tree.abs,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  const out = [];
  for (const [license, entries] of Object.entries(JSON.parse(json))) {
    for (const entry of entries) {
      const versions = (entry.versions ?? []).filter(Boolean); // pnpm reports [null] for link:/file: deps
      out.push({
        id: versions.length > 0 ? `${entry.name}@${versions.join(",")}` : entry.name,
        licenses: toArray(entry.license ?? license),
      });
    }
  }
  return out;
}

const trees = discoverTrees();

// Fail before running anything: an uninstalled tree is the silent blind spot
// this gate exists to close, so it must not be able to end in a pass line.
const uninstalled = trees.filter((t) => !existsSync(path.join(t.abs, "node_modules")));
if (uninstalled.length > 0) {
  console.error(`\nGOLDEN RULE 1: ${uninstalled.length} package tree(s) could not be checked — dependencies are not installed:`);
  for (const t of uninstalled) {
    const install = t.manager === "pnpm" ? `pnpm install --dir ${t.dir}` : `npm ci --prefix ${t.dir}`;
    console.error(`  ${t.dir}  (${t.manager})  ->  ${install}`);
  }
  console.error("\nInstall them and re-run. A tree that was not walked cannot be reported as GPL-free.");
  process.exit(1);
}

const violations = [];
const unknown = [];
let total = 0;

for (const tree of trees) {
  const packages = tree.manager === "pnpm" ? pnpmPackages(tree) : npmPackages(tree);
  for (const { id, licenses } of packages) {
    if (id === tree.self) continue; // the tree's own package is not a third-party dependency
    total += 1;
    for (const license of licenses) {
      if (BANNED.test(license)) violations.push(`${tree.dir}: ${id}  ${license}`);
      else if (/UNKNOWN/i.test(license)) unknown.push(`${tree.dir}: ${id}  ${license}`);
    }
  }
}

if (unknown.length > 0) {
  console.log(`note: ${unknown.length} package(s) declare no license:`);
  for (const u of unknown) console.log(`  ${u}`);
}

if (violations.length > 0) {
  console.error(`\nGOLDEN RULE 1: ${violations.length} strong-copyleft dependency/dependencies found:`);
  for (const v of violations) console.error(`  ${v}`);
  console.error("\nFix the dependency. Do not weaken this check.");
  process.exit(1);
}

console.log(
  `license check passed: ${total} packages across ${trees.length} tree(s) (${trees.map((t) => t.dir).join(", ")}), no GPL/AGPL.`,
);
