import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const GATE = path.join(REPO_ROOT, "scripts", "check-licenses.mjs");

const created: string[] = [];

afterEach(() => {
  for (const dir of created.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function fixture(files: Record<string, string>, dirs: string[] = []): string {
  const root = mkdtempSync(path.join(tmpdir(), "ares-licenses-"));
  created.push(root);
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  for (const dir of dirs) mkdirSync(path.join(root, dir), { recursive: true });
  return root;
}

function runGate(cwd: string) {
  const result = spawnSync(process.execPath, [GATE], { cwd, encoding: "utf8" });
  return { status: result.status, stdout: result.stdout, out: `${result.stdout}${result.stderr}` };
}

const manifest = (name: string, extra: Record<string, unknown> = {}) =>
  `${JSON.stringify({ name, version: "1.0.0", ...extra }, null, 2)}\n`;

/**
 * A package tree with one real dependency per license spelling.
 *
 * Declared through the legacy `licenses: [{type}]` array on purpose: that is
 * the one shape license-checker hands back VERBATIM (the `license` string path
 * goes through its SPDX normaliser first), so it is how a raw non-SPDX
 * spelling actually reaches the gate's matcher — the same way every entry from
 * `pnpm licenses list` does on the auditor-web tree.
 */
function licenseFixture(spellings: string[]) {
  const names = spellings.map((_, i) => `dep-${i}`);
  const files: Record<string, string> = {
    "package.json": manifest("fixture-root", {
      dependencies: Object.fromEntries(names.map((n) => [n, "1.0.0"])),
    }),
    "package-lock.json": '{"lockfileVersion":3}\n',
  };
  spellings.forEach((license, i) => {
    files[`node_modules/${names[i]}/package.json`] = manifest(names[i], { licenses: [{ type: license }] });
  });
  return { root: fixture(files), names };
}

/**
 * These cover the defect the gate was rewritten for: it walked only the root
 * npm tree, so apps/auditor-web's 700+ production packages were outside it, and
 * it still printed an affirmative "license check passed: N packages" that reads
 * as evidence for the whole repo. The walk itself (license-checker / `pnpm
 * licenses list`) needs installed node_modules and is exercised against the
 * real repo by the CI step; what is asserted here is scope and fail-closure,
 * which is what actually went wrong.
 */
describe("check-licenses", () => {
  it("refuses to report a pass when an app's dependencies are not installed", () => {
    const root = fixture(
      {
        "package.json": manifest("fixture-root"),
        "package-lock.json": '{"lockfileVersion":3}\n',
        "apps/web/package.json": manifest("fixture-web"),
        "apps/web/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
      },
      ["node_modules"],
    );

    const { status, stdout, out } = runGate(root);
    expect(status).toBe(1);
    expect(out).toContain("apps/web");
    // The old gate's failure was not a crash — it was a green tick over an
    // unwalked tree. The pass line must be unreachable here.
    expect(stdout).not.toContain("license check passed");
  });

  it("names the right installer per tree, detected from the lockfile", () => {
    const root = fixture({
      "package.json": manifest("fixture-root"),
      "package-lock.json": '{"lockfileVersion":3}\n',
      "apps/web/package.json": manifest("fixture-web"),
      "apps/web/pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
      "apps/sec/package.json": manifest("ares"),
      "apps/sec/package-lock.json": '{"lockfileVersion":3}\n',
    });

    const { status, out } = runGate(root);
    expect(status).toBe(1);
    expect(out).toContain("pnpm install --dir apps/web");
    expect(out).toContain("npm ci --prefix apps/sec");
    expect(out).toContain("npm ci --prefix ."); // the root tree is a tree like any other
  });

  it("does not mistake a non-npm app for an npm tree", () => {
    const root = fixture({
      "package.json": manifest("fixture-root"),
      "package-lock.json": '{"lockfileVersion":3}\n',
      // apps/auditor-api is Python; it has no package.json and pip-audit covers it.
      "apps/api/requirements.txt": "fastapi==0.115.0\n",
    });

    const { status, out } = runGate(root);
    expect(status).toBe(1);
    expect(out).toContain("1 package tree(s) could not be checked");
    expect(out).not.toContain("apps/api");
  });

  // The matcher used to require a literal hyphen after GPL, so it recognised
  // canonical SPDX ids and nothing else. Every spelling below tested false and
  // shipped — and this is the only npm-side enforcement of GOLDEN RULE 1.
  it.each([
    "GPL-3.0", // the canonical ids, which the hyphen-only matcher did catch
    "AGPL-3.0",
    "GPL-2.0-only",
    "GPL", // legacy `licenses: [{type}]` entries, passed through verbatim
    "GPLv2",
    "GPLv3",
    "AGPL",
    "GNU GPL",
    "GNU General Public License v3.0", // prose, from a LICENSE-file inference
    "GNU General Public Licence", // the British spelling npm packages do use
    "GNU Affero General Public License v3.0",
    "GPL-2.0-or-later WITH Classpath-exception-2.0",
    // Dual licensing is blocked too. You may take the MIT half, but that is a
    // judgement call for a human plus a clarifications file, not for a gate
    // whose failure mode is shipping copyleft silently. Unchanged behaviour.
    "MIT OR GPL-2.0",
  ])(
    "blocks strong copyleft spelled %j",
    (license) => {
      const { root, names } = licenseFixture([license]);
      const { status, stdout, out } = runGate(root);
      expect(status).toBe(1);
      expect(out).toContain(`${names[0]}@1.0.0  ${license}`);
      expect(stdout).not.toContain("license check passed");
    },
    // The gate shells out to `npx license-checker-rseidelsohn`; the very
    // first invocation across this whole suite pays a real, one-time
    // resolution cost the default 5s doesn't budget for (every later case
    // here resolves in ~1s once that's warm). Windows' slower per-process
    // spawn overhead makes this worse, not better.
    20_000,
  );

  // The carve-out the rule requires: LGPL and permissive are fine, and "LGPL"
  // contains "GPL", which is the trap any broadened matcher has to survive.
  // MPL/EPL/CDDL are weak copyleft and are not banned either.
  it.each([
    "LGPL-3.0",
    "LGPL-2.1",
    "LGPL",
    "LGPLv3",
    "GNU LGPL",
    "GNU Lesser General Public License v2.1",
    "GNU Library General Public License v2.0", // LGPL 2.0's original name
    "MIT",
    "Apache-2.0",
    "BSD-3-Clause",
    "ISC",
    "MPL-2.0",
    "(MIT AND LGPL-2.1)",
  ])("allows %j", (license) => {
    const { root } = licenseFixture([license]);
    const { status, stdout } = runGate(root);
    expect(status).toBe(0);
    expect(stdout).toContain("license check passed");
  });

  it("catches a legacy spelling that license-checker itself resolves to UNKNOWN", () => {
    // A bare `license: "GPLv3"` is not a parseable SPDX expression, so
    // license-checker reports UNKNOWN — and UNKNOWN is non-fatal by design.
    // Broadening the matcher alone does not help here: the spelling never
    // reaches the matcher. A GPL package with no LICENSE file ships silently.
    const root = fixture({
      "package.json": manifest("fixture-root", { dependencies: { "legacy-gpl": "1.0.0" } }),
      "node_modules/legacy-gpl/package.json": manifest("legacy-gpl", { license: "GPLv3" }),
    });

    const { status, out } = runGate(root);
    expect(status).toBe(1);
    expect(out).toContain("legacy-gpl@1.0.0  GPLv3");
  });

  it("still does not fail on a package that declares no license at all", () => {
    // UNKNOWN stays non-fatal: an omitted field is not evidence of copyleft,
    // and a gate noisy enough to get switched off is how the last one died.
    const root = fixture({
      "package.json": manifest("fixture-root", { dependencies: { anon: "1.0.0" } }),
      "node_modules/anon/package.json": manifest("anon"),
    });

    const { status, stdout } = runGate(root);
    expect(status).toBe(0);
    expect(stdout).toContain("1 package(s) declare no license");
    expect(stdout).toContain("license check passed");
  });
});
