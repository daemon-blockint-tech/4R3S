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
});
