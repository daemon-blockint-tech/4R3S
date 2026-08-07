import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const GATE = path.join(REPO_ROOT, "scripts", "check-import-boundary.mjs");

const created: string[] = [];

afterEach(() => {
  for (const dir of created.splice(0)) rmSync(dir, { recursive: true, force: true });
});

/**
 * A miniature Auditor-side tree. The gate resolves everything from cwd, so a
 * fixture repo is the real thing as far as it is concerned — no shimming.
 */
function fixture(files: Record<string, string>): string {
  const root = mkdtempSync(path.join(tmpdir(), "ares-boundary-"));
  created.push(root);
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    mkdirSync(path.dirname(full), { recursive: true });
    writeFileSync(full, content);
  }
  return root;
}

function runGate(cwd: string) {
  const result = spawnSync(process.execPath, [GATE], { cwd, encoding: "utf8" });
  return { status: result.status, out: `${result.stdout}${result.stderr}` };
}

const WEB_PKG = (deps: Record<string, string>) =>
  `${JSON.stringify({ name: "ares-auditor-web", version: "0.1.0", dependencies: deps }, null, 2)}\n`;

describe("check-import-boundary", () => {
  it("passes on an Auditor tree that only imports Auditor-side code", () => {
    const root = fixture({
      "apps/auditor-web/package.json": WEB_PKG({ next: "15.0.0" }),
      "apps/auditor-web/lib/scan.ts": `import { db } from "@/lib/db"\nimport next from "next"\nexport const go = () => db && next\n`,
      "src/index.ts": `import { readFileSync } from "node:fs"\nexport const f = readFileSync\n`,
    });
    expect(runGate(root).status).toBe(0);
  });

  // The spelling the substring gate could never see: apps/ares-sec/package.json
  // declares `"name": "ares"`, so nothing about a real import mentions "ares-sec".
  it("fails on an import of the offensive package by its npm name", () => {
    const root = fixture({
      "apps/auditor-web/package.json": WEB_PKG({ next: "15.0.0" }),
      "apps/auditor-web/lib/actions/scan.ts": `import { runExploitChain } from "ares"\nexport const go = runExploitChain\n`,
    });
    const { status, out } = runGate(root);
    expect(status).toBe(1);
    expect(out).toContain("apps/auditor-web/lib/actions/scan.ts");
    expect(out).toContain('imports the offensive package "ares"');
  });

  it.each([
    ['require("ares")', `const { chain } = require("ares")\n`],
    ["dynamic import", `export const load = () => import("ares")\n`],
    ["deep import", `import { chain } from "ares/dist/exploit"\n`],
    ["re-export", `export { chain } from "ares"\n`],
    ["relative path", `import { chain } from "../../ares-sec/src/agent"\n`],
  ])("fails on %s", (_label, source) => {
    const root = fixture({
      "apps/auditor-web/package.json": WEB_PKG({}),
      "apps/auditor-web/lib/x.ts": source,
    });
    expect(runGate(root).status).toBe(1);
  });

  // `workspace:*` names no path at all, so only the manifest scan can catch it —
  // and it is the entry that makes `from "ares"` resolve in the first place.
  it("fails on a dependency entry for the offensive package, with no path anywhere", () => {
    const root = fixture({
      "apps/auditor-web/package.json": WEB_PKG({ ares: "workspace:*", next: "15.0.0" }),
    });
    const { status, out } = runGate(root);
    expect(status).toBe(1);
    expect(out).toContain("dependencies on the offensive package");
  });

  // With a paths alias, even the import specifier is opaque (`from "@sec/agent"`),
  // so the tsconfig is the only place the boundary crossing is still visible.
  it("fails on a tsconfig paths alias into apps/ares-sec", () => {
    const root = fixture({
      "apps/auditor-web/package.json": WEB_PKG({}),
      "apps/auditor-web/tsconfig.json": `${JSON.stringify(
        { compilerOptions: { paths: { "@/*": ["./*"], "@sec/*": ["../ares-sec/src/*"] } } },
        null,
        2,
      )}\n`,
      "apps/auditor-web/lib/x.ts": `import { chain } from "@sec/agent"\nexport const go = chain\n`,
    });
    const { status, out } = runGate(root);
    expect(status).toBe(1);
    expect(out).toContain("tsconfig.json");
  });

  it("fails on a root-package dependency on the offensive package", () => {
    const root = fixture({
      "package.json": `${JSON.stringify({ name: "ares-agent", version: "1.0.0", dependencies: { ares: "file:./apps/ares-sec" } }, null, 2)}\n`,
      "src/index.ts": "export const f = 1\n",
    });
    expect(runGate(root).status).toBe(1);
  });

  // The narrowness half. "ares" is the repo's own name and is in a third of its
  // identifiers; a gate that fires on those gets muted and stops being a gate.
  it("does not fire on Auditor-side names that merely contain 'ares'", () => {
    const root = fixture({
      "package.json": `${JSON.stringify({ name: "ares-agent", version: "1.0.0", dependencies: { "ares-agent-sdk": "1.0.0" } }, null, 2)}\n`,
      "src/index.ts": [
        `import { catalog } from "@ares/knowledge"`,
        `import { score } from "ares-agent-sdk"`,
        `const ares = { secure: true }`,
        `const aresSecurityPolicy = ares.secure`,
        `export { ares, aresSecurityPolicy, catalog, score }`,
        ``,
      ].join("\n"),
    });
    const { status, out } = runGate(root);
    expect(status, out).toBe(0);
  });

  // Real input, not a fixture: the gate has to be green on the tree it guards,
  // or the first PR to hit a false positive is the one that turns it off.
  it("passes on this repository", () => {
    const { status, out } = runGate(REPO_ROOT);
    expect(status, out).toBe(0);
  });
});
