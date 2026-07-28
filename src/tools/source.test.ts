import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadSource, citesLoadedFile, formatSourceForPrompt } from "./source.js";

let root: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "ares-source-"));
  mkdirSync(join(root, "src", "instructions"), { recursive: true });
  mkdirSync(join(root, "target", "debug"), { recursive: true });
  mkdirSync(join(root, "node_modules", "junk"), { recursive: true });

  writeFileSync(join(root, "src", "lib.rs"), "pub mod instructions;\n");
  writeFileSync(
    join(root, "src", "instructions", "withdraw.rs"),
    "pub fn withdraw() {\n    let x = 1u128 as u64;\n}\n",
  );
  writeFileSync(join(root, "src", "state.rs"), "pub struct Vault { pub balance: u64 }\n");
  // Must be ignored: build output and dependencies are not auditable source.
  writeFileSync(join(root, "target", "debug", "gen.rs"), "fn generated() {}\n");
  writeFileSync(join(root, "node_modules", "junk", "dep.rs"), "fn dep() {}\n");
  // A non-IDL json is noise; an IDL one is structure worth loading.
  writeFileSync(join(root, "package.json"), '{"name":"x"}\n');
  writeFileSync(join(root, "idl.json"), '{"instructions":[]}\n');
});

afterAll(() => rmSync(root, { recursive: true, force: true }));

describe("loadSource", () => {
  it("reports no-source when given no path", async () => {
    const res = await loadSource(undefined);
    expect(res.available).toBe(false);
    expect(res.reason).toBe("no-source");
  });

  it("reports path-missing for a path that does not exist", async () => {
    const res = await loadSource("/definitely/not/here/xyz");
    expect(res.available).toBe(false);
    expect(res.reason).toBe("path-missing");
  });

  it("loads .rs and IDL files with paths relative to the audit root", async () => {
    const res = await loadSource(root);
    expect(res.available).toBe(true);
    const paths = res.files.map((f) => f.path);
    expect(paths).toContain(join("src", "lib.rs"));
    expect(paths).toContain(join("src", "instructions", "withdraw.rs"));
    expect(paths).toContain("idl.json");
    // Relative, so a finding can cite them and a reader can open them.
    expect(paths.every((p) => !p.startsWith("/"))).toBe(true);
  });

  it("ignores build output, dependencies, and non-IDL json", async () => {
    const res = await loadSource(root);
    const paths = res.files.map((f) => f.path);
    expect(paths.some((p) => p.includes("target"))).toBe(false);
    expect(paths.some((p) => p.includes("node_modules"))).toBe(false);
    expect(paths).not.toContain("package.json");
  });

  it("truncates at the budget and says so rather than silently reading less", async () => {
    const res = await loadSource(root, 40);
    expect(res.truncated).toBe(true);
    // discovered still reports the whole tree, so the report can state the gap.
    expect(res.discovered.length).toBeGreaterThan(res.files.length);
  });

  it("numbers lines so a finding can cite one", async () => {
    const res = await loadSource(root);
    const rendered = formatSourceForPrompt(res);
    expect(rendered).toContain("1 | ");
    expect(rendered).toContain("--- ");
  });
});

describe("citesLoadedFile", () => {
  it("accepts a citation into a file that was actually read", async () => {
    const res = await loadSource(root);
    expect(citesLoadedFile(join("src", "instructions", "withdraw.rs") + ":2", res)).toBe(true);
    expect(citesLoadedFile("withdraw.rs:2", res)).toBe(true);
  });

  it("rejects a citation into a file this run never read", async () => {
    const res = await loadSource(root);
    // The dominant fabrication mode: a plausible path that does not exist here.
    expect(citesLoadedFile("src/vault.rs:88", res)).toBe(false);
    expect(citesLoadedFile("", res)).toBe(false);
    // Excluded directories are not "read" either, so citing them fails.
    expect(citesLoadedFile(join("target", "debug", "gen.rs") + ":1", res)).toBe(false);
  });
});
