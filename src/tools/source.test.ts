import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadSource, formatSourceForPrompt } from "./source.js";

let root: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "ares-source-"));
  mkdirSync(join(root, "programs", "vault", "src", "instructions"), {
    recursive: true,
  });
  mkdirSync(join(root, "target", "debug"), { recursive: true });
  mkdirSync(join(root, "node_modules", "junk"), { recursive: true });

  writeFileSync(
    join(root, "programs", "vault", "src", "lib.rs"),
    "pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> { Ok(()) }",
  );
  writeFileSync(
    join(root, "programs", "vault", "src", "instructions", "withdraw.rs"),
    "#[derive(Accounts)] pub struct Withdraw<'info> { pub authority: Signer<'info> }",
  );
  writeFileSync(join(root, "Cargo.toml"), "[package]\nname = \"vault\"");
  writeFileSync(join(root, "vault_idl.json"), "{\"instructions\":[]}");
  // Must be excluded: build output and dependencies are not the audit target.
  writeFileSync(join(root, "target", "debug", "huge.rs"), "// build artifact");
  writeFileSync(join(root, "node_modules", "junk", "dep.rs"), "// dependency");
});

afterAll(() => rmSync(root, { recursive: true, force: true }));

describe("loadSource", () => {
  it("returns nothing when no source path is given", async () => {
    const res = await loadSource(undefined);
    expect(res.files).toEqual([]);
    expect(res.note).toMatch(/no source path/i);
  });

  it("returns nothing, without throwing, for a path that does not exist", async () => {
    // This is what made `--source /does-not-exist` dangerous: the caller must be
    // able to tell that zero bytes were read, not just that a string was passed.
    const res = await loadSource("/definitely/not/here/xyz");
    expect(res.files).toEqual([]);
    expect(res.note).toMatch(/not found/i);
  });

  it("reads .rs, Cargo.toml and IDL from the tree", async () => {
    const res = await loadSource(root);
    const paths = res.files.map((f) => f.path);
    expect(paths).toContain("programs/vault/src/lib.rs");
    expect(paths).toContain("programs/vault/src/instructions/withdraw.rs");
    expect(paths).toContain("Cargo.toml");
    expect(paths).toContain("vault_idl.json");
  });

  it("excludes build output and dependencies", async () => {
    const res = await loadSource(root);
    const joined = res.files.map((f) => f.path).join("\n");
    expect(joined).not.toContain("target/");
    expect(joined).not.toContain("node_modules");
  });

  it("puts instruction handlers and account structs before manifests", async () => {
    const res = await loadSource(root);
    const paths = res.files.map((f) => f.path);
    // The bounded budget must be spent on code, not on Cargo.toml.
    expect(paths.indexOf("programs/vault/src/lib.rs")).toBeLessThan(
      paths.indexOf("Cargo.toml"),
    );
  });

  it("is deterministic across runs", async () => {
    const a = await loadSource(root);
    const b = await loadSource(root);
    expect(a.files.map((f) => f.path)).toEqual(b.files.map((f) => f.path));
  });

  it("accepts a single file as the source path", async () => {
    const res = await loadSource(join(root, "programs", "vault", "src", "lib.rs"));
    expect(res.files).toHaveLength(1);
    expect(res.files[0]!.content).toContain("withdraw");
  });

  it("reports a directory with no Rust or IDL as empty", async () => {
    const empty = mkdtempSync(join(tmpdir(), "ares-empty-"));
    try {
      const res = await loadSource(empty);
      expect(res.files).toEqual([]);
      expect(res.note).toMatch(/no \.rs or IDL/i);
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });
});

describe("formatSourceForPrompt", () => {
  it("labels each file by path so findings can cite a real location", async () => {
    const res = await loadSource(root);
    const text = formatSourceForPrompt(res.files);
    expect(text).toContain("--- programs/vault/src/lib.rs ---");
    expect(text).toContain("pub fn withdraw");
  });

  it("renders empty input as an empty string", () => {
    expect(formatSourceForPrompt([])).toBe("");
  });
});
