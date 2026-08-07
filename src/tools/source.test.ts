import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from "node:fs";
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

describe("coverage gaps are disclosed, not swallowed", () => {
  // `discovered` counts what the walk FOUND. Anything it could not open is
  // absent from both sides of the `files.length of discovered.length` ratio the
  // report prints, so a swallowed failure reads as complete coverage of a tree
  // whose real size was never learned.
  it("counts a symlink it refused to follow", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ares-links-"));
    mkdirSync(join(dir, "src"), { recursive: true });
    writeFileSync(join(dir, "src", "real.rs"), "pub fn a() {}");
    // Not chmod 0o000: this repo ships a Docker image, and root reads anything,
    // so a permission-based test would pass vacuously in CI.
    symlinkSync(join(dir, "src", "real.rs"), join(dir, "src", "linked.rs"));

    const res = await loadSource(dir);
    expect(res.skippedLinks).toBe(1);
    expect(res.discovered).not.toContain(join("src", "linked.rs"));
    rmSync(dir, { recursive: true, force: true });
  });

  it("reports zero gaps for a clean tree", async () => {
    const res = await loadSource(root);
    expect(res.unreadable).toBe(0);
    expect(res.skippedLinks).toBe(0);
  });

  it("a single named file reports no walk gaps", async () => {
    const res = await loadSource(join(root, "src", "instructions", "withdraw.rs"));
    expect(res.available).toBe(true);
    expect(res.unreadable).toBe(0);
    expect(res.skippedLinks).toBe(0);
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

  // `canBeConfirmed` uses this function as the mechanical evidence that lets an
  // LLM-authored finding be labelled `confirmed`, and REMEMBER persists only
  // confirmed findings durably. A suffix match with no separator boundary let a
  // filename that was never read borrow the identity of one that was, which is
  // how a hallucination would have entered durable memory as fact.
  it("rejects a fabricated filename that merely ends like one that was read", async () => {
    const res = await loadSource(root);
    // Loaded: src/instructions/withdraw.rs. None of these are that file.
    expect(citesLoadedFile("my_withdraw.rs:2", res)).toBe(false);
    expect(citesLoadedFile("xwithdraw.rs", res)).toBe(false);
    expect(citesLoadedFile("src/instructions/not_withdraw.rs:9", res)).toBe(false);
  });

  // `canBeConfirmed` uses this predicate as the mechanical evidence behind
  // `confirmed`, and REMEMBER persists only confirmed findings. The path check
  // above refuses a file nothing read; these refuse a LINE nothing read, which is
  // the same claim one field over. `f.lines` is counted from the truncated
  // content, so it is exactly what the model was shown.
  it("rejects a line beyond the extent of the file that was read", async () => {
    const res = await loadSource(root);
    const file = res.files.find((f) => f.path.endsWith("withdraw.rs"));
    expect(file).toBeDefined();
    const beyond = file!.lines + 1;
    expect(citesLoadedFile(`withdraw.rs:${beyond}`, res)).toBe(false);
    expect(citesLoadedFile(`withdraw.rs:99999`, res)).toBe(false);
  });

  it("accepts the first and last line that were actually read", async () => {
    const res = await loadSource(root);
    const file = res.files.find((f) => f.path.endsWith("withdraw.rs"))!;
    expect(citesLoadedFile("withdraw.rs:1", res)).toBe(true);
    expect(citesLoadedFile(`withdraw.rs:${file.lines}`, res)).toBe(true);
  });

  it("rejects line zero and a negative line", async () => {
    const res = await loadSource(root);
    expect(citesLoadedFile("withdraw.rs:0", res)).toBe(false);
    expect(citesLoadedFile("withdraw.rs:-5", res)).toBe(false);
  });

  it("keeps a bare path legal — on-chain findings carry no line", async () => {
    const res = await loadSource(root);
    // `analyze-onchain` sets no line, and those findings are deterministic; a
    // mandatory line here would reject citations this predicate never judges.
    expect(citesLoadedFile("withdraw.rs", res)).toBe(true);
    expect(citesLoadedFile("withdraw.rs:", res)).toBe(true);
  });

  it("keeps a non-numeric line suffix legal rather than silently failing it", async () => {
    const res = await loadSource(root);
    // Models emit `file.rs:fn_name` and ranges. Treat an unparseable line as
    // "no line stated" — refusing it would demote real citations for a
    // formatting difference, which is the opposite of what this guard is for.
    expect(citesLoadedFile("withdraw.rs:someFunction", res)).toBe(true);
  });

  it("rejects a fractional line", async () => {
    const res = await loadSource(root);
    expect(citesLoadedFile("withdraw.rs:2.5", res)).toBe(false);
  });

  it("still accepts a real file cited from a different root", async () => {
    const res = await loadSource(root);
    // The loader stores paths relative to the audit root; a model citing the
    // same file from a repository root above it is describing the same file.
    const rel = join("src", "instructions", "withdraw.rs");
    expect(citesLoadedFile(join("programs", "vault", rel) + ":2", res)).toBe(true);
  });
});

describe("loadSource with a single file", () => {
  it("loads a `.rs` file named directly, so it is not treated as black-box", async () => {
    const res = await loadSource(join(root, "src", "instructions", "withdraw.rs"));
    expect(res.available).toBe(true);
    expect(res.files).toHaveLength(1);
    expect(res.files[0]!.path).toBe("withdraw.rs");
    expect(res.files[0]!.content).toContain("as u64");
    expect(citesLoadedFile("withdraw.rs:2", res)).toBe(true);
  });

  it("loads a single IDL json but rejects a non-source file", async () => {
    expect((await loadSource(join(root, "idl.json"))).available).toBe(true);
    const notSource = await loadSource(join(root, "package.json"));
    expect(notSource.available).toBe(false);
    expect(notSource.reason).toBe("no-rust-files");
  });

  it("truncates a single file that exceeds the budget", async () => {
    const res = await loadSource(join(root, "src", "state.rs"), 10);
    expect(res.available).toBe(true);
    expect(res.truncated).toBe(true);
    expect(res.files[0]!.content.length).toBe(10);
  });
});
