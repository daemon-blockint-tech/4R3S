import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { validateAnchorPath, ares_binary, COMMANDS } from "./cli.js";

describe("validateAnchorPath — ORC2-F6 guard", () => {
  // ORC2-F6: Rust's own `ares scan` exits 0 with a fully-formed "clean"
  // report for a nonexistent or wrong-shaped path — these tests exist
  // specifically so this CLI never lets one of those through unchecked.
  const dirsToClean: string[] = [];
  afterEach(() => {
    for (const dir of dirsToClean.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  function tempDir(): string {
    const dir = mkdtempSync(path.join(tmpdir(), "int1-test-"));
    dirsToClean.push(dir);
    return dir;
  }

  it("rejects a path that does not exist at all", () => {
    const err = validateAnchorPath("/definitely/not/a/real/path/anywhere");
    expect(err).toMatch(/does not exist/);
  });

  it("rejects a path that exists but is a file, not a directory", () => {
    const dir = tempDir();
    const filePath = path.join(dir, "not-a-directory.txt");
    writeFileSync(filePath, "hello");
    const err = validateAnchorPath(filePath);
    expect(err).toMatch(/not a directory/i);
  });

  it("rejects a flat directory with no Cargo.toml (the exact ORC2-F6 case)", () => {
    const dir = tempDir();
    writeFileSync(path.join(dir, "lib.rs"), "fn main() {}");
    const err = validateAnchorPath(dir);
    expect(err).toMatch(/does not look like an Anchor project/);
    expect(err).toMatch(/ORC2-F6/);
  });

  it("rejects a directory with Cargo.toml but no programs/ or src/", () => {
    const dir = tempDir();
    writeFileSync(path.join(dir, "Cargo.toml"), "[package]\nname = \"x\"");
    const err = validateAnchorPath(dir);
    expect(err).toMatch(/does not look like an Anchor project/);
  });

  it("accepts a real Anchor-shaped directory (Cargo.toml + programs/)", () => {
    const dir = tempDir();
    writeFileSync(path.join(dir, "Cargo.toml"), "[package]\nname = \"x\"");
    mkdirSync(path.join(dir, "programs"));
    const err = validateAnchorPath(dir);
    expect(err).toBeNull();
  });

  it("accepts a directory with Cargo.toml + src/ too (not just programs/)", () => {
    const dir = tempDir();
    writeFileSync(path.join(dir, "Cargo.toml"), "[package]\nname = \"x\"");
    mkdirSync(path.join(dir, "src"));
    const err = validateAnchorPath(dir);
    expect(err).toBeNull();
  });
});

describe("ares_binary", () => {
  it("names the binary .exe on Windows, bare elsewhere", () => {
    // Both branches asserted directly rather than mocking process.platform —
    // this is deliberately a pure, static naming decision, not runtime
    // detection logic worth mocking around.
    const binary = ares_binary();
    if (process.platform === "win32") {
      expect(binary.endsWith("ares.exe")).toBe(true);
    } else {
      expect(binary.endsWith("ares")).toBe(true);
      expect(binary.endsWith(".exe")).toBe(false);
    }
  });

  it("points into core/target/release", () => {
    expect(ares_binary()).toMatch(/core[\\/]target[\\/]release/);
  });
});

describe("COMMANDS dispatch table", () => {
  it("registers exactly the six INT-1 subcommands", () => {
    const names = Object.keys(COMMANDS).sort();
    expect(names).toEqual(["fuzz", "ingest", "poc", "report", "scan", "validate"]);
  });
});
