/**
 * Tests for chain-intake persistence and its manifest.
 *
 * The behaviour worth pinning is not "does it write a row" — it is the two ways
 * this module can quietly produce a wrong audit:
 *
 *   1. Serving a stale cached read as if it were current, which puts a false
 *      on-chain fact into a report with no error attached.
 *   2. Failing loudly when Postgres is unreachable, which would make an
 *      optional cache into a hard dependency and break audits that used to work.
 *
 * The Postgres tests here run against no database on purpose: the connection
 * string points at a port nothing listens on, so every call exercises the
 * degradation path. Testing the happy path would need a live database, which
 * belongs in an integration suite, not here.
 */
import { describe, it, expect, beforeEach, afterAll, vi } from "vitest";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  recallIntake,
  recordIntake,
  ensureChainIntakeSchema,
  isWithinTolerance,
  closeChainIntake,
  __resetChainIntakeForTests,
  CHAIN_INTAKE_DDL,
} from "./chain-intake.js";
import {
  buildManifest,
  manifestEntry,
  writeManifest,
} from "../knowledge/chain-intake-manifest.js";
import type { ProgramInfo } from "../tools/solana.js";

const PROGRAM: ProgramInfo = {
  address: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  exists: true,
  executable: true,
  owner: "BPFLoaderUpgradeab1e11111111111111111111111",
  loader: "upgradeable",
  dataLen: 36,
  upgradeAuthority: null,
  upgradeAuthorityKind: "renounced",
};

let outDir: string;

beforeEach(() => {
  __resetChainIntakeForTests();
  // Point at a port nothing serves, so every Postgres call takes the failure
  // path deterministically rather than depending on whether the developer
  // happens to have a database running.
  process.env.POSTGRES_PORT = "1";
  process.env.POSTGRES_TIMEOUT_MS = "300";
  outDir = mkdtempSync(join(tmpdir(), "ares-manifest-"));
});

afterAll(async () => {
  await closeChainIntake();
  rmSync(outDir, { recursive: true, force: true });
});

describe("chain-intake: an unreachable database never breaks an audit", () => {
  it("reports schema setup as failed rather than throwing", async () => {
    await expect(ensureChainIntakeSchema()).resolves.toBe(false);
  });

  it("reports a failed write rather than throwing", async () => {
    await expect(recordIntake(PROGRAM, "helius", "run-1")).resolves.toBe(false);
  });

  it("returns a cache miss rather than throwing, so the caller falls back to RPC", async () => {
    await expect(recallIntake(PROGRAM.address, 60_000)).resolves.toBeUndefined();
  });

  it("does not throw when closing a pool that was never successfully used", async () => {
    await expect(closeChainIntake()).resolves.toBeUndefined();
  });
});

describe("chain-intake: staleness tolerance is honoured literally", () => {
  // These assert on the pure predicate, not on recallIntake. With no Postgres,
  // recallIntake returns a miss for every input, so a test written against it
  // passes whatever the tolerance logic does — mutation testing proved that by
  // deleting the guard and leaving the suite green.

  it("accepts a row comfortably inside the window", () => {
    expect(isWithinTolerance(60_000, 5 * 60_000)).toBe(true);
  });

  it("accepts a row exactly at the boundary", () => {
    // `<=`, not `<`: a five-minute tolerance should admit a five-minute-old row
    // rather than rejecting it for arriving a millisecond late.
    expect(isWithinTolerance(5 * 60_000, 5 * 60_000)).toBe(true);
  });

  it("rejects a row past the window", () => {
    expect(isWithinTolerance(10 * 60_000, 5 * 60_000)).toBe(false);
  });

  it("treats a tolerance of 0 as 'no cache', not 'younger than a millisecond'", () => {
    // A bare `ageMs > maxAgeMs` gives `0 > 0` → false → served. A caller
    // passing 0 to force a live read must get one.
    expect(isWithinTolerance(0, 0)).toBe(false);
  });

  it("treats a negative tolerance the same way rather than as a huge window", () => {
    // Guards against a sign bug upstream turning into "serve anything".
    expect(isWithinTolerance(0, -5_000)).toBe(false);
    expect(isWithinTolerance(999_999, -1)).toBe(false);
  });

  it("still returns a miss from recallIntake under zero tolerance", async () => {
    // End-to-end sanity on the wiring, distinct from the logic tests above.
    await expect(recallIntake(PROGRAM.address, 0)).resolves.toBeUndefined();
  });

  it("requires the caller to state a tolerance — there is no default", () => {
    // A default would let a caller reuse a read without deciding how old is
    // too old for the claim it is about to make.
    expect(recallIntake.length).toBe(2);
  });
});

describe("chain-intake DDL", () => {
  it("is idempotent, so the migrate script can run it on every deploy", () => {
    expect(CHAIN_INTAKE_DDL).toContain("CREATE TABLE IF NOT EXISTS");
    expect(CHAIN_INTAKE_DDL).toContain("CREATE INDEX IF NOT EXISTS");
  });

  it("constrains rpc_source instead of accepting any string", () => {
    // Without the CHECK, a typo'd source silently becomes part of the audit
    // trail and nothing ever surfaces it.
    expect(CHAIN_INTAKE_DDL).toMatch(/CHECK \(rpc_source IN \('helius', 'default'\)\)/);
  });

  it("indexes (address, fetched_at DESC), matching the only query shape used", () => {
    // A plain index on address alone would still work but would force a sort
    // on every lookup, and lookups are always "most recent for this address".
    expect(CHAIN_INTAKE_DDL).toMatch(/\(address, fetched_at DESC\)/);
  });

  it("does not declare address UNIQUE — rows accumulate as an audit trail", () => {
    // An upsert would answer "what is it now" but destroy "what was it when
    // that finding was made", which is half the reason to persist at all.
    expect(CHAIN_INTAKE_DDL).not.toMatch(/address\s+TEXT\s+.*UNIQUE/i);
  });
});

describe("manifest: entries carry provenance, not just values", () => {
  it("records a live read with its fetch time and no age", () => {
    const at = new Date("2026-08-07T10:00:00.000Z");
    const entry = manifestEntry(PROGRAM, "live-rpc", "helius", at);

    expect(entry.origin).toBe("live-rpc");
    expect(entry.rpcSource).toBe("helius");
    expect(entry.fetchedAt).toBe("2026-08-07T10:00:00.000Z");
    // A live read has no staleness to report; emitting ageMsAtUse: 0 would
    // imply the field was measured rather than inapplicable.
    expect(entry).not.toHaveProperty("ageMsAtUse");
  });

  it("records a cached read with how stale it already was when used", () => {
    const at = new Date("2026-08-07T09:00:00.000Z");
    const entry = manifestEntry(PROGRAM, "cache", "default", at, 3_600_000);

    expect(entry.origin).toBe("cache");
    expect(entry.ageMsAtUse).toBe(3_600_000);
    // fetchedAt must be the ORIGINAL read, not when the cache was consulted —
    // otherwise a week-old value looks minutes old.
    expect(entry.fetchedAt).toBe("2026-08-07T09:00:00.000Z");
  });

  it("carries an error through instead of dropping it", () => {
    const entry = manifestEntry(
      { ...PROGRAM, error: "ProgramData read timed out" },
      "live-rpc",
      "helius",
      new Date(),
    );
    expect(entry.error).toBe("ProgramData read timed out");
  });

  it("omits upgradeAuthorityKind when it could not be resolved", () => {
    const { upgradeAuthorityKind: _drop, ...withoutKind } = PROGRAM;
    const entry = manifestEntry(withoutKind, "live-rpc", "helius", new Date());
    // Absent, not defaulted: "unknown" and "renounced" are different claims.
    expect(entry).not.toHaveProperty("upgradeAuthorityKind");
  });
});

describe("manifest: notes state limitations rather than leaving them implicit", () => {
  it("warns that on-chain state is mutable, on every manifest", () => {
    const m = buildManifest([manifestEntry(PROGRAM, "live-rpc", "helius", new Date())]);
    expect(m.notes.join(" ")).toMatch(/mutable/i);
    expect(m.notes.join(" ")).toMatch(/renounced or transferred at any time/i);
  });

  it("says program-controlled is not a multisig claim", () => {
    // tools/solana.ts is careful about this distinction; a manifest that
    // flattened it would undo that care downstream.
    const m = buildManifest([]);
    expect(m.notes.join(" ")).toMatch(/does NOT mean a multisig/);
  });

  it("counts cached entries explicitly when any were served from cache", () => {
    const entries = [
      manifestEntry(PROGRAM, "cache", "helius", new Date(), 5_000),
      manifestEntry(PROGRAM, "live-rpc", "helius", new Date()),
    ];
    const m = buildManifest(entries);
    expect(m.notes.join(" ")).toContain("1 of 2 entries were served from the");
  });

  it("states plainly when nothing was cached, rather than omitting the note", () => {
    // Silence is ambiguous: it could mean "no caching happened" or "the writer
    // forgot to say".
    const m = buildManifest([manifestEntry(PROGRAM, "live-rpc", "helius", new Date())]);
    expect(m.notes.join(" ")).toContain("none were served from cache");
  });

  it("keeps entry_count consistent with entries, computed not passed in", () => {
    const entries = [
      manifestEntry(PROGRAM, "live-rpc", "helius", new Date()),
      manifestEntry(PROGRAM, "cache", "default", new Date(), 1),
    ];
    expect(buildManifest(entries).entry_count).toBe(2);
  });

  it("copies entries rather than aliasing the caller's array", () => {
    // A manifest that aliases its input can be mutated after it was built,
    // which would make the written file disagree with what was asserted.
    const entries = [manifestEntry(PROGRAM, "live-rpc", "helius", new Date())];
    const m = buildManifest(entries);
    entries.push(manifestEntry(PROGRAM, "cache", "default", new Date(), 1));
    expect(m.entries).toHaveLength(1);
  });
});

describe("manifest: writing", () => {
  it("writes valid JSON that round-trips", async () => {
    const path = join(outDir, "chain-intake-manifest.json");
    const m = buildManifest([manifestEntry(PROGRAM, "live-rpc", "helius", new Date())], "run-7");

    await expect(writeManifest(path, m)).resolves.toBe(true);
    expect(existsSync(path)).toBe(true);

    const parsed = JSON.parse(readFileSync(path, "utf8")) as typeof m;
    expect(parsed.run_id).toBe("run-7");
    expect(parsed.entries[0]!.address).toBe(PROGRAM.address);
    expect(parsed.notes.length).toBeGreaterThan(0);
  });

  it("creates the parent directory rather than failing on a missing path", async () => {
    const path = join(outDir, "nested", "deeper", "manifest.json");
    await expect(writeManifest(path, buildManifest([]))).resolves.toBe(true);
    expect(existsSync(path)).toBe(true);
  });

  it("reports a write failure rather than throwing", async () => {
    // A directory where a file should go: the write cannot succeed, and the
    // audit that already produced findings must not die because of it.
    const path = outDir; // outDir is a directory
    await expect(writeManifest(path, buildManifest([]))).resolves.toBe(false);
  });

  it("ends the file with a newline", async () => {
    const path = join(outDir, "newline.json");
    await writeManifest(path, buildManifest([]));
    expect(readFileSync(path, "utf8").endsWith("}\n")).toBe(true);
  });
});
