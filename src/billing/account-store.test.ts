import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  InMemoryAccountStore,
  FileAccountStore,
  createAccountStore,
} from "./account-store.js";
import { CreditLedger, type CreditAccount, type LedgerEntry } from "./credits.js";

function account(over: Partial<CreditAccount> = {}): CreditAccount {
  return {
    id: "acct-1",
    systemCredits: 100,
    onDemandEnabled: false,
    onDemandSpent: 0,
    ...over,
  };
}

function entry(over: Partial<LedgerEntry> = {}): LedgerEntry {
  return {
    id: "e1",
    at: Date.now(),
    kind: "debit",
    credits: 5,
    fromSystem: 5,
    fromOnDemand: 0,
    reason: "audit x",
    ref: "acct-1",
    ...over,
  };
}

describe("InMemoryAccountStore", () => {
  it("round-trips an account", () => {
    const store = new InMemoryAccountStore();
    expect(store.load("acct-1")).toBeUndefined();
    store.save(account({ systemCredits: 42 }));
    expect(store.load("acct-1")).toMatchObject({ systemCredits: 42 });
  });

  it("returns copies, not references", () => {
    const store = new InMemoryAccountStore();
    store.save(account({ systemCredits: 10 }));
    const a = store.load("acct-1")!;
    a.systemCredits = 999;
    expect(store.load("acct-1")!.systemCredits).toBe(10);
  });

  it("collects ledger entries by account ref", () => {
    const store = new InMemoryAccountStore();
    store.append(entry({ id: "a", ref: "acct-1" }));
    store.append(entry({ id: "b", ref: "acct-2" }));
    expect(store.ledger("acct-1").map((e) => e.id)).toEqual(["a"]);
  });
});

describe("FileAccountStore", () => {
  const dirs: string[] = [];
  function tmpFile(): string {
    const dir = mkdtempSync(join(tmpdir(), "ares-billing-"));
    dirs.push(dir);
    return join(dir, "nested", "account.json");
  }
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  it("persists an account across store instances", () => {
    const path = tmpFile();
    const store = new FileAccountStore(path);
    store.save(account({ systemCredits: 70, onDemandSpent: 5 }));
    expect(existsSync(path)).toBe(true);

    // A fresh instance reads the same file back.
    const reopened = new FileAccountStore(path);
    expect(reopened.load("acct-1")).toMatchObject({
      systemCredits: 70,
      onDemandSpent: 5,
    });
  });

  it("acts as a ledger sink that survives a reopen", () => {
    const path = tmpFile();
    const store = new FileAccountStore(path);
    const acct = account({ systemCredits: 100 });
    // Wiring the store as the ledger sink records debits durably.
    const ledger = new CreditLedger(acct, store);
    ledger.charge(30, "audit A", "acct-1");
    store.save(acct);

    const reopened = new FileAccountStore(path);
    expect(reopened.ledger("acct-1")).toHaveLength(1);
    expect(reopened.load("acct-1")!.systemCredits).toBe(70);
  });

  it("starts fresh on a corrupt file rather than throwing", () => {
    const path = tmpFile();
    const store = new FileAccountStore(path);
    store.save(account());
    // Corrupt it, then reopen.
    writeFileSync(path, "{ not json");
    const reopened = new FileAccountStore(path);
    expect(reopened.load("acct-1")).toBeUndefined();
  });
});

describe("createAccountStore", () => {
  it("returns undefined without a configured path", () => {
    expect(createAccountStore({})).toBeUndefined();
  });

  it("returns a FileAccountStore when the path env is set", () => {
    const dir = mkdtempSync(join(tmpdir(), "ares-billing-env-"));
    try {
      const store = createAccountStore({
        BILLING_ACCOUNT_STORE_PATH: join(dir, "a.json"),
      });
      expect(store).toBeInstanceOf(FileAccountStore);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
