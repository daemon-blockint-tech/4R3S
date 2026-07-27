import { describe, it, expect, afterEach } from "vitest";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import {
  InMemoryAccountStore,
  FileAccountStore,
  AccountStoreCorruptError,
  ConcurrentAccountUpdateError,
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
    accountId: "acct-1",
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

  it("collects ledger entries by account, not by audit reference", () => {
    const store = new InMemoryAccountStore();
    // `ref` names the audit (a thread id in production), so filtering on it
    // would return nothing for a real run. `accountId` is the account key.
    store.append(entry({ id: "a", accountId: "acct-1", ref: "ares-9f2c" }));
    store.append(entry({ id: "b", accountId: "acct-2", ref: "ares-9f2c" }));
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
    // The debit is keyed by account even though its ref names the audit.
    expect(reopened.ledger("acct-1")).toHaveLength(1);
    expect(reopened.load("acct-1")!.systemCredits).toBe(70);
  });

  it("refuses to start from an empty balance when the file is corrupt", () => {
    const path = tmpFile();
    new FileAccountStore(path).save(account({ systemCredits: 100 }));
    writeFileSync(path, "{ not json");

    // Silently starting fresh would hand the payer a full prepaid allotment
    // every time the balance file is damaged.
    expect(() => new FileAccountStore(path)).toThrow(AccountStoreCorruptError);
  });

  it("rejects a save that would overwrite another run's balance", () => {
    const path = tmpFile();
    const a = new FileAccountStore(path);
    a.save(account({ systemCredits: 100 }));

    // Two concurrent audits: both load 100, both debit, both write back.
    const first = new FileAccountStore(path);
    const second = new FileAccountStore(path);
    const loadedByFirst = first.load("acct-1")!;
    const loadedBySecond = second.load("acct-1")!;

    first.save({ ...loadedByFirst, systemCredits: 90 });
    // Without the revision guard the second write silently erases the first.
    expect(() =>
      second.save({ ...loadedBySecond, systemCredits: 80 }),
    ).toThrow(ConcurrentAccountUpdateError);
    expect(new FileAccountStore(path).load("acct-1")!.systemCredits).toBe(90);
  });

  it("allows sequential saves from the same loaded store", () => {
    const path = tmpFile();
    const store = new FileAccountStore(path);
    store.save(account({ systemCredits: 100 }));
    const loaded = store.load("acct-1")!;
    store.save({ ...loaded, systemCredits: 90 });
    store.save({ ...loaded, systemCredits: 80 });
    expect(new FileAccountStore(path).load("acct-1")!.systemCredits).toBe(80);
  });

  it("merges ledger appends made by another store instance", () => {
    const path = tmpFile();
    const a = new FileAccountStore(path);
    const b = new FileAccountStore(path);
    a.append(entry({ id: "from-a" }));
    b.append(entry({ id: "from-b" }));

    // b re-reads inside the lock, so a's entry is not clobbered.
    const ids = new FileAccountStore(path).ledger("acct-1").map((e) => e.id);
    expect(ids.sort()).toEqual(["from-a", "from-b"]);
  });

  it("leaves no temp or lock files behind", () => {
    const path = tmpFile();
    const store = new FileAccountStore(path);
    store.save(account());
    store.append(entry());
    expect(existsSync(`${path}.lock`)).toBe(false);
    expect(readdirSync(dirname(path)).filter((f) => f.endsWith(".tmp"))).toEqual([]);
  });

  it("surfaces a write failure instead of reporting a phantom settlement", () => {
    const path = tmpFile();
    const store = new FileAccountStore(path);
    store.save(account());

    // Occupy the staging path with a directory so the atomic write cannot be
    // staged. (Permission-based setups are useless here: tests may run as root.)
    const staging = `${path}.${process.pid}.tmp`;
    mkdirSync(staging, { recursive: true });
    try {
      expect(() => store.save(account({ systemCredits: 1 }))).toThrow(
        /Could not persist the billing account store/,
      );
      // The previous balance is still intact on disk.
      rmSync(staging, { recursive: true, force: true });
      expect(new FileAccountStore(path).load("acct-1")!.systemCredits).toBe(100);
    } finally {
      rmSync(staging, { recursive: true, force: true });
    }
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
