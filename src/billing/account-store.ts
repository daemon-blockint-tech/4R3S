/**
 * Account persistence — the seam that lets credit balances and the ledger
 * survive across runs.
 *
 * Without this, `createBilling` mints a brand-new account with a full prepaid
 * allotment on every invocation, so on-demand overflow can never trigger and
 * spend never accumulates. An `AccountStore` loads a previously-saved account
 * (balance + on-demand spend) and persists it back after settlement, and its
 * `sink()` appends every ledger entry for auditability.
 *
 * `InMemoryAccountStore` is the hermetic default (no durability, but a real
 * seam). `FileAccountStore` persists to a JSON file at
 * `BILLING_ACCOUNT_STORE_PATH`. Both are optional: with no store wired, billing
 * behaves exactly as before.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import { log } from "../config/logger.js";
import type { CreditAccount, LedgerEntry, LedgerSink } from "./credits.js";

/** Durable store for a billing account plus its ledger. */
export interface AccountStore extends LedgerSink {
  /** Load a saved account by id, or undefined if none is stored yet. */
  load(id: string): CreditAccount | undefined;
  /** Persist the account's current balances. */
  save(account: CreditAccount): void;
  /** All ledger entries recorded for an account (oldest first). */
  ledger(id: string): LedgerEntry[];
}

interface StoreShape {
  accounts: Record<string, CreditAccount>;
  ledger: LedgerEntry[];
}

function emptyShape(): StoreShape {
  return { accounts: {}, ledger: [] };
}

/** Non-durable store — a real seam with no persistence. */
export class InMemoryAccountStore implements AccountStore {
  private readonly data: StoreShape = emptyShape();

  load(id: string): CreditAccount | undefined {
    const a = this.data.accounts[id];
    return a ? { ...a } : undefined;
  }

  save(account: CreditAccount): void {
    this.data.accounts[account.id] = { ...account };
  }

  append(entry: LedgerEntry): void {
    this.data.ledger.push(entry);
  }

  ledger(id: string): LedgerEntry[] {
    return this.data.ledger.filter((e) => e.ref === id || id === "*");
  }
}

/** JSON-file-backed store. Reads on construction; writes on every mutation. */
export class FileAccountStore implements AccountStore {
  private data: StoreShape;

  constructor(private readonly path: string) {
    this.data = this.read();
  }

  load(id: string): CreditAccount | undefined {
    const a = this.data.accounts[id];
    return a ? { ...a } : undefined;
  }

  save(account: CreditAccount): void {
    this.data.accounts[account.id] = { ...account };
    this.write();
  }

  append(entry: LedgerEntry): void {
    this.data.ledger.push(entry);
    this.write();
  }

  ledger(id: string): LedgerEntry[] {
    return this.data.ledger.filter((e) => e.ref === id || id === "*");
  }

  private read(): StoreShape {
    try {
      if (!existsSync(this.path)) return emptyShape();
      const parsed = JSON.parse(readFileSync(this.path, "utf8")) as Partial<StoreShape>;
      return {
        accounts: parsed.accounts ?? {},
        ledger: Array.isArray(parsed.ledger) ? parsed.ledger : [],
      };
    } catch (err) {
      log.warn(
        { component: "billing.account-store", path: this.path, err: String(err) },
        "Could not read account store; starting fresh",
      );
      return emptyShape();
    }
  }

  private write(): void {
    try {
      mkdirSync(dirname(this.path), { recursive: true });
      writeFileSync(this.path, JSON.stringify(this.data, null, 2));
    } catch (err) {
      log.warn(
        { component: "billing.account-store", path: this.path, err: String(err) },
        "Could not write account store (balances will not persist)",
      );
    }
  }
}

/**
 * Build the account store for the current environment: a `FileAccountStore`
 * when `BILLING_ACCOUNT_STORE_PATH` is set, otherwise undefined (no
 * persistence — balances reset each run, as before).
 */
export function createAccountStore(
  env: NodeJS.ProcessEnv = process.env,
): AccountStore | undefined {
  const path = env.BILLING_ACCOUNT_STORE_PATH?.trim();
  if (!path) return undefined;
  log.info(
    { component: "billing.account-store", path },
    "Billing account persistence enabled",
  );
  return new FileAccountStore(path);
}
