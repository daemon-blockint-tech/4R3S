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
import { randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";

import { log } from "../config/logger.js";
import type { CreditAccount, LedgerEntry, LedgerSink } from "./credits.js";

/** Durable store for a billing account plus its ledger. */
export interface AccountStore extends LedgerSink {
  /** Load a saved account by id, or undefined if none is stored yet. */
  load(id: string): CreditAccount | undefined;
  /** Persist the account's current balances. */
  save(account: CreditAccount): void;
  /**
   * Persist a new balance and the entries that produced it as ONE transaction.
   *
   * `save` and `append` are separate locked writes, so a debit could reach disk
   * while the balance that debit produced did not — a crash, a disk-full
   * staging failure or a lost `ConcurrentAccountUpdateError` between the two
   * left the ledger and the balance permanently disagreeing, with the error
   * message ("The charge was not persisted") stating the opposite of what had
   * happened. Settlement uses this instead: one lock, one revision check, one
   * atomic write, both halves or neither.
   */
  commit(account: CreditAccount, entries: readonly LedgerEntry[]): void;
  /** All ledger entries recorded for an account (oldest first). */
  ledger(id: string): LedgerEntry[];
}

interface StoreShape {
  accounts: Record<string, CreditAccount>;
  ledger: LedgerEntry[];
  /** Per-account revision, bumped on every save; guards against lost updates. */
  revs: Record<string, number>;
}

function emptyShape(): StoreShape {
  return { accounts: {}, ledger: [], revs: {} };
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

  commit(account: CreditAccount, entries: readonly LedgerEntry[]): void {
    this.data.accounts[account.id] = { ...account };
    this.data.ledger.push(...entries);
  }

  ledger(id: string): LedgerEntry[] {
    return this.data.ledger.filter((e) => e.accountId === id || id === "*");
  }
}

/** Thrown when another process changed an account while this run held it. */
export class ConcurrentAccountUpdateError extends Error {
  constructor(
    readonly accountId: string,
    readonly expectedRev: number,
    readonly actualRev: number,
  ) {
    super(
      `Account ${accountId} was modified by another run (expected revision ` +
        `${expectedRev}, found ${actualRev}). The charge was not persisted; ` +
        "re-run the audit so it settles against the current balance.",
    );
    this.name = "ConcurrentAccountUpdateError";
  }
}

/** Thrown when the store file exists but cannot be read as an account store. */
export class AccountStoreCorruptError extends Error {
  constructor(path: string, cause: unknown) {
    super(
      `Account store at ${path} exists but could not be parsed (${String(cause)}). ` +
        "Refusing to start from an empty balance — restore or delete the file " +
        "deliberately.",
      { cause },
    );
    this.name = "AccountStoreCorruptError";
  }
}

/** How long a lock may be held before it is treated as abandoned. */
const LOCK_STALE_MS = 30_000;
/** Total time to wait for a contended lock before giving up. */
const LOCK_TIMEOUT_MS = 5_000;
const LOCK_POLL_MS = 25;

/** Block the current thread briefly — the AccountStore API is synchronous. */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * JSON-file-backed store.
 *
 * Money makes the failure modes matter, so three things are deliberate here:
 *
 *  - **Every mutation is serialized by a lock file.** Two audits running at once
 *    would otherwise each read the balance, each debit it, and each write back
 *    an absolute figure — the second silently erasing the first.
 *  - **Writes are atomic.** The payload goes to a temp file and is `rename`d
 *    into place, so a crash mid-write can never truncate the balances and the
 *    ledger. Failure to write throws: a charge that isn't recorded must not be
 *    reported as settled.
 *  - **A corrupt file is fatal, not empty.** Parsing an existing file into
 *    `{}` would hand the payer a fresh prepaid allotment every time the file is
 *    damaged.
 *
 * A per-account revision guards the read-modify-write cycle that spans a whole
 * audit: `load` records the revision it saw and `save` refuses to overwrite a
 * newer one, so a race is reported instead of silently costing revenue.
 */
export class FileAccountStore implements AccountStore {
  private data: StoreShape;
  /** Revision each account was at when this process loaded it. */
  private readonly loadedRev = new Map<string, number>();
  /**
   * Identifies this instance's hold on the lock file. The pid alone is not
   * enough: pids are reused, and two stores in one process share one.
   */
  private readonly lockToken = `${process.pid}:${randomUUID()}`;

  constructor(private readonly path: string) {
    this.data = this.read();
  }

  private get lockPath(): string {
    return `${this.path}.lock`;
  }

  load(id: string): CreditAccount | undefined {
    // Read through to disk: another run may have moved the balance since
    // construction, and starting from a stale figure is how credits get lost.
    this.data = this.read();
    const a = this.data.accounts[id];
    this.loadedRev.set(id, this.data.revs[id] ?? 0);
    return a ? { ...a } : undefined;
  }

  save(account: CreditAccount): void {
    this.commit(account, []);
  }

  commit(account: CreditAccount, entries: readonly LedgerEntry[]): void {
    this.withLock(() => {
      const current = this.data.revs[account.id] ?? 0;
      const expected = this.loadedRev.get(account.id) ?? current;
      if (current !== expected) {
        // Nothing has been mutated yet, so throwing here leaves neither the
        // balance nor the entries on disk — the whole point of one transaction.
        throw new ConcurrentAccountUpdateError(account.id, expected, current);
      }
      this.data.accounts[account.id] = { ...account };
      // Re-read inside the lock means concurrent appends merge rather than
      // being clobbered; pushing here keeps them under the same revision bump.
      if (entries.length > 0) this.data.ledger.push(...entries);
      this.data.revs[account.id] = current + 1;
      this.loadedRev.set(account.id, current + 1);
    });
  }

  append(entry: LedgerEntry): void {
    // Ledger entries only ever accumulate, so re-reading inside the lock merges
    // concurrent appends instead of dropping them.
    this.withLock(() => {
      this.data.ledger.push(entry);
    });
  }

  ledger(id: string): LedgerEntry[] {
    return this.data.ledger.filter((e) => e.accountId === id || id === "*");
  }

  /**
   * Run `mutate` against state freshly read from disk, then write the result
   * atomically — all while holding the lock file.
   */
  private withLock(mutate: () => void): void {
    mkdirSync(dirname(this.path), { recursive: true });
    this.acquireLock();
    try {
      this.data = this.read();
      mutate();
      this.write();
    } finally {
      this.releaseLock();
    }
  }

  private acquireLock(): void {
    const deadline = Date.now() + LOCK_TIMEOUT_MS;
    for (;;) {
      try {
        writeFileSync(this.lockPath, this.lockToken, { flag: "wx" });
        return;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
        // Break a lock abandoned by a crashed run rather than deadlocking.
        try {
          if (Date.now() - statSync(this.lockPath).mtimeMs > LOCK_STALE_MS) {
            log.warn(
              { component: "billing.account-store", path: this.lockPath },
              "Removing stale account-store lock",
            );
            rmSync(this.lockPath, { force: true });
            continue;
          }
        } catch {
          // The lock vanished between the two calls: retry immediately.
          continue;
        }
        if (Date.now() >= deadline) {
          throw new Error(
            `Timed out after ${LOCK_TIMEOUT_MS}ms waiting for the account-store ` +
              `lock at ${this.lockPath}. Another audit is probably still settling.`,
            { cause: err },
          );
        }
        sleepSync(LOCK_POLL_MS);
      }
    }
  }

  /**
   * Release the lock, but only if we still hold it.
   *
   * `rmSync` unconditionally was a second-order bug. The stale break above can
   * revoke a lock held by a process that stalled past `LOCK_STALE_MS`; that
   * process then finished its critical section and deleted whatever lock file
   * it found — its *successor's* — admitting a third writer while the second
   * was mid read-modify-write. That converted a bounded two-writer race into an
   * unbounded one. Reading the token back turns the wrong case into a warning
   * instead of a cascade.
   */
  private releaseLock(): void {
    try {
      const held = readFileSync(this.lockPath, "utf8");
      if (held !== this.lockToken) {
        log.warn(
          { component: "billing.account-store", path: this.lockPath },
          "Account-store lock was taken over by another run; leaving it alone",
        );
        return;
      }
      rmSync(this.lockPath, { force: true });
    } catch (err) {
      // ENOENT means someone already broke it — same situation, nothing to do.
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
      log.warn(
        { component: "billing.account-store", path: this.lockPath, err: String(err) },
        "Could not remove account-store lock",
      );
    }
  }

  private read(): StoreShape {
    if (!existsSync(this.path)) return emptyShape();
    let parsed: Partial<StoreShape>;
    try {
      parsed = JSON.parse(readFileSync(this.path, "utf8")) as Partial<StoreShape>;
    } catch (err) {
      // Never degrade a damaged balance file into a fresh, fully-funded account.
      throw new AccountStoreCorruptError(this.path, err);
    }
    return {
      accounts: parsed.accounts ?? {},
      ledger: Array.isArray(parsed.ledger) ? parsed.ledger : [],
      revs: parsed.revs ?? {},
    };
  }

  /** Atomic write: stage to a temp file, then rename over the target. */
  private write(): void {
    const tmp = `${this.path}.${process.pid}.tmp`;
    try {
      writeFileSync(tmp, JSON.stringify(this.data, null, 2));
      renameSync(tmp, this.path);
    } catch (err) {
      try {
        rmSync(tmp, { force: true, recursive: true });
      } catch {
        // Cleanup is best-effort; it must never mask the real write failure.
      }
      // Throw: a charge that could not be recorded must not look settled.
      throw new Error(
        `Could not persist the billing account store at ${this.path}: ${String(err)}`,
        { cause: err },
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
