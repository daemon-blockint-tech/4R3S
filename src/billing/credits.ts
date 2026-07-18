/**
 * Credit accounting — the two-tier business model on top of raw token cost.
 *
 * ARES sells access in **credits**. One credit is a fixed slice of USD
 * (default $0.01, i.e. 100 credits = $1 — mirroring the "Consumption Unit"
 * convention). An audit's raw provider cost is marked up by a margin, converted
 * to credits, and charged against an account with two tiers:
 *
 *   1. **System credits** — a prepaid balance (a subscription's monthly
 *      allotment, or a one-off top-up). Drawn down first.
 *   2. **On-demand credits** — pay-as-you-go overflow once the prepaid balance
 *      is exhausted. Accrued as postpaid usage and settled out-of-band (see
 *      `mpp.ts`). Off unless the account opts in, and optionally capped.
 *
 * A ledger records every grant and debit for auditability.
 */
import { v4 as uuidv4 } from "uuid";

/** Convert a USD amount to whole credits (rounded up so we never under-charge). */
export function usdToCredits(usd: number, creditUsd: number): number {
  if (creditUsd <= 0) throw new Error("creditUsd must be > 0");
  return Math.ceil(Math.max(0, usd) / creditUsd);
}

/** Convert credits back to USD. */
export function creditsToUsd(credits: number, creditUsd: number): number {
  return credits * creditUsd;
}

/** A billing account with prepaid + on-demand tiers. */
export interface CreditAccount {
  id: string;
  /** Prepaid balance in credits (drawn down first). */
  systemCredits: number;
  /** Whether pay-as-you-go overflow is allowed once system credits run out. */
  onDemandEnabled: boolean;
  /** Postpaid credits accrued via on-demand (settled out-of-band). */
  onDemandSpent: number;
  /** Optional ceiling on total on-demand credits; undefined = unlimited. */
  onDemandLimit?: number;
}

/** One immutable ledger record. */
export interface LedgerEntry {
  id: string;
  at: number;
  kind: "grant" | "debit";
  /** Total credits moved by this entry (magnitude, always positive). */
  credits: number;
  /** For a debit: how many credits came from the prepaid balance. */
  fromSystem: number;
  /** For a debit: how many credits were billed on-demand (postpaid). */
  fromOnDemand: number;
  reason: string;
  /** Optional external reference (audit thread id, MPP receipt id, …). */
  ref?: string;
}

/** Outcome of a charge. */
export interface DebitResult {
  credits: number;
  fromSystem: number;
  fromOnDemand: number;
  /** True when on-demand credits were used and therefore need settlement. */
  requiresSettlement: boolean;
}

/** Thrown when a charge can't be covered by prepaid balance or on-demand. */
export class InsufficientCreditsError extends Error {
  constructor(
    readonly needed: number,
    readonly available: number,
  ) {
    super(
      `Insufficient credits: need ${needed}, have ${available} (on-demand exhausted or disabled)`,
    );
    this.name = "InsufficientCreditsError";
  }
}

/** Optional persistence hook; defaults to in-memory. */
export interface LedgerSink {
  append(entry: LedgerEntry): void;
}

/**
 * Mutable ledger over a single account. Draws prepaid balance first, then
 * on-demand. In-memory by default; pass a `LedgerSink` to also persist entries.
 */
export class CreditLedger {
  private readonly entries: LedgerEntry[] = [];

  constructor(
    private readonly account: CreditAccount,
    private readonly sink?: LedgerSink,
  ) {}

  /** Add prepaid (system) credits — a subscription refill or top-up. */
  grant(credits: number, reason: string, ref?: string): LedgerEntry {
    if (credits <= 0) throw new Error("grant credits must be > 0");
    this.account.systemCredits += credits;
    return this.record({
      kind: "grant",
      credits,
      fromSystem: credits,
      fromOnDemand: 0,
      reason,
      ref,
    });
  }

  /**
   * Charge `credits`, drawing the prepaid balance first and overflowing to
   * on-demand when enabled (and within `onDemandLimit`). Throws
   * `InsufficientCreditsError` if the charge can't be covered.
   */
  charge(credits: number, reason: string, ref?: string): DebitResult {
    if (credits < 0) throw new Error("charge credits must be >= 0");
    const fromSystem = Math.min(this.account.systemCredits, credits);
    const overflow = credits - fromSystem;

    if (overflow > 0) {
      if (!this.account.onDemandEnabled) {
        throw new InsufficientCreditsError(credits, this.account.systemCredits);
      }
      if (this.account.onDemandLimit !== undefined) {
        const remaining = this.account.onDemandLimit - this.account.onDemandSpent;
        if (overflow > remaining) {
          throw new InsufficientCreditsError(
            credits,
            this.account.systemCredits + Math.max(0, remaining),
          );
        }
      }
    }

    this.account.systemCredits -= fromSystem;
    this.account.onDemandSpent += overflow;

    this.record({
      kind: "debit",
      credits,
      fromSystem,
      fromOnDemand: overflow,
      reason,
      ref,
    });

    return {
      credits,
      fromSystem,
      fromOnDemand: overflow,
      requiresSettlement: overflow > 0,
    };
  }

  /** Current balances. */
  balance(): { systemCredits: number; onDemandSpent: number } {
    return {
      systemCredits: this.account.systemCredits,
      onDemandSpent: this.account.onDemandSpent,
    };
  }

  /** Immutable copy of the full ledger, oldest first. */
  history(): readonly LedgerEntry[] {
    return [...this.entries];
  }

  private record(partial: Omit<LedgerEntry, "id" | "at">): LedgerEntry {
    const entry: LedgerEntry = { id: uuidv4(), at: Date.now(), ...partial };
    this.entries.push(entry);
    this.sink?.append(entry);
    return entry;
  }
}
