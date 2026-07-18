/**
 * Usage metering + settlement — the glue between an audit run and billing.
 *
 * A `UsageMeter` accumulates token usage across every LLM call in a run. At the
 * end, `settleUsage` prices that usage (`pricing.ts`), applies the business
 * margin and converts to credits (`credits.ts`), charges the account
 * prepaid-first, and — when the charge overflows into on-demand — settles the
 * overflow through MPP (`mpp.ts`).
 */
import { log } from "../config/logger.js";
import { computeUsdCost, type TokenUsage } from "./pricing.js";
import {
  CreditLedger,
  usdToCredits,
  creditsToUsd,
  type DebitResult,
} from "./credits.js";
import {
  createChallenge,
  type MppClient,
  type MppReceipt,
} from "./mpp.js";
import { effectiveMarkup, computeProfit, type Profit } from "./profit.js";
import type { BillingConfig } from "./config.js";

/** Accumulates token usage across the calls in a run. */
export class UsageMeter {
  private readonly totals: Required<TokenUsage> = {
    inputTokens: 0,
    outputTokens: 0,
    cacheWrite5mTokens: 0,
    cacheWrite1hTokens: 0,
    cacheReadTokens: 0,
    webSearches: 0,
  };

  /** Add one call's usage to the running totals. */
  record(usage: TokenUsage): void {
    this.totals.inputTokens += Math.max(0, usage.inputTokens ?? 0);
    this.totals.outputTokens += Math.max(0, usage.outputTokens ?? 0);
    this.totals.cacheWrite5mTokens += Math.max(0, usage.cacheWrite5mTokens ?? 0);
    this.totals.cacheWrite1hTokens += Math.max(0, usage.cacheWrite1hTokens ?? 0);
    this.totals.cacheReadTokens += Math.max(0, usage.cacheReadTokens ?? 0);
    this.totals.webSearches += Math.max(0, usage.webSearches ?? 0);
  }

  /** Snapshot of accumulated usage. */
  snapshot(): TokenUsage {
    return { ...this.totals };
  }

  reset(): void {
    for (const k of Object.keys(this.totals) as (keyof TokenUsage)[]) {
      this.totals[k] = 0;
    }
  }
}

/** Priced, charged, and (if needed) settled result of a run. */
export interface BillingResult {
  model: string;
  usage: TokenUsage;
  /** Raw provider cost before margin. */
  providerUsd: number;
  /** Amount charged to the customer (providerUsd × markup). */
  chargedUsd: number;
  /** Credits debited. */
  credits: number;
  debit: DebitResult;
  /** Cost / revenue / profit breakdown — always non-negative profit. */
  profit: Profit;
  /** MPP receipt when on-demand overflow was settled; undefined otherwise. */
  receipt?: MppReceipt;
  /** One-line human-readable summary. */
  summary: string;
}

/**
 * Price `usage`, charge the account, and settle any on-demand overflow via MPP.
 * `resource` labels the settlement (e.g. the audit thread id).
 */
export async function settleUsage(opts: {
  usage: TokenUsage;
  model: string;
  ledger: CreditLedger;
  mpp: MppClient;
  config: BillingConfig;
  resource: string;
}): Promise<BillingResult> {
  const { usage, model, ledger, mpp, config, resource } = opts;

  const providerUsd = computeUsdCost(usage, model);
  // Guaranteed-profit pricing: floor the markup at the minimum margin, then
  // floor the credit count at the per-audit minimum so no run bills below cost.
  const chargedUsd = providerUsd * effectiveMarkup(config);
  const credits = Math.max(
    config.minChargeCredits,
    usdToCredits(chargedUsd, config.creditUsd),
  );
  // Revenue is the credits actually billed (post-rounding, post-floor).
  const revenueUsd = creditsToUsd(credits, config.creditUsd);
  const profit = computeProfit(providerUsd, revenueUsd);

  const debit = ledger.charge(credits, `audit ${resource}`, resource);

  let receipt: MppReceipt | undefined;
  if (debit.requiresSettlement && debit.fromOnDemand > 0) {
    const owedUsd = creditsToUsd(debit.fromOnDemand, config.creditUsd);
    const challenge = createChallenge(resource, owedUsd, "pay-per-request");
    receipt = await mpp.settle(challenge, {
      challengeNonce: challenge.nonce,
      payerId: config.mppPayerId,
      token: `voucher-${challenge.nonce}`,
    });
  }

  const summary =
    `Billed ${credits} credits ($${revenueUsd.toFixed(4)}) for ${model}: ` +
    `cost $${providerUsd.toFixed(4)}, profit $${profit.profitUsd.toFixed(4)} ` +
    `(${(profit.marginPct * 100).toFixed(1)}% margin); ` +
    `${debit.fromSystem} from balance` +
    (debit.fromOnDemand > 0
      ? `, ${debit.fromOnDemand} on-demand${receipt ? ` (MPP ${receipt.receiptId.slice(0, 8)})` : ""}`
      : "");

  log.info("Usage settled", {
    component: "billing.meter",
    model,
    providerUsd,
    revenueUsd,
    profitUsd: profit.profitUsd,
    marginPct: profit.marginPct,
    credits,
    fromSystem: debit.fromSystem,
    fromOnDemand: debit.fromOnDemand,
    settled: Boolean(receipt),
  });

  return {
    model,
    usage,
    providerUsd,
    chargedUsd: revenueUsd,
    credits,
    debit,
    profit,
    receipt,
    summary,
  };
}
