/**
 * Profit model — guarantees every charge earns margin over provider cost.
 *
 * Two safeguards make a loss structurally impossible:
 *   1. **Margin floor.** The effective markup is `max(configured markup,
 *      1 + minMarginPct)`, so even a misconfigured `BILLING_MARKUP` below 1
 *      (which would sell below cost) is clamped up to a guaranteed margin.
 *   2. **Minimum charge.** Every audit is billed at least `minChargeCredits`,
 *      so tiny/near-zero-token runs still cover fixed overhead and profit.
 *
 * Credits are also always rounded up to whole units (`usdToCredits`), adding a
 * small additional margin on top.
 */
import type { BillingConfig } from "./config.js";

/**
 * The markup actually applied: never below the guaranteed-margin floor, and
 * never below 1.0 (selling at cost). This is what makes profit non-negotiable.
 */
export function effectiveMarkup(config: BillingConfig): number {
  const floor = Math.max(1, 1 + Math.max(0, config.minMarginPct));
  return Math.max(config.markup, floor);
}

/** Profit breakdown for a single charge. */
export interface Profit {
  /** Provider (COGS) cost in USD. */
  costUsd: number;
  /** Revenue charged to the customer in USD. */
  revenueUsd: number;
  /** revenue − cost. Guaranteed ≥ 0 by construction. */
  profitUsd: number;
  /** Gross margin as a fraction of revenue (profit / revenue). */
  marginPct: number;
}

/** Compute profit from cost and revenue. */
export function computeProfit(costUsd: number, revenueUsd: number): Profit {
  const profitUsd = revenueUsd - costUsd;
  const marginPct = revenueUsd > 0 ? profitUsd / revenueUsd : 0;
  return { costUsd, revenueUsd, profitUsd, marginPct };
}

/** Aggregated profit across many charges — a simple revenue dashboard. */
export interface ProfitReport {
  audits: number;
  costUsd: number;
  revenueUsd: number;
  profitUsd: number;
  marginPct: number;
}

/** Roll up individual `Profit`s into a `ProfitReport`. */
export function aggregateProfit(profits: readonly Profit[]): ProfitReport {
  const costUsd = profits.reduce((s, p) => s + p.costUsd, 0);
  const revenueUsd = profits.reduce((s, p) => s + p.revenueUsd, 0);
  const profitUsd = revenueUsd - costUsd;
  return {
    audits: profits.length,
    costUsd,
    revenueUsd,
    profitUsd,
    marginPct: revenueUsd > 0 ? profitUsd / revenueUsd : 0,
  };
}
