import { describe, it, expect } from "vitest";

import {
  effectiveMarkup,
  computeProfit,
  aggregateProfit,
} from "./profit.js";
import { loadBillingConfig, type BillingConfig } from "./config.js";

function config(over: Partial<BillingConfig> = {}): BillingConfig {
  return { ...loadBillingConfig({}), ...over };
}

describe("effectiveMarkup — the profit guarantee", () => {
  it("honors a configured markup above the floor", () => {
    expect(effectiveMarkup(config({ markup: 1.5, minMarginPct: 0.2 }))).toBe(1.5);
  });

  it("floors a below-margin markup up to 1 + minMarginPct", () => {
    // A misconfigured markup of 1.05 with a 20% min margin is clamped to 1.2.
    expect(effectiveMarkup(config({ markup: 1.05, minMarginPct: 0.2 }))).toBeCloseTo(1.2);
  });

  it("never sells below cost, even if markup < 1 and minMargin is 0", () => {
    expect(effectiveMarkup(config({ markup: 0.5, minMarginPct: 0 }))).toBe(1);
  });
});

describe("computeProfit", () => {
  it("computes profit and margin", () => {
    const p = computeProfit(1.0, 1.3);
    expect(p.profitUsd).toBeCloseTo(0.3);
    expect(p.marginPct).toBeCloseTo(0.3 / 1.3);
  });

  it("is zero-margin on zero revenue", () => {
    expect(computeProfit(0, 0)).toMatchObject({ profitUsd: 0, marginPct: 0 });
  });
});

describe("aggregateProfit", () => {
  it("rolls up cost, revenue, and blended margin", () => {
    const report = aggregateProfit([
      computeProfit(1.0, 1.3),
      computeProfit(2.0, 3.0),
    ]);
    expect(report.audits).toBe(2);
    expect(report.costUsd).toBeCloseTo(3.0);
    expect(report.revenueUsd).toBeCloseTo(4.3);
    expect(report.profitUsd).toBeCloseTo(1.3);
    expect(report.marginPct).toBeCloseTo(1.3 / 4.3);
  });
});
