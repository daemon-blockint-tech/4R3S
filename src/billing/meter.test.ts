import { describe, it, expect } from "vitest";

import { UsageMeter, settleUsage } from "./meter.js";
import { CreditLedger, type CreditAccount } from "./credits.js";
import { LocalMppClient, createChallenge } from "./mpp.js";
import { extractUsage } from "./usage.js";
import { loadBillingConfig, type BillingConfig } from "./config.js";

function config(over: Partial<BillingConfig> = {}): BillingConfig {
  return { ...loadBillingConfig({}), enabled: true, ...over };
}

function account(over: Partial<CreditAccount> = {}): CreditAccount {
  return { id: "a", systemCredits: 0, onDemandEnabled: false, onDemandSpent: 0, ...over };
}

describe("UsageMeter", () => {
  it("accumulates usage across calls", () => {
    const meter = new UsageMeter();
    meter.record({ inputTokens: 100, outputTokens: 50 });
    meter.record({ inputTokens: 200, cacheReadTokens: 10 });
    expect(meter.snapshot()).toMatchObject({
      inputTokens: 300,
      outputTokens: 50,
      cacheReadTokens: 10,
    });
    meter.reset();
    expect(meter.snapshot().inputTokens).toBe(0);
  });
});

describe("extractUsage", () => {
  it("reads canonical usage_metadata", () => {
    const usage = extractUsage({
      usage_metadata: {
        input_tokens: 1000,
        output_tokens: 200,
        input_token_details: { cache_read: 500, cache_creation: 100 },
      },
    });
    expect(usage).toMatchObject({
      inputTokens: 1000,
      outputTokens: 200,
      cacheReadTokens: 500,
      cacheWrite5mTokens: 100,
    });
  });

  it("reads OpenAI/OpenRouter response_metadata.tokenUsage", () => {
    const usage = extractUsage({
      response_metadata: { tokenUsage: { promptTokens: 42, completionTokens: 7 } },
    });
    expect(usage).toMatchObject({ inputTokens: 42, outputTokens: 7 });
  });

  it("returns empty usage for unknown shapes", () => {
    expect(extractUsage({ foo: "bar" })).toEqual({});
    expect(extractUsage(null)).toEqual({});
  });
});

describe("settleUsage — end to end", () => {
  const usage = { inputTokens: 1_000_000, outputTokens: 1_000_000 }; // opus: $30 cost

  it("charges prepaid credits and always earns a positive profit", async () => {
    const acct = account({ systemCredits: 100_000 });
    const ledger = new CreditLedger(acct);
    const result = await settleUsage({
      usage,
      model: "claude-opus-4-8",
      ledger,
      mpp: new LocalMppClient(),
      config: config({ markup: 1.3, creditUsd: 0.01 }),
      resource: "thread-1",
    });

    // $30 cost × 1.3 markup = $39 revenue = 3900 credits.
    expect(result.providerUsd).toBeCloseTo(30);
    expect(result.credits).toBe(3900);
    expect(result.profit.profitUsd).toBeGreaterThan(0);
    expect(result.profit.marginPct).toBeCloseTo(9 / 39, 2);
    expect(result.debit.fromSystem).toBe(3900);
    expect(result.receipt).toBeUndefined(); // fully covered by prepaid
  });

  it("settles on-demand overflow through MPP", async () => {
    const acct = account({ systemCredits: 1000, onDemandEnabled: true });
    const ledger = new CreditLedger(acct);
    const mpp = new LocalMppClient();
    const result = await settleUsage({
      usage,
      model: "claude-opus-4-8",
      ledger,
      mpp,
      config: config({ markup: 1.3 }),
      resource: "thread-2",
    });

    expect(result.debit.fromSystem).toBe(1000);
    expect(result.debit.fromOnDemand).toBe(2900);
    expect(result.receipt).toBeDefined();
    expect(result.receipt!.model).toBe("pay-per-request");
    expect(mpp.history()).toHaveLength(1);
  });

  it("guarantees profit even when markup is misconfigured below cost", async () => {
    const acct = account({ systemCredits: 1_000_000 });
    const result = await settleUsage({
      usage,
      model: "claude-opus-4-8",
      ledger: new CreditLedger(acct),
      mpp: new LocalMppClient(),
      // markup 0.5 would sell at a loss — the margin floor rescues it.
      config: config({ markup: 0.5, minMarginPct: 0.2 }),
      resource: "thread-3",
    });
    expect(result.chargedUsd).toBeGreaterThan(result.providerUsd);
    expect(result.profit.profitUsd).toBeGreaterThan(0);
  });

  it("applies the minimum per-audit charge to tiny runs", async () => {
    const result = await settleUsage({
      usage: { inputTokens: 1 }, // ~$0 cost
      model: "claude-opus-4-8",
      ledger: new CreditLedger(account({ systemCredits: 100 })),
      mpp: new LocalMppClient(),
      config: config({ minChargeCredits: 5 }),
      resource: "thread-4",
    });
    expect(result.credits).toBe(5);
  });
});

describe("LocalMppClient", () => {
  it("rejects a credential whose nonce does not match the challenge", async () => {
    const mpp = new LocalMppClient();
    const challenge = createChallenge("res", 1.0);
    await expect(
      mpp.settle(challenge, { challengeNonce: "wrong", payerId: "p", token: "t" }),
    ).rejects.toThrow();
  });
});
