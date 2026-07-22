import { describe, it, expect } from "vitest";

import { createBilling, canAffordAudit } from "./index.js";
import { InMemoryAccountStore } from "./account-store.js";
import { loadBillingConfig, type BillingConfig } from "./config.js";
import type { CreditAccount } from "./credits.js";

function config(over: Partial<BillingConfig> = {}): BillingConfig {
  return { ...loadBillingConfig({}), enabled: true, ...over };
}

describe("createBilling — account hydration", () => {
  it("seeds a fresh account from planCredits when the store is empty", () => {
    const store = new InMemoryAccountStore();
    const billing = createBilling({
      config: config({ planCredits: 500 }),
      store,
    });
    expect(billing.account.systemCredits).toBe(500);
    expect(billing.account.onDemandSpent).toBe(0);
  });

  it("loads persisted balances instead of reseeding", () => {
    const store = new InMemoryAccountStore();
    const persisted: CreditAccount = {
      id: "default",
      systemCredits: 12,
      onDemandEnabled: false,
      onDemandSpent: 88,
    };
    store.save(persisted);

    const billing = createBilling({
      config: config({ planCredits: 500 }),
      store,
    });
    // Persisted balance wins over the plan allotment; spend carries over.
    expect(billing.account.systemCredits).toBe(12);
    expect(billing.account.onDemandSpent).toBe(88);
  });

  it("lets config re-toggle on-demand policy on a persisted account", () => {
    const store = new InMemoryAccountStore();
    store.save({
      id: "default",
      systemCredits: 0,
      onDemandEnabled: false,
      onDemandSpent: 0,
    });
    const billing = createBilling({
      config: config({ onDemandEnabled: true, onDemandLimitCredits: 50 }),
      store,
    });
    expect(billing.account.onDemandEnabled).toBe(true);
    expect(billing.account.onDemandLimit).toBe(50);
  });

  it("persists ledger debits through the store sink", () => {
    const store = new InMemoryAccountStore();
    const billing = createBilling({
      config: config({ planCredits: 100 }),
      store,
    });
    billing.ledger.charge(20, "audit", "default");
    expect(store.ledger("default")).toHaveLength(1);
  });
});

describe("canAffordAudit", () => {
  it("is always true when billing is disabled", () => {
    const billing = createBilling({ config: config({ enabled: false }) });
    expect(canAffordAudit(billing)).toBe(true);
  });

  it("is true with prepaid balance", () => {
    const billing = createBilling({ config: config({ planCredits: 10 }) });
    expect(canAffordAudit(billing)).toBe(true);
  });

  it("is true with on-demand enabled even at zero balance", () => {
    const billing = createBilling({
      config: config({ planCredits: 0, onDemandEnabled: true }),
    });
    expect(canAffordAudit(billing)).toBe(true);
  });

  it("is false with no balance and on-demand disabled", () => {
    const billing = createBilling({
      config: config({ planCredits: 0, onDemandEnabled: false }),
    });
    expect(canAffordAudit(billing)).toBe(false);
  });
});
