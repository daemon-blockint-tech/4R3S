import { describe, it, expect } from "vitest";

import {
  CreditLedger,
  InsufficientCreditsError,
  usdToCredits,
  creditsToUsd,
  type CreditAccount,
} from "./credits.js";

const CREDIT_USD = 0.01;

function account(over: Partial<CreditAccount> = {}): CreditAccount {
  return {
    id: "acct-1",
    systemCredits: 0,
    onDemandEnabled: false,
    onDemandSpent: 0,
    ...over,
  };
}

describe("usd<->credit conversion", () => {
  it("rounds credits up so we never under-charge", () => {
    expect(usdToCredits(0.011, CREDIT_USD)).toBe(2); // $0.011 → 2 credits
    expect(usdToCredits(0.01, CREDIT_USD)).toBe(1);
    expect(usdToCredits(0, CREDIT_USD)).toBe(0);
  });

  it("round-trips credits to usd", () => {
    expect(creditsToUsd(250, CREDIT_USD)).toBeCloseTo(2.5);
  });

  it("rejects a non-positive credit unit", () => {
    expect(() => usdToCredits(1, 0)).toThrow();
  });
});

describe("CreditLedger — prepaid (system) tier", () => {
  it("grants and debits from the system balance", () => {
    const acct = account({ systemCredits: 100 });
    const ledger = new CreditLedger(acct);
    const debit = ledger.charge(30, "audit A");
    expect(debit).toMatchObject({ fromSystem: 30, fromOnDemand: 0, requiresSettlement: false });
    expect(ledger.balance().systemCredits).toBe(70);
  });

  it("throws when balance is exhausted and on-demand is disabled", () => {
    const ledger = new CreditLedger(account({ systemCredits: 10 }));
    expect(() => ledger.charge(25, "audit B")).toThrow(InsufficientCreditsError);
  });

  it("records grant + debit entries in the ledger", () => {
    const ledger = new CreditLedger(account());
    ledger.grant(100, "monthly plan");
    ledger.charge(40, "audit C");
    const history = ledger.history();
    expect(history).toHaveLength(2);
    expect(history[0]!.kind).toBe("grant");
    expect(history[1]!.kind).toBe("debit");
  });
});

describe("CreditLedger — on-demand (postpaid) tier", () => {
  it("overflows to on-demand once prepaid is spent", () => {
    const acct = account({ systemCredits: 10, onDemandEnabled: true });
    const ledger = new CreditLedger(acct);
    const debit = ledger.charge(25, "audit D");
    expect(debit).toMatchObject({ fromSystem: 10, fromOnDemand: 15, requiresSettlement: true });
    expect(ledger.balance()).toEqual({ systemCredits: 0, onDemandSpent: 15 });
  });

  it("enforces the on-demand limit", () => {
    const acct = account({
      systemCredits: 0,
      onDemandEnabled: true,
      onDemandLimit: 20,
    });
    const ledger = new CreditLedger(acct);
    ledger.charge(20, "ok");
    expect(() => ledger.charge(1, "over the cap")).toThrow(InsufficientCreditsError);
  });
});
