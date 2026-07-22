/**
 * ARES billing — a credits/monetization layer over the audit engine.
 *
 * Model: audits consume LLM tokens (priced by `pricing.ts`), which are marked
 * up with a guaranteed margin and charged in **credits** against a two-tier
 * account (`credits.ts`): prepaid **system credits** first, then pay-as-you-go
 * **on-demand** credits settled via the Machine Payments Protocol (`mpp.ts`).
 * `meter.ts` accumulates usage and settles a run; `profit.ts` guarantees every
 * charge earns margin over cost.
 *
 * Opt-in: with `BILLING_ENABLED` unset, none of this runs.
 */
export * from "./pricing.js";
export * from "./credits.js";
export * from "./mpp.js";
export * from "./meter.js";
export * from "./profit.js";
export * from "./config.js";
export * from "./account-store.js";
export { extractUsage } from "./usage.js";

import { log } from "../config/logger.js";
import { CreditLedger, type CreditAccount } from "./credits.js";
import { createMppClient, type MppClient } from "./mpp.js";
import { UsageMeter } from "./meter.js";
import { extractUsage } from "./usage.js";
import { loadBillingConfig, type BillingConfig } from "./config.js";
import {
  createAccountStore,
  type AccountStore,
} from "./account-store.js";

/**
 * Wrap a chat model so every `invoke` records its token usage into `meter`,
 * without changing behavior. Non-`invoke` members are passed through; usage
 * extraction is best-effort and never throws into the audit path.
 */
export function meterChat<T extends { invoke: (...args: never[]) => Promise<unknown> }>(
  chat: T,
  meter: UsageMeter,
): T {
  return new Proxy(chat, {
    get(target, prop, receiver) {
      if (prop === "invoke") {
        return async (...args: never[]) => {
          const res = await target.invoke(...args);
          try {
            meter.record(extractUsage(res));
          } catch {
            /* metering must never break an audit */
          }
          return res;
        };
      }
      const value = Reflect.get(target, prop, receiver);
      return typeof value === "function"
        ? (value as (...a: unknown[]) => unknown).bind(target)
        : value;
    },
  });
}

/** A ready-to-use billing context for one account/run. */
export interface Billing {
  config: BillingConfig;
  account: CreditAccount;
  ledger: CreditLedger;
  mpp: MppClient;
  meter: UsageMeter;
  /** Durable account store, when persistence is configured. */
  store?: AccountStore;
}

export interface CreateBillingOptions {
  config?: BillingConfig;
  accountId?: string;
  /** Durable account store; defaults to `createAccountStore()` (env-driven). */
  store?: AccountStore;
}

/**
 * Assemble a billing context from config. When a durable `store` is available
 * and holds this account, the saved balances (prepaid remaining + on-demand
 * spent) are loaded so spend accumulates across runs; otherwise the account is
 * seeded fresh from the plan's prepaid allotment. Uses hermetic local MPP
 * settlement unless `MPP_ENDPOINT` is set.
 */
export function createBilling(options: CreateBillingOptions = {}): Billing {
  const config = options.config ?? loadBillingConfig();
  const accountId = options.accountId ?? "default";
  const store = options.store ?? createAccountStore();

  const persisted = store?.load(accountId);
  const account: CreditAccount = persisted ?? {
    id: accountId,
    systemCredits: Math.max(0, config.planCredits),
    onDemandEnabled: config.onDemandEnabled,
    onDemandSpent: 0,
    onDemandLimit: config.onDemandLimitCredits,
  };
  // Keep persisted balances but let config toggle on-demand policy each run.
  if (persisted) {
    account.onDemandEnabled = config.onDemandEnabled;
    account.onDemandLimit = config.onDemandLimitCredits;
  }

  return {
    config,
    account,
    ledger: new CreditLedger(account, store),
    mpp: createMppClient({
      endpoint: config.mppEndpoint,
      allowLocalFallback: config.mppAllowLocalFallback,
      payerId: config.mppPayerId,
    }),
    meter: new UsageMeter(),
    store,
  };
}

/**
 * Pre-flight sanity check: with billing enabled, warn loudly if the account
 * cannot possibly pay for a run — no prepaid balance and on-demand disabled —
 * so a misconfiguration surfaces before the audit runs rather than as an
 * `InsufficientCreditsError` after value has already been produced. Returns
 * false when the account is structurally unable to settle any non-zero charge.
 */
export function canAffordAudit(billing: Billing): boolean {
  const { account, config } = billing;
  if (!config.enabled) return true;
  const affordable = account.systemCredits > 0 || account.onDemandEnabled;
  if (!affordable) {
    log.warn(
      {
        component: "billing",
        accountId: account.id,
        systemCredits: account.systemCredits,
        onDemandEnabled: account.onDemandEnabled,
      },
      "Billing enabled but account has no prepaid balance and on-demand is disabled; " +
        "any non-zero charge will fail. Set BILLING_PLAN_CREDITS or BILLING_ONDEMAND_ENABLED.",
    );
  }
  return affordable;
}
