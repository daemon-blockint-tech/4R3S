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
export { extractUsage } from "./usage.js";

import { CreditLedger, type CreditAccount } from "./credits.js";
import { createMppClient, type MppClient } from "./mpp.js";
import { UsageMeter } from "./meter.js";
import { extractUsage } from "./usage.js";
import { loadBillingConfig, type BillingConfig } from "./config.js";

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
}

/**
 * Assemble a billing context from config, seeding the account with the plan's
 * prepaid allotment. Uses hermetic local MPP settlement unless `MPP_ENDPOINT`
 * is set.
 */
export function createBilling(
  config: BillingConfig = loadBillingConfig(),
  accountId = "default",
): Billing {
  const account: CreditAccount = {
    id: accountId,
    systemCredits: Math.max(0, config.planCredits),
    onDemandEnabled: config.onDemandEnabled,
    onDemandSpent: 0,
    onDemandLimit: config.onDemandLimitCredits,
  };
  return {
    config,
    account,
    ledger: new CreditLedger(account),
    mpp: createMppClient({
      endpoint: config.mppEndpoint,
      payerId: config.mppPayerId,
    }),
    meter: new UsageMeter(),
  };
}
