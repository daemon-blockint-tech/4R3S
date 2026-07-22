/**
 * Billing configuration, loaded from the environment.
 *
 * Kept separate from `src/config/env.ts` (which validates core ARES config at
 * import) so billing stays modular and opt-in: with `BILLING_ENABLED` unset,
 * nothing here affects a normal audit run. Read lazily via `loadBillingConfig`
 * so tests can inject env.
 */

export interface BillingConfig {
  /** Master switch. When false, ARES does no metering or settlement. */
  enabled: boolean;
  /** USD value of one credit (default $0.01 → 100 credits = $1). */
  creditUsd: number;
  /** Margin applied to raw provider cost before charging (1.0 = at cost). */
  markup: number;
  /**
   * Guaranteed minimum gross margin as a fraction of revenue. The effective
   * markup is floored at `1 + minMarginPct`, so a charge can never sell below
   * cost even if `markup` is misconfigured. Default 0.20 (20%).
   */
  minMarginPct: number;
  /** Minimum credits billed per audit, so tiny runs still turn a profit. */
  minChargeCredits: number;
  /** Prepaid system-credit allotment granted at the start of a run/plan. */
  planCredits: number;
  /** Allow pay-as-you-go overflow once system credits are exhausted. */
  onDemandEnabled: boolean;
  /** Optional cap on total on-demand credits; undefined = unlimited. */
  onDemandLimitCredits?: number;
  /** MPP settlement endpoint; unset → hermetic local settlement. */
  mppEndpoint?: string;
  /**
   * When an `mppEndpoint` is set but the real HTTP-402 client isn't wired,
   * allow falling back to hermetic local settlement. Defaults to false so a
   * configured endpoint fails loudly rather than silently pretending to settle
   * real money locally.
   */
  mppAllowLocalFallback: boolean;
  /** Payer identity presented to MPP. */
  mppPayerId: string;
}

function num(raw: string | undefined, fallback: number): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

function bool(raw: string | undefined, fallback = false): boolean {
  if (raw === undefined) return fallback;
  return /^(1|true|yes|on)$/i.test(raw.trim());
}

/** Load billing config from `env` (defaults to `process.env`). */
export function loadBillingConfig(
  env: NodeJS.ProcessEnv = process.env,
): BillingConfig {
  const onDemandLimit = env.BILLING_ONDEMAND_LIMIT_CREDITS;
  return {
    enabled: bool(env.BILLING_ENABLED, false),
    creditUsd: num(env.BILLING_CREDIT_USD, 0.01),
    markup: num(env.BILLING_MARKUP, 1.3),
    minMarginPct: num(env.BILLING_MIN_MARGIN_PCT, 0.2),
    minChargeCredits: num(env.BILLING_MIN_CHARGE_CREDITS, 1),
    planCredits: num(env.BILLING_PLAN_CREDITS, 0),
    onDemandEnabled: bool(env.BILLING_ONDEMAND_ENABLED, false),
    onDemandLimitCredits:
      onDemandLimit && onDemandLimit.trim() !== ""
        ? num(onDemandLimit, 0)
        : undefined,
    mppEndpoint: env.MPP_ENDPOINT?.trim() || undefined,
    mppAllowLocalFallback: bool(env.MPP_ALLOW_LOCAL_FALLBACK, false),
    mppPayerId: env.MPP_PAYER_ID?.trim() || "ares-agent",
  };
}
