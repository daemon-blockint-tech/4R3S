/**
 * Bounded retry with exponential backoff for transient LLM failures.
 *
 * The audit graph makes several sequential + parallel LLM calls per run
 * (intake, four analyzers, verify, remember, report). Without retry, a single
 * transient blip — a 429 rate-limit, a 5xx, or a dropped socket from
 * OpenRouter — aborts the entire audit. `withRetry` re-attempts only errors
 * that look transient, backing off exponentially (with jitter) between tries,
 * and re-throws immediately on errors that will never succeed on retry
 * (malformed request, auth failure, not-found).
 */
import { logger } from "../config/logger.js";

export interface RetryOptions {
  /** Retries after the first attempt (so total attempts = retries + 1). Default 3. */
  retries?: number;
  /** Initial backoff in ms; doubled each retry. Default 250. */
  baseDelayMs?: number;
  /** Upper bound on any single backoff. Default 8000. */
  maxDelayMs?: number;
  /** Add random jitter (0..delay) to avoid thundering-herd retries. Default true. */
  jitter?: boolean;
  /** Predicate deciding whether an error is worth retrying. Default `isTransientError`. */
  isRetryable?: (err: unknown) => boolean;
  /** Sleep function; injectable so tests run without real delays. */
  sleep?: (ms: number) => Promise<void>;
  /** Label for logs. */
  label?: string;
}

const DEFAULTS: Required<Omit<RetryOptions, "label">> = {
  retries: 3,
  baseDelayMs: 250,
  maxDelayMs: 8000,
  jitter: true,
  isRetryable: isTransientError,
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
};

/** Best-effort extraction of an HTTP-ish status code from an unknown error. */
function statusOf(err: unknown): number | undefined {
  if (!err || typeof err !== "object") return undefined;
  const e = err as Record<string, unknown>;
  const direct = e.status ?? e.statusCode ?? e.code;
  if (typeof direct === "number") return direct;
  const resp = e.response;
  if (resp && typeof resp === "object") {
    const s = (resp as Record<string, unknown>).status;
    if (typeof s === "number") return s;
  }
  return undefined;
}

/**
 * Heuristic: is this error likely to succeed if retried? Retries rate-limits
 * (429), server errors (5xx), and connection-level failures; refuses to retry
 * client errors (4xx other than 429), which are deterministic.
 */
export function isTransientError(err: unknown): boolean {
  const status = statusOf(err);
  if (typeof status === "number") {
    if (status === 429) return true;
    if (status >= 500 && status <= 599) return true;
    if (status >= 400 && status <= 499) return false; // deterministic client error
  }
  // Network-level errors surface as messages/codes rather than HTTP status.
  const msg = String(
    (err as { message?: unknown })?.message ?? err ?? "",
  ).toLowerCase();
  return (
    msg.includes("econnreset") ||
    msg.includes("etimedout") ||
    msg.includes("econnrefused") ||
    msg.includes("enotfound") ||
    msg.includes("timeout") ||
    msg.includes("socket hang up") ||
    msg.includes("network") ||
    msg.includes("fetch failed") ||
    msg.includes("rate limit") ||
    msg.includes("overloaded")
  );
}

/**
 * Run `fn`, retrying transient failures with exponential backoff. Non-transient
 * errors (and exhaustion of the retry budget) propagate to the caller.
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {},
): Promise<T> {
  const cfg = { ...DEFAULTS, ...options };
  let attempt = 0;
  for (;;) {
    try {
      return await fn();
    } catch (err) {
      const canRetry = attempt < cfg.retries && cfg.isRetryable(err);
      if (!canRetry) throw err;
      const backoff = Math.min(cfg.maxDelayMs, cfg.baseDelayMs * 2 ** attempt);
      const delay = cfg.jitter ? Math.random() * backoff : backoff;
      logger.warn(
        {
          component: "llm.retry",
          label: options.label,
          attempt: attempt + 1,
          retries: cfg.retries,
          delayMs: Math.round(delay),
          err: String((err as { message?: unknown })?.message ?? err),
        },
        "Transient LLM error; retrying after backoff",
      );
      await cfg.sleep(delay);
      attempt += 1;
    }
  }
}
