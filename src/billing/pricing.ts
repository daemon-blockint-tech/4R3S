/**
 * Token-cost pricing for ARES's LLM usage.
 *
 * ARES bills each audit on the LLM tokens it consumes. This module turns a
 * `TokenUsage` record into a raw provider cost in USD, using a per-model rate
 * table (USD per million tokens). Rates track Anthropic's published pricing;
 * ARES routes through OpenRouter, which passes provider prices through, so the
 * table is keyed by both OpenRouter-style ids (`anthropic/claude-3.5-sonnet`)
 * and canonical Anthropic ids (`claude-opus-4-8`).
 *
 * The business layer (`credits.ts`) applies margin and converts USD to credits;
 * this module is pure provider cost, no markup.
 */

/** USD-per-million-token rates for one model. */
export interface ModelRate {
  /** Base input tokens. */
  input: number;
  /** Output tokens. */
  output: number;
  /** 5-minute prompt-cache write (1.25x input). */
  cacheWrite5m: number;
  /** 1-hour prompt-cache write (2x input). */
  cacheWrite1h: number;
  /** Prompt-cache read / hit (0.1x input). */
  cacheRead: number;
}

/** Token counts for a single call or an accumulated run. All fields optional. */
export interface TokenUsage {
  inputTokens?: number;
  outputTokens?: number;
  cacheWrite5mTokens?: number;
  cacheWrite1hTokens?: number;
  cacheReadTokens?: number;
  /** Server-side web searches performed (billed per search, not per token). */
  webSearches?: number;
}

/** Web search is billed at $10 per 1,000 searches. */
export const WEB_SEARCH_USD = 10 / 1000;

const TOKENS_PER_MILLION = 1_000_000;

/**
 * Build a rate from just input+output, deriving the cache multipliers from the
 * standard Anthropic ratios (5m write 1.25x, 1h write 2x, read 0.1x of input).
 */
function rate(input: number, output: number): ModelRate {
  return {
    input,
    output,
    cacheWrite5m: input * 1.25,
    cacheWrite1h: input * 2,
    cacheRead: input * 0.1,
  };
}

/**
 * Canonical rate table (USD / MTok). Keyed by canonical Anthropic model id.
 * OpenRouter aliases are resolved to these via `MODEL_ALIASES` + normalization.
 */
export const MODEL_RATES: Record<string, ModelRate> = {
  "claude-fable-5": rate(10, 50),
  "claude-opus-4-8": rate(5, 25),
  "claude-opus-4-7": rate(5, 25),
  "claude-opus-4-6": rate(5, 25),
  "claude-opus-4-5": rate(5, 25),
  "claude-sonnet-5": rate(3, 15),
  "claude-sonnet-4-6": rate(3, 15),
  "claude-sonnet-4-5": rate(3, 15),
  "claude-3-5-sonnet": rate(3, 15),
  "claude-haiku-4-5": rate(1, 5),
  "claude-3-5-haiku": rate(0.8, 4),
};

/**
 * Conservative fallback used when a model id isn't in the table — priced at the
 * Opus tier so an unknown model is never under-billed.
 */
export const DEFAULT_RATE: ModelRate = MODEL_RATES["claude-opus-4-8"]!;

/**
 * Normalize a raw model id to a canonical rate-table key. Strips an OpenRouter
 * provider prefix (`anthropic/…`), a variant/date suffix, and `:tags`, then
 * best-effort matches the longest known key that the id starts with.
 */
export function normalizeModelId(model: string): string {
  let id = model.trim().toLowerCase();
  const slash = id.lastIndexOf("/");
  if (slash >= 0) id = id.slice(slash + 1); // drop "anthropic/" etc.
  const colon = id.indexOf(":");
  if (colon >= 0) id = id.slice(0, colon); // drop ":beta" / ":free"
  // OpenRouter versions with dots (claude-3.5-sonnet) → canonical dashes.
  id = id.replace(/\./g, "-");
  if (MODEL_RATES[id]) return id;
  // Longest-prefix match so "claude-3-5-sonnet-20241022" → "claude-3-5-sonnet".
  const keys = Object.keys(MODEL_RATES).sort((a, b) => b.length - a.length);
  for (const key of keys) {
    if (id.startsWith(key)) return key;
  }
  return id;
}

/** Look up the rate for a model id, falling back to `DEFAULT_RATE`. */
export function getRate(model: string): ModelRate {
  return MODEL_RATES[normalizeModelId(model)] ?? DEFAULT_RATE;
}

/**
 * Compute the raw provider cost (USD) of `usage` under `model`. Negative or
 * missing token counts are treated as zero. No markup is applied.
 */
export function computeUsdCost(usage: TokenUsage, model: string): number {
  const r = getRate(model);
  const t = (n?: number) => Math.max(0, n ?? 0);
  const tokenCost =
    t(usage.inputTokens) * r.input +
    t(usage.outputTokens) * r.output +
    t(usage.cacheWrite5mTokens) * r.cacheWrite5m +
    t(usage.cacheWrite1hTokens) * r.cacheWrite1h +
    t(usage.cacheReadTokens) * r.cacheRead;
  return tokenCost / TOKENS_PER_MILLION + t(usage.webSearches) * WEB_SEARCH_USD;
}
