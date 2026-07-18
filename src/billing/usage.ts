/**
 * Extract a normalized `TokenUsage` from a LangChain chat response.
 *
 * Different providers surface token counts under different shapes:
 *   - `usage_metadata` (canonical @langchain/core): input_tokens, output_tokens,
 *     and input_token_details.{cache_read, cache_creation}.
 *   - `response_metadata.tokenUsage` / `.usage` (OpenAI/OpenRouter passthrough):
 *     promptTokens / completionTokens (or prompt_tokens / completion_tokens).
 *
 * This reader is defensive — unknown shapes yield zero usage rather than throw,
 * so metering never breaks an audit.
 */
import type { TokenUsage } from "./pricing.js";

function pick(obj: unknown, key: string): unknown {
  return obj && typeof obj === "object"
    ? (obj as Record<string, unknown>)[key]
    : undefined;
}

function toNum(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

/** Normalize a LangChain AIMessage-like response into `TokenUsage`. */
export function extractUsage(response: unknown): TokenUsage {
  // 1. Canonical usage_metadata.
  const um = pick(response, "usage_metadata");
  if (um) {
    const details = pick(um, "input_token_details");
    return {
      inputTokens: toNum(pick(um, "input_tokens")),
      outputTokens: toNum(pick(um, "output_tokens")),
      cacheReadTokens: toNum(pick(details, "cache_read")),
      cacheWrite5mTokens: toNum(pick(details, "cache_creation")),
    };
  }

  // 2. OpenAI/OpenRouter-style response_metadata.
  const rm = pick(response, "response_metadata");
  const tokenUsage = pick(rm, "tokenUsage") ?? pick(rm, "usage");
  if (tokenUsage) {
    return {
      inputTokens: toNum(
        pick(tokenUsage, "promptTokens") ?? pick(tokenUsage, "prompt_tokens"),
      ),
      outputTokens: toNum(
        pick(tokenUsage, "completionTokens") ??
          pick(tokenUsage, "completion_tokens"),
      ),
    };
  }

  return {};
}
