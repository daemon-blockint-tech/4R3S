import { describe, it, expect } from "vitest";

import {
  computeUsdCost,
  getRate,
  normalizeModelId,
  MODEL_RATES,
  DEFAULT_RATE,
  WEB_SEARCH_USD,
} from "./pricing.js";

describe("normalizeModelId", () => {
  it("strips OpenRouter provider prefix and tags, and dot→dash versions", () => {
    expect(normalizeModelId("anthropic/claude-opus-4-8")).toBe("claude-opus-4-8");
    // Provider prefix stripped, ":beta" tag dropped, dots reconciled to dashes.
    expect(normalizeModelId("anthropic/claude-3.5-sonnet:beta")).toBe(
      "claude-3-5-sonnet",
    );
  });

  it("prices the project's default OpenRouter model at the sonnet rate", () => {
    // Default OPENROUTER_MODEL is anthropic/claude-3.5-sonnet ($3/$15).
    expect(getRate("anthropic/claude-3.5-sonnet")).toEqual(
      MODEL_RATES["claude-3-5-sonnet"],
    );
  });

  it("longest-prefix matches dated snapshots", () => {
    expect(normalizeModelId("claude-3-5-sonnet-20241022")).toBe("claude-3-5-sonnet");
  });

  it("returns the id unchanged when unknown", () => {
    expect(normalizeModelId("some/mystery-model")).toBe("mystery-model");
  });
});

describe("getRate", () => {
  it("resolves a known model", () => {
    expect(getRate("claude-opus-4-8")).toEqual(MODEL_RATES["claude-opus-4-8"]);
  });

  it("resolves an OpenRouter-prefixed known model", () => {
    expect(getRate("anthropic/claude-haiku-4-5")).toEqual(
      MODEL_RATES["claude-haiku-4-5"],
    );
  });

  it("falls back to DEFAULT_RATE (opus tier) for unknown models", () => {
    expect(getRate("unknown-model-x")).toEqual(DEFAULT_RATE);
  });
});

describe("computeUsdCost", () => {
  it("prices input + output tokens correctly (opus 4.8: $5/$25 per MTok)", () => {
    // 1M input + 1M output = $5 + $25 = $30.
    const cost = computeUsdCost(
      { inputTokens: 1_000_000, outputTokens: 1_000_000 },
      "claude-opus-4-8",
    );
    expect(cost).toBeCloseTo(30);
  });

  it("applies cache-read discount (0.1x input)", () => {
    // 1M cache-read on opus (input $5) → $0.50.
    expect(
      computeUsdCost({ cacheReadTokens: 1_000_000 }, "claude-opus-4-8"),
    ).toBeCloseTo(0.5);
  });

  it("bills web searches at $10 per 1000", () => {
    expect(computeUsdCost({ webSearches: 5 }, "claude-opus-4-8")).toBeCloseTo(
      5 * WEB_SEARCH_USD,
    );
  });

  it("treats missing/negative counts as zero", () => {
    expect(computeUsdCost({}, "claude-opus-4-8")).toBe(0);
    expect(
      computeUsdCost({ inputTokens: -100 }, "claude-opus-4-8"),
    ).toBe(0);
  });
});
