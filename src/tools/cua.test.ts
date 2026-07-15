import { describe, it, expect, afterEach } from "vitest";

import { hasCua, setCuaOverride, runCuaInvestigation } from "./cua.js";

describe("hasCua", () => {
  afterEach(() => {
    setCuaOverride(false);
  });

  it("is false by default in the test env (no CUA/Scrapybara keys)", () => {
    expect(hasCua()).toBe(false);
  });

  it("stays false even with the runtime override when API keys are missing", () => {
    setCuaOverride(true);
    // OPENAI_API_KEY / SCRAPYBARA_API_KEY are unset in the test env, so CUA
    // must remain unavailable regardless of the enable flag.
    expect(hasCua()).toBe(false);
  });
});

describe("runCuaInvestigation", () => {
  it("returns unavailable without calling Scrapybara/OpenAI when not configured", async () => {
    const result = await runCuaInvestigation("investigate program X");
    expect(result.available).toBe(false);
    expect(result.transcript).toBe("");
    expect(result.note).toBeTruthy();
  });
});
