import { describe, it, expect } from "vitest";

import { modelEndpointMismatch } from "./env.js";

/**
 * The pairing this catches is a guaranteed 401, and it took two debugging
 * sessions to find because nothing reported it: a `.env` carrying both an
 * OpenRouter block and an LM Studio block, where one `OPENROUTER_BASE_URL` line
 * is removed and the key from the *other* block survives.
 */
describe("modelEndpointMismatch", () => {
  const REMOTE = "https://openrouter.ai/api/v1";
  const LOCAL = "http://localhost:1234/v1";
  const REAL_KEY = "sk-or-v1-0123456789abcdef";

  it("flags a remote endpoint reached with a local placeholder key", () => {
    const warning = modelEndpointMismatch(REMOTE, "lm-studio");
    expect(warning).toBeDefined();
    expect(warning).toContain("openrouter.ai");
    expect(warning).toContain("lm-studio");
  });

  it("flags the other placeholders local servers tell you to send", () => {
    // LM Studio, Ollama and llama.cpp docs each suggest one of these.
    for (const key of ["not-needed", "none", "local", "ollama"]) {
      expect(modelEndpointMismatch(REMOTE, key), key).toBeDefined();
    }
  });

  it("never leaks the key itself, only a short prefix", () => {
    const secret = "lm-studio-but-actually-a-real-secret-value";
    const warning = modelEndpointMismatch(REMOTE, secret)!;
    expect(warning).not.toContain(secret);
    expect(warning).not.toContain("actually-a-real-secret");
  });

  // The other direction matters as much: a check that fires on working setups
  // gets muted, and then it is not a check.

  it("stays silent for a real key against a remote endpoint", () => {
    expect(modelEndpointMismatch(REMOTE, REAL_KEY)).toBeUndefined();
    expect(modelEndpointMismatch("https://api.openai.com/v1", "sk-proj-abc")).toBeUndefined();
  });

  it("stays silent for a placeholder key against a local server", () => {
    // The correct LM Studio setup. Loopback servers ignore the key entirely.
    for (const url of [
      "http://localhost:1234/v1",
      "http://127.0.0.1:1234/v1",
      "http://0.0.0.0:1234/v1",
    ]) {
      expect(modelEndpointMismatch(url, "lm-studio"), url).toBeUndefined();
    }
  });

  it("stays silent for a real key against a local server", () => {
    // Odd but harmless — a loopback server ignores the key, so nothing breaks.
    expect(modelEndpointMismatch(LOCAL, REAL_KEY)).toBeUndefined();
  });

  it("reports an unparseable base URL rather than passing it through", () => {
    const warning = modelEndpointMismatch("not a url", "lm-studio");
    expect(warning).toBeDefined();
    expect(warning).toContain("not a valid URL");
  });
});
