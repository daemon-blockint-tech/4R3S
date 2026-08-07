import { describe, it, expect } from "vitest";

import { isLocalEndpoint } from "./chat-openrouter.js";

/**
 * The base URL decides which client is built, so this predicate decides whether
 * `data_collection: "deny"` is applied to a request carrying the audited party's
 * source code. Getting it wrong in the "local" direction silently drops that
 * policy on a remote call.
 */
describe("isLocalEndpoint", () => {
  it("recognises the loopback forms a local server is reached by", () => {
    for (const url of [
      "http://localhost:1234/v1",
      "http://127.0.0.1:1234/v1",
      "http://0.0.0.0:8080/v1",
      "https://localhost:1234/v1",
      "http://[::1]:1234/v1",
    ]) {
      expect(isLocalEndpoint(url), url).toBe(true);
    }
  });

  it("treats OpenRouter and other remote hosts as remote", () => {
    for (const url of [
      "https://openrouter.ai/api/v1",
      "https://api.openai.com/v1",
      "https://some-proxy.example.com/v1",
    ]) {
      expect(isLocalEndpoint(url), url).toBe(false);
    }
  });

  it("does not treat a host that merely contains 'localhost' as local", () => {
    // `notlocalhost.example.com` resolves off-machine. A substring check would
    // route it to the generic client and drop the data-collection policy.
    expect(isLocalEndpoint("https://notlocalhost.example.com/v1")).toBe(false);
    expect(isLocalEndpoint("https://localhost.attacker.tld/v1")).toBe(false);
  });

  it("falls back to the generic client for an unparseable URL", () => {
    // Reporting a malformed base URL as an OpenRouter auth error would send the
    // reader chasing credentials for what is really a config typo.
    expect(isLocalEndpoint("not a url")).toBe(true);
    expect(isLocalEndpoint("")).toBe(true);
  });
});
