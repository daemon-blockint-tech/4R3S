import { describe, it, expect } from "vitest";

import {
  LocalMppClient,
  createChallenge,
  createMppClient,
} from "./mpp.js";

describe("LocalMppClient", () => {
  it("settles a matching challenge and records a receipt", async () => {
    const client = new LocalMppClient();
    const challenge = createChallenge("thread-1", 0.25);
    const receipt = await client.settle(challenge, {
      challengeNonce: challenge.nonce,
      payerId: "payer-1",
      token: "voucher",
    });
    expect(receipt).toMatchObject({
      resource: "thread-1",
      amountUsd: 0.25,
      payerId: "payer-1",
    });
    expect(client.history()).toHaveLength(1);
  });

  it("rejects a credential whose nonce doesn't match", async () => {
    const client = new LocalMppClient();
    const challenge = createChallenge("thread-2", 1);
    await expect(
      client.settle(challenge, {
        challengeNonce: "wrong",
        payerId: "p",
        token: "v",
      }),
    ).rejects.toThrow(/nonce/);
  });
});

describe("createMppClient", () => {
  it("returns a local client when no endpoint is configured", () => {
    expect(createMppClient({ payerId: "p" })).toBeInstanceOf(LocalMppClient);
  });

  it("throws when an endpoint is set but local fallback is not allowed", () => {
    expect(() =>
      createMppClient({ endpoint: "https://mpp.example", payerId: "p" }),
    ).toThrow(/not wired/i);
  });

  it("allows local settlement for a configured endpoint only when opted in", () => {
    const client = createMppClient({
      endpoint: "https://mpp.example",
      allowLocalFallback: true,
      payerId: "p",
    });
    expect(client).toBeInstanceOf(LocalMppClient);
  });
});
