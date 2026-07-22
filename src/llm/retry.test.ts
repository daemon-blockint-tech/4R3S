import { describe, it, expect, vi } from "vitest";

import { withRetry, isTransientError } from "./retry.js";

/** A sleep stub that records requested delays and resolves instantly. */
function fakeSleep() {
  const delays: number[] = [];
  return {
    delays,
    fn: async (ms: number) => {
      delays.push(ms);
    },
  };
}

describe("isTransientError", () => {
  it("treats 429 and 5xx as transient", () => {
    expect(isTransientError({ status: 429 })).toBe(true);
    expect(isTransientError({ status: 503 })).toBe(true);
    expect(isTransientError({ response: { status: 500 } })).toBe(true);
  });

  it("treats other 4xx as permanent", () => {
    expect(isTransientError({ status: 400 })).toBe(false);
    expect(isTransientError({ status: 401 })).toBe(false);
    expect(isTransientError({ status: 404 })).toBe(false);
  });

  it("treats connection-level error messages as transient", () => {
    expect(isTransientError(new Error("ECONNRESET"))).toBe(true);
    expect(isTransientError(new Error("fetch failed"))).toBe(true);
    expect(isTransientError(new Error("model overloaded"))).toBe(true);
  });

  it("treats an unknown deterministic error as permanent", () => {
    expect(isTransientError(new Error("bad request: invalid schema"))).toBe(false);
  });
});

describe("withRetry", () => {
  it("returns the first successful result without sleeping", async () => {
    const sleep = fakeSleep();
    const fn = vi.fn().mockResolvedValue("ok");
    const result = await withRetry(fn, { sleep: sleep.fn });
    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(1);
    expect(sleep.delays).toHaveLength(0);
  });

  it("retries transient failures then succeeds", async () => {
    const sleep = fakeSleep();
    const fn = vi
      .fn()
      .mockRejectedValueOnce({ status: 503 })
      .mockRejectedValueOnce({ status: 429 })
      .mockResolvedValue("recovered");
    const result = await withRetry(fn, {
      sleep: sleep.fn,
      jitter: false,
      baseDelayMs: 100,
    });
    expect(result).toBe("recovered");
    expect(fn).toHaveBeenCalledTimes(3);
    // Exponential backoff: 100, 200.
    expect(sleep.delays).toEqual([100, 200]);
  });

  it("does not retry a permanent (4xx) error", async () => {
    const sleep = fakeSleep();
    const fn = vi.fn().mockRejectedValue({ status: 400, message: "bad request" });
    await expect(withRetry(fn, { sleep: sleep.fn })).rejects.toMatchObject({
      status: 400,
    });
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("gives up after exhausting the retry budget and rethrows", async () => {
    const sleep = fakeSleep();
    const err = { status: 500, message: "always down" };
    const fn = vi.fn().mockRejectedValue(err);
    await expect(
      withRetry(fn, { retries: 2, sleep: sleep.fn, jitter: false }),
    ).rejects.toBe(err);
    // 1 initial + 2 retries = 3 attempts, 2 backoffs.
    expect(fn).toHaveBeenCalledTimes(3);
    expect(sleep.delays).toHaveLength(2);
  });

  it("caps the backoff at maxDelayMs", async () => {
    const sleep = fakeSleep();
    const fn = vi
      .fn()
      .mockRejectedValueOnce({ status: 500 })
      .mockRejectedValueOnce({ status: 500 })
      .mockRejectedValueOnce({ status: 500 })
      .mockResolvedValue("done");
    await withRetry(fn, {
      retries: 5,
      baseDelayMs: 1000,
      maxDelayMs: 1500,
      jitter: false,
      sleep: sleep.fn,
    });
    // 1000, then 2000→capped 1500, then 4000→capped 1500.
    expect(sleep.delays).toEqual([1000, 1500, 1500]);
  });
});
