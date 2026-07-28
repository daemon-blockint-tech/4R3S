import { describe, it, expect } from "vitest";

import { deadlineSignal, timedFetch } from "./timeout.js";

describe("deadlineSignal", () => {
  it("aborts on its own once the deadline passes", async () => {
    const signal = deadlineSignal(10);
    expect(signal.aborted).toBe(false);
    await new Promise((r) => setTimeout(r, 40));
    expect(signal.aborted).toBe(true);
  });

  it("still honours a caller's signal", () => {
    const caller = new AbortController();
    const signal = deadlineSignal(60_000, caller.signal);
    caller.abort(new Error("caller cancelled"));
    expect(signal.aborted).toBe(true);
  });
});

describe("timedFetch", () => {
  it("aborts a request that never settles", async () => {
    // A fetch that only resolves when its signal fires — i.e. a hung socket.
    const hung: typeof fetch = (_input, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(init.signal?.reason ?? new Error("aborted")),
        );
      });

    await expect(timedFetch(20, hung)("https://example.invalid")).rejects.toThrow();
  });

  it("passes the response through when the call completes in time", async () => {
    const ok: typeof fetch = async () => new Response("pong");
    const res = await timedFetch(5_000, ok)("https://example.invalid");
    expect(await res.text()).toBe("pong");
  });

  it("does not discard other request options", async () => {
    let seen: RequestInit | undefined;
    const spy: typeof fetch = async (_input, init) => {
      seen = init;
      return new Response("ok");
    };
    await timedFetch(5_000, spy)("https://example.invalid", {
      method: "POST",
      body: "payload",
    });
    expect(seen?.method).toBe("POST");
    expect(seen?.body).toBe("payload");
    expect(seen?.signal).toBeInstanceOf(AbortSignal);
  });
});
