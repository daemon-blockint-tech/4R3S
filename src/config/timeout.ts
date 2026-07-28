/**
 * Request deadlines for outbound calls.
 *
 * Every network dependency here is reached through a client that, left alone,
 * waits forever: `fetch` has no default timeout, and neither the Solana RPC
 * connection nor the chat model sets one. A hung socket therefore hangs the
 * whole audit, and `withRetry` cannot help because it only reacts to errors —
 * a request that never settles never produces one.
 *
 * `withTimeout` attaches a deadline to a `fetch` call without discarding a
 * caller-supplied signal, so cancellation still propagates.
 */

/**
 * Combine an existing abort signal with a fresh timeout. Falls back to the
 * timeout alone on runtimes without `AbortSignal.any` (added in Node 20.3).
 */
export function deadlineSignal(
  timeoutMs: number,
  existing?: AbortSignal | null,
): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);
  if (!existing) return timeout;
  return typeof AbortSignal.any === "function"
    ? AbortSignal.any([existing, timeout])
    : timeout;
}

/** A `fetch` implementation with a per-request deadline applied. */
export type TimedFetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

/**
 * Wrap `fetch` so every request through it aborts after `timeoutMs`.
 * Used where a client accepts a fetch override rather than a timeout option.
 */
export function timedFetch(timeoutMs: number, base: typeof fetch = fetch): TimedFetch {
  return (input, init) =>
    base(input, {
      ...init,
      signal: deadlineSignal(timeoutMs, init?.signal),
    });
}
