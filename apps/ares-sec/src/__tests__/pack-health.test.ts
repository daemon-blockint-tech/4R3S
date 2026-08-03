/**
 * Rate-limit / degraded-health + LLM semaphore — Phase-0 pack-hunt safety primitive (HT-3).
 * A rate-limited slot must NEVER read as "clean / found-nothing", and a single global semaphore
 * must cap ALL local-agent calls. Pins: isRateLimited on real quota strings, the 0.5 degraded
 * threshold, and that the Semaphore never exceeds max concurrent holders.
 */
import { describe, it, expect } from 'vitest';
import { isRateLimited, DegradedTracker, Semaphore } from '../pack/health.js';

describe('isRateLimited', () => {
  it('catches real usage-limit / 429 / quota signatures', () => {
    // real Claude/Anthropic banner
    expect(isRateLimited("ERROR: You've hit your usage limit. try again at 12:10 PM")).toBe(true);
    expect(isRateLimited('Claude: you have hit your usage limit')).toBe(true);
    expect(isRateLimited('429 Too Many Requests')).toBe(true);
    expect(isRateLimited('HTTP 429')).toBe(true);
    expect(isRateLimited('rate limit reached for this model')).toBe(true);
    expect(isRateLimited('rate-limited')).toBe(true);
    expect(isRateLimited('quota exceeded')).toBe(true);
    expect(isRateLimited('{"error":{"code":"insufficient_quota"}}')).toBe(true);
    expect(isRateLimited('Too Many Requests')).toBe(true);
  });

  it('catches provider-specific throttle signals the original regex missed', () => {
    expect(isRateLimited('Error: Overloaded (overloaded_error)')).toBe(true); // Anthropic 529
    expect(isRateLimited('HTTP 529: overloaded')).toBe(true);
    expect(isRateLimited('TooManyRequestsException: Rate exceeded')).toBe(true); // AWS Bedrock
    expect(isRateLimited('grpc status RESOURCE_EXHAUSTED')).toBe(true); // gRPC / Vertex
    expect(isRateLimited('You exceeded your current quota, please check your plan')).toBe(true); // OpenAI reversed
    expect(isRateLimited('request was throttled, retry-after 30s')).toBe(true);
    expect(isRateLimited('503 Service Unavailable')).toBe(true);
  });

  it('does NOT false-positive on a bare integer that merely looks like a status code', () => {
    expect(isRateLimited('see line 429 of the file')).toBe(false);
    expect(isRateLimited('CWE-529: exposure of sensitive information')).toBe(false);
    expect(isRateLimited('found 4290 candidate sinks')).toBe(false);
  });

  it('does NOT false-positive on benign prose that incidentally contains throttle vocabulary', () => {
    // the signals must be the SPECIFIC provider tokens, not bare words in finding narratives
    expect(isRateLimited('resource exhausted state in the parser')).toBe(false); // not RESOURCE_EXHAUSTED
    expect(isRateLimited('a note about an overloaded operator')).toBe(false); // not overloaded_error
    expect(isRateLimited('the quota management module')).toBe(false); // not "quota exceeded"
    expect(isRateLimited('capacity planning document')).toBe(false); // not "at capacity"
    expect(isRateLimited('opened the throttle valve')).toBe(false); // "throttle" (noun) != "throttled"/"throttling"
    expect(isRateLimited('disk quota for the container')).toBe(false);
  });

  it('does NOT flag a rate-limit / DoS FINDING body as a throttled slot (finding vs throttle)', () => {
    // a pack agent's OWN result describing a rate-limit/DoS vuln must read as a FINDING, not degraded
    expect(isRateLimited('Found: rate limiting is MISSING on /login (CWE-307)')).toBe(false);
    expect(isRateLimited('no rate-limit on password reset — brute force possible')).toBe(false);
    expect(isRateLimited('CWE-400: uncontrolled resource consumption leads to service unavailable')).toBe(false);
    expect(isRateLimited('recommend: slow down the attacker via a captcha')).toBe(false);
    expect(isRateLimited('concurrent request handling bug (race)')).toBe(false);
    expect(isRateLimited('the endpoint enforces no usage limit at all')).toBe(false);
    // but a limit actually being HIT (a genuine throttle) is still caught
    expect(isRateLimited('rate limit exceeded')).toBe(true);
    expect(isRateLimited('rate-limited')).toBe(true);
  });

  it('still catches the canonical provider throttles the tightening must not lose (8th-pass regression)', () => {
    expect(isRateLimited('{"type":"error","error":{"type":"rate_limit_error"}}')).toBe(true); // Anthropic 429 body
    expect(isRateLimited('exceeded your per-minute rate limit')).toBe(true); // qualifier between verb and "rate limit"
    expect(isRateLimited('usage limit reached')).toBe(true); // Claude subscription banner (verb after)
    expect(isRateLimited("You've reached your usage limit")).toBe(true); // verb before
    expect(isRateLimited('Message limit reached')).toBe(true);
    // and the finding-vs-throttle discrimination still holds
    expect(isRateLimited('the endpoint enforces no usage limit at all')).toBe(false);
    expect(isRateLimited('rate limiting is MISSING on /login')).toBe(false);
  });

  it('catches the provider throttles the tightening MUST NOT lose (9th-pass false-negatives)', () => {
    expect(isRateLimited('You have exceeded a secondary rate limit')).toBe(true); // GitHub/GitLab
    expect(isRateLimited('ServiceQuotaExceededException: rate exceeded')).toBe(true); // AWS Bedrock
    expect(isRateLimited('The engine is currently overloaded, please try again')).toBe(true); // OpenAI/Anthropic 529 prose
    expect(isRateLimited('Overloaded')).toBe(true); // Anthropic 529 bare body
    expect(isRateLimited('grpc error: Resource has been exhausted (e.g. check quota)')).toBe(true); // gRPC/Vertex prose
    // still NOT a false-positive on benign code-review vocabulary
    expect(isRateLimited('a note about an overloaded operator')).toBe(false);
    expect(isRateLimited('resource exhausted state in the parser')).toBe(false);
  });

  it('catches the underscore 429 enum and future-tense throttle bodies (11th-pass false-negatives)', () => {
    expect(isRateLimited('{"reason":"too_many_requests"}')).toBe(true); // HTTP 429 reason enum
    expect(isRateLimited('TOO_MANY_REQUESTS')).toBe(true);
    expect(isRateLimited("This request would exceed your organization's rate limit")).toBe(true); // Anthropic future-tense
    expect(isRateLimited('you will exceed your per-minute rate limit')).toBe(true);
    // and still not a finding body
    expect(isRateLimited('rate limiting is MISSING on /login')).toBe(false);
  });

  it('ignores normal findings output and empty/undefined text', () => {
    expect(isRateLimited('[{"title":"x","file":"a.py","line":5,"cwe":"CWE-22"}]')).toBe(false);
    expect(isRateLimited('Clean — nothing exploitable in my specialty')).toBe(false);
    expect(isRateLimited('')).toBe(false);
    // guards against undefined leaking in despite the string type (matches cli-swarm's String(x||'') coercion)
    expect(isRateLimited(undefined as unknown as string)).toBe(false);
  });
});

describe('DegradedTracker — 0.5 threshold', () => {
  it('is OK when all calls succeed', () => {
    const t = new DegradedTracker();
    t.record(true);
    t.record(true);
    t.record(true);
    expect(t.calls).toBe(3);
    expect(t.fails).toBe(0);
    expect(t.verdict()).toBe('OK');
  });

  it('stays OK just below the threshold (2 of 5 failed = 0.4)', () => {
    const t = new DegradedTracker();
    [true, true, true, false, false].forEach((ok) => t.record(ok));
    expect(t.failRatio()).toBeCloseTo(0.4);
    expect(t.verdict()).toBe('OK');
  });

  it('flips to INVALID_DEGRADED exactly AT the 0.5 threshold (2 of 4 failed)', () => {
    const t = new DegradedTracker();
    [true, true, false, false].forEach((ok) => t.record(ok));
    expect(t.failRatio()).toBe(0.5);
    expect(t.verdict()).toBe('INVALID_DEGRADED');
  });

  it('is INVALID_DEGRADED when failures dominate', () => {
    const t = new DegradedTracker();
    [false, false, false, true].forEach((ok) => t.record(ok));
    expect(t.verdict()).toBe('INVALID_DEGRADED');
  });

  it('a rate-limited slot poisons the verdict — never clean', () => {
    const t = new DegradedTracker();
    // two slots came back "successfully" but one is actually a quota banner
    t.recordResult(true, 'Clean — no findings');
    t.recordResult(true, "You've hit your usage limit");
    // the quota banner is booked as a failure => 1/2 = 0.5 => degraded
    expect(t.fails).toBe(1);
    expect(t.verdict()).toBe('INVALID_DEGRADED');
  });

  it('an empty run (no calls) is INVALID_DEGRADED, not clean', () => {
    const t = new DegradedTracker();
    expect(t.verdict()).toBe('INVALID_DEGRADED');
    expect(t.failRatio()).toBe(0);
  });
});

describe('Semaphore', () => {
  it('rejects a non-positive max', () => {
    expect(() => new Semaphore(0)).toThrow(RangeError);
    expect(() => new Semaphore(-1)).toThrow(RangeError);
  });

  it('never exceeds max concurrent holders under a burst', async () => {
    const MAX = 3;
    const N = 40;
    const sem = new Semaphore(MAX);
    let live = 0;
    let peak = 0;

    const task = async (): Promise<void> => {
      const release = await sem.acquire();
      live += 1;
      peak = Math.max(peak, live);
      expect(live).toBeLessThanOrEqual(MAX); // invariant checked WHILE holding
      // yield across a macrotask so overlap is real, not artificial
      await new Promise((r) => setTimeout(r, Math.floor(Math.random() * 5)));
      live -= 1;
      release();
    };

    await Promise.all(Array.from({ length: N }, task));
    expect(peak).toBe(MAX); // saturates (N >> MAX) but never over
    expect(live).toBe(0);
    expect(sem.inFlight).toBe(0);
    expect(sem.queued).toBe(0);
  });

  it('serializes fully at max=1', async () => {
    const sem = new Semaphore(1);
    let live = 0;
    let peak = 0;
    const task = async (): Promise<void> => {
      const release = await sem.acquire();
      live += 1;
      peak = Math.max(peak, live);
      await new Promise((r) => setTimeout(r, 1));
      live -= 1;
      release();
    };
    await Promise.all([task(), task(), task(), task()]);
    expect(peak).toBe(1);
  });

  it('serves waiters FIFO', async () => {
    const sem = new Semaphore(1);
    const order: number[] = [];
    const first = await sem.acquire(); // occupy the only slot
    // three callers queue up in order
    const p2 = sem.acquire().then((rel) => { order.push(2); rel(); });
    const p3 = sem.acquire().then((rel) => { order.push(3); rel(); });
    const p4 = sem.acquire().then((rel) => { order.push(4); rel(); });
    expect(sem.queued).toBe(3);
    first(); // release => drains in enqueue order
    await Promise.all([p2, p3, p4]);
    expect(order).toEqual([2, 3, 4]);
  });

  it('double-release is a no-op (cannot inflate the pool past max)', async () => {
    const sem = new Semaphore(1);
    const release = await sem.acquire();
    release();
    release(); // second call must NOT free a phantom extra slot

    let live = 0;
    let peak = 0;
    const task = async (): Promise<void> => {
      const rel = await sem.acquire();
      live += 1;
      peak = Math.max(peak, live);
      await new Promise((r) => setTimeout(r, 1));
      live -= 1;
      rel();
    };
    await Promise.all([task(), task(), task()]);
    expect(peak).toBe(1); // still fully serialized
  });

  it('run() releases even when the body throws', async () => {
    const sem = new Semaphore(1);
    await expect(sem.run(async () => { throw new Error('boom'); })).rejects.toThrow('boom');
    expect(sem.inFlight).toBe(0);
    // slot is free again — a subsequent acquire resolves immediately
    const release = await sem.acquire();
    expect(sem.inFlight).toBe(1);
    release();
  });
});
