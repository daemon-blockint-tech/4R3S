import { describe, it, expect, vi, afterEach } from "vitest";

import { logger, redact, REDACTED } from "./logger.js";

function capture(run: () => void): { out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  const so = vi.spyOn(process.stdout, "write").mockImplementation((c) => {
    out.push(String(c));
    return true;
  });
  const se = vi.spyOn(process.stderr, "write").mockImplementation((c) => {
    err.push(String(c));
    return true;
  });
  try {
    run();
  } finally {
    so.mockRestore();
    se.mockRestore();
  }
  return { out, err };
}

afterEach(() => vi.restoreAllMocks());

describe("logger stream discipline", () => {
  it("writes every level to stderr and nothing to stdout", () => {
    // stdout carries the audit report; a log line there corrupts a piped report.
    const { out, err } = capture(() => {
      logger.error("boom");
      logger.warn("careful");
      logger.info("progress");
    });

    expect(out).toEqual([]);
    // ARES_LOG_LEVEL is "error" under vitest, so only the error line is emitted.
    expect(err.length).toBeGreaterThanOrEqual(1);
    expect(err.join("")).toContain("boom");
  });

  it("emits one JSON line per record, with level, message and metadata", () => {
    const { err } = capture(() => {
      logger.error({ component: "test", findings: 3 }, "audit complete");
    });

    const parsed = JSON.parse(err[0]!.trim());
    expect(parsed.level).toBe("error");
    expect(parsed.msg).toBe("audit complete");
    expect(parsed.component).toBe("test");
    expect(parsed.findings).toBe(3);
    expect(typeof parsed.t).toBe("string");
    expect(err[0]!.endsWith("\n")).toBe(true);
  });

  it("accepts the message-first call style too", () => {
    const { err } = capture(() => {
      logger.error("message first", { component: "test" });
    });
    const parsed = JSON.parse(err[0]!.trim());
    expect(parsed.msg).toBe("message first");
    expect(parsed.component).toBe("test");
  });
});

describe("redaction", () => {
  it("drops values under credential-shaped keys", () => {
    expect(
      redact({
        OPENROUTER_API_KEY: "sk-or-v1-real",
        supabaseServiceRoleKey: "svc",
        authorization: "Bearer abc",
        password: "hunter2",
        model: "claude-sonnet-5",
      }),
    ).toEqual({
      OPENROUTER_API_KEY: REDACTED,
      supabaseServiceRoleKey: REDACTED,
      authorization: REDACTED,
      password: REDACTED,
      model: "claude-sonnet-5",
    });
  });

  it("strips the password from a Postgres DSN wherever it appears", () => {
    // SECURITY.md promises secrets stay out of the logs, and this is the way
    // one actually escapes: inside a stringified driver error, not under a
    // helpfully-named field.
    const err = redact({
      err: 'connect ECONNREFUSED postgresql://ares:ares_dev_password@localhost:5432/ares',
    }) as { err: string };
    expect(err.err).not.toContain("ares_dev_password");
    expect(err.err).toContain("postgresql://ares:[redacted]@localhost:5432/ares");
  });

  it("reaches nested objects and arrays", () => {
    const out = redact({
      outer: { inner: { apiKey: "secret" }, list: ["bolt://neo4j:pw@host:7687"] },
    }) as { outer: { inner: { apiKey: string }; list: string[] } };
    expect(out.outer.inner.apiKey).toBe(REDACTED);
    expect(out.outer.list[0]).toBe("bolt://neo4j:[redacted]@host:7687");
  });

  it("leaves ordinary values untouched", () => {
    expect(redact({ findings: 3, ok: true, name: "onchain" })).toEqual({
      findings: 3,
      ok: true,
      name: "onchain",
    });
  });

  it("redacts the emitted line, not just the helper", () => {
    const err: string[] = [];
    const spy = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((c) => (err.push(String(c)), true));
    try {
      logger.error({ apiKey: "sk-live-123" }, "boom");
    } finally {
      spy.mockRestore();
    }
    expect(err.join("")).not.toContain("sk-live-123");
    expect(JSON.parse(err[0]!).apiKey).toBe(REDACTED);
  });
});

describe("query-string secret redaction (N4)", () => {
  it("redacts the api-key shape .env.example actually documents", () => {
    // HELIUS_RPC_URL=https://mainnet.helius-rpc.com/?api-key=xxxxxxxx
    const out = redact({
      err: "FetchError: request to https://mainnet.helius-rpc.com/?api-key=SECRET123 failed",
    }) as { err: string };
    expect(out.err).not.toContain("SECRET123");
    expect(out.err).toContain("api-key=[redacted]");
  });

  it("covers the common secret parameter names", () => {
    for (const param of ["api_key", "apikey", "access_token", "token", "secret", "password", "auth"]) {
      const out = redact({ url: `https://h/x?${param}=LEAK&page=2` }) as { url: string };
      expect(out.url).not.toContain("LEAK");
      // Non-secret parameters are left alone: over-redacting makes logs useless.
      expect(out.url).toContain("page=2");
    }
  });

  it("still redacts user:pass@ credentials", () => {
    const out = redact({ err: "postgresql://ares:hunter2@localhost:5432/ares" }) as {
      err: string;
    };
    expect(out.err).toBe("postgresql://ares:[redacted]@localhost:5432/ares");
  });

  it("redacts both shapes in one string", () => {
    const out = redact({
      err: "bolt://neo4j:pw@host used https://rpc/?api-key=K1",
    }) as { err: string };
    expect(out.err).not.toContain("pw@host".slice(0, 2) + "@");
    expect(out.err).not.toContain("K1");
  });

  it("leaves a URL with no secret untouched", () => {
    const url = "https://api.mainnet-beta.solana.com/?commitment=confirmed";
    expect((redact({ url }) as { url: string }).url).toBe(url);
  });
});
