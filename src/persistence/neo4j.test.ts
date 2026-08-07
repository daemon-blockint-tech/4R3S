import { describe, it, expect } from "vitest";

import { deadlined, NEO4J_TX_CONFIG } from "./neo4j.js";

/**
 * The regression this covers: `withNeo4jSession` handed out the raw driver
 * `Session`, so the per-query deadline was the caller's job — and the REMEMBER
 * writeback, the ingest script and the migration all left it off. Bolt's
 * connection timeouts bound *connecting*; a server that accepts a query and
 * then stalls on a lock never answers and never errors, so the `try/catch`
 * around the write cannot fire and the audit hangs after VERIFY with no further
 * log line. Callers now receive a session that already carries the deadline.
 */
describe("deadlined", () => {
  it("sends the per-query deadline on every run", async () => {
    const calls: unknown[][] = [];
    const session = {
      run: (...args: unknown[]) => {
        calls.push(args);
        return Promise.resolve({}) as never;
      },
    };

    const s = deadlined(session as never);
    await s.run("MERGE (ch:Chunk { chunk_id: $id })", { id: "c1" });
    await s.run("CREATE INDEX chunk_id IF NOT EXISTS FOR (c:Chunk) ON c.chunk_id");

    expect(calls).toHaveLength(2);
    expect(calls.map((c) => c[2])).toEqual([NEO4J_TX_CONFIG, NEO4J_TX_CONFIG]);
    // A zero/absent timeout is "no deadline" to the server, which is the bug.
    expect(NEO4J_TX_CONFIG.timeout).toBeGreaterThan(0);
  });
});
