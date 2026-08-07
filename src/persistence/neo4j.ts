/**
 * Neo4j driver factory.
 *
 * Returns a lazily-constructed driver only when NEO4J_URI/USER/PASSWORD are all
 * configured. Downstream code treats `undefined` as "graph layer unavailable"
 * and skips graph expansion, so the agent runs fine without Neo4j.
 */
import neo4j, {
  type Driver,
  type QueryResult,
  type Session,
  type SessionMode,
} from "neo4j-driver";

import { env } from "../config/env.js";
import { logger } from "../config/logger.js";

let cached: Driver | null | undefined;

/** Get the shared Neo4j driver, or `undefined` if not configured. */
export function getNeo4jDriver(): Driver | undefined {
  if (cached !== undefined) return cached ?? undefined;

  if (!env.NEO4J_URI || !env.NEO4J_USER || !env.NEO4J_PASSWORD) {
    logger.debug(
      { component: "neo4j" },
      "Neo4j not configured — graph expansion / reranking disabled",
    );
    cached = null;
    return undefined;
  }

  // Deadlines, for the reason config/timeout.ts exists: a hung socket hangs the
  // whole audit and `withRetry` cannot help, because a request that never
  // settles never produces an error to retry. Neo4j is the harder case of the
  // two uncovered dependencies — it speaks Bolt over raw TCP, so unlike
  // Supabase there is no `fetch` to wrap and no undici headers timeout as a
  // backstop. RECALL and REMEMBER both sit on hard joins in the graph, so an
  // unbounded wait here stalls the run with no log line after the phase starts.
  cached = neo4j.driver(
    env.NEO4J_URI,
    neo4j.auth.basic(env.NEO4J_USER, env.NEO4J_PASSWORD),
    {
      // Bounds establishing a socket.
      connectionTimeout: env.NEO4J_TIMEOUT_MS,
      // Bounds waiting for a connection from the pool when it is exhausted.
      connectionAcquisitionTimeout: env.NEO4J_TIMEOUT_MS,
      // Bounds an idle-but-open connection; without it a silently dead peer is
      // indistinguishable from a slow one.
      maxConnectionLifetime: 60 * 60 * 1000,
    },
  );
  logger.debug({ component: "neo4j" }, "Neo4j driver initialized");
  return cached;
}

/** True when Neo4j credentials are present. */
export function hasNeo4j(): boolean {
  return Boolean(env.NEO4J_URI && env.NEO4J_USER && env.NEO4J_PASSWORD);
}

/**
 * Per-query deadline, for `session.run`'s third argument.
 *
 * The driver options bound *connecting*, not executing. A query the server
 * accepts and then never answers — the 1–2 hop `expand()` over a large graph is
 * the realistic case — is unbounded without this.
 */
export const NEO4J_TX_CONFIG = { timeout: env.NEO4J_TIMEOUT_MS };

/**
 * The session surface callers get: `run`, with the deadline already applied.
 *
 * Handing out the raw driver `Session` made the deadline above opt-in, and
 * three of the four call sites opted out by simply not passing a third
 * argument — including the REMEMBER writeback (`knowledge-writer.ts`) that the
 * driver comment names as the reason deadlines exist here at all. A stalled
 * write on that path never settles, so the `try/catch` around it never fires
 * and the audit hangs after VERIFY with no further log line. Narrowing the type
 * is what makes forgetting impossible rather than merely discouraged.
 */
export interface Neo4jSession {
  run(cypher: string, params?: Record<string, unknown>): Promise<QueryResult>;
}

/** Bind `NEO4J_TX_CONFIG` to a session's `run`. */
export function deadlined(session: Pick<Session, "run">): Neo4jSession {
  return {
    run: (cypher, params) => session.run(cypher, params, NEO4J_TX_CONFIG),
  };
}

/**
 * Run `fn` with a fresh session, always closing it afterward. Returns
 * `undefined` when the driver is not configured.
 */
async function withSession<T>(
  mode: SessionMode,
  fn: (session: Neo4jSession) => Promise<T>,
): Promise<T | undefined> {
  const driver = getNeo4jDriver();
  if (!driver) return undefined;
  const session = driver.session({ defaultAccessMode: mode });
  try {
    return await fn(deadlined(session));
  } finally {
    await session.close();
  }
}

/** Read-only session (queries, traversals). Routed to a replica in a cluster. */
export async function withNeo4jSession<T>(
  fn: (session: Neo4jSession) => Promise<T>,
): Promise<T | undefined> {
  return withSession(neo4j.session.READ, fn);
}

/**
 * Write session, for `MERGE` and DDL. Routed to the leader.
 *
 * The mode is not an optimisation. Neo4j routes READ sessions to replicas, and
 * a replica REJECTS writes — so a `MERGE` issued on a READ session fails against
 * any clustered deployment while passing silently on a single instance, where
 * every session is the leader. Collapsing both into one READ helper therefore
 * breaks writeback exactly where it is hardest to notice: in production, not in
 * local testing.
 *
 * Callers that mutate the graph: `knowledge-writer` (the REMEMBER writeback),
 * `scripts/migrate`, `scripts/ingest-solsec`.
 */
export async function withNeo4jWriteSession<T>(
  fn: (session: Neo4jSession) => Promise<T>,
): Promise<T | undefined> {
  return withSession(neo4j.session.WRITE, fn);
}

/** Close the shared driver (call on shutdown). */
export async function closeNeo4j(): Promise<void> {
  if (cached) {
    await cached.close();
    cached = undefined;
  }
}
