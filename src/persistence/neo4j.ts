/**
 * Neo4j driver factory.
 *
 * Returns a lazily-constructed driver only when NEO4J_URI/USER/PASSWORD are all
 * configured. Downstream code treats `undefined` as "graph layer unavailable"
 * and skips graph expansion, so the agent runs fine without Neo4j.
 */
import neo4j, { type Driver, type Session } from "neo4j-driver";

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

  cached = neo4j.driver(
    env.NEO4J_URI,
    neo4j.auth.basic(env.NEO4J_USER, env.NEO4J_PASSWORD),
  );
  logger.debug({ component: "neo4j" }, "Neo4j driver initialized");
  return cached;
}

/** True when Neo4j credentials are present. */
export function hasNeo4j(): boolean {
  return Boolean(env.NEO4J_URI && env.NEO4J_USER && env.NEO4J_PASSWORD);
}

/**
 * Run `fn` with a fresh session, always closing it afterward. Returns
 * `undefined` when the driver is not configured.
 */
export async function withNeo4jSession<T>(
  fn: (session: Session) => Promise<T>,
): Promise<T | undefined> {
  const driver = getNeo4jDriver();
  if (!driver) return undefined;
  const session = driver.session();
  try {
    return await fn(session);
  } finally {
    await session.close();
  }
}

/** Close the shared driver (call on shutdown). */
export async function closeNeo4j(): Promise<void> {
  if (cached) {
    await cached.close();
    cached = undefined;
  }
}
