/**
 * Database migration.
 *
 * - Postgres: creates LangGraph checkpoint tables via `PostgresSaver.setup()`.
 * - Neo4j (if configured): applies constraints/indexes from
 *   `db/neo4j/schema.cypher`.
 *
 * Supabase schema (`db/supabase/0001_hybrid_search.sql`) is applied separately
 * with the Supabase CLI / SQL editor — see the README.
 */
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { logger } from "../config/logger.js";
import { createPostgresCheckpointer } from "../persistence/checkpointer.js";
import { hasNeo4j, withNeo4jSession, closeNeo4j } from "../persistence/neo4j.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");

async function migratePostgres(): Promise<void> {
  const saver = createPostgresCheckpointer();
  try {
    await saver.setup();
    logger.info({ component: "migrate" }, "Postgres checkpoint tables ready");
  } finally {
    await saver.end();
  }
}

async function migrateNeo4j(): Promise<void> {
  if (!hasNeo4j()) {
    logger.info({ component: "migrate" }, "Neo4j not configured; skipping graph schema");
    return;
  }
  const schemaPath = resolve(REPO_ROOT, "db", "neo4j", "schema.cypher");
  const raw = await readFile(schemaPath, "utf8");
  const statements = raw
    .split(";")
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && !s.startsWith("//"));

  await withNeo4jSession(async (session) => {
    for (const stmt of statements) {
      await session.run(stmt);
    }
  });
  logger.info(
    { component: "migrate", statements: statements.length },
    "Neo4j schema applied",
  );
}

async function main(): Promise<void> {
  await migratePostgres();
  await migrateNeo4j();
  await closeNeo4j();
  logger.info({ component: "migrate" }, "Migration complete");
}

main().catch((err) => {
  logger.error({ component: "migrate", err: String(err) }, "Migration failed");
  process.exitCode = 1;
});
