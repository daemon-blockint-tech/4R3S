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
import { hasNeo4j, withNeo4jWriteSession, closeNeo4j } from "../persistence/neo4j.js";
import { ensureChainIntakeSchema, closeChainIntake } from "../persistence/chain-intake.js";

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

  // chain_intake is separate from the checkpoint tables and owns its own DDL,
  // so it is created here rather than inside PostgresSaver.setup(). A failure
  // is reported, not thrown: chain-intake caching is an optimisation and an
  // audit must still run without it (see persistence/chain-intake.ts).
  const intakeReady = await ensureChainIntakeSchema();
  logger.info(
    { component: "migrate", ready: intakeReady },
    intakeReady
      ? "chain_intake table ready"
      : "chain_intake table unavailable; audits will read chain without caching",
  );
  await closeChainIntake();
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

  await withNeo4jWriteSession(async (session) => {
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
