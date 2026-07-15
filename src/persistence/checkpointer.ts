/**
 * Checkpointer factory.
 *
 * Wraps LangGraph's PostgresSaver so graph state (per audit thread) survives
 * process restarts. Use `createCheckpointer` at runtime and call `setup()` once
 * (via the migrate script) to create the checkpoint tables.
 */
import { PostgresSaver } from "@langchain/langgraph-checkpoint-postgres";
import { MemorySaver } from "@langchain/langgraph";
import type { BaseCheckpointSaver } from "@langchain/langgraph";

import { env, postgresConnectionString } from "../config/env.js";
import { logger } from "../config/logger.js";

/**
 * Build a Postgres-backed checkpointer. The caller owns its lifecycle and
 * should `await saver.end()` on shutdown (see `src/index.ts`).
 */
export function createPostgresCheckpointer(): PostgresSaver {
  const saver = PostgresSaver.fromConnString(postgresConnectionString(), {
    schema: "public",
  });
  logger.debug(
    { component: "checkpointer", host: env.POSTGRES_HOST },
    "Postgres checkpointer created",
  );
  return saver;
}

/**
 * In-memory checkpointer for tests / offline runs. State does not persist
 * across process restarts.
 */
export function createMemoryCheckpointer(): BaseCheckpointSaver {
  logger.debug({ component: "checkpointer" }, "In-memory checkpointer created");
  return new MemorySaver();
}
