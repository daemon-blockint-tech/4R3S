/**
 * ARES-AGENT entry point.
 *
 * Usage:
 *   npm run audit -- --program <address>
 *   npm run audit -- --source <path>
 *   npm run audit -- --program <address> --source <path> [--ephemeral]
 *
 * Runs the audit graph end-to-end for one target and prints the report.
 * `--ephemeral` uses an in-memory checkpointer (no Postgres needed) for quick
 * local runs.
 */
import { parseArgs } from "node:util";

import { env } from "./config/env.js";
import { logger } from "./config/logger.js";
import { defaultChat } from "./llm/chat-openrouter.js";
import { CrystallineStore } from "./memory/crystalline-store.js";
import { createStore } from "./persistence/store.js";
import {
  createPostgresCheckpointer,
  createMemoryCheckpointer,
} from "./persistence/checkpointer.js";
import { closeNeo4j } from "./persistence/neo4j.js";
import { createHybridRetriever } from "./retrieval/index.js";
import { buildAuditGraph } from "./graph/build-graph.js";

interface Cli {
  program?: string;
  source?: string;
  ephemeral: boolean;
  request: string;
}

function parseCli(): Cli {
  const { values } = parseArgs({
    options: {
      program: { type: "string" },
      source: { type: "string" },
      ephemeral: { type: "boolean", default: false },
      request: { type: "string" },
    },
    allowPositionals: true,
  });

  if (!values.program && !values.source) {
    throw new Error(
      "Provide at least one target: --program <address> and/or --source <path>",
    );
  }

  const request =
    values.request ??
    [
      "Audit the following Solana target.",
      values.program ? `Program: ${values.program}` : "",
      values.source ? `Source: ${values.source}` : "",
    ]
      .filter(Boolean)
      .join(" ");

  return {
    program: values.program,
    source: values.source,
    ephemeral: Boolean(values.ephemeral),
    request,
  };
}

async function main(): Promise<void> {
  const cli = parseCli();

  const store = createStore();
  const crystalline = new CrystallineStore(store);
  await crystalline.start();
  const retriever = createHybridRetriever(crystalline);

  const checkpointer = cli.ephemeral
    ? createMemoryCheckpointer()
    : createPostgresCheckpointer();

  const graph = buildAuditGraph({
    deps: { chat: defaultChat, crystalline, retriever },
    checkpointer,
    store,
  });

  logger.info(
    { component: "ares", program: cli.program, source: cli.source },
    "Starting audit",
  );

  try {
    const result = await graph.invoke(
      {
        request: cli.request,
        programAddress: cli.program,
        sourcePath: cli.source,
      },
      {
        configurable: { thread_id: env.ARES_THREAD_ID },
        recursionLimit: env.ARES_MAX_ITERATIONS * 4,
      },
    );

    process.stdout.write("\n" + (result.report || "(no report generated)") + "\n");
    logger.info(
      { component: "ares", findings: result.mergedFindings.length },
      "Audit complete",
    );
  } finally {
    await crystalline.stop();
    if ("end" in checkpointer && typeof checkpointer.end === "function") {
      await (checkpointer as { end: () => Promise<void> }).end();
    }
    await closeNeo4j();
  }
}

main().catch((err) => {
  logger.error({ component: "ares", err: String(err) }, "Audit failed");
  process.exitCode = 1;
});
