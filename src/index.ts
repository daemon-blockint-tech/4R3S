/**
 * ARES-AGENT entry point.
 *
 * Usage:
 *   npm run audit -- --program <address>
 *   npm run audit -- --source <path>
 *   npm run audit -- --program <address> --source <path> [--ephemeral]
 *   npm run audit -- --program <address> --cua
 *
 * Runs the audit graph end-to-end for one target and prints the report.
 * `--ephemeral` uses an in-memory checkpointer (no Postgres needed) for quick
 * local runs. `--cua` opts this run into the browser-driving CUA analyzer
 * (requires OPENAI_API_KEY + SCRAPYBARA_API_KEY; see .env.example).
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
import { createKnowledgeWriter } from "./persistence/knowledge-writer.js";
import { createHybridRetriever } from "./retrieval/index.js";
import { setCuaOverride } from "./tools/cua.js";
import { buildAuditGraph } from "./graph/build-graph.js";
import {
  createBilling,
  canAffordAudit,
  meterChat,
  settleUsage,
  InsufficientCreditsError,
} from "./billing/index.js";

interface Cli {
  program?: string;
  source?: string;
  ephemeral: boolean;
  cua: boolean;
  request: string;
}

function parseCli(): Cli {
  const { values } = parseArgs({
    options: {
      program: { type: "string" },
      source: { type: "string" },
      ephemeral: { type: "boolean", default: false },
      cua: { type: "boolean", default: false },
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
    cua: Boolean(values.cua),
    request,
  };
}

async function main(): Promise<void> {
  const cli = parseCli();
  setCuaOverride(cli.cua);

  const store = createStore();
  const crystalline = new CrystallineStore(store);
  await crystalline.start();
  const retriever = createHybridRetriever(crystalline);
  const knowledge = createKnowledgeWriter();

  const checkpointer = cli.ephemeral
    ? createMemoryCheckpointer()
    : createPostgresCheckpointer();

  // Billing is opt-in (BILLING_ENABLED). When on, meter each LLM call so the
  // run can be priced and charged in credits after it completes.
  const billing = createBilling();
  const chat = billing.config.enabled
    ? meterChat(defaultChat, billing.meter)
    : defaultChat;

  // Pre-flight: surface an unpayable configuration before spending on the audit.
  if (billing.config.enabled) {
    canAffordAudit(billing);
  }

  const graph = buildAuditGraph({
    deps: { chat, crystalline, retriever, knowledge },
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

    logger.info(
      { component: "ares", findings: result.mergedFindings.length },
      "Audit complete",
    );

    const report = result.report || "(no report generated)";

    if (!billing.config.enabled) {
      process.stdout.write("\n" + report + "\n");
    } else {
      // Enforce payment BEFORE delivering the report: price and charge the run
      // (prepaid first, on-demand overflow settled via MPP), persist the new
      // balance, and only then release the report. If the account can't cover
      // the charge, the report is withheld rather than given away for free.
      try {
        const bill = await settleUsage({
          usage: billing.meter.snapshot(),
          model: env.OPENROUTER_MODEL,
          ledger: billing.ledger,
          mpp: billing.mpp,
          config: billing.config,
          resource: env.ARES_THREAD_ID,
        });
        billing.store?.save(billing.account);
        process.stdout.write("\n" + report + "\n");
        process.stdout.write(`\n[billing] ${bill.summary}\n`);
      } catch (err) {
        if (err instanceof InsufficientCreditsError) {
          logger.error(
            { component: "ares", err: err.message },
            "Settlement failed; report withheld",
          );
          process.stdout.write(`\n[billing] Payment required: ${err.message}\n`);
          process.stdout.write(
            "[billing] Report withheld until the account balance is settled.\n",
          );
          process.exitCode = 1;
        } else {
          throw err;
        }
      }
    }
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
