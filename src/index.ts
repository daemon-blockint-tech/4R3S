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
import { auditThreadId } from "./config/thread.js";
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
import { fallbackReport } from "./graph/nodes/report.js";
import {
  analyzerStatusTable,
  retrievalStatusTable,
  withAssuranceBanner,
} from "./graph/analyzer-status.js";
import {
  severityDistribution,
  severitySummaryTable,
} from "./knowledge/severity.js";
import type { AresState } from "./graph/state.js";
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

  // Checkpoint thread for this audit. Derived per target unless pinned by
  // ARES_THREAD_ID, so one target's state can never be resumed into another's.
  const threadId = auditThreadId({
    program: cli.program,
    source: cli.source,
    override: env.ARES_THREAD_ID,
  });

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
    { component: "ares", program: cli.program, source: cli.source, threadId },
    "Starting audit",
  );

  // Checked BEFORE the graph runs, not after. `canAffordAudit` was computed and
  // its result discarded, so an account that cannot pay still bought a full
  // audit at the provider — every analyzer, verify, remember and report — and
  // only then had the report withheld at settlement. Every run, on the config
  // .env.example leaves you in (BILLING_ENABLED=true, zero plan credits, no
  // on-demand).
  if (billing.config.enabled && !canAffordAudit(billing)) {
    throw new Error(
      "Payment required: the account has no prepaid credits and on-demand billing is " +
        "unavailable or its cap is exhausted. Top up before running — refusing to " +
        "spend on an audit whose report could not be released.",
    );
  }

  const runConfig = {
    configurable: { thread_id: threadId },
    recursionLimit: env.ARES_MAX_ITERATIONS * 4,
  };

  try {
    let result;
    try {
      result = await graph.invoke(
        {
          request: cli.request,
          programAddress: cli.program,
          sourcePath: cli.source,
        },
        runConfig,
      );
    } catch (err) {
      // A node that throws parks the run at that node with everything completed
      // so far checkpointed, so the fix is to resume — not to re-audit. Without
      // this the operator sees "Audit failed" and nothing else, even when every
      // analyzer already ran and was paid for.
      await reportParkedRun(graph, runConfig, threadId, err, billing.config.enabled);
      throw err;
    }

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
          resource: threadId,
        });
        // One transaction: the debit entries and the balance they produced go
        // to disk together, or neither does. Writing them separately let a
        // crash or a lost revision race leave the two permanently disagreeing.
        billing.store?.commit(billing.account, billing.ledger.drainUncommitted());
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
          process.exitCode = 2; // distinct from a generic audit failure (1) —
          // callers such as apps/auditor-api's worker need to tell "out of
          // credits" apart from "the audit itself failed" (see worker.py's
          // run_audit, which previously could not make this distinction)
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

/**
 * Emit whatever a failed run already produced, and say how to finish it.
 *
 * The checkpointer parks an interrupted run at the node that threw, with the
 * prior phases' output intact, so re-invoking on the same thread id resumes
 * from there rather than re-running the analyzers. Exiting with nothing but
 * "Audit failed" hides both the work already done and that fact.
 *
 * When billing is enabled the findings are withheld: settlement runs after the
 * graph, so nothing has been charged, and releasing a partial report here would
 * hand over unpaid output. The operator still gets the resume instruction.
 */
async function reportParkedRun(
  graph: ReturnType<typeof buildAuditGraph>,
  config: Parameters<ReturnType<typeof buildAuditGraph>["getState"]>[0],
  threadId: string,
  err: unknown,
  billingEnabled: boolean,
): Promise<void> {
  let parked;
  try {
    parked = await graph.getState(config);
  } catch {
    return; // No checkpointer, or it is unreachable — nothing to recover.
  }

  const values = parked?.values as Partial<AresState> | undefined;
  const pending = parked?.next ?? [];
  const findings = values?.verifiedFindings?.length
    ? values.verifiedFindings
    : (values?.mergedFindings ?? []);

  logger.error(
    {
      component: "ares",
      err: String(err),
      pendingNode: pending,
      findings: findings.length,
      threadId,
    },
    "Audit interrupted; run is parked and resumable",
  );

  if (pending.length > 0) {
    process.stderr.write(
      `\n[ares] Run parked at ${pending.join(", ")} with ${findings.length} finding(s) ` +
        `checkpointed. Re-run with the same target (thread ${threadId}) to resume from ` +
        "there rather than re-running the analyzers.\n",
    );
  }

  if (findings.length === 0) return;
  if (billingEnabled) {
    process.stderr.write(
      "[ares] Partial findings withheld: the run was not settled, so there is nothing to release.\n",
    );
    return;
  }

  const dist = severityDistribution(findings);
  process.stdout.write(
    "\n" +
      withAssuranceBanner(
        fallbackReport({
          target: values?.intake?.target ?? values?.request ?? "(unknown target)",
          summaryTable: severitySummaryTable(dist),
          statusTable: analyzerStatusTable(values?.analyzers ?? []),
          sourceTable: retrievalStatusTable(values?.retrieval ?? []),
          findings,
          coverage: values?.coverage ?? [],
          error: String(err),
        }),
        values?.analyzers ?? [],
        values?.retrieval ?? [],
      ) +
      "\n",
  );
}

main().catch((err) => {
  logger.error({ component: "ares", err: String(err) }, "Audit failed");
  process.exitCode = 1;
});
