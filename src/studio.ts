/**
 * LangGraph Studio entry point.
 *
 * `langgraph dev` needs a graph it can construct with no arguments, but
 * `buildAuditGraph` takes `{ deps, checkpointer, store }` — the CLI in
 * `index.ts` assembles those and then owns the run. This module assembles the
 * same dependencies and hands back the compiled graph, so Studio drives the real
 * pipeline rather than a parallel copy of it that could drift.
 *
 * Two deliberate differences from the CLI, both because Studio is a debugger and
 * not a delivery path:
 *
 * 1. **No checkpointer and no store are passed.** `graph.compile()` treats both
 *    as optional, and the Agent Server injects its own — that is what makes
 *    Studio's thread list and time-travel work. Passing the Postgres
 *    checkpointer here would give the graph two sources of truth for the same
 *    thread and require `POSTGRES_URL` just to open the UI.
 *
 * 2. **Billing is not wired.** `index.ts` wraps the chat model in `meterChat`
 *    and settles the run before releasing the report. A Studio session is
 *    iteration, not a delivered audit; metering it would bill an operator for
 *    stepping through their own graph. The trade is that token spend in Studio
 *    is invisible to the ledger, which is the correct direction for a debugger
 *    but worth knowing before running a long session against a paid model.
 *
 * Crystalline is started here because `CrystallineStore.start()` is async and
 * RECALL reads from it on the first superstep; a lazily-started store would make
 * the first Studio run behave differently from every later one.
 */
import { CrystallineStore } from "./memory/crystalline-store.js";
import { createStore } from "./persistence/store.js";
import { createKnowledgeWriter } from "./persistence/knowledge-writer.js";
import { createHybridRetriever } from "./retrieval/index.js";
import { defaultChat } from "./llm/chat-openrouter.js";
import { buildAuditGraph } from "./graph/build-graph.js";
import { logger } from "./config/logger.js";
import { env } from "./config/env.js";

/**
 * Built once per server process, not once per run.
 *
 * `langgraph dev` calls the export for every invocation. Rebuilding would spin
 * up a fresh Crystalline store each time, so memory written by REMEMBER in one
 * Studio run would be invisible to the next — the opposite of what someone
 * stepping through the recall path is trying to observe.
 */
let compiled: ReturnType<typeof buildAuditGraph> | undefined;

export async function graph(): Promise<ReturnType<typeof buildAuditGraph>> {
  if (compiled) return compiled;

  // The most common Studio failure is not a graph problem: the model endpoint is
  // misconfigured and every LLM node dies on the first call. Say where the calls
  // are going, once, at startup — a wrong base URL is otherwise reported as a
  // bare "Connection error" several layers down.
  logger.info(
    {
      component: "studio",
      baseUrl: env.OPENROUTER_BASE_URL,
      model: env.OPENROUTER_MODEL,
    },
    "Building the ARES audit graph for Studio",
  );

  const store = createStore();
  const crystalline = new CrystallineStore(store);
  await crystalline.start();

  compiled = buildAuditGraph({
    deps: {
      chat: defaultChat,
      crystalline,
      retriever: createHybridRetriever(crystalline),
      knowledge: createKnowledgeWriter(),
    },
  });

  return compiled;
}

export default graph;
