/**
 * Computer Use Agent (CUA) tool.
 *
 * Drives a real, Scrapybara-hosted browser to investigate an audit target
 * (block explorers, source repos, docs) and returns a text transcript for the
 * analyzer node to turn into findings. Opt-in and read-only:
 *   - Gated behind CUA_ENABLED (env) or a per-run override (the `--cua` CLI
 *     flag), AND both OPENAI_API_KEY + SCRAPYBARA_API_KEY being present.
 *   - Given `cuaInvestigationSystemPrompt`, which forbids authentication,
 *     form submission, and any other state-changing action.
 *
 * Unlike the rest of ARES (OpenRouter), the CUA computer-use model
 * (`computer-use-preview`) is invoked directly by `@langchain/langgraph-cua`
 * via `ChatOpenAI`, which reads `OPENAI_API_KEY` from the environment — there
 * is no way to route it through OpenRouter.
 */
import { HumanMessage } from "@langchain/core/messages";
import { createCua } from "@langchain/langgraph-cua";
import { stopInstance } from "@langchain/langgraph-cua/utils";

import { env } from "../config/env.js";
import { logger } from "../config/logger.js";
import { messageText } from "../llm/message-text.js";
import { cuaInvestigationSystemPrompt } from "../llm/prompts.js";

/** Per-run override so `--cua` can enable CUA without editing env (env is
 * validated/frozen at import time). */
let runtimeOverride = false;

export function setCuaOverride(enabled: boolean): void {
  runtimeOverride = enabled;
}

/** True when CUA is opted in AND both required API keys are configured. */
export function hasCua(): boolean {
  return (
    (env.CUA_ENABLED || runtimeOverride) &&
    Boolean(env.OPENAI_API_KEY) &&
    Boolean(env.SCRAPYBARA_API_KEY)
  );
}

export interface CuaResult {
  available: boolean;
  transcript: string;
  streamUrl?: string;
  note?: string;
}

/**
 * Build the CUA graph, reporting the VM id the moment the graph has one.
 *
 * The VM is started *inside* the graph (`createVMInstance` calls Scrapybara's
 * `startBrowser`) and its id reaches us only through the returned state, so it
 * exists nowhere outside discarded in-memory state until `invoke` resolves. Any
 * throw from `invoke` therefore skipped the cleanup below — and throwing is the
 * normal outcome this is meant to cover: LangGraph raises `GraphRecursionError`
 * when the browsing agent does not converge within `CUA_RECURSION_LIMIT`, which
 * is roughly 24 actions, and a transient OpenAI or Scrapybara error mid-loop
 * does the same. The leaked VM then runs billed until `CUA_TIMEOUT_HOURS`.
 *
 * `nodeBeforeAction` is the node the graph runs immediately after
 * `createVMInstance`, and again before every later action, so it observes the
 * id while the run is still alive. Exported so that capture can be exercised
 * against the real graph without a live VM.
 */
export function createCuaGraph(
  onInstance: (id: string) => void,
): ReturnType<typeof createCua> {
  return createCua({
    scrapybaraApiKey: env.SCRAPYBARA_API_KEY,
    timeoutHours: env.CUA_TIMEOUT_HOURS,
    environment: env.CUA_ENVIRONMENT,
    recursionLimit: env.CUA_RECURSION_LIMIT,
    prompt: cuaInvestigationSystemPrompt(),
    nodeBeforeAction: async (state) => {
      if (state.instanceId) onInstance(state.instanceId);
      return {};
    },
  });
}

/** Run a read-only CUA investigation. Never throws. */
export async function runCuaInvestigation(objective: string): Promise<CuaResult> {
  if (!hasCua()) {
    return {
      available: false,
      transcript: "",
      note: "CUA not enabled or not configured (CUA_ENABLED/--cua, OPENAI_API_KEY, SCRAPYBARA_API_KEY)",
    };
  }

  let instanceId: string | undefined;
  const graph = createCuaGraph((id) => {
    instanceId = id;
  });

  try {
    const result = await graph.invoke(
      { messages: [new HumanMessage(objective)] },
      { recursionLimit: env.CUA_RECURSION_LIMIT },
    );
    // The hook has already seen the id if any node ran after the VM was
    // created; this covers only a graph shape where none did.
    instanceId ??= result.instanceId;

    if (result.streamUrl) {
      logger.info(
        { component: "cua", streamUrl: result.streamUrl },
        "CUA investigation stream",
      );
    }

    const last = result.messages[result.messages.length - 1];
    const transcript = last ? messageText(last.content) : "";

    logger.info(
      { component: "cua", length: transcript.length },
      "CUA investigation complete",
    );
    return { available: true, transcript, streamUrl: result.streamUrl };
  } catch (err) {
    logger.warn(
      { component: "cua", err: String(err) },
      "CUA investigation failed",
    );
    return { available: false, transcript: "", note: String(err) };
  } finally {
    if (instanceId) {
      try {
        await stopInstance(instanceId);
      } catch (err) {
        logger.warn(
          { component: "cua", instanceId, err: String(err) },
          "Failed to stop CUA VM instance (non-fatal)",
        );
      }
    }
  }
}
