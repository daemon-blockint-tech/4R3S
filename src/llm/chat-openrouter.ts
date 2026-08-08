/**
 * The chat client for every graph node, chosen by where the endpoint points.
 *
 * Two clients, one seam. `ChatOpenAI` with a `baseURL` override talks to
 * anything OpenAI-compatible, which is why a local LM Studio server works today.
 * `ChatOpenRouter` talks only to OpenRouter, and in exchange exposes controls
 * the generic client cannot reach.
 *
 * The one that matters here is **`data_collection: "deny"`**. ARES sends the
 * audited party's *source code* to the model — confidential third-party code we
 * were given to review. Through the generic client there is no way to say
 * whether a downstream provider may retain or train on it, and therefore no way
 * to answer that question for a client. Through `ChatOpenRouter` there is, and
 * requests are routed only to providers that accept the policy.
 *
 * Two more, both real rather than nice-to-have:
 *   - `usage_metadata` carries `output_token_details.reasoning` and
 *     `input_token_details.cache_read`. `billing/` prices a run in credits from
 *     the meter's snapshot, and those two lines are real cost the generic client
 *     never reports.
 *   - `models` + `route: "fallback"` makes a fallback tier a routing decision
 *     rather than a try/catch around every node.
 *
 * Switching wholesale is the wrong trade: `ChatOpenRouter` cannot address
 * `http://localhost:1234/v1`, so it would delete local development. Hence the
 * branch — the base URL already says which world we are in.
 *
 * Model *selection* is deliberately untouched here. This function decides which
 * client class to build, not which model to name; the two are independent and
 * changing both at once makes neither reviewable.
 */
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { ChatOpenAI } from "@langchain/openai";
import { ChatOpenRouter } from "@langchain/openrouter";

import { env } from "../config/env.js";
import { logger } from "../config/logger.js";

export interface ChatOpenRouterOptions {
  /** Override the default model from env. */
  model?: string;
  /** Sampling temperature (0 = deterministic). */
  temperature?: number;
  /** Max output tokens. */
  maxTokens?: number;
  /** Per-request deadline in ms; defaults to OPENROUTER_TIMEOUT_MS. */
  timeout?: number;
  /** Enable tool calling by default. */
  streaming?: boolean;
  /**
   * Models to fall back to, in order, when the primary is unavailable.
   *
   * OpenRouter-only — a loopback server serves one model and has nothing to
   * fall back to. Ignored on the local path rather than throwing, so the same
   * call site works in both worlds.
   */
  fallbackModels?: string[];
}

/**
 * Hosts where the API key is a placeholder the server ignores.
 *
 * Mirrors the list in `config/env.ts`, which uses it to warn about a remote
 * endpoint paired with a local key. Kept as its own copy rather than imported
 * because the two answer different questions: that one asks "is this pairing
 * impossible?", this one asks "which client can reach it?".
 */
const LOOPBACK_HOSTS = new Set([
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "::1",
  "[::1]",
]);

/** True when the base URL names a local server rather than OpenRouter. */
export function isLocalEndpoint(baseUrl: string): boolean {
  try {
    return LOOPBACK_HOSTS.has(new URL(baseUrl).hostname);
  } catch {
    // An unparseable URL is not a local server. Falling back to the generic
    // client keeps the failure where it belongs — at the request — instead of
    // routing it to OpenRouter, which would report a confusing auth error for
    // what is really a malformed configuration.
    return true;
  }
}

/**
 * Build the chat client for the configured endpoint.
 *
 * Returns `BaseChatModel` rather than a concrete class: the graph takes
 * `deps.chat` as a `BaseChatModel` and calls only `invoke`, so nothing
 * downstream needs to know which of the two it received.
 */
export function createChatOpenRouter(
  opts: ChatOpenRouterOptions = {},
): BaseChatModel {
  const model = opts.model ?? env.OPENROUTER_MODEL;
  const temperature = opts.temperature ?? 0;
  const timeout = opts.timeout ?? env.OPENROUTER_TIMEOUT_MS;
  const streaming = opts.streaming ?? false;

  if (isLocalEndpoint(env.OPENROUTER_BASE_URL)) {
    return new ChatOpenAI({
      apiKey: env.OPENROUTER_API_KEY,
      modelName: model,
      temperature,
      maxTokens: opts.maxTokens,
      // Without this the SDK waits indefinitely on a stalled connection, and
      // the retry wrapper never sees an error to react to.
      timeout,
      streaming,
      configuration: {
        baseURL: env.OPENROUTER_BASE_URL,
        defaultHeaders: {
          "HTTP-Referer": env.OPENROUTER_REFERRER,
          "X-Title": "ARES-Agent",
        },
      },
    });
  }

  // NOTE: `ChatOpenRouter` takes neither `streaming` nor `timeout` in its
  // constructor — streaming is a call-time choice, and the deadline is a
  // per-request `AbortSignal`. Losing the deadline would restore the hang the
  // local branch's comment warns about, so it is applied at the call site
  // instead (`graph/util.ts`), where it now covers both clients.
  void streaming;
  return new ChatOpenRouter({
    apiKey: env.OPENROUTER_API_KEY,
    model,
    temperature,
    maxTokens: opts.maxTokens,
    // Non-negotiable for this product: the prompt carries the audited party's
    // source. Providers that will not accept the policy are not routed to.
    provider: { data_collection: "deny" },
    ...(opts.fallbackModels?.length
      ? { models: [model, ...opts.fallbackModels], route: "fallback" as const }
      : {}),
    // Attribution, and the same identity the local path sends as headers.
    siteUrl: env.OPENROUTER_REFERRER,
    siteName: "ARES-Agent",
  });
}

/**
 * Default shared client. Reuse across nodes to benefit from connection
 * pooling. Recreate only if you need a different model/temperature.
 */
export const defaultChat = createChatOpenRouter();

logger.debug(
  {
    component: "llm",
    client: isLocalEndpoint(env.OPENROUTER_BASE_URL)
      ? "ChatOpenAI (local endpoint)"
      : "ChatOpenRouter (data_collection=deny)",
    baseUrl: env.OPENROUTER_BASE_URL,
  },
  "Chat client selected",
);
