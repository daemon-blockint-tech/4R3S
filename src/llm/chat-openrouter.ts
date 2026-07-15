/**
 * ChatOpenRouter — thin wrapper around LangChain's ChatOpenAI that targets
 * the OpenRouter API.
 *
 * OpenRouter is OpenAI-compatible, so we reuse ChatOpenAI with the base URL
 * pointed at OpenRouter and the API key injected. This keeps tool-calling,
 * streaming, and structured-output support identical to OpenAI usage.
 */
import { ChatOpenAI } from "@langchain/openai";
import { env } from "../config/env.js";

export interface ChatOpenRouterOptions {
  /** Override the default model from env. */
  model?: string;
  /** Sampling temperature (0 = deterministic). */
  temperature?: number;
  /** Max output tokens. */
  maxTokens?: number;
  /** Enable tool calling by default. */
  streaming?: boolean;
}

/**
 * Build a ChatOpenAI client configured for OpenRouter.
 */
export function createChatOpenRouter(
  opts: ChatOpenRouterOptions = {}
): ChatOpenAI {
  return new ChatOpenAI({
    apiKey: env.OPENROUTER_API_KEY,
    modelName: opts.model ?? env.OPENROUTER_MODEL,
    temperature: opts.temperature ?? 0,
    maxTokens: opts.maxTokens,
    streaming: opts.streaming ?? false,
    configuration: {
      baseURL: env.OPENROUTER_BASE_URL,
      defaultHeaders: {
        "HTTP-Referer": env.OPENROUTER_REFERRER,
        "X-Title": "ARES-Agent",
      },
    },
  });
}

/**
 * Default shared client. Reuse across nodes to benefit from connection
 * pooling. Recreate only if you need a different model/temperature.
 */
export const defaultChat = createChatOpenRouter();
