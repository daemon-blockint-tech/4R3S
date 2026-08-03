/**
 * LangSmith tracing for ARES pipelines.
 *
 * Wraps LLM calls and multi-step agent/orchestration flows with `traceable`
 * spans. Honors LANGSMITH_* / LANGCHAIN_TRACING_V2 env vars (see .env.example).
 */

import { traceable } from 'langsmith/traceable';
import type { LLMMessage, LLMResponse, LLMProvider } from '../types/index.js';

/** Minimal adapter surface for invokeLLM (avoids llm ↔ tracing circular import). */
export interface TracedLLMAdapter {
  name: string;
  chat(messages: LLMMessage[], options?: TracedChatOptions): Promise<LLMResponse>;
}

export interface TracedChatOptions {
  maxTokens?: number;
  temperature?: number;
  topP?: number;
  stopSequences?: string[];
  systemPrompt?: string;
  tools?: Array<{ name: string; description: string; parameters: Record<string, unknown> }>;
}

// =============================================================================
// ENV HELPERS
// =============================================================================

/** True when LangSmith tracing is enabled via standard env vars. */
export function isLangSmithTracingEnabled(): boolean {
  const tracing = process.env.LANGSMITH_TRACING ?? process.env.LANGCHAIN_TRACING_V2;
  return /^(true|1|yes|on)$/i.test((tracing || '').trim());
}

/** Resolved LangSmith project name (never includes secrets). */
export function getLangSmithProject(): string | undefined {
  return process.env.LANGSMITH_PROJECT?.trim()
    || process.env.LANGCHAIN_PROJECT?.trim()
    || undefined;
}

// =============================================================================
// CORE TRACEABLE STEPS (reference pattern)
// =============================================================================

/** Build message list from system + user prompt parts. */
export const formatPrompt = traceable(
  (parts: { system?: string; user: string }): LLMMessage[] => {
    const messages: LLMMessage[] = [];
    if (parts.system) {
      messages.push({ role: 'system', content: parts.system });
    }
    messages.push({ role: 'user', content: parts.user });
    return messages;
  },
  { name: 'formatPrompt' },
) as unknown as (parts: { system?: string; user: string }) => LLMMessage[];

/** Execute a provider adapter chat completion (all LLM HTTP/CLI calls flow here). */
export const invokeLLM = traceable(
  async (
    adapter: TracedLLMAdapter,
    messages: LLMMessage[],
    options?: TracedChatOptions,
    meta?: { provider?: LLMProvider; model?: string },
  ): Promise<LLMResponse> => {
    void meta;
    return adapter.chat(messages, options);
  },
  {
    run_type: 'llm',
    name: 'invokeLLM',
    // The first positional arg is a live adapter instance whose `config` holds the
    // provider API key. Never ship that to LangSmith — log only its name plus the
    // prompt/options/model, so traces stay useful without leaking a secret.
    processInputs: (inputs) => {
      const [adapter, messages, options, meta] = inputs.args;
      return {
        provider: meta?.provider ?? adapter?.name,
        model: meta?.model,
        messages,
        options,
      };
    },
    // Surface token usage in LangSmith's native shape so llm runs report tokens/cost.
    processOutputs: (output) => {
      const usage = output?.usage;
      if (!usage) return output;
      return {
        ...output,
        usage_metadata: {
          input_tokens: usage.promptTokens,
          output_tokens: usage.completionTokens,
          total_tokens: usage.totalTokens,
        },
      };
    },
  },
) as (
  adapter: TracedLLMAdapter,
  messages: LLMMessage[],
  options?: TracedChatOptions,
  meta?: { provider?: LLMProvider; model?: string },
) => Promise<LLMResponse>;

/** Parse structured output from raw LLM text via a caller-supplied parser. */
export const parseOutput = traceable(
  <T>(raw: string, parser: (text: string) => T, label?: string): T => {
    void label;
    return parser(raw);
  },
  { name: 'parseOutput' },
) as unknown as <T>(raw: string, parser: (text: string) => T, label?: string) => T;

// =============================================================================
// PIPELINE SPANS
// =============================================================================

/** Top-level ReAct agent loop (task → tools → debrief). */
export const runAgentPipeline = traceable(
  async <T>(runner: () => Promise<T>): Promise<T> => runner(),
  { name: 'runAgentPipeline' },
) as <T>(runner: () => Promise<T>) => Promise<T>;

/** Multi-round decomposition orchestrator (decompose → worker → synthesize). */
export const runDecompositionPipeline = traceable(
  async <T>(runner: () => Promise<T>): Promise<T> => runner(),
  { name: 'runDecompositionPipeline' },
) as <T>(runner: () => Promise<T>) => Promise<T>;

/** Orchestrator planning step: objective → innocuous worker queries. */
export const decomposeObjective = traceable(
  async <T>(runner: () => Promise<T>): Promise<T> => runner(),
  { name: 'decomposeObjective' },
) as <T>(runner: () => Promise<T>) => Promise<T>;

/** Orchestrator synthesis step: worker answers → attack-surface model. */
export const synthesizeRound = traceable(
  async <T>(runner: () => Promise<T>): Promise<T> => runner(),
  { name: 'synthesizeRound' },
) as <T>(runner: () => Promise<T>) => Promise<T>;

/** Format the initial agent task prompt (system context + target intel). */
export const formatAgentTaskPrompt = traceable(
  (builder: () => string): string => builder(),
  { name: 'formatAgentTaskPrompt' },
) as unknown as (builder: () => string) => string;

export { traceable };
