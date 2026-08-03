import { describe, expect, it } from 'vitest';
import {
  formatPrompt,
  invokeLLM,
  parseOutput,
  isLangSmithTracingEnabled,
  getLangSmithProject,
} from '../tracing/index.js';
import type { LLMMessage, LLMResponse } from '../types/index.js';

describe('LangSmith tracing module', () => {
  it('formatPrompt builds system + user messages', () => {
    const messages = formatPrompt({ system: 'sys', user: 'hello' });
    expect(messages).toEqual([
      { role: 'system', content: 'sys' },
      { role: 'user', content: 'hello' },
    ] satisfies LLMMessage[]);
  });

  it('formatPrompt omits system when absent', () => {
    const messages = formatPrompt({ user: 'only user' });
    expect(messages).toEqual([{ role: 'user', content: 'only user' }]);
  });

  it('invokeLLM delegates to adapter.chat', async () => {
    const fakeResponse: LLMResponse = {
      content: 'ok',
      model: 'mock',
      finishReason: 'stop',
    };
    const adapter = {
      name: 'mock',
      chat: async () => fakeResponse,
    };
    const result = await invokeLLM(adapter, [{ role: 'user', content: 'ping' }]);
    expect(result).toBe(fakeResponse);
  });

  it('parseOutput runs the supplied parser', () => {
    const parsed = parseOutput('{"a":1}', (t) => JSON.parse(t) as { a: number });
    expect(parsed).toEqual({ a: 1 });
  });

  it('isLangSmithTracingEnabled respects LANGSMITH_TRACING', () => {
    const prev = process.env.LANGSMITH_TRACING;
    process.env.LANGSMITH_TRACING = 'true';
    expect(isLangSmithTracingEnabled()).toBe(true);
    process.env.LANGSMITH_TRACING = 'off';
    expect(isLangSmithTracingEnabled()).toBe(false);
    if (prev === undefined) delete process.env.LANGSMITH_TRACING;
    else process.env.LANGSMITH_TRACING = prev;
  });

  it('getLangSmithProject reads LANGSMITH_PROJECT without throwing', () => {
    const prev = process.env.LANGSMITH_PROJECT;
    process.env.LANGSMITH_PROJECT = 'test-project';
    expect(getLangSmithProject()).toBe('test-project');
    if (prev === undefined) delete process.env.LANGSMITH_PROJECT;
    else process.env.LANGSMITH_PROJECT = prev;
  });
});
