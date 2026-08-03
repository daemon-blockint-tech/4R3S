/**
 * ARES LangGraph agent — minimal chat graph for `langgraph dev` / Studio.
 *
 * Wraps the existing LLMBackbone so LangSmith Studio can drive the same
 * provider stack as the Express server, without reimplementing orchestration.
 */
import 'dotenv/config';
import { Annotation, END, START, StateGraph } from '@langchain/langgraph';
import { AIMessage, type BaseMessage } from '@langchain/core/messages';
import { config } from '../config/index.js';
import { LLMBackbone } from '../llm/index.js';
import type { LLMMessage } from '../types/index.js';

const GraphState = Annotation.Root({
  messages: Annotation<BaseMessage[]>({
    reducer: (prev, next) => prev.concat(next),
    default: () => [],
  }),
});

function toAresMessages(messages: BaseMessage[]): LLMMessage[] {
  return messages.map((m) => {
    // Studio / REST may pass plain { role, content } objects before coercion.
    if (typeof (m as BaseMessage).getType === 'function') {
      const type = (m as BaseMessage).getType();
      const role: LLMMessage['role'] =
        type === 'human' ? 'user' : type === 'ai' ? 'assistant' : type === 'system' ? 'system' : 'user';
      const content =
        typeof m.content === 'string' ? m.content : JSON.stringify(m.content);
      return { role, content };
    }

    const raw = m as unknown as { role?: string; type?: string; content?: unknown };
    const r = raw.role ?? raw.type ?? 'human';
    const role: LLMMessage['role'] =
      r === 'human' || r === 'user'
        ? 'user'
        : r === 'ai' || r === 'assistant'
          ? 'assistant'
          : r === 'system'
            ? 'system'
            : 'user';
    const content =
      typeof raw.content === 'string' ? raw.content : JSON.stringify(raw.content ?? '');
    return { role, content };
  });
}

async function invokeAres(state: typeof GraphState.State) {
  const llm = new LLMBackbone(config.getLLMConfig());
  const response = await llm.chat(toAresMessages(state.messages), {
    maxTokens: 4096,
    temperature: 0.2,
  });
  return { messages: [new AIMessage(response.content)] };
}

const workflow = new StateGraph(GraphState)
  .addNode('agent', invokeAres)
  .addEdge(START, 'agent')
  .addEdge('agent', END);

export const graph = workflow.compile();
