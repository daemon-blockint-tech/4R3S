import { createOpenAI } from '@ai-sdk/openai'
import { generateText, type LanguageModel } from 'ai'
import {
  getLmStudioApiKey,
  getLmStudioBaseUrl,
  getLmStudioModel,
  isLmStudioEnabled,
  isLmStudioConfigured,
} from './lmstudio'

export type LlmProvider = 'gateway' | 'lmstudio'

export function getLlmProvider(): LlmProvider {
  return isLmStudioEnabled() ? 'lmstudio' : 'gateway'
}

/** Whether server-side text generation (titles, branch names, commits) can run. */
export function isLlmConfigured(): boolean {
  if (getLlmProvider() === 'lmstudio') {
    return isLmStudioConfigured()
  }
  return Boolean(process.env.AI_GATEWAY_API_KEY)
}

function lmStudioModel(): LanguageModel {
  const modelId = getLmStudioModel()
  if (!modelId) {
    throw new Error('LM_STUDIO_MODEL is required when using LM Studio (LLM_PROVIDER=lmstudio)')
  }

  const client = createOpenAI({
    baseURL: getLmStudioBaseUrl(),
    apiKey: getLmStudioApiKey(),
  })
  return client.chat(modelId)
}

function gatewayModel(): LanguageModel {
  const modelId = process.env.AI_GATEWAY_MODEL ?? 'openai/gpt-5-nano'
  return modelId as LanguageModel
}

export function getTextGenerationModel(): LanguageModel {
  return getLlmProvider() === 'lmstudio' ? lmStudioModel() : gatewayModel()
}

/** Uses POST /v1/chat/completions on the LM Studio OpenAI-compatible server. */
export async function generateLlmText(prompt: string, temperature = 0.3) {
  return generateText({
    model: getTextGenerationModel(),
    prompt,
    temperature,
  })
}

export {
  getLmStudioApiKey,
  getLmStudioBaseUrl,
  getLmStudioModel,
  isLmStudioConfigured,
  isLmStudioEnabled,
  LM_STUDIO_DEFAULT_BASE_URL,
  LM_STUDIO_OPENAI_COMPAT_PATHS,
} from './lmstudio'
