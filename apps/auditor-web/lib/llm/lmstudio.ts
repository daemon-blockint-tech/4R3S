/** LM Studio OpenAI-compatible API (default local port 1234). */
export const LM_STUDIO_DEFAULT_BASE_URL = 'http://localhost:1234/v1'

/**
 * OpenAI-compatible paths served by LM Studio (see LM Studio developer docs):
 * GET  /v1/models
 * POST /v1/chat/completions  — chat (AI SDK, LangChain)
 * POST /v1/responses         — Codex CLI wire API
 * POST /v1/embeddings
 * POST /v1/completions
 */
export const LM_STUDIO_OPENAI_COMPAT_PATHS = [
  '/v1/models',
  '/v1/chat/completions',
  '/v1/responses',
  '/v1/embeddings',
  '/v1/completions',
] as const

export function isLmStudioEnabled(): boolean {
  const explicit = process.env.LLM_PROVIDER?.toLowerCase()
  if (explicit === 'lmstudio' || explicit === 'lm-studio') return true
  return Boolean(process.env.LM_STUDIO_BASE_URL)
}

export function getLmStudioBaseUrl(): string {
  const raw = process.env.LM_STUDIO_BASE_URL ?? LM_STUDIO_DEFAULT_BASE_URL
  return raw.replace(/\/+$/, '')
}

export function getLmStudioApiKey(): string {
  return process.env.LM_STUDIO_API_KEY ?? process.env.OPENAI_API_KEY ?? 'lm-studio'
}

export function getLmStudioModel(): string | undefined {
  return process.env.LM_STUDIO_MODEL
}

/** LM Studio mode with a loaded model id configured. */
export function isLmStudioConfigured(): boolean {
  return isLmStudioEnabled() && Boolean(getLmStudioModel())
}
