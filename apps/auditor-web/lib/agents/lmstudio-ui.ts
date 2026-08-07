import type { AgentType } from '@/lib/sandbox/agents'

/** UI agent id for LM Studio (runs Codex CLI against local OpenAI-compatible server). */
export const LM_STUDIO_AGENT = 'lmstudio' as const

/** Max length for model dropdown trigger text. */
const MAX_LM_STUDIO_LABEL_LEN = 24

/** Org / hub prefixes to skip when deriving a short label from a model id. */
const LM_STUDIO_LABEL_SKIP = new Set([
  'meta',
  'google',
  'microsoft',
  'mistralai',
  'huggingface',
  'lmstudio',
  'openai',
  'thebloke',
  'nousresearch',
  'cognitivecomputations',
])

export function isLmStudioAgent(agent: string | null | undefined): agent is typeof LM_STUDIO_AGENT {
  return agent === LM_STUDIO_AGENT
}

/**
 * Short human-readable label for LM Studio model dropdowns.
 * Prefer LM_STUDIO_MODEL_LABEL when set; otherwise derive from the model id.
 * Full model id remains the select value / selectedModel.
 */
export function formatLmStudioModelLabel(modelId: string): string {
  const fromEnv = process.env.LM_STUDIO_MODEL_LABEL?.trim()
  if (fromEnv) {
    return truncateLabel(fromEnv)
  }
  return truncateLabel(deriveLmStudioModelLabel(modelId))
}

function truncateLabel(label: string): string {
  if (label.length <= MAX_LM_STUDIO_LABEL_LEN) {
    return label
  }
  return `${label.slice(0, MAX_LM_STUDIO_LABEL_LEN - 1)}…`
}

/**
 * Derive a short label from a model id, e.g.
 * `gemma-4-e4b-it-ultra-uncensored-heretic-mlx-mixed_4_6` → `Gemma 4 (local)`
 */
function deriveLmStudioModelLabel(modelId: string): string {
  const base = modelId.split('/').pop()?.trim() || modelId.trim()
  if (!base) {
    return 'Local model'
  }

  const parts = base.split(/[-_]+/).filter(Boolean)
  let i = 0
  while (i < parts.length && LM_STUDIO_LABEL_SKIP.has(parts[i]!.toLowerCase())) {
    i++
  }

  const head = parts[i] || base
  const familyMatch = head.match(/^([a-zA-Z]+)(\d+(?:\.\d+)*)?$/i)
  const family = familyMatch?.[1] || head
  let version = familyMatch?.[2] || ''

  if (!version && parts[i + 1] && /^\d+(\.\d+)*$/.test(parts[i + 1]!)) {
    version = parts[i + 1]!
  }

  const titled = family.charAt(0).toUpperCase() + family.slice(1).toLowerCase()
  const name = version ? `${titled} ${version}` : titled
  return `${name} (local)`
}

/** Map UI agent to sandbox executor agent. */
export function resolveSandboxAgent(agent: string): AgentType {
  if (isLmStudioAgent(agent)) {
    return 'codex'
  }
  return agent as AgentType
}
