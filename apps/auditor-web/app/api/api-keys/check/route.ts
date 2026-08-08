import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db/client'
import { keys } from '@/lib/db/schema'
import { eq, and } from 'drizzle-orm'
import { getServerSession } from '@/lib/session/get-server-session'
import { isLmStudioConfigured } from '@/lib/llm/lmstudio'
import { isLmStudioAgent } from '@/lib/agents/lmstudio-ui'

type KeyProvider = 'openai' | 'gemini' | 'cursor' | 'anthropic' | 'aigateway'

// Map agents to their required providers
const AGENT_PROVIDER_MAP: Record<string, KeyProvider | null> = {
  claude: 'aigateway', // Claude uses Vercel AI Gateway
  codex: 'aigateway', // Codex uses Vercel AI Gateway
  copilot: null, // Copilot uses user's GitHub token from their account
  cursor: 'cursor',
  gemini: 'gemini',
  opencode: 'openai', // OpenCode can use OpenAI or Anthropic, but primarily OpenAI
}

// Check if a model is an Anthropic model
function isAnthropicModel(model: string): boolean {
  const anthropicPatterns = ['claude', 'sonnet', 'opus']
  const lowerModel = model.toLowerCase()
  return anthropicPatterns.some((pattern) => lowerModel.includes(pattern))
}

// Check if a model is an OpenAI model
function isOpenAIModel(model: string): boolean {
  const openaiPatterns = ['gpt', 'openai']
  const lowerModel = model.toLowerCase()
  return openaiPatterns.some((pattern) => lowerModel.includes(pattern))
}

// Check if a model is a Gemini model
function isGeminiModel(model: string): boolean {
  const geminiPatterns = ['gemini']
  const lowerModel = model.toLowerCase()
  return geminiPatterns.some((pattern) => lowerModel.includes(pattern))
}

export async function GET(req: NextRequest) {
  try {
    const session = await getServerSession()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const { searchParams } = new URL(req.url)
    const agent = searchParams.get('agent')
    const model = searchParams.get('model')

    if (!agent) {
      return NextResponse.json({ error: 'Agent parameter is required' }, { status: 400 })
    }

    // Local (LM Studio) agent — Codex CLI against OpenAI-compatible /v1/responses
    if (isLmStudioAgent(agent)) {
      return NextResponse.json({
        success: true,
        hasKey: isLmStudioConfigured(),
        provider: 'lmstudio',
        agentName: 'Local (LM Studio)',
      })
    }

    let provider = AGENT_PROVIDER_MAP[agent]
    if (provider === undefined) {
      return NextResponse.json({ error: 'Invalid agent' }, { status: 400 })
    }

    // Special handling for Copilot - check if user has GitHub token
    if (agent === 'copilot') {
      const { getUserGitHubToken } = await import('@/lib/github/user-token')
      const githubToken = await getUserGitHubToken()
      const hasKey = !!githubToken

      return NextResponse.json({
        success: true,
        hasKey,
        provider: 'github',
        agentName: 'Copilot',
      })
    }

    // Codex can run against local LM Studio when explicitly configured server-side
    if (agent === 'codex' && isLmStudioConfigured()) {
      return NextResponse.json({
        success: true,
        hasKey: true,
        provider: 'lmstudio',
        agentName: 'Codex',
      })
    }

    // Override provider based on model for multi-provider agents
    if (model && (agent === 'cursor' || agent === 'opencode')) {
      if (isAnthropicModel(model)) {
        provider = 'anthropic'
      } else if (isGeminiModel(model)) {
        provider = 'gemini'
      } else if (isOpenAIModel(model)) {
        // For OpenAI models, prefer AI Gateway if available, otherwise use OpenAI
        provider = 'aigateway'
      }
      // For cursor with no recognizable pattern, keep the default 'cursor' provider
    }

    // Check only the user's stored keys; platform env keys must not leak
    // provider configuration through this status endpoint
    const userKey = await db
      .select({ value: keys.value })
      .from(keys)
      .where(and(eq(keys.userId, session.user.id), eq(keys.provider, provider!)))
      .limit(1)
    const hasKey = !!userKey[0]?.value

    return NextResponse.json({
      success: true,
      hasKey,
      provider,
      agentName: agent.charAt(0).toUpperCase() + agent.slice(1),
    })
  } catch (error) {
    console.error('Error checking API key:', error)
    return NextResponse.json({ error: 'Failed to check API key' }, { status: 500 })
  }
}
