import { NextResponse } from 'next/server'
import { getLmStudioModel, isLmStudioConfigured, isLmStudioEnabled } from '@/lib/llm/lmstudio'
import { formatLmStudioModelLabel } from '@/lib/agents/lmstudio-ui'
import { getServerSession } from '@/lib/session/get-server-session'
import { withObservedRoute } from '@/lib/observability/route-handler'

async function getLlmStatus() {
  const session = await getServerSession()
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const enabled = isLmStudioEnabled()
  const configured = isLmStudioConfigured()
  const model = getLmStudioModel()

  // Internal baseUrl is intentionally omitted from the response
  return NextResponse.json({
    lmStudio: {
      enabled,
      configured,
      model: model ?? null,
      modelLabel: model ? formatLmStudioModelLabel(model) : null,
    },
  })
}

export const GET = withObservedRoute('/api/llm/status', 'usage', getLlmStatus)
