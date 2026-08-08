import { NextResponse } from 'next/server'
import { getServerSession } from '@/lib/session/get-server-session'
import { getUserUsageSummary } from '@/lib/db/usage'
import { withObservedRoute } from '@/lib/observability/route-handler'

async function getUsage() {
  const session = await getServerSession()
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  try {
    const usage = await getUserUsageSummary(session.user.id)
    return NextResponse.json(usage)
  } catch (error) {
    console.error('Failed to fetch usage summary:', error)
    return NextResponse.json({ error: 'Failed to fetch usage' }, { status: 500 })
  }
}

export const GET = withObservedRoute('/api/billing/usage', 'usage', getUsage)
