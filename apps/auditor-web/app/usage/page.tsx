import { getServerSession } from '@/lib/session/get-server-session'
import { getGitHubStars } from '@/lib/github-stars'
import { UsagePageClient } from '@/components/usage-page-client'

export default async function UsagePage() {
  const session = await getServerSession()
  const stars = await getGitHubStars()

  return <UsagePageClient user={session?.user ?? null} initialStars={stars} />
}
