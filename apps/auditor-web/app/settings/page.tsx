import { getServerSession } from '@/lib/session/get-server-session'
import { getGitHubStars } from '@/lib/github-stars'
import { SettingsPageClient } from '@/components/settings-page-client'

export default async function SettingsPage() {
  const session = await getServerSession()
  const stars = await getGitHubStars()

  return <SettingsPageClient user={session?.user ?? null} initialStars={stars} />
}
