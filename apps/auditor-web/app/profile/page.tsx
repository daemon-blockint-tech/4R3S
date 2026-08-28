import { getServerSession } from '@/lib/session/get-server-session'
import { getGitHubStars } from '@/lib/github-stars'
import { ProfilePageClient } from '@/components/profile-page-client'

export default async function ProfilePage() {
  const session = await getServerSession()
  const stars = await getGitHubStars()

  return (
    <ProfilePageClient user={session?.user ?? null} authProvider={session?.authProvider ?? null} initialStars={stars} />
  )
}
