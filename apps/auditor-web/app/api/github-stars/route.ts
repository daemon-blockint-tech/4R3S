import { GITHUB_REPO } from '@/lib/constants'

const CACHE_DURATION = 5 * 60

export async function GET() {
  try {
    const response = await fetch(`https://api.github.com/repos/${GITHUB_REPO}`, {
      headers: {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'ares-auditor-web',
      },
      next: { revalidate: CACHE_DURATION },
    })

    if (!response.ok) {
      return Response.json({ stars: 0 }, { status: 200 })
    }

    const data = await response.json()
    return Response.json({ stars: data.stargazers_count ?? 0 })
  } catch {
    return Response.json({ stars: 0 }, { status: 200 })
  }
}
