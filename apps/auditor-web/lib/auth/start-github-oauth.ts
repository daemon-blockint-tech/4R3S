/**
 * Start dashboard GitHub OAuth (sign-in, connect, or profile refresh).
 * Uses the unified route that picks the correct flow server-side.
 */
export function startGitHubOAuth(next?: string): void {
  const path = next ?? `${window.location.pathname}${window.location.search}`
  const params = new URLSearchParams()
  if (path && path !== '/') {
    params.set('next', path)
  }
  const query = params.toString()
  window.location.href = query ? `/api/auth/signin/github?${query}` : '/api/auth/signin/github'
}

export type GitHubOAuthAction = 'sign-in' | 'connect' | 'refresh'

/** Label for the GitHub OAuth button based on current session state. */
export function getGitHubOAuthAction(
  session: { user?: { id?: string }; authProvider?: 'github' | 'vercel' } | undefined,
  githubConnected: boolean,
  sessionReady: boolean,
): GitHubOAuthAction {
  if (!sessionReady || !session?.user) {
    return 'sign-in'
  }
  if (session.authProvider === 'github' || githubConnected) {
    return 'refresh'
  }
  return 'connect'
}

export function getGitHubOAuthButtonLabel(action: GitHubOAuthAction): string {
  switch (action) {
    case 'connect':
      return 'Connect GitHub'
    case 'refresh':
      return 'Continue with GitHub'
    default:
      return 'Sign in with GitHub'
  }
}
