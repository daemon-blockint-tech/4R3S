import { type NextRequest } from 'next/server'
import { cookies } from 'next/headers'
import { db } from '@/lib/db/client'
import { users, accounts, tasks, connectors, keys } from '@/lib/db/schema'
import { eq, and } from 'drizzle-orm'
import { nanoid } from 'nanoid'
import { createGitHubSession, saveSession } from '@/lib/session/create-github'
import { encrypt } from '@/lib/crypto'
import { isRelativeUrl } from '@/lib/utils/is-relative-url'
import { buildRequestContext, runWithRequestContextAsync } from '@/lib/observability/context'
import { logger } from '@/lib/observability/logger'
import { hashId } from '@/lib/observability/redaction'
import { withObservedRoute } from '@/lib/observability/route-handler'

async function githubCallback(req: NextRequest): Promise<Response> {
  const ctx = buildRequestContext(req)

  return runWithRequestContextAsync(ctx, async () => {
    const code = req.nextUrl.searchParams.get('code')
    const state = req.nextUrl.searchParams.get('state')
    const cookieStore = await cookies()

    const authMode = cookieStore.get(`github_auth_mode`)?.value ?? null
    const isSignInFlow = authMode === 'signin'

    const storedState = cookieStore.get(authMode ? `github_auth_state` : `github_oauth_state`)?.value ?? null
    const storedRedirectTo =
      cookieStore.get(authMode ? `github_auth_redirect_to` : `github_oauth_redirect_to`)?.value ?? null
    const storedUserId = cookieStore.get(`github_oauth_user_id`)?.value ?? null

    if (isSignInFlow) {
      if (code === null || state === null || storedState !== state || storedRedirectTo === null) {
        logger.warn('OAuth state validation failed', {
          component: 'auth.github',
          meta: {
            auth: { provider: 'github', mode: 'signin', outcome: 'failure' },
            error: { name: 'OAuthStateError', message: 'Invalid OAuth state', code: 'INVALID_OAUTH_STATE' },
          },
        })
        return new Response('Invalid OAuth state', { status: 400 })
      }
    } else if (
      code === null ||
      state === null ||
      storedState !== state ||
      storedRedirectTo === null ||
      storedUserId === null
    ) {
      logger.warn('OAuth state validation failed', {
        component: 'auth.github',
        meta: {
          auth: { provider: 'github', mode: 'connect', outcome: 'failure' },
          error: { name: 'OAuthStateError', message: 'Invalid OAuth state', code: 'INVALID_OAUTH_STATE' },
        },
      })
      return new Response('Invalid OAuth state', { status: 400 })
    }

    // The redirect cookie is unsigned and client-controlled: re-validate before
    // using it as a redirect target (reject absolute, protocol-relative, and
    // backslash URLs), falling back to the default path
    const safeRedirectTo =
      storedRedirectTo &&
      isRelativeUrl(storedRedirectTo) &&
      !storedRedirectTo.startsWith('//') &&
      !storedRedirectTo.includes('\\')
        ? storedRedirectTo
        : '/'

    const clientId = process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID
    const clientSecret = process.env.GITHUB_CLIENT_SECRET

    if (!clientId || !clientSecret) {
      logger.error('GitHub OAuth not configured', {
        component: 'auth.github',
        meta: {
          auth: { provider: 'github', outcome: 'failure' },
          error: { name: 'ConfigurationError', message: 'Missing OAuth credentials', code: 'OAUTH_NOT_CONFIGURED' },
        },
      })
      return new Response('GitHub OAuth not configured', { status: 500 })
    }

    try {
      logger.info('OAuth callback started', {
        component: 'auth.github',
        meta: {
          auth: {
            provider: 'github',
            mode: isSignInFlow ? 'signin' : 'connect',
            outcome: 'partial',
          },
        },
      })

      const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({
          client_id: clientId,
          client_secret: clientSecret,
          code: code,
        }),
      })

      if (!tokenResponse.ok) {
        logger.error('Token exchange failed', {
          component: 'auth.github',
          meta: {
            auth: { provider: 'github', mode: isSignInFlow ? 'signin' : 'connect', outcome: 'failure' },
            error: {
              name: 'OAuthExchangeError',
              message: 'Token exchange failed',
              code: 'OAUTH_EXCHANGE_FAILED',
              upstream_status: tokenResponse.status,
            },
          },
        })
        return new Response('Failed to exchange code for token', { status: 400 })
      }

      const tokenData = (await tokenResponse.json()) as {
        access_token: string
        scope: string
        token_type: string
        error?: string
        error_description?: string
      }

      if (!tokenData.access_token) {
        logger.error('Token exchange failed', {
          component: 'auth.github',
          meta: {
            auth: { provider: 'github', mode: isSignInFlow ? 'signin' : 'connect', outcome: 'failure' },
            error: {
              name: 'OAuthExchangeError',
              message: 'Access token missing from exchange response',
              code: 'OAUTH_EXCHANGE_FAILED',
              upstream_status: tokenResponse.status,
            },
          },
        })
        return new Response(
          `Failed to authenticate with GitHub: ${tokenData.error_description || tokenData.error || 'Unknown error'}`,
          { status: 400 },
        )
      }

      logger.info('Token exchange completed', {
        component: 'auth.github',
        meta: {
          auth: { provider: 'github', mode: isSignInFlow ? 'signin' : 'connect', outcome: 'success' },
          tokenPresent: true,
        },
      })

      const userResponse = await fetch('https://api.github.com/user', {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
          Accept: 'application/vnd.github.v3+json',
        },
      })

      if (!userResponse.ok) {
        logger.error('GitHub profile fetch failed', {
          component: 'auth.github',
          meta: {
            auth: { provider: 'github', mode: isSignInFlow ? 'signin' : 'connect', outcome: 'failure' },
            error: {
              name: 'GitHubProfileError',
              message: 'Failed to fetch GitHub profile',
              code: 'GITHUB_PROFILE_FETCH_FAILED',
              upstream_status: userResponse.status,
            },
          },
        })
        return new Response('Failed to fetch GitHub profile', { status: 400 })
      }

      const githubUser = (await userResponse.json()) as {
        login: string
        id: number
        email: string | null
        name: string | null
        avatar_url: string
      }

      if (isSignInFlow) {
        logger.info('Sign-in flow session creation started', {
          component: 'auth.github',
          meta: { auth: { provider: 'github', mode: 'signin', outcome: 'partial' } },
        })

        const session = await createGitHubSession(tokenData.access_token, tokenData.scope)

        if (!session) {
          logger.error('Session creation failed', {
            component: 'auth.github',
            meta: {
              auth: { provider: 'github', mode: 'signin', outcome: 'failure' },
              error: {
                name: 'SessionCreationError',
                message: 'Failed to create GitHub session',
                code: 'SESSION_CREATE_FAILED',
              },
            },
          })
          return new Response('Failed to create session', { status: 500 })
        }

        logger.info('Session created', {
          component: 'auth.github',
          meta: {
            auth: {
              provider: 'github',
              mode: 'signin',
              outcome: 'success',
              userIdHash: hashId(session.user.id),
            },
          },
        })

        const response = new Response(null, {
          status: 302,
          headers: { Location: safeRedirectTo },
        })

        await saveSession(response, session)

        cookieStore.delete(`github_auth_state`)
        cookieStore.delete(`github_auth_redirect_to`)
        cookieStore.delete(`github_auth_mode`)

        return response
      }

      const encryptedToken = encrypt(tokenData.access_token)

      const existingAccount = await db
        .select()
        .from(accounts)
        .where(and(eq(accounts.provider, 'github'), eq(accounts.externalUserId, `${githubUser.id}`)))
        .limit(1)

      if (existingAccount.length > 0) {
        const connectedUserId = existingAccount[0].userId

        if (connectedUserId !== storedUserId) {
          logger.info('Account merge started', {
            component: 'auth.github',
            meta: {
              auth: {
                provider: 'github',
                mode: 'connect',
                outcome: 'partial',
                userIdHash: storedUserId ? hashId(storedUserId) : undefined,
              },
              githubId: githubUser.id,
            },
          })

          await db.update(tasks).set({ userId: storedUserId! }).where(eq(tasks.userId, connectedUserId))
          await db.update(connectors).set({ userId: storedUserId! }).where(eq(connectors.userId, connectedUserId))
          await db.update(accounts).set({ userId: storedUserId! }).where(eq(accounts.userId, connectedUserId))
          await db.update(keys).set({ userId: storedUserId! }).where(eq(keys.userId, connectedUserId))
          await db.delete(users).where(eq(users.id, connectedUserId))

          logger.info('Account merge completed', {
            component: 'auth.github',
            meta: {
              auth: {
                provider: 'github',
                mode: 'connect',
                outcome: 'success',
                userIdHash: storedUserId ? hashId(storedUserId) : undefined,
              },
            },
          })

          await db
            .update(accounts)
            .set({
              userId: storedUserId!,
              accessToken: encryptedToken,
              scope: tokenData.scope,
              username: githubUser.login,
              updatedAt: new Date(),
            })
            .where(eq(accounts.id, existingAccount[0].id))
        } else {
          await db
            .update(accounts)
            .set({
              accessToken: encryptedToken,
              scope: tokenData.scope,
              username: githubUser.login,
              updatedAt: new Date(),
            })
            .where(eq(accounts.id, existingAccount[0].id))
        }
      } else {
        await db.insert(accounts).values({
          id: nanoid(),
          userId: storedUserId!,
          provider: 'github',
          externalUserId: `${githubUser.id}`,
          accessToken: encryptedToken,
          scope: tokenData.scope,
          username: githubUser.login,
        })
      }

      await db
        .update(users)
        .set({
          email: githubUser.email ?? undefined,
          name: githubUser.name ?? githubUser.login,
          avatarUrl: githubUser.avatar_url,
          updatedAt: new Date(),
          lastLoginAt: new Date(),
        })
        .where(eq(users.id, storedUserId!))

      logger.info('GitHub account connected', {
        component: 'auth.github',
        meta: {
          auth: {
            provider: 'github',
            mode: 'connect',
            outcome: 'success',
            userIdHash: storedUserId ? hashId(storedUserId) : undefined,
          },
        },
      })

      if (authMode) {
        cookieStore.delete(`github_auth_state`)
        cookieStore.delete(`github_auth_redirect_to`)
        cookieStore.delete(`github_auth_mode`)
      } else {
        cookieStore.delete(`github_oauth_state`)
        cookieStore.delete(`github_oauth_redirect_to`)
      }
      cookieStore.delete(`github_oauth_user_id`)

      return Response.redirect(new URL(safeRedirectTo, req.nextUrl.origin))
    } catch (error) {
      logger.error('OAuth callback failed', {
        component: 'auth.github',
        meta: {
          auth: { provider: 'github', mode: isSignInFlow ? 'signin' : 'connect', outcome: 'failure' },
          error: {
            name: error instanceof Error ? error.name : 'UnknownError',
            message: error instanceof Error ? error.message : 'Unknown error occurred',
            code: 'OAUTH_CALLBACK_FAILED',
          },
        },
      })
      return new Response(
        `Failed to complete GitHub authentication: ${error instanceof Error ? error.message : 'Unknown error'}`,
        { status: 500 },
      )
    }
  })
}

export const GET = withObservedRoute('/api/auth/github/callback', 'signin', githubCallback)
