'use client'

import { SharedHeader } from '@/components/shared-header'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { GitHubIcon } from '@/components/icons/github-icon'
import { SignIn } from '@/components/auth/sign-in'
import { useAtomValue } from 'jotai'
import { githubConnectionAtom } from '@/lib/atoms/github-connection'
import { CheckCircle2, XCircle } from 'lucide-react'
import type { Session } from '@/lib/session/types'

interface ProfilePageClientProps {
  user: Session['user'] | null
  authProvider: Session['authProvider'] | null
  initialStars?: number
}

function AuthProviderBadge({ provider }: { provider: Session['authProvider'] }) {
  if (provider === 'github') {
    return (
      <Badge variant="outline" className="gap-1">
        <GitHubIcon className="h-3 w-3" />
        GitHub
      </Badge>
    )
  }

  return (
    <Badge variant="outline" className="gap-1">
      <svg viewBox="0 0 76 65" className="h-3 w-3" fill="currentColor" aria-hidden>
        <path d="M37.5274 0L75.0548 65H0L37.5274 0Z" />
      </svg>
      Vercel
    </Badge>
  )
}

export function ProfilePageClient({ user, authProvider, initialStars }: ProfilePageClientProps) {
  const githubConnection = useAtomValue(githubConnectionAtom)

  return (
    <div className="flex-1 bg-background flex flex-col h-full overflow-hidden">
      <div className="flex-shrink-0 p-3">
        <SharedHeader initialStars={initialStars} />
      </div>

      <div className="flex-1 overflow-auto px-4 pb-6">
        <div className="max-w-3xl mx-auto space-y-6">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Profile</h1>
            <p className="text-sm text-muted-foreground mt-1">Your account details and connected services.</p>
          </div>

          {!user ? (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Sign in required</CardTitle>
                <CardDescription>Connect your account to view and manage your profile.</CardDescription>
              </CardHeader>
              <CardContent>
                <SignIn />
              </CardContent>
            </Card>
          ) : (
            <>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
                    <Avatar className="h-16 w-16">
                      <AvatarImage src={user.avatar ? `${user.avatar}&s=144` : undefined} alt={user.username} />
                      <AvatarFallback className="text-lg">{user.username.slice(0, 2).toUpperCase()}</AvatarFallback>
                    </Avatar>
                    <div className="space-y-1 min-w-0">
                      <h2 className="text-xl font-semibold truncate">{user.name ?? user.username}</h2>
                      <p className="text-sm text-muted-foreground truncate">@{user.username}</p>
                      {user.email && <p className="text-sm text-muted-foreground truncate">{user.email}</p>}
                      <div className="pt-1">
                        <AuthProviderBadge provider={authProvider ?? 'vercel'} />
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Connected services</CardTitle>
                  <CardDescription>External accounts linked to your ARES workspace.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex items-center gap-3 min-w-0">
                      <GitHubIcon className="h-5 w-5 shrink-0" />
                      <div className="min-w-0">
                        <p className="text-sm font-medium">GitHub</p>
                        <p className="text-xs text-muted-foreground truncate">
                          {githubConnection.connected
                            ? `Connected as @${githubConnection.username ?? user.username}`
                            : authProvider === 'github'
                              ? 'Signed in via GitHub OAuth'
                              : 'Not connected — link from the account menu'}
                        </p>
                      </div>
                    </div>
                    {githubConnection.connected || authProvider === 'github' ? (
                      <Badge variant="secondary" className="gap-1 shrink-0">
                        <CheckCircle2 className="h-3 w-3 text-green-600" />
                        Connected
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="gap-1 shrink-0">
                        <XCircle className="h-3 w-3 text-muted-foreground" />
                        Not connected
                      </Badge>
                    )}
                  </div>

                  <Separator />

                  <div className="flex items-center justify-between gap-4">
                    <div className="min-w-0">
                      <p className="text-sm font-medium">Authentication provider</p>
                      <p className="text-xs text-muted-foreground">
                        Primary sign-in method for this account.
                      </p>
                    </div>
                    <AuthProviderBadge provider={authProvider ?? 'vercel'} />
                  </div>
                </CardContent>
              </Card>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
