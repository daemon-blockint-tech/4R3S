'use client'

import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { redirectToSignIn } from '@/lib/session/redirect-to-sign-in'
import { GitHubIcon } from '@/components/icons/github-icon'
import { useEffect, useState } from 'react'
import { useAtomValue } from 'jotai'
import { getEnabledAuthProviders } from '@/lib/auth/providers'
import {
  getGitHubOAuthAction,
  getGitHubOAuthButtonLabel,
  startGitHubOAuth,
} from '@/lib/auth/start-github-oauth'
import { sessionAtom, sessionInitializedAtom } from '@/lib/atoms/session'
import { githubConnectionAtom, githubConnectionInitializedAtom } from '@/lib/atoms/github-connection'
import { toast } from 'sonner'

export function SignIn() {
  const [showDialog, setShowDialog] = useState(false)
  const [loadingVercel, setLoadingVercel] = useState(false)
  const [loadingGitHub, setLoadingGitHub] = useState(false)

  const session = useAtomValue(sessionAtom)
  const sessionInitialized = useAtomValue(sessionInitializedAtom)
  const githubConnection = useAtomValue(githubConnectionAtom)
  const githubConnectionInitialized = useAtomValue(githubConnectionInitializedAtom)

  // Check which auth providers are enabled
  const { github: hasGitHub, vercel: hasVercel } = getEnabledAuthProviders()

  const githubAction = getGitHubOAuthAction(
    session,
    githubConnection.connected,
    sessionInitialized && githubConnectionInitialized,
  )
  const githubButtonLabel = getGitHubOAuthButtonLabel(githubAction)

  useEffect(() => {
    if (!showDialog || !sessionInitialized) {
      return
    }
    if (session.user && githubAction === 'refresh') {
      setShowDialog(false)
      toast.info("You're already signed in with GitHub.")
    }
  }, [showDialog, sessionInitialized, session.user, githubAction])

  const handleVercelSignIn = async () => {
    setLoadingVercel(true)
    await redirectToSignIn()
  }

  const handleGitHubSignIn = () => {
    setLoadingGitHub(true)
    startGitHubOAuth()
  }

  const handleOpenDialog = () => {
    if (sessionInitialized && session.user && githubAction === 'refresh') {
      toast.info("You're already signed in with GitHub.")
      return
    }
    setShowDialog(true)
  }

  return (
    <>
      <Button onClick={handleOpenDialog} variant="outline" size="sm">
        Sign in
      </Button>

      <Dialog open={showDialog} onOpenChange={setShowDialog}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Sign in</DialogTitle>
            <DialogDescription>
              {hasGitHub && hasVercel
                ? 'Choose how you want to sign in to continue.'
                : hasVercel
                  ? 'Sign in with Vercel to continue.'
                  : githubAction === 'connect'
                    ? 'Connect your GitHub account to create your profile and access repositories.'
                    : 'Sign in with GitHub to create your profile or continue with an existing account.'}
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col gap-3 py-4">
            {hasVercel && (
              <Button
                onClick={handleVercelSignIn}
                disabled={loadingVercel || loadingGitHub}
                variant="outline"
                size="lg"
                className="w-full"
              >
                {loadingVercel ? (
                  <>
                    <svg
                      className="animate-spin -ml-1 mr-2 h-4 w-4"
                      xmlns="http://www.w3.org/2000/svg"
                      fill="none"
                      viewBox="0 0 24 24"
                    >
                      <circle
                        className="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        strokeWidth="4"
                      ></circle>
                      <path
                        className="opacity-75"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                      ></path>
                    </svg>
                    Loading...
                  </>
                ) : (
                  <>
                    <svg viewBox="0 0 76 65" className="h-3 w-3 mr-2" fill="currentColor">
                      <path d="M37.5274 0L75.0548 65H0L37.5274 0Z" />
                    </svg>
                    Sign in with Vercel
                  </>
                )}
              </Button>
            )}

            {hasGitHub && (
              <Button
                onClick={handleGitHubSignIn}
                disabled={loadingVercel || loadingGitHub}
                variant="outline"
                size="lg"
                className="w-full"
              >
                {loadingGitHub ? (
                  <>
                    <svg
                      className="animate-spin -ml-1 mr-2 h-4 w-4"
                      xmlns="http://www.w3.org/2000/svg"
                      fill="none"
                      viewBox="0 0 24 24"
                    >
                      <circle
                        className="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        strokeWidth="4"
                      ></circle>
                      <path
                        className="opacity-75"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                      ></path>
                    </svg>
                    Loading...
                  </>
                ) : (
                  <>
                    <GitHubIcon className="h-4 w-4 mr-2" />
                    {githubButtonLabel}
                  </>
                )}
              </Button>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </>
  )
}
