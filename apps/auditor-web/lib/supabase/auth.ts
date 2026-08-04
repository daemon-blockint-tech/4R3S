'use client'

import { createClient } from '@/lib/supabase/client'
import { isSupabaseConfigured } from '@/lib/supabase/env'

/**
 * Supabase GitHub OAuth for knowledge-base access (separate from dashboard OAuth).
 * Requires a second GitHub OAuth app registered with Supabase callback URL.
 * @see docs/user/guides/github-auth.mdx
 */
export async function signInWithGithub(options?: { redirectTo?: string }) {
  if (!isSupabaseConfigured()) {
    return { error: new Error('Supabase Auth is not configured') }
  }

  const supabase = createClient()
  const origin = typeof window !== 'undefined' ? window.location.origin : ''
  const redirectTo = options?.redirectTo ?? `${origin}/auth/callback`

  return supabase.auth.signInWithOAuth({
    provider: 'github',
    options: { redirectTo },
  })
}

/** End Supabase Auth session (knowledge-base JWT). Does not affect dashboard JWE session. */
export async function signOutSupabase() {
  if (!isSupabaseConfigured()) {
    return { error: new Error('Supabase Auth is not configured') }
  }

  const supabase = createClient()
  return supabase.auth.signOut()
}
