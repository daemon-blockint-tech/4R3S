import { createBrowserClient } from '@supabase/ssr'

import { requireSupabaseEnv } from '@/lib/supabase/env'

/** Browser Supabase client (PKCE session in cookies via @supabase/ssr). */
export function createClient() {
  const { url, anonKey } = requireSupabaseEnv()
  return createBrowserClient(url, anonKey)
}
