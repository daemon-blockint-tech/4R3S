import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

import { requireSupabaseEnv } from '@/lib/supabase/env'

/** Server Supabase client for Server Components, Server Actions, and route handlers. */
export async function createClient() {
  const { url, anonKey } = requireSupabaseEnv()
  const cookieStore = await cookies()

  return createServerClient(url, anonKey, {
    cookies: {
      getAll() {
        return cookieStore.getAll()
      },
      setAll(cookiesToSet) {
        try {
          cookiesToSet.forEach(({ name, value, options }) => {
            cookieStore.set(name, value, options)
          })
        } catch {
          // setAll from a Server Component — session refresh handled in middleware or route handlers
        }
      },
    },
  })
}
