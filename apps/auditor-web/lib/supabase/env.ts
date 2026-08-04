/**
 * Supabase browser Auth env (anon key only — never use service role here).
 * See docs/user/guides/github-auth.mdx § "Supabase GitHub Auth (knowledge base)".
 */
export function getSupabaseUrl(): string | undefined {
  return process.env.NEXT_PUBLIC_SUPABASE_URL
}

export function getSupabaseAnonKey(): string | undefined {
  return process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
}

/** True when both public Supabase vars are set (knowledge-base Auth + Data API). */
export function isSupabaseConfigured(): boolean {
  return Boolean(getSupabaseUrl() && getSupabaseAnonKey())
}

function requireSupabaseEnv(): { url: string; anonKey: string } {
  const url = getSupabaseUrl()
  const anonKey = getSupabaseAnonKey()
  if (!url || !anonKey) {
    throw new Error(
      'Supabase is not configured. Set NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY in .env.local',
    )
  }
  return { url, anonKey }
}

export { requireSupabaseEnv }
