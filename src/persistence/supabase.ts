/**
 * Supabase client factory.
 *
 * Returns a lazily-constructed client only when both SUPABASE_URL and
 * SUPABASE_SERVICE_ROLE_KEY are configured. Everything downstream treats an
 * `undefined` client as "Supabase not available" and degrades gracefully, so
 * the agent stays runnable offline / in tests without Supabase.
 */
import { createClient, type SupabaseClient } from "@supabase/supabase-js";

import { env } from "../config/env.js";
import { logger } from "../config/logger.js";
import { timedFetch } from "../config/timeout.js";

let cached: SupabaseClient | null | undefined;

/**
 * Get the shared Supabase client, or `undefined` if not configured.
 * The result is memoized (including the "not configured" case).
 */
export function getSupabase(): SupabaseClient | undefined {
  if (cached !== undefined) return cached ?? undefined;

  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) {
    logger.debug(
      { component: "supabase" },
      "Supabase not configured — hybrid keyword/vector retrieval disabled",
    );
    cached = null;
    return undefined;
  }

  cached = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
    // Without a deadline the `hybrid_search` RPC inherits bare `fetch`, and a
    // project that accepts the connection but never answers hangs RECALL
    // forever — `withRetry` cannot help, because a request that never settles
    // never produces an error to retry. See config/timeout.ts.
    global: { fetch: timedFetch(env.SUPABASE_TIMEOUT_MS) },
  });
  logger.debug({ component: "supabase" }, "Supabase client initialized");
  return cached;
}

/** True when Supabase credentials are present. */
export function hasSupabase(): boolean {
  return Boolean(env.SUPABASE_URL && env.SUPABASE_SERVICE_ROLE_KEY);
}
