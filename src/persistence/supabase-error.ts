/**
 * Structured handling for supabase-js PostgREST errors.
 *
 * Postgres often puts the fix in `hint` (e.g. the exact GRANT to run on 42501).
 * Log the full error object — not only `message`.
 */
import { logger } from "../config/logger.js";

/** Fields shared by PostgREST database-call errors. */
export interface PostgrestErrorFields {
  code?: string;
  message?: string;
  hint?: string | null;
  details?: string | null;
}

/** Metadata for structured logs — preserves hint/code/details. */
export function postgrestErrorMeta(
  error: PostgrestErrorFields,
): Record<string, unknown> {
  return {
    code: error.code,
    message: error.message,
    hint: error.hint ?? undefined,
    details: error.details ?? undefined,
  };
}

/**
 * Human-readable summary for UI strings and thrown errors.
 * When Postgres includes a hint, append it — that's usually the fix.
 */
export function describePostgrestError(error: PostgrestErrorFields): string {
  const message = error.message ?? "Supabase request failed";
  const parts = [error.code ? `[${error.code}] ${message}` : message];
  if (error.hint) parts.push(`hint: ${error.hint}`);
  if (error.details) parts.push(`details: ${error.details}`);
  return parts.join(" — ");
}

/** Log a PostgREST error with code/hint/details preserved. */
export function logPostgrestError(
  component: string,
  error: PostgrestErrorFields,
  msg: string,
): void {
  logger.warn({ component, supabase: postgrestErrorMeta(error) }, msg);
}
