/** Placeholder returned in API responses instead of a decrypted secret. */
export const SECRET_MASK = '********'

/** Replace a stored secret with the fixed placeholder for API responses. */
export function maskSecret(value: string | null): string | null {
  return value ? SECRET_MASK : null
}

/** Preserve env var keys while hiding every value behind the placeholder. */
export function maskEnvValues(env: Record<string, unknown>): Record<string, string> {
  return Object.fromEntries(Object.keys(env).map((key) => [key, SECRET_MASK]))
}
