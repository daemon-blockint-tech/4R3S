import { createHash } from 'crypto'

export const REDACTED = '[REDACTED]'

/** Metadata keys whose values must never appear in logs. */
const SENSITIVE_KEY =
  /key|token|password|secret|authorization|credential|dsn|cookie|session|email|encryption/i

/** `scheme://user:secret@host` */
const URL_CREDENTIALS = /(\b[a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+):([^/\s@]+)@/gi

/** Query-string secrets such as `?api-key=...` or `&access_token=...` */
const URL_SECRET_PARAM =
  /([?&](?:[a-z0-9_-]*(?:key|token|secret|password|auth|credential|access_token)[a-z0-9_-]*)=)([^&\s"'<>]+)/gi

/** GitHub, OpenAI, Anthropic, and similar token prefixes. */
const TOKEN_PATTERNS = [
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  /\bBearer\s+[A-Za-z0-9._-]{20,}\b/gi,
]

/** ENCRYPTION_KEY and similar env-style assignments. */
const ENV_SECRET_ASSIGNMENT =
  /(ENCRYPTION_KEY|JWE_SECRET|GITHUB_CLIENT_SECRET|AI_GATEWAY_API_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY)[=\s:]*["']?([^\s"'&]+)["']?/gi

export function scrubString(value: string): string {
  let scrubbed = value
    .replace(URL_CREDENTIALS, (_match, scheme, user) => `${scheme}${user}:${REDACTED}@`)
    .replace(URL_SECRET_PARAM, (_match, prefix) => `${prefix}${REDACTED}`)
    .replace(ENV_SECRET_ASSIGNMENT, (_match, name) => `${name}=${REDACTED}`)

  for (const pattern of TOKEN_PATTERNS) {
    scrubbed = scrubbed.replace(pattern, REDACTED)
  }

  return scrubbed
}

/** Redact a metadata value recursively. */
export function redact(value: unknown, keyIsSensitive = false): unknown {
  if (keyIsSensitive) {
    return value === undefined ? undefined : REDACTED
  }

  if (typeof value === 'string') {
    return scrubString(value)
  }

  if (Array.isArray(value)) {
    return value.map((item) => redact(item))
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, nested]) => [
        key,
        redact(nested, SENSITIVE_KEY.test(key)),
      ]),
    )
  }

  return value
}

/** Hash an identifier for correlation without logging raw PII. */
export function hashId(value: string): string {
  return `h_${createHash('sha256').update(value).digest('hex').slice(0, 8)}`
}

/** Safe JSON stringify for log metadata objects. */
export function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(redact(value))
  } catch {
    return JSON.stringify({ serializationError: true })
  }
}
