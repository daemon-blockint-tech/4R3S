/**
 * Lightweight structured logger.
 *
 * Emits JSON lines at or above the configured ARES_LOG_LEVEL.
 * Keeps the dependency surface small — no pino/winston needed for
 * a CLI-style audit agent.
 *
 * Every level goes to **stderr**. stdout is reserved for the one artifact the
 * caller wants to capture — the audit report — so `npm run audit … > report.md`
 * yields clean markdown instead of markdown with JSON log lines spliced in.
 *
 * Two call styles are accepted so callers can pick whichever reads best:
 *   logger.info("message", { some: "meta" })   // message-first
 *   logger.info({ some: "meta" }, "message")    // pino-style, meta-first
 */
import { env } from "./env.js";

type Level = "debug" | "info" | "warn" | "error";

const ORDER: Record<Level, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

const THRESHOLD = ORDER[env.ARES_LOG_LEVEL];

/** Normalize the two accepted call signatures into `(msg, meta)`. */
function normalize(
  a: string | Record<string, unknown>,
  b?: string | Record<string, unknown>,
): { msg: string; meta?: Record<string, unknown> } {
  if (typeof a === "string") {
    return { msg: a, meta: b as Record<string, unknown> | undefined };
  }
  // meta-first (pino-style): (meta, msg)
  return { msg: typeof b === "string" ? b : "", meta: a };
}

/** Metadata keys whose values are never printed. */
const SENSITIVE_KEY = /key|token|password|secret|authorization|credential|dsn/i;

/** `scheme://user:secret@host` — the shape of the Postgres DSN, among others. */
const URL_CREDENTIALS = /(\b[a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+):([^/\s@]+)@/gi;

export const REDACTED = "[redacted]";

/** Record fields a caller's metadata may not overwrite. */
const RESERVED_FIELDS = new Set(["t", "level", "msg"]);

/**
 * Secrets carried as a URL query parameter rather than as `user:pass@`.
 *
 * This is the shape the project actually documents: `.env.example` shows
 * `HELIUS_RPC_URL=https://mainnet.helius-rpc.com/?api-key=xxxxxxxx`. The
 * `user:pass@` pattern above never covered it, and neither did `SENSITIVE_KEY`,
 * which matches metadata *keys* — a URL inside a string under a key like `err`
 * is not one.
 *
 * No live leak path was found when this was added: `solana.ts` logs
 * `String(err)` after an RPC failure, and under Node's undici a failed fetch
 * yields "TypeError: fetch failed" with no URL, while the timeout path yields
 * "TimeoutError". This closes the gap before a dependency upgrade or a
 * different client starts putting request URLs in error strings — which is the
 * kind of change nobody reviews for secret exposure.
 */
const URL_SECRET_PARAM =
  /([?&](?:[a-z0-9_-]*(?:key|token|secret|password|auth|credential)[a-z0-9_-]*)=)([^&\s"'<>]+)/gi;

/** Strip credentials embedded in any URL inside a string. */
function scrubUrls(value: string): string {
  return value
    .replace(URL_CREDENTIALS, (_m, scheme, user) => `${scheme}${user}:${REDACTED}@`)
    .replace(URL_SECRET_PARAM, (_m, prefix) => `${prefix}${REDACTED}`);
}

/**
 * Redact a metadata value: anything under a sensitive key is dropped entirely,
 * and URL credentials are stripped from every string, however deeply nested —
 * a leaked DSN usually arrives inside a stringified driver error, not under a
 * conveniently-named field.
 */
export function redact(value: unknown, keyIsSensitive = false): unknown {
  if (keyIsSensitive) return value === undefined ? undefined : REDACTED;
  if (typeof value === "string") return scrubUrls(value);
  if (Array.isArray(value)) return value.map((v) => redact(v));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([k, v]) => [
        k,
        redact(v, SENSITIVE_KEY.test(k)),
      ]),
    );
  }
  return value;
}

function emit(
  level: Level,
  a: string | Record<string, unknown>,
  b?: string | Record<string, unknown>,
): void {
  if (ORDER[level] < THRESHOLD) return;
  const { msg, meta } = normalize(a, b);
  // Metadata is spread after the record's own fields, so a caller passing a key
  // named `level` (or `t`/`msg`) would overwrite the log's severity — a metadata
  // field called `level` is an easy thing to log, and losing the real severity
  // breaks every downstream filter. Collisions are prefixed instead of dropped,
  // so the caller's value survives without displacing ours.
  const redacted = redact(meta ?? {}) as Record<string, unknown>;
  const safeMeta: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(redacted)) {
    safeMeta[RESERVED_FIELDS.has(k) ? `meta_${k}` : k] = v;
  }
  const line = JSON.stringify({
    t: new Date().toISOString(),
    level,
    msg: scrubUrls(msg),
    ...safeMeta,
  });
  // Never stdout: that stream carries the report.
  process.stderr.write(line + "\n");
}

type LogFn = (
  a: string | Record<string, unknown>,
  b?: string | Record<string, unknown>,
) => void;

export interface Logger {
  debug: LogFn;
  info: LogFn;
  warn: LogFn;
  error: LogFn;
}

export const log: Logger = {
  debug: (a, b) => emit("debug", a, b),
  info: (a, b) => emit("info", a, b),
  warn: (a, b) => emit("warn", a, b),
  error: (a, b) => emit("error", a, b),
};

/** Alias — some modules import `logger`, others `log`. Same instance. */
export const logger = log;
