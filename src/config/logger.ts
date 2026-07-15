/**
 * Lightweight structured logger.
 *
 * Emits JSON lines at or above the configured ARES_LOG_LEVEL.
 * Keeps the dependency surface small — no pino/winston needed for
 * a CLI-style audit agent.
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

function emit(
  level: Level,
  a: string | Record<string, unknown>,
  b?: string | Record<string, unknown>,
): void {
  if (ORDER[level] < THRESHOLD) return;
  const { msg, meta } = normalize(a, b);
  const line = JSON.stringify({
    t: new Date().toISOString(),
    level,
    msg,
    ...meta,
  });
  const stream =
    level === "error" || level === "warn" ? process.stderr : process.stdout;
  stream.write(line + "\n");
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
