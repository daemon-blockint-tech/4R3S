/**
 * Lightweight structured logger.
 *
 * Emits JSON lines at or above the configured ARES_LOG_LEVEL.
 * Keeps the dependency surface small — no pino/winston needed for
 * a CLI-style audit agent.
 */
import { env } from "../config/env.js";

type Level = "debug" | "info" | "warn" | "error";

const ORDER: Record<Level, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

const THRESHOLD = ORDER[env.ARES_LOG_LEVEL];

function emit(level: Level, msg: string, meta?: Record<string, unknown>): void {
  if (ORDER[level] < THRESHOLD) return;
  const line = JSON.stringify({
    t: new Date().toISOString(),
    level,
    msg,
    ...meta,
  });
  const stream = level === "error" || level === "warn" ? process.stderr : process.stdout;
  stream.write(line + "\n");
}

export const log = {
  debug: (msg: string, meta?: Record<string, unknown>) => emit("debug", msg, meta),
  info: (msg: string, meta?: Record<string, unknown>) => emit("info", msg, meta),
  warn: (msg: string, meta?: Record<string, unknown>) => emit("warn", msg, meta),
  error: (msg: string, meta?: Record<string, unknown>) => emit("error", msg, meta),
};
