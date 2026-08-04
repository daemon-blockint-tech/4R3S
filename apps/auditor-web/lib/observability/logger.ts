/**
 * Lightweight structured logger for auditor-web server-side ops.
 * Emits single-line JSON to stdout/stderr — compatible with Vercel Runtime Logs.
 * No pino/winston — aligned with src/config/logger.ts in the monorepo root.
 */
import { getRequestId } from './context'
import { redact as redactValue, scrubString } from './redaction'
export { hashId } from './redaction'

export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

export type LogComponent =
  | 'auth.github'
  | 'auth.vercel'
  | 'auth.supabase'
  | 'auth.session'
  | 'tasks.lifecycle'
  | 'tasks.sandbox'
  | 'tasks.agent'
  | 'tasks.files'
  | 'usage'
  | 'github.api'
  | 'vercel.api'
  | 'db'
  | 'http'
  | 'metrics'

export type LogOutcome = 'success' | 'failure' | 'partial' | 'skipped'

export interface AresWebLogEntry {
  t: string
  level: LogLevel
  msg: string
  request_id: string
  task_id?: string
  component: LogComponent
  http?: {
    method: string
    path: string
    status?: number
    duration_ms?: number
  }
  auth?: {
    provider?: 'github' | 'vercel' | 'supabase'
    mode?: 'signin' | 'connect' | 'signout' | 'refresh'
    outcome: LogOutcome
    user_id_hash?: string
  }
  task?: {
    action: 'create' | 'continue' | 'stop' | 'complete' | 'error' | 'timeout'
    agent?: string
    progress?: number
    outcome: LogOutcome
  }
  error?: {
    name: string
    message: string
    code?: string
    upstream_status?: number
  }
  env: 'development' | 'preview' | 'production'
  vercel?: {
    deployment_id?: string
    region?: string
  }
  sampled?: boolean
  metric?: Record<string, unknown>
}

const ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
}

const THRESHOLD = ORDER[(process.env.ARES_WEB_LOG_LEVEL as LogLevel) ?? 'info'] ?? ORDER.info

const RESERVED_FIELDS = new Set(['t', 'level', 'msg', 'request_id'])

function getEnv(): AresWebLogEntry['env'] {
  const vercelEnv = process.env.VERCEL_ENV
  if (vercelEnv === 'production') return 'production'
  if (vercelEnv === 'preview') return 'preview'
  return 'development'
}

function shouldSample(level: LogLevel, component: LogComponent): boolean {
  if (level === 'error') return true
  if (component.startsWith('auth.')) return true
  if (component.startsWith('tasks.') && level === 'info') return true
  if (component === 'metrics') return true
  if (component === 'tasks.agent' && level === 'debug') return false
  if (process.env.VERCEL_ENV === 'production' && level === 'info' && component === 'http') {
    return Math.random() < 0.1
  }
  return true
}

function emit(level: LogLevel, msg: string, component: LogComponent, meta?: Record<string, unknown>): void {
  if (ORDER[level] < THRESHOLD) return

  const sampled = shouldSample(level, component)
  if (!sampled && level !== 'error') return

  const flattened = meta?.meta && typeof meta.meta === 'object' ? { ...meta, ...(meta.meta as Record<string, unknown>) } : meta
  if (flattened?.meta) delete flattened.meta

  const resolvedComponent = (flattened?.component as LogComponent | undefined) ?? component
  if (flattened?.component) delete flattened.component

  const requestId =
    (flattened?.correlationId as string | undefined) ??
    (flattened?.request_id as string | undefined) ??
    getRequestId()
  if (flattened?.correlationId) delete flattened.correlationId
  if (flattened?.request_id) delete flattened.request_id

  const safeMeta = flattened ? (redactValue(flattened) as Record<string, unknown>) : {}
  for (const key of RESERVED_FIELDS) {
    delete safeMeta[key]
  }

  const entry: AresWebLogEntry = {
    t: new Date().toISOString(),
    level,
    msg: scrubString(msg),
    request_id: requestId,
    component: resolvedComponent,
    env: getEnv(),
    sampled,
    ...safeMeta,
  }

  if (process.env.VERCEL_DEPLOYMENT_ID) {
    entry.vercel = {
      deployment_id: process.env.VERCEL_DEPLOYMENT_ID,
      region: process.env.VERCEL_REGION,
    }
  }

  const line = JSON.stringify(entry)
  if (level === 'error' || level === 'warn') {
    console.error(line)
  } else {
    console.log(line)
  }
}

export const logger = {
  debug(msg: string, meta?: Record<string, unknown> & { component?: LogComponent }) {
    emit('debug', msg, meta?.component ?? 'http', meta)
  },
  info(msg: string, meta?: Record<string, unknown> & { component?: LogComponent }) {
    emit('info', msg, meta?.component ?? 'http', meta)
  },
  warn(msg: string, meta?: Record<string, unknown> & { component?: LogComponent }) {
    emit('warn', msg, meta?.component ?? 'http', meta)
  },
  error(msg: string, meta?: Record<string, unknown> & { component?: LogComponent }) {
    emit('error', msg, meta?.component ?? 'http', meta)
  },
}
