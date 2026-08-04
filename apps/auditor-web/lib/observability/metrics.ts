/**
 * Lightweight HTTP metrics for Vercel serverless — no OTel SDK dependency.
 *
 * Emits structured metric log lines (`component: metrics`) compatible with
 * log-based aggregation. In-memory counters support local debugging.
 *
 * Metric names align with docs/internal/reliability-auditor-web.md §3.2.
 */
import { logger } from './logger'

export type Journey = 'signin' | 'create_task' | 'list_tasks' | 'connect_repo' | 'sandbox' | 'unknown'

export type StatusClass = '2xx' | '3xx' | '4xx' | '5xx'

const DURATION_BUCKETS_MS = [50, 100, 200, 300, 500, 1000, 2000, 5000] as const

export interface ApiRequestLabels {
  route: string
  method: string
  status: number
  journey?: Journey
}

interface CounterKey {
  route: string
  method: string
  status: string
  journey: Journey
}

interface HistogramKey {
  route: string
  method: string
  journey: Journey
}

const requestCounters = new Map<string, number>()
const durationHistograms = new Map<string, number[]>()

function counterKey(labels: CounterKey): string {
  return `${labels.route}|${labels.method}|${labels.status}|${labels.journey}`
}

function histogramKey(labels: HistogramKey): string {
  return `${labels.route}|${labels.method}|${labels.journey}`
}

export function statusClass(status: number): StatusClass {
  if (status >= 500) return '5xx'
  if (status >= 400) return '4xx'
  if (status >= 300) return '3xx'
  return '2xx'
}

export function durationBucket(durationMs: number): number {
  for (const bucket of DURATION_BUCKETS_MS) {
    if (durationMs <= bucket) return bucket
  }
  return DURATION_BUCKETS_MS[DURATION_BUCKETS_MS.length - 1]
}

/** Normalize dynamic segments to keep cardinality low. */
export function normalizeRoute(pathname: string): string {
  return pathname
    .replace(/\/api\/tasks\/[^/]+/g, '/api/tasks/[taskId]')
    .replace(/\/api\/repos\/[^/]+\/[^/]+/g, '/api/repos/[owner]/[repo]')
}

export function recordApiRequest(labels: ApiRequestLabels, durationMs: number): void {
  const journey: Journey = labels.journey ?? 'unknown'
  const status = String(labels.status)
  const statusCls = statusClass(labels.status)

  const cKey = counterKey({ route: labels.route, method: labels.method, status, journey })
  requestCounters.set(cKey, (requestCounters.get(cKey) ?? 0) + 1)

  const hKey = histogramKey({ route: labels.route, method: labels.method, journey })
  const bucket = durationHistograms.get(hKey) ?? []
  bucket.push(durationMs)
  durationHistograms.set(hKey, bucket)

  logger.info('HTTP request recorded', {
    component: 'metrics',
    metric: {
      name: 'ares_auditor_web_api_requests_total',
      type: 'counter',
      value: 1,
      labels: {
        route: labels.route,
        method: labels.method,
        status,
        status_class: statusCls,
        journey,
      },
    },
    http: {
      method: labels.method,
      path: labels.route,
      status: labels.status,
      duration_ms: Math.round(durationMs),
    },
  })

  logger.info('HTTP request duration recorded', {
    component: 'metrics',
    metric: {
      name: 'ares_auditor_web_api_request_duration_ms',
      type: 'histogram',
      value: Math.round(durationMs),
      bucket_ms: durationBucket(durationMs),
      labels: {
        route: labels.route,
        method: labels.method,
        journey,
      },
    },
  })
}

/** Test-only: reset in-memory aggregates. */
export function resetMetricsForTests(): void {
  requestCounters.clear()
  durationHistograms.clear()
}

/** Test-only: read counter value. */
export function getRequestCounter(route: string, method: string, status: number, journey: Journey = 'unknown'): number {
  return requestCounters.get(counterKey({ route, method, status: String(status), journey })) ?? 0
}
