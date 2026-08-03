/** Named SSE event types emitted by the ARES backend via broadcastEvent / emitContractEvent. */
export const SSE_EVENT_TYPES = [
  'connected',
  'heartbeat',
  'ping',
  'mission:started',
  'mission:stopped',
  'mission:paused',
  'mission:resumed',
  'operator:spawned',
  'operator:terminated',
  'operator:prompt_updated',
  'task:dispatched',
  'task:completed',
  'task:failed',
  'general:planning',
  'general:plan_ready',
  'general:plan_failed',
  'general:review',
  'general:sitrep',
  'general:adapting',
  'general:assessment',
  'general:executing',
  'admiral:launch',
  'approval.requested',
  'approval.approved',
  'approval.rejected',
  'finding.created',
  'finding.updated',
  'evidence.created',
  'retest.created',
  'retest.updated',
  'hypothesis.created',
  'hypothesis.updated',
  'hypothesis.promoted',
  'work_order.created',
  'work_order.updated',
  'work_order.completed',
  'memory.proposed',
  'memory.accepted',
  'memory.rejected',
  'memory.linked_existing',
  'memory.reobserved',
  'watch_loop.pulsed',
  'pressure.canary',
  'pressure.duel',
  'pressure.mutations',
  'pressure.chains',
  'draft.created',
  'draft.updated',
  'route.previewed',
  'improvement.proposed',
  'promotion.evaluated',
] as const

export type SseEventType = (typeof SSE_EVENT_TYPES)[number]

const DANGER = new Set(['task:failed', 'general:plan_failed', 'approval.rejected', 'memory.rejected'])
const SUCCESS = new Set([
  'mission:started',
  'mission:resumed',
  'task:completed',
  'finding.created',
  'approval.approved',
  'memory.accepted',
  'operator:spawned',
  'admiral:launch',
  'general:executing',
])
const WARNING = new Set([
  'mission:paused',
  'mission:stopped',
  'approval.requested',
  'operator:terminated',
  'task:dispatched',
])

export function levelForEventType(type: string): 'info' | 'success' | 'warning' | 'danger' {
  if (DANGER.has(type)) return 'danger'
  if (SUCCESS.has(type)) return 'success'
  if (WARNING.has(type)) return 'warning'
  return 'info'
}

export function sourceFromEventType(type: string): string {
  const colon = type.indexOf(':')
  if (colon > 0) return type.slice(0, colon).toUpperCase()
  const dot = type.indexOf('.')
  if (dot > 0) return type.slice(0, dot).toUpperCase()
  return type.toUpperCase()
}

export function messageFromPayload(type: string, payload: Record<string, unknown>): string {
  if (typeof payload.message === 'string' && payload.message) return payload.message
  if (typeof payload.msg === 'string' && payload.msg) return payload.msg
  if (typeof payload.reason === 'string' && payload.reason) return payload.reason
  if (typeof payload.objective === 'string') return payload.objective
  if (typeof payload.taskName === 'string') return `${payload.taskName} → ${payload.callsign ?? payload.operatorId ?? ''}`
  if (typeof payload.callsign === 'string') return payload.callsign
  if (typeof payload.archetype === 'string') return payload.archetype
  if (typeof payload.findingId === 'string') return `finding ${payload.findingId}`
  if (typeof payload.approvalId === 'string') return `${payload.action ?? 'approval'} ${payload.target ?? payload.approvalId}`
  if (typeof payload.name === 'string') return payload.name
  if (typeof payload.error === 'string') return payload.error
  return type
}

export function tsFromPayload(payload: Record<string, unknown>): number {
  if (typeof payload.timestamp === 'number') return payload.timestamp
  if (typeof payload.ts === 'number') return payload.ts
  if (typeof payload.ts === 'string') {
    const parsed = Date.parse(payload.ts)
    if (!Number.isNaN(parsed)) return parsed
  }
  return Date.now()
}
