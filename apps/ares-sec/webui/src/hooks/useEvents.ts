import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '@/lib/api'
import {
  SSE_EVENT_TYPES,
  levelForEventType,
  messageFromPayload,
  sourceFromEventType,
  tsFromPayload,
} from '@/lib/sse-events'

export interface AresEvent {
  id: string
  type: string
  ts: number
  source: string
  message: string
  level: 'info' | 'success' | 'warning' | 'danger'
  raw?: Record<string, unknown>
}

export function normalizeSsePayload(type: string, data: string): AresEvent {
  let payload: Record<string, unknown> = {}
  try {
    payload = JSON.parse(data) as Record<string, unknown>
  } catch {
    payload = { message: data }
  }
  return {
    id: String(payload.id ?? `${type}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`),
    type,
    ts: tsFromPayload(payload),
    source: String(payload.source ?? sourceFromEventType(type)),
    message: messageFromPayload(type, payload),
    level: levelForEventType(type),
    raw: payload,
  }
}

/**
 * Subscribes to the backend SSE stream at /api/events. Registers listeners for
 * every named event type the server emits (onmessage alone never fires for those).
 */
export function useEvents(limit = 200, filter?: string[]) {
  const [events, setEvents] = useState<AresEvent[]>([])
  const [live, setLive] = useState(false)
  const filterRef = useRef(filter)
  filterRef.current = filter

  const push = useCallback(
    (evt: AresEvent) => {
      const f = filterRef.current
      if (f?.length && !f.some((prefix) => evt.type.startsWith(prefix) || evt.type.includes(prefix))) {
        return
      }
      if (evt.type === 'heartbeat' || evt.type === 'ping') return
      setEvents((prev) => [...prev.slice(-(limit - 1)), evt])
    },
    [limit],
  )

  useEffect(() => {
    const base = api.base
    let source: EventSource | null = null
    try {
      source = new EventSource(`${base}/api/events`)
    } catch {
      return
    }

    const handler = (type: string) => (e: MessageEvent) => {
      push(normalizeSsePayload(type, e.data))
    }

    const listeners: Array<{ type: string; fn: (e: MessageEvent) => void }> = []
    for (const type of SSE_EVENT_TYPES) {
      const fn = handler(type)
      source.addEventListener(type, fn)
      listeners.push({ type, fn })
    }

    source.onopen = () => setLive(true)
    source.onerror = () => setLive(false)
    source.onmessage = (e) => push(normalizeSsePayload('message', e.data))

    return () => {
      for (const { type, fn } of listeners) {
        source?.removeEventListener(type, fn)
      }
      source?.close()
    }
  }, [push])

  return { events, live }
}
