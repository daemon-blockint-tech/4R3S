/**
 * ARES API client. In dev, Vite proxies /api → the backend (see vite.config.ts),
 * so relative paths work with no CORS. Precedence for the base URL:
 *   1. localStorage `ares_api_url` (set in Settings) — reach a remote server
 *   2. VITE_ARES_API build-time env
 *   3. '' (same origin that serves the UI)
 */
function base(): string {
  if (typeof localStorage !== 'undefined') {
    const override = localStorage.getItem('ares_api_url')
    if (override) return override.replace(/\/$/, '')
  }
  return import.meta.env.VITE_ARES_API ?? ''
}

export interface ApprovalPayload {
  id: string
  action: string
  target: string
  reason: string
  status: string
  requestedBy?: string
  createdAt?: string
  updatedAt?: string
  expiresAt?: string
}

export class ApiError extends Error {
  status: number
  approval?: ApprovalPayload
  next?: string

  constructor(message: string, status: number, body?: Record<string, unknown>) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    if (body?.approval && typeof body.approval === 'object') {
      this.approval = body.approval as ApprovalPayload
    }
    if (typeof body?.next === 'string') this.next = body.next
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${base()}${path}`, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  const data = text ? JSON.parse(text) : null
  if (!res.ok) {
    const message = (data && (data.error || data.message)) || `${res.status} ${res.statusText}`
    throw new ApiError(message, res.status, data ?? undefined)
  }
  return data as T
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body),
  patch: <T>(path: string, body?: unknown) => request<T>('PATCH', path, body),
  del: <T>(path: string) => request<T>('DELETE', path),
  get base() {
    return base()
  },
}

export interface HealthResponse {
  status?: string
  llm?: { connected?: boolean } | string
  missionDispatch?: boolean
  version?: string
}

export type ConnState = 'checking' | 'llm' | 'connected' | 'offline'

export function healthToState(h: HealthResponse | null): ConnState {
  if (!h) return 'offline'
  const llm = h.llm === 'connected' || (typeof h.llm === 'object' && !!h.llm?.connected)
  if (llm) return 'llm'
  if (h.status === 'operational') return 'connected'
  return 'offline'
}
