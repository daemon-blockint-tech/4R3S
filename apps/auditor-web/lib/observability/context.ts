import { AsyncLocalStorage } from 'async_hooks'
import type { NextRequest } from 'next/server'
import { nanoid } from 'nanoid'

export const REQUEST_ID_HEADER = 'x-request-id'
export const CORRELATION_ID_HEADER = 'x-correlation-id'

export interface RequestContext {
  request_id: string
  /** Alias used by async task processing for log correlation. */
  correlationId: string
  task_id?: string
  user_id_hash?: string
}

export const requestContext = new AsyncLocalStorage<RequestContext>()

export function getRequestId(): string {
  return requestContext.getStore()?.request_id ?? 'req_unknown'
}

export function getRequestContext(): RequestContext | undefined {
  return requestContext.getStore()
}

export function runWithRequestContext<T>(context: RequestContext, fn: () => T): T {
  return requestContext.run(context, fn)
}

export async function runWithRequestContextAsync<T>(context: RequestContext, fn: () => Promise<T>): Promise<T> {
  return requestContext.run(context, fn)
}

/** Read correlation ID propagated from middleware (Edge cannot use ALS). */
export function getRequestIdFromHeaders(headers: Headers): string {
  return (
    headers.get('x-correlation-id') ??
    headers.get('x-request-id') ??
    headers.get('x-ares-request-id') ??
    'req_unknown'
  )
}

/** Build request context from incoming API request headers. */
export function buildRequestContext(req: NextRequest): RequestContext {
  const requestId = getRequestIdFromHeaders(req.headers)
  if (requestId === 'req_unknown') {
    const generated = `req_${nanoid(12)}`
    return { request_id: generated, correlationId: generated }
  }
  return { request_id: requestId, correlationId: requestId }
}
