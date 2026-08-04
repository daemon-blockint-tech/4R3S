import type { NextRequest } from 'next/server'
import { getRequestIdFromHeaders, runWithRequestContext } from './context'
import { recordApiRequest, type Journey } from './metrics'

type RouteHandler<T extends unknown[] = [NextRequest]> = (...args: T) => Promise<Response>

/**
 * Wrap an API route handler with request timing and metric emission.
 * Reads correlation ID from middleware headers when ALS is unavailable.
 */
export function withObservedRoute<T extends unknown[]>(
  routeTemplate: string,
  journey: Journey,
  handler: (...args: T) => Promise<Response>,
): (...args: T) => Promise<Response> {
  return async (...args: T) => {
    const req = args[0] as NextRequest | undefined
    const method = req?.method ?? 'GET'
    const requestId = req ? getRequestIdFromHeaders(req.headers) : 'req_unknown'
    const start = performance.now()

    const run = async (): Promise<Response> => {
      let status = 500
      try {
        const response = await handler(...args)
        status = response.status
        return response
      } catch (error) {
        status = 500
        throw error
      } finally {
        recordApiRequest(
          {
            route: routeTemplate,
            method,
            status,
            journey,
          },
          performance.now() - start,
        )
      }
    }

    return runWithRequestContext({ request_id: requestId, correlationId: requestId }, run)
  }
}
