import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { CORRELATION_ID_HEADER, REQUEST_ID_HEADER } from '@/lib/observability/context'

export function middleware(request: NextRequest) {
  const correlationId =
    request.headers.get(CORRELATION_ID_HEADER) ?? request.headers.get(REQUEST_ID_HEADER) ?? crypto.randomUUID()

  const requestHeaders = new Headers(request.headers)
  requestHeaders.set(CORRELATION_ID_HEADER, correlationId)
  requestHeaders.set(REQUEST_ID_HEADER, correlationId)
  requestHeaders.set('x-ares-request-id', correlationId)

  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  })

  response.headers.set(CORRELATION_ID_HEADER, correlationId)
  response.headers.set(REQUEST_ID_HEADER, correlationId)
  response.headers.set('x-ares-request-id', correlationId)

  return response
}

export const config = {
  matcher: [
    '/api/:path*',
    '/auth/:path*',
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)',
  ],
}
