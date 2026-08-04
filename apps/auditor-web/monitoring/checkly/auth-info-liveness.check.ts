import { ApiCheck, AssertionBuilder, Frequency } from 'checkly/constructs'
import { baseUrl, assertCorrelation } from './checkly.config'

/**
 * Primary liveness probe — GET /api/auth/info
 * Alert: A-001 when failing in 2+ regions for 3 minutes.
 */
new ApiCheck('auth-info-liveness', {
  name: 'auth-info-liveness',
  activated: true,
  muted: false,
  shouldFail: false,
  runParallel: true,
  locations: ['us-east-1', 'ap-southeast-1'],
  frequency: Frequency.EVERY_1M,
  maxResponseTime: 3000,
  degradedResponseTime: 1000,
  request: {
    method: 'GET',
    url: `${baseUrl}/api/auth/info`,
    followRedirects: true,
    skipSSL: false,
    assertions: [
      AssertionBuilder.status().lessThan(500),
      AssertionBuilder.status().in([200, 401]),
      AssertionBuilder.headers('Content-Type').contains('application/json'),
      ...(assertCorrelation
        ? [AssertionBuilder.headers('x-correlation-id').isNotEmpty()]
        : []),
    ],
  },
  tags: ['auth', 'liveness', 'A-001'],
})
