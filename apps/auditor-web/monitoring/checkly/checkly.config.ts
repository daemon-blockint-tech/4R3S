import { defineConfig } from 'checkly'

/**
 * Checkly project config — auth-info-liveness synthetic probe.
 * Set ARES_WEB_MONITOR_URL before deploy.
 */
const baseUrl = process.env.ARES_WEB_MONITOR_URL ?? 'https://REPLACE_ME.vercel.app'
const assertCorrelation = process.env.ARES_WEB_MONITOR_ASSERT_CORRELATION === 'true'

export default defineConfig({
  projectName: 'ares-auditor-web',
  logicalId: 'ares-auditor-web',
  repoUrl: 'https://github.com/REPLACE_ORG/4R3S',
  checks: {
    activated: true,
    muted: false,
    runtimeId: '2024.02',
    locations: ['us-east-1', 'ap-southeast-1'],
    tags: ['auditor-web', 'mvp', 'auth'],
    checkMatch: '**/*.check.ts',
    browserChecks: { frequency: 0, testMatch: '' },
  },
  cli: {
    runLocation: 'us-east-1',
  },
})

export { baseUrl, assertCorrelation }
