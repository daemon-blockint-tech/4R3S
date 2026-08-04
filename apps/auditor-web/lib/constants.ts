export const APP_NAME = 'ARES Auditor'
export const APP_TAGLINE =
  'Autonomous Solana program security auditing — task dashboard, reports, and agent orchestration.'
export const GITHUB_REPO = 'daemon-blockint-tech/4R3S'

// Rate limiting configuration
export const MAX_MESSAGES_PER_DAY = parseInt(process.env.MAX_MESSAGES_PER_DAY || '5', 10)

// Sandbox configuration (in minutes)
export const MAX_SANDBOX_DURATION = parseInt(process.env.MAX_SANDBOX_DURATION || '300', 10)

export const GITHUB_REPO_URL = `https://github.com/${GITHUB_REPO}`
