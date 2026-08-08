import path from 'path'
import { PROJECT_DIR } from './commands'

/**
 * Resolve a user-supplied file path against the sandbox project directory.
 * URL-decodes once, normalizes separators, and rejects anything that escapes
 * PROJECT_DIR. Returns the project-relative path, or null when the input is
 * invalid or escapes the project root.
 */
export function resolveSandboxPath(input: string): string | null {
  if (!input) return null

  let decoded = input
  try {
    decoded = decodeURIComponent(input)
  } catch {
    // Not percent-encoded (e.g. a JSON body containing a literal '%'); use raw value
  }

  if (decoded.includes('\0')) return null

  const normalized = path.posix.normalize(decoded.replace(/\\/g, '/')).replace(/^\/+/, '')
  const resolved = path.posix.resolve(PROJECT_DIR, normalized)

  if (resolved === PROJECT_DIR || !resolved.startsWith(`${PROJECT_DIR}/`)) {
    return null
  }

  return resolved.slice(PROJECT_DIR.length + 1)
}
