# Dokumen Desain Observability — ARES auditor-web

| Field | Value |
|-------|-------|
| **Scope** | `apps/auditor-web` + konteks monorepo |
| **Version** | 2026-08-04 |
| **Status** | OBS-1 P0 landed on `main`; P1 `console.*` migration pending |
| **Related docs** | [reliability-auditor-web.md](./reliability-auditor-web.md) · [security-auditor-web.md](./security-auditor-web.md) |

---

> **Implementation note (2026-08-04):** OBS-1 P0 is on `main` (`lib/observability/*`, `middleware.ts`, `withObservedRoute` on critical API routes). Sections below include baseline audit plus current P0 state; P1 migration of remaining `console.*` is pending.

## Ringkasan Eksekutif

Auditor-web saat ini memiliki **dua sistem logging terpisah tanpa korelasi**:

| Sistem | Destinasi | Format | Audience |
|--------|-----------|--------|----------|
| `TaskLogger` | Postgres (`tasks.logs`) | JSON array per task | User (UI logs pane) |
| `console.log/error` | Vercel Runtime Logs | Plain text, tidak konsisten | Engineer (server-side) |

**Temuan audit codebase:**

- **~200+** pemanggilan `console.*` di `app/api/` dan `lib/` — mayoritas `console.error`, beberapa `console.log` dengan **pelanggaran keamanan** (user ID, sandbox ID, error response body).
- **Tidak ada** `middleware.ts`, `request_id`, Sentry, atau logger terstruktur server-side.
- `next.config.ts` — **tanpa** konfigurasi logging.
- `@vercel/analytics` + `@vercel/speed-insights` sudah terpasang di `app/layout.tsx` (product analytics, bukan ops logs).
- Dual auth: **Dashboard OAuth** (GitHub/Vercel JWE) + **Supabase OAuth** (knowledge base JWT) — path berbeda, belum ada trace unified.

---

### 1. Skema Log Terstruktur

Semua log server-side (API routes, lib, middleware) harus emit **satu baris JSON per event** ke stdout/stderr — kompatibel dengan Vercel Log Drain dan generic JSON log aggregator.

#### 1.1 Interface TypeScript

```typescript
/** Level log — selaras dengan src/config/logger.ts di monorepo root */
type LogLevel = 'debug' | 'info' | 'warn' | 'error'

/** Komponen/subsystem — untuk filter dan dashboard */
type LogComponent =
  | 'auth.github'
  | 'auth.vercel'
  | 'auth.supabase'
  | 'auth.session'
  | 'tasks.lifecycle'
  | 'tasks.sandbox'
  | 'tasks.agent'
  | 'tasks.files'
  | 'usage'
  | 'github.api'
  | 'vercel.api'
  | 'db'
  | 'http'

/** Event outcome — untuk metrik success rate */
type LogOutcome = 'success' | 'failure' | 'partial' | 'skipped'

interface AresWebLogEntry {
  /** ISO 8601 timestamp */
  t: string

  /** Severity */
  level: LogLevel

  /** Pesan human-readable, static string (no PII) */
  msg: string

  /** Wajib: correlation ID — lihat §3 */
  request_id: string

  /** Opsional: task ID jika dalam konteks task */
  task_id?: string

  /** Subsystem */
  component: LogComponent

  /** HTTP context (API routes) */
  http?: {
    method: string
    path: string          // templated: /api/tasks/[taskId]/files
    status?: number
    duration_ms?: number
  }

  /** Auth context — NEVER include tokens */
  auth?: {
    provider?: 'github' | 'vercel' | 'supabase'
    mode?: 'signin' | 'connect' | 'signout' | 'refresh'
    outcome: LogOutcome
    /** Hanya hash/truncated — lihat §4 */
    user_id_hash?: string
  }

  /** Task lifecycle */
  task?: {
    action: 'create' | 'continue' | 'stop' | 'complete' | 'error' | 'timeout'
    agent?: string        // 'claude' | 'cursor' | 'codex' — enum, bukan dynamic
    progress?: number
    outcome: LogOutcome
  }

  /** Error detail — server-side only, redacted */
  error?: {
    name: string
    /** Generic message — no stack in info/warn */
    message: string
    /** Hanya di level error, untuk Sentry fingerprint */
    code?: string
    /** HTTP upstream status jika applicable */
    upstream_status?: number
  }

  /** Deployment context — auto-injected */
  env: 'development' | 'preview' | 'production'
  vercel?: {
    deployment_id?: string
    region?: string
  }

  /** Sampling metadata */
  sampled?: boolean
}
```

#### 1.2 Contoh Output

```json
{
  "t": "2026-08-04T13:32:01.234Z",
  "level": "info",
  "msg": "OAuth callback completed",
  "request_id": "req_8f3k2m",
  "component": "auth.github",
  "auth": {
    "provider": "github",
    "mode": "signin",
    "outcome": "success",
    "user_id_hash": "usr_a1b2"
  },
  "http": {
    "method": "GET",
    "path": "/api/auth/github/callback",
    "status": 302,
    "duration_ms": 847
  },
  "env": "production"
}
```

```json
{
  "t": "2026-08-04T13:35:22.100Z",
  "level": "error",
  "msg": "Task processing failed",
  "request_id": "req_8f3k2m",
  "task_id": "tsk_x9y8",
  "component": "tasks.lifecycle",
  "task": {
    "action": "create",
    "agent": "claude",
    "outcome": "failure"
  },
  "error": {
    "name": "SandboxCreationError",
    "message": "Sandbox creation failed",
    "code": "SANDBOX_CREATE_FAILED"
  },
  "env": "production"
}
```

#### 1.3 Pemisahan TaskLogger vs Server Logger

| Concern | TaskLogger (existing) | Server Logger (new: `lib/observability/logger.ts`) |
|---------|---------------------|---------------------------------------------------|
| Audience | End user (UI) | Engineers / Vercel logs |
| Storage | Postgres `tasks.logs` | Vercel Runtime → optional Log Drain |
| Content | Static strings only (AGENTS.md) | Structured JSON + redacted metadata |
| Correlation | Implicit via `task_id` | `request_id` + optional `task_id` |
| Retention | Per task lifecycle | Platform default (§6) |

**Prinsip:** TaskLogger **tidak diganti** — tetap user-facing progress log. Server logger **melengkapi** untuk debugging operasional.

#### 1.4 Implementasi Ringan (referensi monorepo)

Adaptasi pola dari `src/config/logger.ts`:

- Tanpa pino/winston (dependency surface kecil).
- `redact()` untuk metadata keys sensitif + URL query-string secrets.
- Reserved fields: `t`, `level`, `msg`, `request_id` — caller tidak boleh overwrite.

---

### 2. Tingkat Log

#### 2.1 Definisi Level

| Level | Kapan | Contoh auditor-web | Default prod |
|-------|-------|-------------------|--------------|
| `debug` | Trace detail dev-only | Sandbox command output, MCP config steps | **OFF** |
| `info` | Lifecycle events, success paths | Auth completed, task created, sandbox ready | **ON** (sampled) |
| `warn` | Degraded but recovered | MCP servers unavailable, fallback branch name | **ON** |
| `error` | Failure requiring attention | OAuth exchange failed, task timeout, DB error | **ON** (100%) |

#### 2.2 Environment Threshold

```typescript
const LOG_THRESHOLDS: Record<string, LogLevel> = {
  development: 'debug',
  preview: 'info',
  production: 'info',
}

// Override via env: ARES_WEB_LOG_LEVEL=warn
```

#### 2.3 Mapping dari State Saat Ini

| Pola existing | Target level | Catatan |
|---------------|-------------|---------|
| `console.log('[GitHub Callback] Starting...')` | `info` | Ganti ke structured, hapus dynamic values |
| `console.error('Error fetching task files:', error)` | `error` | Extract `error.name`, redact message |
| `console.log('Detected port ${port}...')` | `debug` | **Jangan log port** — gunakan enum `port_detected: true` |
| `TaskLogger.info('Sandbox created')` | Tetap TaskLogger | Parallel: server `info` dengan `task_id` |
| Agent command output via `logger.command()` | TaskLogger only | Server: `debug` + redacted, sampled 0% prod |

#### 2.4 Level per Komponen (production defaults)

| Component | debug | info | warn | error |
|-----------|-------|------|------|-------|
| `auth.*` | — | signin/signout/connect events | rate limit approaching | exchange/session failures |
| `tasks.lifecycle` | — | create/complete/stop | timeout warning | processing failure |
| `tasks.sandbox` | install steps | created/connected | reconnect failed | creation/kill failure |
| `tasks.agent` | CLI output | execution start/end | MCP unavailable | agent execution failed |
| `usage` | — | page view server-side (optional) | — | data fetch failure |
| `http` (middleware) | — | 2xx/3xx (sampled) | 4xx | 5xx |

---

### 3. Correlation ID

#### 3.1 Problem

Saat ini **tidak ada** `request_id`, `x-request-id`, atau `middleware.ts`. Log auth callback dan task processing tidak bisa di-join across requests (mis. sign-in → create task → sandbox error).

#### 3.2 Desain

```
Client Request
    │
    ▼
┌─────────────────────────────────────┐
│  middleware.ts (Edge/Node)          │
│  1. Read X-Request-ID header        │
│  2. If missing → generate req_<nanoid(12)> │
│  3. Set AsyncLocalStorage context   │
│  4. Inject response header          │
│  5. Log http.request (sampled)      │
└─────────────────────────────────────┘
    │
    ▼
API Route / Server Action
    │
    ├─ logger.info(..., { request_id })  ← from ALS
    ├─ Pass request_id to background task via closure
    └─ TaskLogger: store request_id on first log (optional DB column)
```

#### 3.3 Propagation Rules

| Scenario | `request_id` source |
|----------|---------------------|
| Browser → API route | Generated/propagated di middleware |
| OAuth redirect (GitHub → callback) | **New** request_id per hop; link via `auth.correlation_token` cookie (opaque, 10min TTL, no PII) |
| Long-running task (`processTaskAsync`) | Inherit dari POST `/api/tasks` request_id; log semua events dengan ID sama |
| Task continuation | New request_id untuk HTTP; include `parent_request_id` + same `task_id` |
| Supabase callback (`/auth/callback`) | Separate flow; component=`auth.supabase` |

#### 3.4 Middleware Pseudocode

```typescript
// middleware.ts — apps/auditor-web/middleware.ts
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { nanoid } from 'nanoid'

const REQUEST_ID_HEADER = 'x-request-id'

export function middleware(request: NextRequest) {
  const requestId =
    request.headers.get(REQUEST_ID_HEADER) ?? `req_${nanoid(12)}`

  const response = NextResponse.next()
  response.headers.set(REQUEST_ID_HEADER, requestId)

  // Store in header for downstream route handlers to read
  response.headers.set('x-ares-request-id', requestId)

  // Optional: log entry (sampled in production — see §6)
  // logHttpRequest({ request_id: requestId, method, path, ... })

  return response
}

export const config = {
  matcher: [
    '/api/:path*',
    '/auth/:path*',
    // Exclude static assets
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
}
```

```typescript
// lib/observability/context.ts
import { AsyncLocalStorage } from 'async_hooks'

interface RequestContext {
  request_id: string
  task_id?: string
  user_id_hash?: string
}

export const requestContext = new AsyncLocalStorage<RequestContext>()

export function getRequestId(): string {
  return requestContext.getStore()?.request_id ?? 'req_unknown'
}
```

#### 3.5 Response Header

Expose `X-Request-ID` ke client untuk support tickets:

```
X-Request-ID: req_8f3k2m
```

User-facing error pages: "Referensi error: req_8f3k2m" (bukan stack trace).

---

### 4. Penyamaran Data (Redaction)

#### 4.1 Dua Lapisan Pertahanan

| Lapisan | Scope | Mekanisme |
|---------|-------|-----------|
| **Primary** | TaskLogger + server `msg` | Static strings only (AGENTS.md) — **no dynamic values** |
| **Backup** | Server metadata + TaskLogger messages | `redactSensitiveInfo()` (existing) + `redact()` from monorepo pattern |

#### 4.2 Field yang WAJIB `[REDACTED]` atau Dihash

| Category | Raw (FORBIDDEN) | Safe alternative |
|----------|-----------------|------------------|
| OAuth tokens | `ghp_xxx`, `access_token` value | `token_present: true` |
| Session/JWE | cookie value, `JWE_SECRET` | `session_valid: true/false` |
| API keys | `ANTHROPIC_API_KEY=sk-...` | omit entirely |
| Encryption | `ENCRYPTION_KEY`, encrypted blob | `encrypted: true` |
| User identity | `session.user.id` (UUID) | `user_id_hash: sha256(id).slice(0,8)` |
| GitHub user | `login`, `email` | `github_id: <numeric id only>` or hash |
| Repo URLs | `https://github.com/org/repo` | `repo_ref: hash(org/repo)` |
| Sandbox IDs | full sandbox ID | `sandbox_present: true` |
| Error bodies | GitHub API error text (may contain tokens) | `upstream_status: 401`, generic msg |
| Supabase JWT | access_token, refresh_token | `supabase_session: active/inactive` |

#### 4.3 Pelanggaran Existing yang Harus Dihapus (prioritas migrasi)

Ditemukan di codebase saat ini:

```typescript
// ❌ app/api/auth/github/callback/route.ts
console.log('[GitHub Callback] GitHub session created for user:', session.user.id)
console.error('[GitHub Callback] Error response:', errorText)  // may contain secrets
console.error('[GitHub Callback] Failed to get GitHub access token:', tokenData)

// ❌ app/api/auth/github/disconnect/route.ts
console.log('Disconnecting GitHub account for user:', session.user.id)
console.error('Session user.id is undefined. Session:', session)

// ❌ app/api/tasks/[taskId]/continue/route.ts
console.log('Calling Sandbox.get with sandboxId:', currentTask.sandboxId)
console.error('Detailed error:', { message, stack, taskId, ... })
```

#### 4.4 Redaction Function (extended)

```typescript
const SENSITIVE_KEY = /key|token|password|secret|authorization|credential|dsn|cookie|session/i
const URL_SECRET_PARAM = /([?&](?:api[_-]?key|access_token|token|secret)=)([^&\s]+)/gi

/** Hash untuk correlation tanpa PII */
export function hashId(value: string): string {
  // sha256 → first 8 hex chars, prefixed
  return `h_${createHash('sha256').update(value).digest('hex').slice(0, 8)}`
}
```

#### 4.5 TaskLogger vs Server Logger

- **TaskLogger:** Tetap strict static strings — ditampilkan ke user di UI.
- **Server logger:** Boleh structured metadata **jika redacted** — tidak pernah reach UI/API response logs endpoint.

---

### 5. Pelacakan Error (Sentry Grouping)

#### 5.1 Status Saat Ini

- **Zero** integrasi Sentry di `auditor-web` (confirmed: no `@sentry/*` in package.json).
- Gap terdokumentasi di `docs/PLAT-3-SALVAGE-ANALYSIS.md` sebagai prioritas future.
- `@vercel/analytics` = page views, **bukan** error tracking.

#### 5.2 Rekomendasi: Sentry Optional (Tier 2)

Untuk ~50 DAU, Sentry **Developer plan (free)** cukup:
- 5K errors/month
- 10K performance units

**Aktivasi:** Env-gated — hanya jika `SENTRY_DSN` set.

#### 5.3 Integrasi Points

| Layer | File | Behavior |
|-------|------|----------|
| Next.js | `instrumentation.ts` | `Sentry.init()` on startup |
| API routes | `lib/observability/logger.ts` | `level: error` → `Sentry.captureException()` |
| Edge | `middleware.ts` | `Sentry.captureException()` for unhandled |
| Client | `app/global-error.tsx` | React error boundary → Sentry |

#### 5.4 Fingerprint Strategy (Grouping)

```typescript
// Custom fingerprint — prevent alert noise at low volume
Sentry.withScope((scope) => {
  scope.setFingerprint([
    '{{ default }}',
    logEntry.component,
    logEntry.error?.code ?? 'unknown',
    logEntry.http?.path ?? 'no-path',
  ])
  scope.setTag('component', logEntry.component)
  scope.setTag('request_id', logEntry.request_id)
  if (logEntry.task_id) scope.setTag('task_id', logEntry.task_id)
  // NEVER set user.email — use hash only
  scope.setUser({ id: logEntry.auth?.user_id_hash })
  Sentry.captureException(error)
})
```

#### 5.5 Grouping Rules

| Error pattern | Fingerprint key | Rationale |
|---------------|-------------------|-----------|
| GitHub OAuth 401 | `auth.github` + `OAUTH_EXCHANGE_FAILED` | Group all token exchange failures |
| Sandbox timeout | `tasks.sandbox` + `SANDBOX_TIMEOUT` | Per-agent sub-tag, not per-task |
| Task processing | `tasks.lifecycle` + `TASK_PROCESS_FAILED` + agent enum | Avoid 1 issue per task |
| DB connection | `db` + `CONNECTION_ERROR` | Infra-level grouping |
| 404 on API | **Do NOT send to Sentry** | Expected client errors |

#### 5.6 Before Send Hook

```typescript
beforeSend(event) {
  // Strip cookies, headers with Authorization
  delete event.request?.cookies
  if (event.request?.headers) {
    delete event.request.headers['Authorization']
    delete event.request.headers['Cookie']
  }
  // Scrub breadcrumbs
  event.breadcrumbs = event.breadcrumbs?.map(scrubBreadcrumb)
  return event
}
```

---

### 6. Sampling dan Retensi

#### 6.1 Volume Estimate (~50 DAU)

| Source | Events/day (est.) | Size/event | Daily volume |
|--------|-------------------|------------|--------------|
| HTTP requests (all pages + API) | ~2,000 | ~300 B | ~600 KB |
| Task lifecycle (info) | ~100 | ~400 B | ~40 KB |
| Agent debug (if enabled) | ~5,000+ | ~500 B | **~2.5 MB** ⚠️ |
| Errors | ~10-50 | ~600 B | ~30 KB |

**Risk:** Agent/sandbox command logging dominates volume. **Must sample/disable in prod.**

#### 6.2 Sampling Policy

| Log type | Production | Preview | Development |
|----------|------------|---------|-------------|
| HTTP 2xx/3xx | **10%** | 50% | 100% |
| HTTP 4xx | 100% | 100% | 100% |
| HTTP 5xx | 100% | 100% | 100% |
| Auth events | 100% | 100% | 100% |
| Task lifecycle (info) | 100% | 100% | 100% |
| Sandbox/agent debug | **0%** | 10% | 100% |
| Sentry performance traces | **0%** (errors only) | 5% | 10% |

```typescript
function shouldSample(level: LogLevel, component: LogComponent): boolean {
  if (level === 'error') return true
  if (component.startsWith('auth.')) return true
  if (component.startsWith('tasks.') && level === 'info') return true
  if (component === 'tasks.agent' && level === 'debug') return false
  // HTTP success — 10% in production
  if (process.env.VERCEL_ENV === 'production') return Math.random() < 0.1
  return true
}
```

#### 6.3 Retensi

| Destination | Default retention | Cost | Recommendation |
|-------------|-------------------|------|----------------|
| Vercel Runtime Logs | 1 hour (Hobby) / 1 day (Pro) | Included | Primary for debugging |
| Vercel Log Drain → external | Configurable | Drain free; storage cost | **Defer** until needed |
| Sentry errors | 90 days (free) | Free tier | Enable when DSN set |
| Postgres `tasks.logs` | Task lifetime | DB storage | Cap at 500 entries/task |
| Vercel Analytics | 30 days | Included | Product metrics only |

#### 6.4 Budget Guardrails

1. **Never enable debug logging globally in production.**
2. **Cap TaskLogger entries:** truncate oldest when `logs.length > 500`.
3. **No log drain until** sustained >100 DAU or compliance requirement.
4. **Monitor Vercel log usage** monthly — alert if >50 MB/day.
5. **Structured JSON only** — no multi-line stack dumps (single line with `\n` escaped).

---

### 7. Kueri yang Sering Dipakai

Format asumsi: JSON lines di Vercel Log Drain atau `jq` pada export.

#### 7.1 Auth — OAuth failures (24 jam)

```sql
-- Vercel Log Drain → ClickHouse/Better Stack (SQL-like)
SELECT t, request_id, auth.provider, auth.mode, error.code, error.upstream_status
FROM logs
WHERE component LIKE 'auth.%'
  AND level = 'error'
  AND t > now() - INTERVAL 24 HOUR
ORDER BY t DESC
```

```bash
# Generic jq on JSONL export
jq -c 'select(.component | startswith("auth.")) | select(.level == "error")' logs.jsonl
```

#### 7.2 Auth — Success rate by provider

```bash
jq -s '
  [.[] | select(.component | startswith("auth.")) | select(.level == "info")]
  | group_by(.auth.provider)
  | map({
      provider: .[0].auth.provider,
      total: length,
      success: [.[] | select(.auth.outcome == "success")] | length
    })
' logs.jsonl
```

#### 7.3 Tasks — Failure rate by agent

```bash
jq -s '
  [.[] | select(.component == "tasks.lifecycle") | select(.task.action == "create")]
  | group_by(.task.agent)
  | map({agent: .[0].task.agent, total: length, failed: [.[] | select(.task.outcome == "failure")] | length})
' logs.jsonl
```

#### 7.4 Trace single request

```bash
REQUEST_ID="req_8f3k2m"
jq -c --arg rid "$REQUEST_ID" 'select(.request_id == $rid)' logs.jsonl | jq -s 'sort_by(.t)'
```

#### 7.5 Trace task lifecycle (cross-request)

```bash
TASK_ID="tsk_x9y8"
jq -c --arg tid "$TASK_ID" 'select(.task_id == $tid)' logs.jsonl | jq -s 'sort_by(.t) | .[] | {t, level, msg, component, task}'
```

#### 7.6 Sandbox errors

```bash
jq -c 'select(.component == "tasks.sandbox") | select(.level == "error")' logs.jsonl
```

#### 7.7 HTTP 5xx by route

```bash
jq -s '
  [.[] | select(.http.status >= 500)]
  | group_by(.http.path)
  | map({path: .[0].http.path, count: length})
  | sort_by(-.count)
' logs.jsonl
```

#### 7.8 P95 task processing duration

```bash
jq -s '
  [.[] | select(.component == "tasks.lifecycle")
        | select(.task.action == "complete")
        | .http.duration_ms // empty]
  | sort
  | .[length * 0.95 | floor]
' logs.jsonl
```

#### 7.9 Rate limit / auth abuse (warn+)

```bash
jq -c 'select(.component == "auth.session") | select(.level == "warn" or .level == "error")' logs.jsonl
```

#### 7.10 Verify no token leakage (audit)

```bash
# Should return ZERO matches
grep -E 'ghp_|gho_|sk-ant-|sk-proj-|Bearer [a-zA-Z0-9]{20,}|access_token.*[a-zA-Z0-9]{20,}' logs.jsonl
```

---

### 8. Instrumentasi per Komponen

#### 8.1 Auth — GitHub OAuth (Dashboard)

**Routes:** `app/api/auth/signin/github`, `app/api/auth/github/callback`, `app/api/auth/github/disconnect`, `app/api/auth/github/status`

| Event | Level | Fields | Static msg |
|-------|-------|--------|------------|
| OAuth initiate | info | `auth.provider=github`, `auth.mode=signin\|connect` | `OAuth flow initiated` |
| State validation fail | warn | `auth.outcome=failure`, `error.code=INVALID_OAUTH_STATE` | `OAuth state validation failed` |
| Token exchange fail | error | `error.upstream_status`, `error.code=OAUTH_EXCHANGE_FAILED` | `Token exchange failed` |
| Token exchange ok | info | `auth.outcome=success`, `token_present=true` | `Token exchange completed` |
| Session created | info | `auth.outcome=success`, `user_id_hash` | `Session created` |
| Account merge | info | `auth.mode=connect`, `auth.outcome=success` | `Account merge completed` |
| Disconnect | info | `auth.mode=signout`, `auth.outcome=success` | `GitHub disconnected` |
| Disconnect no session | warn | `auth.outcome=failure` | `Disconnect attempted without session` |

**Remove:** All `console.log` with user IDs, tokenData dumps, errorText bodies.

#### 8.2 Auth — Vercel OAuth

**Routes:** `app/api/auth/signin/vercel`, `app/api/auth/callback/vercel`, `app/api/auth/signout`

| Event | Level | msg |
|-------|-------|-----|
| Callback started | info | `Vercel OAuth callback started` |
| Session creation failed | error | `Vercel session creation failed` |
| Signout token revoke fail | warn | `Token revocation failed` (per provider, no token value) |
| Signout complete | info | `Signout completed` |

#### 8.3 Auth — Supabase (Knowledge Base)

**Routes:** `app/auth/callback/route.ts`, `lib/supabase/auth.ts` (client-side — minimal server log)

| Event | Level | msg |
|-------|-------|-----|
| Callback success | info | `Supabase auth callback completed` |
| Callback error | error | `Supabase auth callback failed` |
| Config missing | warn | `Supabase auth not configured` |

**Note:** Dual auth — dashboard JWE session dan Supabase JWT **independent**. Log `component=auth.supabase` vs `auth.github`/`auth.vercel` untuk avoid confusion.

#### 8.4 Auth — Session & Rate Limit

**Routes:** `app/api/auth/info`, `app/api/auth/rate-limit`

| Event | Level | msg |
|-------|-------|-----|
| Session check | debug | `Session info requested` |
| Rate limit hit | warn | `Rate limit exceeded` |
| Rate limit check error | error | `Rate limit check failed` |

#### 8.5 Tasks — Lifecycle

**Routes:** `app/api/tasks/route.ts`, `app/api/tasks/[taskId]/route.ts`, `app/api/tasks/[taskId]/continue/route.ts`

| Event | Level | component | task.action | Parallel TaskLogger |
|-------|-------|-----------|-------------|---------------------|
| POST create | info | tasks.lifecycle | create | `Task created` |
| Background start | info | tasks.lifecycle | create | `Initializing task execution` |
| Background complete | info | tasks.lifecycle | complete | `Task completed successfully` |
| Background error | error | tasks.lifecycle | error | `Error occurred during task processing` |
| Timeout warning | warn | tasks.lifecycle | timeout | `Task is approaching timeout` |
| Timeout | error | tasks.lifecycle | timeout | `Task execution timed out` |
| Stop request | info | tasks.lifecycle | stop | `Stop request received` |
| Continue | info | tasks.lifecycle | create | `Processing follow-up message` |

**Correlation:** Set `task_id` in ALS context when entering `processTaskAsync()`.

#### 8.6 Tasks — Sandbox

**Routes:** `start-sandbox`, `stop-sandbox`, `sandbox-health`, `lib/sandbox/creation.ts`

| Event | Level | msg |
|-------|-------|-----|
| Creation started | info | `Sandbox creation started` |
| Creation success | info | `Sandbox created successfully` |
| Creation failed | error | `Sandbox creation failed` |
| Reconnect attempt | info | `Sandbox reconnect attempted` |
| Reconnect failed | warn | `Sandbox reconnect failed` |
| Health check fail | warn | `Sandbox health check failed` |
| Kill on stop | info | `Sandbox stopped` |

**Do NOT log:** sandboxId, port numbers, command output (TaskLogger handles user-facing redacted version).

#### 8.7 Tasks — Agent Execution

**Routes/lib:** `lib/sandbox/agents/*`, task route agent invocation

| Event | Level | msg |
|-------|-------|-----|
| Agent selected | info | `Agent execution started` (+ `task.agent` enum) |
| MCP servers loaded | info | `MCP servers configured` |
| MCP fetch failed | warn | `MCP server fetch failed` |
| Agent completed | info | `Agent execution completed` |
| Agent failed | error | `Agent execution failed` |
| Push to branch failed | error | `Push to repository failed` |

**Debug only (0% prod sample):** CLI install steps, config file contents.

#### 8.8 Tasks — Files & Git Operations

**Routes:** `files`, `file-content`, `save-file`, `diff`, `sync-changes`, `merge-pr`, etc.

| Event | Level | msg |
|-------|-------|-----|
| File fetch error | error | `File fetch failed` |
| GitHub API error | error | `GitHub API request failed` (+ upstream_status) |
| Sandbox file op error | error | `Sandbox file operation failed` |
| PR created | info | `Pull request created` |
| PR merged | info | `Pull request merged` |

**Do NOT log:** file paths, repo URLs, branch names (AGENTS.md).

#### 8.9 Usage

**Routes/pages:** `app/usage/page.tsx`, `components/usage-page-client.tsx`, `lib/mock/usage.ts`

| Event | Level | msg |
|-------|-------|-----|
| Page render (server) | info | `Usage page rendered` |
| Mock data served | debug | `Usage mock data served` |
| Future: real metrics fetch fail | error | `Usage data fetch failed` |

**Note:** Usage page currently mock data — instrument for future real billing/usage API integration. Product analytics via `@vercel/analytics` covers page views; server log covers backend failures only.

#### 8.10 HTTP Middleware (All Routes)

| Event | Level | Sampled |
|-------|-------|---------|
| Request start | debug | 10% prod |
| Request complete | info | 10% prod (2xx), 100% (4xx/5xx) |

Fields: `http.method`, `http.path` (templated), `http.status`, `http.duration_ms`, `request_id`.

---

## Migration Roadmap (Referensi, Bukan Implementasi)

| Phase | Scope | Effort |
|-------|-------|--------|
| P0 | `lib/observability/logger.ts` + redaction | 1-2 days |
| P0 | `middleware.ts` + request_id | 0.5 day |
| P1 | Migrate auth routes (highest security risk) | 1 day |
| P1 | Migrate `tasks/route.ts` + `continue/route.ts` | 1-2 days |
| P2 | Remaining API routes (mechanical) | 2-3 days |
| P2 | Sentry optional integration | 0.5 day |
| P3 | ESLint rule: ban `console.*` in `app/api/` | 0.5 day |

---

## Self-Check Checklist

### Skema & Arsitektur
- [ ] Semua server log emit single-line JSON dengan field `t`, `level`, `msg`, `request_id`, `component`
- [ ] TaskLogger (user-facing) tetap terpisah dengan static strings
- [ ] Tidak menambah pino/winston — logger ringan selaras `src/config/logger.ts`
- [ ] `next.config.ts` tidak perlu logging config (stdout JSON cukup untuk Vercel)

### Keamanan
- [ ] Zero raw tokens (`ghp_`, `access_token`, Bearer, API keys) di semua log
- [ ] Zero user UUID plain text — gunakan `user_id_hash`
- [ ] Zero repo URL, branch name, file path di server logs
- [ ] Error upstream body tidak di-log (hanya `upstream_status` + generic code)
- [ ] Sentry `beforeSend` scrub cookies/Authorization
- [ ] Audit grep: `ghp_|sk-ant-|Bearer ` returns zero on production logs

### Correlation
- [ ] `middleware.ts` generate/propagate `X-Request-ID`
- [ ] Semua API route logs include `request_id`
- [ ] Long-running tasks inherit `request_id` dari POST request
- [ ] `task_id` di-set in ALS context selama task processing

### Sampling & Cost
- [ ] Agent/sandbox debug = 0% sample di production
- [ ] HTTP 2xx = 10% sample di production
- [ ] Auth + errors = 100%
- [ ] TaskLogger capped at 500 entries per task
- [ ] No Log Drain until justified by scale

### Error Tracking
- [ ] Sentry env-gated (`SENTRY_DSN`)
- [ ] Custom fingerprint by `component` + `error.code`
- [ ] 4xx tidak dikirim ke Sentry
- [ ] `@vercel/analytics` tetap untuk product metrics (bukan ops)

### Dual Auth
- [ ] `component=auth.github|vercel` untuk dashboard OAuth
- [ ] `component=auth.supabase` untuk knowledge base JWT
- [ ] Log tidak assume single auth path

### Existing Violations Addressed
- [ ] `github/callback/route.ts` — remove user ID logging, tokenData dump, errorText dump
- [ ] `github/disconnect/route.ts` — remove session dump
- [ ] `tasks/continue/route.ts` — remove sandboxId, detailed error object logging
- [ ] `tasks/route.ts` — migrate console.log milestones ke structured logger

### Operability
- [ ] Documented queries work on JSONL export
- [ ] Response header `X-Request-ID` exposed for support
- [ ] Error pages show request ID reference (not stack trace)

---

**Dokumen ini intentionally design-only.** Implementasi kode (`lib/observability/`, `middleware.ts`, migrasi `console.*`) adalah backlog terpisah — disarankan tie ke backlog ID platform (mis. PLAT-3 Sentry gap atau task observability baru).

[REDACTED]