# Observability design — ARES auditor-web

**Scope:** `apps/auditor-web` (Next.js 16 monolith, Vercel)  
**Context:** Lightweight logger pattern from `src/config/logger.ts`; Sentry gap in `docs/PLAT-3-SALVAGE-ANALYSIS.md`  
**Date:** 2026-08-04  
**Target:** ~50 DAU, low QPS, budget-conscious  
**Related:** [Reliability design](./reliability-auditor-web.md) · [Monitoring README](../../apps/auditor-web/monitoring/README.md)

---

## Executive summary

Auditor-web now has a **unified server-side observability stack** (OBS-1 P0, uncommitted):

| Component | Path | Role |
|-----------|------|------|
| Middleware | `middleware.ts` | Generate/propagate correlation ID on every matched request |
| Logger | `lib/observability/logger.ts` | Structured JSON to stdout/stderr |
| Redaction | `lib/observability/redaction.ts` | PII/token scrubbing at write time |
| Context | `lib/observability/context.ts` | `AsyncLocalStorage` + header helpers |
| Metrics | `lib/observability/metrics.ts` | Log-based HTTP counters/histograms |
| Route wrapper | `lib/observability/route-handler.ts` | `withObservedRoute()` — timing + metrics + ALS |

**Legacy paths still coexist:**

| System | Destination | Audience |
|--------|-------------|----------|
| `TaskLogger` | Postgres `tasks.logs` | End user (UI) |
| Residual `console.*` | Vercel Runtime Logs | Engineers — being migrated (P1) |

---

## Current state (2026-08-04)

| Capability | Status | Notes |
|------------|--------|-------|
| `middleware.ts` | ✅ Implemented | Sets `x-correlation-id`, `x-request-id`, `x-ares-request-id` |
| Structured logger | ✅ Implemented | JSON schema with `t`, `level`, `msg`, `request_id`, `component` |
| Redaction | ✅ Implemented | Tokens, credentials, URL secrets, `hashId()` for user IDs |
| Request context (ALS) | ✅ Implemented | `buildRequestContext()`, `runWithRequestContextAsync()` |
| HTTP metrics | ✅ Implemented | `ares_auditor_web_api_*` via log lines (`component=metrics`) |
| Auth callback → logger | ✅ Migrated | `auth.github` component, `withObservedRoute` |
| `POST /api/tasks` → logger | ✅ Partial | Structured errors on sync path; async path still uses `console.*` |
| `GET /api/tasks` → logger | ✅ Partial | 5xx uses logger; other paths still `console.*` |
| `/api/auth/info` metrics | ✅ Wired | Primary synthetic probe target |
| Remaining `app/api/` routes | ⏳ P1 backlog | ~50 routes still on `console.*` |
| Sentry | ⏳ P2 | Env-gated via `SENTRY_DSN` — not required for MVP |
| ESLint ban `console.*` in API | ⏳ P3 | Backlog |

### Routes instrumented with `withObservedRoute`

| Route | Journey | Logger migration |
|-------|---------|------------------|
| `GET /api/auth/info` | signin | Metrics only (no structured logs yet) |
| `GET /api/auth/github/callback` | signin | ✅ Logger |
| `GET /api/auth/github/status` | connect_repo | Metrics only |
| `GET /api/tasks` | list_tasks | ✅ 5xx path |
| `POST /api/tasks` | create_task | ✅ Sync error paths |
| `POST /api/tasks/[taskId]/continue` | create_task | Metrics only |
| `POST /api/tasks/[taskId]/start-sandbox` | sandbox | Metrics only |
| `GET /api/tasks/[taskId]/sandbox-health` | sandbox | Metrics only |
| `GET /api/github/user-repos` | connect_repo | Metrics only |

---

## 1. Structured log schema

Single-line JSON per event to stdout/stderr — compatible with Vercel Log Drain.

Key fields: `t`, `level`, `msg`, `request_id`, `component`, `http`, `auth`, `task`, `error`, `env`.

Implementation: `apps/auditor-web/lib/observability/logger.ts`

**TaskLogger is unchanged** — user-facing progress only. Server logger complements for ops.

---

## 2. Log levels

| Level | Production default |
|-------|-------------------|
| debug | OFF (except dev) |
| info | ON (sampled for HTTP 2xx) |
| warn | ON |
| error | ON (100%) |

Override: `ARES_WEB_LOG_LEVEL=warn`

**Sampling (production):** HTTP 2xx 10% · auth/errors 100% · agent debug 0%

---

## 3. Correlation ID

### 3.1 Flow

```
Client → middleware.ts → generate/propagate ID → API route → logger (request_id)
```

### 3.2 Headers

| Header | Constant | Purpose |
|--------|----------|---------|
| `x-correlation-id` | `CORRELATION_ID_HEADER` | Primary — synthetic probes may assert |
| `x-request-id` | `REQUEST_ID_HEADER` | Alias for client compatibility |
| `x-ares-request-id` | — | Internal downstream read |

Implementation: `apps/auditor-web/middleware.ts`  
Context: `apps/auditor-web/lib/observability/context.ts`

**Edge note:** Middleware runs on Edge; route handlers read headers into `AsyncLocalStorage` via `buildRequestContext()`.

### 3.3 Propagation rules

| Scenario | ID source |
|----------|-----------|
| Browser → API | Middleware |
| OAuth redirect hops | New ID per hop; link via auth flow logs |
| `after()` task processing | Inherit POST `/api/tasks` correlation ID |
| Task continue | New HTTP ID; same `task_id` in logs |

---

## 4. Redaction

Implementation: `apps/auditor-web/lib/observability/redaction.ts`

**Never log raw:** OAuth tokens, JWE cookies, API keys, user UUIDs, repo URLs, sandbox IDs, upstream error bodies.

Use: `hashId()`, `token_present: true`, `upstream_status`.

---

## 5. Error tracking (optional)

Sentry env-gated via `SENTRY_DSN` — not required for MVP.  
`@vercel/analytics` = product metrics only.

---

## 6. Retention

| Destination | Retention |
|-------------|-----------|
| Vercel Runtime Logs | 1 h (Hobby) / 1 d (Pro) |
| Sentry (if enabled) | 90 d free tier |
| Postgres `tasks.logs` | Task lifetime (cap 500 entries) |

Defer Log Drain until >100 DAU or compliance need.

---

## 7. Common queries

Assumes JSON lines export from Vercel.

```bash
# OAuth errors (24 h)
jq -c 'select(.component | startswith("auth.")) | select(.level == "error")' logs.jsonl

# Trace single request
jq -c --arg rid "req_abc123" 'select(.request_id == $rid)' logs.jsonl

# HTTP 5xx by route
jq -s '[.[] | select(.http.status >= 500)] | group_by(.http.path) | map({path: .[0].http.path, count: length})' logs.jsonl

# Metric events
jq -c 'select(.component == "metrics")' logs.jsonl
```

---

## 8. Metrics integration (REL-1)

Reliability doc §3.2 routes emit:

- `ares_auditor_web_api_requests_total`
- `ares_auditor_web_api_request_duration_ms`

Via `withObservedRoute()` wrapper — log-based counters/histograms, no OTel SDK on Vercel serverless.

In-memory aggregates available for local debugging (`getRequestCounter`, `resetMetricsForTests`).

---

## Cross-references

| Reliability | Observability |
|-------------|---------------|
| SLI on `/api/auth/info` | Synthetic asserts `x-correlation-id` |
| Alert A-101 OAuth 5xx | `component=auth.github`, `error.code=OAUTH_*` |
| Async task SLI | `tasks.lifecycle` + inherited `request_id` |
| Dashboard HTTP panels | `component=metrics` log lines |

---

## Migration roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| **P0** | `logger` + `middleware` + `redaction` + `context` + `metrics` | ✅ Implemented (uncommitted) |
| **P0** | Metrics on critical routes via `withObservedRoute` | ✅ Implemented (uncommitted) |
| **P1** | Auth callback → structured logger | ✅ Done |
| **P1** | `POST /api/tasks` sync path → logger | ✅ Partial (errors; async still `console.*`) |
| **P1** | `GET /api/tasks` 5xx → logger | ✅ Done |
| **P1** | Remaining auth routes (`signin`, `rate-limit`, Vercel callback) | ⏳ Backlog |
| **P1** | Remaining task/sandbox routes | ⏳ Backlog |
| **P2** | Sentry optional integration | ⏳ Backlog |
| **P3** | ESLint ban `console.*` in `app/api/` | ⏳ Backlog |
