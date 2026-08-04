# Reliability design — ARES auditor-web

**Scope:** `apps/auditor-web` (Next.js App Router, Vercel, PostgreSQL/Drizzle)  
**Baseline MVP:** 99.5% availability · p95 GET pages/API < 300 ms · OAuth end-to-end < 2 s · ~50 DAU, low QPS  
**Date:** 2026-08-04  
**Status:** v1 — implementation in progress (REL-1)  
**Related:** [Observability design](./observability-auditor-web.md) · [Runbooks](./runbooks/)

---

## Principles

1. **Alert on symptoms, not causes.** Users care whether sign-in works, not whether CPU is high.
2. **Every pageable alert must be actionable** with a linked runbook.
3. **Alert fatigue is a system failure.** Tune thresholds from SLO error budgets.
4. **SLOs drive alerts**, not the reverse.

---

## 1. Critical user journeys

Four journeys map directly to production routes. If any fails, the product is considered degraded.

### 1.1 Sign in with GitHub

| Step | Component | Endpoint | Dependencies |
|------|-----------|----------|--------------|
| 1 | UI | `startGitHubOAuth()` redirect | Browser |
| 2 | API | `GET /api/auth/signin/github?next=` | Cookies, `NEXT_PUBLIC_GITHUB_CLIENT_ID` |
| 3 | External | GitHub OAuth authorize | GitHub |
| 4 | Callback | `GET /api/auth/github/callback` | GitHub token/user API, PostgreSQL |
| 5 | Session | JWE cookie via `saveSession()` | `JWE_SECRET` |
| 6 | Hydration | `GET /api/auth/info` | Cookie read, optional Vercel token refresh |

**Failure modes:** invalid OAuth state (400), missing env (500), token/DB failures (4xx/5xx).

### 1.2 Create task

| Step | Endpoint | Notes |
|------|----------|-------|
| Sync accept | `POST /api/tasks` | 200 or 429 within 10 s |
| Rate limit | `checkRateLimit(userId)` | 429 = quota enforcement, not infra failure |
| Async | `after()` sandbox + agent | Failures → task `error`; **not** counted in HTTP accept SLI |

**Config:** `maxDuration: 300` on task routes.

### 1.3 List tasks

| Step | Endpoint | Notes |
|------|----------|-------|
| Layout mount | `GET /api/tasks` | 401 → empty sidebar (graceful) |
| Detail poll | `GET /api/tasks/[taskId]` | Separate from list journey |

### 1.4 Connect GitHub repo

| Step | Endpoint | Notes |
|------|----------|-------|
| Status | `GET /api/auth/github/status` | `{ connected: false }` is expected |
| Repos | `GET /api/github/user-repos` | Requires connected token |

---

## 2. SLI and SLO

**Window:** Rolling 30 days  
**Error budget:** `(1 - SLO) × total_events`

### 2.1 Global targets

| Dimension | MVP target | 30-day error budget |
|-----------|------------|---------------------|
| Platform availability | 99.5% | ~3.6 h downtime |
| p95 GET (non-OAuth) | < 300 ms | 5% slow |
| p95 OAuth end-to-end | < 2 s | 5% slow |
| Synthetic probe success | 99.9% | ~43 min failed checks @ 1 min interval |

### 2.2 Per journey (summary)

| Journey | Key SLI | SLO |
|---------|---------|-----|
| Sign in | Callback not 5xx | 99.5% |
| Sign in | `/api/auth/info` 200 + JSON | 99.9% |
| Create task | `POST /api/tasks` 200 or 429 | 99.5% |
| Create task | p95 accept < 500 ms | 95% |
| Create task | pending → processing < 60 s | 98% |
| List tasks | `GET /api/tasks` 200 (auth) | 99.5% |
| Connect repo | `/api/github/user-repos` 200 | 99.0% |

**Excluded from availability SLI:** OAuth user denial, unauthenticated 401, expected 429 quota responses.

---

## 3. Metrics

Prefix: `ares_auditor_web_`  
See [observability doc](./observability-auditor-web.md) for log correlation (`request_id`, `x-correlation-id`).

### 3.1 Standard labels (low cardinality)

| Label | Values |
|-------|--------|
| `env` | production, preview |
| `route` | Normalized template, ~15 critical routes |
| `method` | GET, POST, PATCH, DELETE |
| `status_class` | 2xx, 3xx, 4xx, 5xx |
| `journey` | signin, create_task, list_tasks, connect_repo, sandbox |

**Never label:** `user_id`, `task_id`, `repo_url`, raw `error_message`.

### 3.2 Critical routes (instrumented REL-1)

```
/api/auth/info
/api/auth/signin/github
/api/auth/github/callback
/api/auth/github/status
/api/auth/rate-limit
/api/tasks                          GET, POST
/api/tasks/[taskId]/continue        POST
/api/tasks/[taskId]/start-sandbox   POST
/api/tasks/[taskId]/sandbox-health  GET
/api/github/user-repos
```

| Metric | Type | Labels |
|--------|------|--------|
| `ares_auditor_web_api_requests_total` | Counter | route, method, status, journey |
| `ares_auditor_web_api_request_duration_ms` | Histogram | route, method, journey |

Implementation: `apps/auditor-web/lib/observability/metrics.ts` (log-based, no OTel SDK — Vercel-compatible).

### 3.3 Cardinality budget

| Scope | Max series | Action if exceeded |
|-------|------------|-------------------|
| Per route | 50 | Drop per-status detail, keep status_class |
| Global | 5,000 | Review label explosion |
| Per user | 0 | Forbidden |

---

## 4. Alerts

**Recipients:** P1 → PagerDuty `#ares-oncall` · P2 → `#ares-engineering` · P3 → Linear ticket

### 4.1 Platform / synthetic

| ID | Symptom | Condition | Sev | Duration | Runbook |
|----|---------|-----------|-----|----------|---------|
| **A-001** | App unreachable externally | Synthetic `GET /api/auth/info` fail ≥2 regions | P1 | 3 min | [A-001](./runbooks/A-001-auth-signin-degradation.md) |
| **A-002** | High platform latency | p95 `/api/auth/info` > 500 ms | P2 | 10 min | — |
| **A-003** | Platform 5xx spike | All routes 5xx > 1% | P1 | 5 min | — |
| **A-004** | TLS expiry | SSL days remaining < 14 | P3 | 1 day | — |

### 4.2 Sign in

| ID | Symptom | Condition | Sev | Runbook |
|----|---------|-----------|-----|---------|
| **A-101** | Cannot sign in | OAuth callback 5xx > 2% | P1 | [A-001](./runbooks/A-001-auth-signin-degradation.md) |
| **A-102** | Slow sign-in | p95 callback > 3 s | P2 | — |
| **A-103** | Session hydration fail | `/api/auth/info` 5xx > 0.5% | P1 | — |
| **A-104** | OAuth state spike | state_mismatch > 10/min | P2 | — |

\* Runbook filenames follow priority implementation set; see §7.4.

### 4.3 Create task

| ID | Symptom | Condition | Sev | Runbook |
|----|---------|-----------|-----|---------|
| **A-201** | Cannot submit task | `POST /api/tasks` 5xx > 2% | P1 | [A-101](./runbooks/A-101-task-creation-failures.md) |
| **A-202** | Slow task accept | p95 POST > 1 s | P2 | — |
| **A-203** | Tasks stuck pending | >20% pending > 60 s | P2 | [A-201](./runbooks/A-201-sandbox-agent-failures.md) |
| **A-204** | Processing error spike | transition to `error` > 30%/h | P2 | [A-201](./runbooks/A-201-sandbox-agent-failures.md) |

### 4.4 List tasks

| ID | Symptom | Condition | Sev | Runbook |
|----|---------|-----------|-----|---------|
| **A-301** | Sidebar empty/error | `GET /api/tasks` 5xx > 1% | P1 | [A-101](./runbooks/A-101-task-creation-failures.md) |

### 4.5 GitHub integration

| ID | Symptom | Condition | Sev | Runbook |
|----|---------|-----------|-----|---------|
| **A-401** | Repo list fail | `/api/github/user-repos` 5xx > 5% | P2 | [A-301](./runbooks/A-301-github-oauth-integration.md) |
| **A-402** | Status check fail | `/api/auth/github/status` 5xx > 1% | P2 | — |
| **A-403** | GitHub upstream | github_api_errors > 10/min | P2 | — |

### 4.6 Dependencies

| ID | Symptom | Condition | Sev | Runbook |
|----|---------|-----------|-----|---------|
| **A-501** | DB / quota degradation | db_errors > 5/min **or** sustained 429 misconfiguration | P1 | [A-501](./runbooks/A-501-rate-limit-quota.md) |
| **A-502** | DB slow | p95 select_tasks > 200 ms | P2 | — |

---

## 5. Dashboards

### 5.1 Overview — "ARES auditor-web Health"

- SLO gauges (availability, p95, OAuth p95, synthetic uptime)
- Request rate by journey; 5xx by route
- Journey success rates (24 h)
- Dependency panels (PostgreSQL p95, GitHub errors, Vercel function duration)

### 5.2 Per component

Auth · Tasks · GitHub · Database · Vercel embed — see observability queries in [observability doc](./observability-auditor-web.md#7-common-queries).

---

## 6. Synthetic checks

Probe config: `apps/auditor-web/monitoring/`

### 6.1 Primary — `auth-info-liveness` (1 min, multi-region)

| Field | Value |
|-------|-------|
| Method | GET |
| URL | `/api/auth/info` |
| Expected | 200 or 401, JSON body, optional `x-correlation-id` |
| Regions | us-east-1, ap-southeast-1 |
| Alert | A-001 |

Do **not** assert authenticated `user` shape — anonymous responses are valid.

### 6.2 Secondary (5 min)

| Probe | Expected |
|-------|----------|
| `GET /` | 200 |
| `GET /api/tasks` (no auth) | 401 |
| `GET /api/auth/github/status` | 200, `{ connected: false }` |
| `GET /api/auth/rate-limit` | 401 |
| `GET /api/auth/signin/github` | 302 → github.com |

### 6.3 Authenticated (15 min, test account)

Pre-seeded session cookie → `/api/auth/info`, `/api/tasks`, `/api/auth/rate-limit`, `/api/github/user-repos`.

---

## 7. On-call (MVP ~50 DAU)

| Role | Coverage |
|------|----------|
| Primary | 24/7 PagerDuty |
| Secondary | Escalation +15 min no-ack |
| Service owner | Business hours SLO review |

**Rotation:** Weekly, handoff Monday 09:00 UTC+7.

### 7.4 Priority runbooks (implemented)

| Priority | ID | Runbook |
|----------|-----|---------|
| 1 | A-001 | [Auth / sign-in degradation](./runbooks/A-001-auth-signin-degradation.md) |
| 2 | A-501 | [Rate limit / quota exhaustion](./runbooks/A-501-rate-limit-quota.md) |
| 3 | A-101 | [Task creation failures](./runbooks/A-101-task-creation-failures.md) |
| 4 | A-201 | [Sandbox / agent failures](./runbooks/A-201-sandbox-agent-failures.md) |
| 5 | A-301 | [GitHub OAuth / integration failures](./runbooks/A-301-github-oauth-integration.md) |

### Escalation matrix

| Layer | When |
|-------|------|
| L1 Primary on-call | All P1/P2 |
| L2 Secondary + owner | P1 > 30 min |
| L3 Vercel Support | Platform-wide function failures |
| L3 GitHub Support | OAuth/API widespread issues |
| L3 Database provider | Pool / replication issues |

---

## Cross-references

- **Observability:** [observability-auditor-web.md](./observability-auditor-web.md) — structured logs, `X-Request-ID` / `x-correlation-id`, sampling
- **Monitoring as code:** [apps/auditor-web/monitoring/README.md](../../apps/auditor-web/monitoring/README.md)
- **Instrumentation:** `apps/auditor-web/lib/observability/`

---

## Self-check

| # | Criterion | Status |
|---|-----------|--------|
| 1 | Four critical journeys mapped to routes | ✅ |
| 2 | Rate limit endpoint covered | ✅ |
| 3 | `/api/auth/info` as primary synthetic | ✅ |
| 4 | SLI/SLO with numeric error budgets | ✅ |
| 5 | Symptom-based alerts with runbook links | ✅ |
| 6 | Sync vs async SLI separation | ✅ |
| 7 | 401/429 handled correctly | ✅ |
| 8 | ~50 DAU scope (no over-engineering) | ✅ |
