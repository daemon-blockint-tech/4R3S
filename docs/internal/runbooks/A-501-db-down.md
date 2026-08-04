# Runbook A-501 — Database errors

**Alert ID:** A-501  
**Severity:** P1  
**Service:** auditor-web  
**Related:** [Reliability §4.6](../reliability-auditor-web.md)

---

## Symptom

- Multiple routes return 500 with database-related failures
- OAuth callback, task create/list, or rate-limit checks fail together
- Logs show `component=db` errors or connection/query timeouts
- Sustained 429 misconfiguration (rate-limit count queries failing → 500 instead of 429)

## Verify

| Check | How |
|-------|-----|
| Error rate | `ares_auditor_web_api_requests_total` with `status_class=5xx` across auth + tasks routes |
| Logs | `jq -c 'select(.component == "db" or .error.code == "DB_ERROR")'` |
| Provider status | Supabase / Neon / Postgres host status page |
| Connection string | `DATABASE_URL` present in Vercel production env |
| Pool limits | Connection pool exhaustion in provider dashboard |
| Migrations | Pending Drizzle migrations (`pnpm db:migrate` in CI or manual) |

**Correlate:** If only rate-limit endpoint fails, check `checkRateLimit()` query errors separately from general DB outage.

## Mitigate

| Cause | Action |
|-------|--------|
| Provider outage | Wait for recovery; communicate status |
| Connection string wrong/rotated | Update `DATABASE_URL`; redeploy |
| Pool exhausted | Scale pooler; reduce connection leaks; restart functions |
| Migration drift | Apply pending migrations; rollback bad migration if needed |
| Query timeout | Identify slow queries; add indexes; temporarily disable non-critical writes |

**Do not** confuse expected user quota 429 with DB failure — 429 with valid JSON is not this alert.

## Escalate

| When | Who |
|------|-----|
| Provider incident | Database provider support |
| Data corruption suspected | Service owner + DBA |
| 30 min unresolved | Secondary on-call |

## Resolve criteria

- DB error log rate = 0 for 15 minutes
- OAuth callback, `POST /api/tasks`, and `GET /api/tasks` succeed for test account
- Rate-limit endpoint returns 200 (not 500)

## Related links

- [DB client](../../apps/auditor-web/lib/db/client.ts)
- [Rate limit util](../../apps/auditor-web/lib/utils/rate-limit.ts)
