# Runbook A-301 — GET /api/tasks failures

**Alert ID:** A-301  
**Severity:** P1  
**Service:** auditor-web  
**Related:** [Reliability §4.4](../reliability-auditor-web.md)

---

## Symptom

- Task sidebar empty or shows error for authenticated users
- `GET /api/tasks` returns 5xx > 1% (401 for anonymous is expected — graceful empty sidebar)
- Dashboard layout fails to load task list on mount
- Logs: `LIST_TASKS_FAILED` or DB select errors

## Verify

| Check | How |
|-------|-----|
| Metrics | `ares_auditor_web_api_requests_total{route="/api/tasks",method="GET",status_class="5xx"}` |
| Logs | `component=tasks.lifecycle`, `error.code=LIST_TASKS_FAILED` |
| Auth session | Valid session cookie? 401 → auth issue, not list failure |
| DB query | `SELECT` on `tasks` with `userId` filter — slow or failing? |
| Soft delete filter | Query excludes `deletedAt IS NOT NULL` — verify schema intact |

**Manual test (authenticated):**

```bash
curl -sS -H "Cookie: <session>" "$ARES_WEB_MONITOR_URL/api/tasks"
```

## Mitigate

| Cause | Action |
|-------|--------|
| DB unreachable | Follow [A-501](./A-501-db-down.md) |
| Session invalidation bug | Check JWE/session after recent auth deploy |
| Query timeout | Add index on `tasks.userId`; scale DB |
| Bad deploy | Roll back Vercel deployment |

## Escalate

| When | Who |
|------|-----|
| Correlated auth + list failures | [A-101](./A-101-oauth-callback-fail.md) |
| 30 min unresolved | Secondary + service owner |

## Resolve criteria

- `GET /api/tasks` 5xx < 0.5% for 15 minutes (authenticated traffic)
- Test user sees task list in sidebar
- No `LIST_TASKS_FAILED` errors in 15-minute window

## Related links

- [Tasks route GET handler](../../apps/auditor-web/app/api/tasks/route.ts)
