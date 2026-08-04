# Runbook A-201 — POST /api/tasks failures

**Alert ID:** A-201  
**Severity:** P1  
**Service:** auditor-web  
**Related:** [Reliability §4.3](../reliability-auditor-web.md)

---

## Symptom

- Users click "Create task" — request fails with 5xx (not 429)
- Sidebar never shows new task after submit
- `POST /api/tasks` 5xx rate > 2%
- Logs: `TASK_CREATE_FAILED` or DB errors on task insert

**Not this alert:** 429 rate limit (expected quota), async sandbox/agent failures after 200 accept.

## Verify

| Check | How |
|-------|-----|
| Metrics | `ares_auditor_web_api_requests_total{route="/api/tasks",method="POST",status_class="5xx"}` |
| Logs | `component=tasks.lifecycle`, `error.code=TASK_CREATE_FAILED` |
| Auth | 401 on POST → session issue ([A-101](./A-101-oauth-callback-fail.md)) |
| Rate limit | 429 → expected quota, not infra failure |
| DB insert | Can insert into `tasks` table? Check [A-501](./A-501-db-down.md) |
| Reproduce | Test account + minimal valid payload |

**Distinguish sync vs async:** POST may return 200 while sandbox fails later — check HTTP status on POST only.

## Mitigate

| Cause | Action |
|-------|--------|
| DB insert failure | Restore DB; run migrations (`pnpm db:migrate`) |
| Schema mismatch | Deploy fix or rollback bad migration |
| Session/auth bug | Fix JWE/session path |
| Validation errors | 400 responses — not this runbook |
| Bad deploy | Roll back Vercel deployment |

## Escalate

| When | Who |
|------|-----|
| DB errors correlated | [A-501](./A-501-db-down.md) path + provider support |
| 30 min unresolved | Secondary + service owner |

## Resolve criteria

- `POST /api/tasks` 5xx < 0.5% for 15 minutes
- Test task creation returns 200 with task object
- No `TASK_CREATE_FAILED` errors in 15-minute window

## Related links

- [Tasks route](../../apps/auditor-web/app/api/tasks/route.ts)
