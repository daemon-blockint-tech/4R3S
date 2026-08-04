# Runbook A-001 — App unreachable (synthetic down)

**Alert ID:** A-001  
**Severity:** P1  
**Service:** auditor-web  
**Related:** [Reliability §4.1](../reliability-auditor-web.md) · [Monitoring README](../../apps/auditor-web/monitoring/README.md)

---

## Symptom

- External synthetic probe `auth-info-liveness` fails in **2+ regions** for ≥3 minutes
- Users report the app is down or stuck loading
- `GET /api/auth/info` returns non-2xx/401, timeout, or invalid JSON from outside Vercel

## Verify

| Check | How |
|-------|-----|
| Synthetic status | Checkly / Better Stack dashboard — `auth-info-liveness` in us-east + ap-southeast |
| Manual probe | `curl -sS -o /dev/null -w '%{http_code}' "$ARES_WEB_MONITOR_URL/api/auth/info"` — expect 200 or 401 |
| Vercel deployment | Latest deploy status, function errors, edge config |
| Regional blip | Compare single-region failure vs both regions failing |
| Correlation header | Optional: `curl -I` and confirm `x-correlation-id` when middleware is live |

**Log query (Vercel export):**

```bash
jq -c 'select(.http.path == "/api/auth/info" and .level == "error")' logs.jsonl
```

## Mitigate

| Cause | Action |
|-------|--------|
| Bad deploy | Roll back Vercel to last known good deployment |
| DNS / TLS | Verify domain, certificate, and Vercel project settings |
| Platform outage | Check [Vercel status](https://www.vercel-status.com); open support ticket if widespread |
| Env misconfiguration | Restore `JWE_SECRET`, database URL, and auth env vars; redeploy |
| Cold-start storm | Scale plan or reduce concurrent deploys; wait for function warm-up |

**Communicate** if outage exceeds 15 minutes for ~50 DAU MVP.

## Escalate

| When | Who |
|------|-----|
| No ack in 5 min | Secondary on-call |
| Unresolved 30 min | Service owner + Vercel support |
| Auth-specific after platform green | [A-101](./A-101-oauth-callback-fail.md) or [A-501](./A-501-db-down.md) |

## Resolve criteria

- Synthetic green in **all probe regions** for ≥15 minutes
- Manual `GET /api/auth/info` returns 200 or 401 with valid JSON
- No platform-wide 5xx spike on critical routes

## Related links

- [Auth info route](../../apps/auditor-web/app/api/auth/info/route.ts)
- [Middleware](../../apps/auditor-web/middleware.ts)
