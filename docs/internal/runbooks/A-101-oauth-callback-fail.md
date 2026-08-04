# Runbook A-101 — OAuth callback 5xx

**Alert ID:** A-101  
**Severity:** P1  
**Service:** auditor-web  
**Related:** [Reliability §4.2](../reliability-auditor-web.md)

---

## Symptom

- Users complete GitHub OAuth but land on error page or remain logged out
- `GET /api/auth/github/callback` returns 5xx > 2% (not 400 state mismatch)
- Spike in `OAUTH_CALLBACK_FAILED` or `OAUTH_EXCHANGE_FAILED` log codes
- Session hydration (`GET /api/auth/info`) may also fail (A-103)

## Verify

| Check | How |
|-------|-----|
| Metrics | `ares_auditor_web_api_requests_total{route="/api/auth/github/callback",status_class="5xx"}` |
| Logs | `component=auth.github` AND `level=error` |
| Env vars | `NEXT_PUBLIC_GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `JWE_SECRET` in production |
| GitHub status | [githubstatus.com](https://www.githubstatus.com) |
| OAuth app config | Callback URL = `{origin}/api/auth/github/callback` |
| DB writes | Callback inserts/updates `users` and `accounts` — see [A-501](./A-501-db-down.md) if correlated |

**Log query:**

```bash
jq -c 'select(.component == "auth.github") | select(.error.code | test("OAUTH"))' logs.jsonl
```

## Mitigate

| Cause | Action |
|-------|--------|
| Missing/rotated secret | Restore GitHub client secret and `JWE_SECRET`; redeploy |
| GitHub token exchange failure | Retry; check GitHub API status; verify OAuth app not suspended |
| DB failure during user upsert | Follow [A-501](./A-501-db-down.md) |
| Bad deploy regression | Roll back Vercel deployment |
| State cookie issues | Advise users to retry in private window; check cookie domain/TTL |

**Note:** 400 `INVALID_OAUTH_STATE` is user error or expired flow — not this alert.

## Escalate

| When | Who |
|------|-----|
| GitHub OAuth widespread | GitHub support / status comms |
| 30 min unresolved | Secondary + service owner |
| Full app unreachable | [A-001](./A-001-synthetic-down.md) |

## Resolve criteria

- OAuth callback 5xx < 0.5% for 15 minutes
- Manual sign-in test succeeds end-to-end
- `GET /api/auth/info` returns 200 with user object after sign-in

## Related links

- [Callback route](../../apps/auditor-web/app/api/auth/github/callback/route.ts)
- [Sign-in route](../../apps/auditor-web/app/api/auth/signin/github/route.ts)
