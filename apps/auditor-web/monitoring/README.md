# Synthetic monitoring — auditor-web

Config-as-code for external uptime probes. **Do not commit API keys.** Deploy manually to Checkly or Better Stack when credentials are available.

## Probes

| Name | Interval | Regions | Path |
|------|----------|---------|------|
| `auth-info-liveness` | 1 min | us-east, ap-southeast | `GET /api/auth/info` |

## Required environment variables

| Variable | Used by | Description |
|----------|---------|-------------|
| `CHECKLY_API_KEY` | Checkly CLI / deploy | Account API key ([Checkly dashboard](https://app.checklyhq.com/settings/account/api-keys)) |
| `CHECKLY_ACCOUNT_ID` | Checkly CLI | Account ID |
| `BETTERSTACK_UPTIME_TOKEN` | Better Stack API | Uptime monitor API token (optional) |
| `ARES_WEB_MONITOR_URL` | Both | Production base URL, e.g. `https://auditor.example.com` (no trailing slash) |
| `ARES_WEB_MONITOR_ASSERT_CORRELATION` | Both | Set to `true` to assert `x-correlation-id` response header |

## Expected behavior — `auth-info-liveness`

- **Method:** `GET`
- **URL:** `${ARES_WEB_MONITOR_URL}/api/auth/info`
- **Accept status:** `200` or `401` (anonymous session check)
- **Timeout:** 3000 ms (critical), 1000 ms (warning)
- **Body:** Valid JSON; do not assert `user` shape (anonymous responses omit or null `user`)
- **Headers (optional):** `x-correlation-id` or `x-request-id` present when `ARES_WEB_MONITOR_ASSERT_CORRELATION=true`

## Deploy (manual)

```bash
# Checkly — from apps/auditor-web/monitoring/checkly
export CHECKLY_API_KEY=...
export CHECKLY_ACCOUNT_ID=...
export ARES_WEB_MONITOR_URL=https://your-production-url.vercel.app
npx checkly deploy

# Better Stack — import monitors/betterstack-auth-info-liveness.yaml via dashboard
# or use their API with BETTERSTACK_UPTIME_TOKEN
```

## Alert mapping

Probe failures feed alert **A-001** (see [reliability doc](../../../docs/internal/reliability-auditor-web.md)).

## Related

- [Observability design](../../../docs/internal/observability-auditor-web.md) — correlation headers
- [Runbook A-001](../../../docs/internal/runbooks/A-001-auth-signin-degradation.md)
