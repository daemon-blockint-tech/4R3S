# Internal engineering docs

Design and operational documents for ARES platform engineering. **Not user-facing.**

| Document | Scope | Status (2026-08-04) |
|----------|-------|---------------------|
| [reliability-auditor-web.md](./reliability-auditor-web.md) | SLI/SLO, alerts, synthetic checks, on-call | v1 design |
| [observability-auditor-web.md](./observability-auditor-web.md) | Structured logging, correlation, sampling | P0 implemented (uncommitted) |
| [runbooks/](./runbooks/) | Incident response playbooks (A-001 … A-501) | On disk |

## Implementation status

### Observability (OBS-1 / REL-1)

| Item | Status |
|------|--------|
| `middleware.ts` — correlation ID | ✅ Uncommitted |
| `lib/observability/{logger,redaction,context,metrics}.ts` | ✅ Uncommitted |
| `withObservedRoute` on critical routes | ✅ Uncommitted |
| Auth callback + tasks route logger migration | ✅ Partial (P1) |
| Remaining `console.*` in `app/api/` | ⏳ P1 backlog |

### Reliability artifacts

| Item | Status |
|------|--------|
| Runbooks A-001, A-101, A-201, A-301, A-501 | ✅ `docs/internal/runbooks/` |
| Synthetic monitoring config-as-code | ✅ `apps/auditor-web/monitoring/` (Checkly + Better Stack) |
| External deploy of probes | ⏳ Manual — requires `CHECKLY_API_KEY`, `ARES_WEB_MONITOR_URL` |
| OTel / HTTP metrics | ✅ Lightweight log-based metrics in `metrics.ts` (no OTel SDK) |
| Dashboards / PagerDuty wiring | ⏳ Deferred — design only in reliability doc |

### Synthetic probe

Primary probe: **`auth-info-liveness`** — `GET /api/auth/info`, 1 min interval, regions `us-east-1` + `ap-southeast-1`. See [monitoring README](../apps/auditor-web/monitoring/README.md).
