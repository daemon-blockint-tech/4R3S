# Internal engineering docs

Design and operational documents for ARES platform engineering. **Not user-facing.**

> **Provenance:** These specs were recovered from agent transcripts and local design sessions (August 2026). They describe target architecture and current codebase baselines; verify against `apps/auditor-web` before treating any section as production truth.
>
> **Repo policy:** Per [docs/README.md](../README.md), full internal specs (PRD, Development Plan, Backlog) are maintained by the team and are **not committed** to this public repo. The files in `docs/internal/` are kept locally for engineering reference until a deliberate publish decision.

---

## Implementation status (2026-08-04)

| Document / artifact | Type | Code / disk status |
|---------------------|------|-------------------|
| [reliability-auditor-web.md](./reliability-auditor-web.md) | Design + REL-1 spec | Metrics/logger **partial** — see observability P0 (on main) |
| [observability-auditor-web.md](./observability-auditor-web.md) | Design + OBS-1 spec | **P0 implemented, landed on main (2026-08-04)** (`middleware.ts`, `lib/observability/*`) |
| [rate-limiting-auditor-web.md](./rate-limiting-auditor-web.md) | Design | **Tier S live** — `checkRateLimit()` on tasks POST/continue; Tier A/B/C design only |
| [infrastructure-platform.md](./infrastructure-platform.md) | Design | No provisioning; Vercel + Supabase as deployed target |
| [caching-auditor-web.md](./caching-auditor-web.md) | Design | React `cache()` + client fetch only; no Redis |
| [auth-auditor-web.md](./auth-auditor-web.md) | Design | OAuth JWE live; Supabase Auth optional |
| [backend-auditor-web.md](./backend-auditor-web.md) | Design | API routes live; aligns with monolith |
| [frontend-auditor-web.md](./frontend-auditor-web.md) | Design | App Router + polling baselines documented |
| [database-auditor-web.md](./database-auditor-web.md) | Design | Drizzle + Postgres live |
| [security-auditor-web.md](./security-auditor-web.md) | Design | AGENTS.md logging rules enforced in review |
| [performance-auditor-web.md](./performance-auditor-web.md) | Design | Targets only |
| [test-auditor-web.md](./test-auditor-web.md) | Design | Minimal automated API tests today |
| [cdn-delivery-auditor-web.md](./cdn-delivery-auditor-web.md) | Design | Vercel Edge default |
| [platform-cicd.md](./platform-cicd.md) | Design | CI live; deploy workflow proposed |
| [runbooks/](./runbooks/) | Ops playbooks | **5 runbooks on main** (A-001, A-101, A-201, A-301, A-501) |
| [apps/auditor-web/monitoring/](../../apps/auditor-web/monitoring/) | Synthetic probe config | **Checkly + Better Stack YAML on disk** — deploy manual; keys not committed |

### Remaining backlog

- **OBS-1 P1:** migrate remaining `app/api/` routes off `console.*` (see observability doc).
- **REL-1:** `withObservedRoute()` wiring on critical routes — bundled with OBS-1 changeset.
- **`docs/internal/`** — entire directory untracked in git at time of writing.

---

## Document index

| Document | Scope |
|----------|-------|
| [reliability-auditor-web.md](./reliability-auditor-web.md) | SLI/SLO, alerts, synthetic checks, on-call |
| [observability-auditor-web.md](./observability-auditor-web.md) | Structured logging, correlation, sampling |
| [rate-limiting-auditor-web.md](./rate-limiting-auditor-web.md) | Daily quota, tier design, Vercel multi-instance |
| [infrastructure-platform.md](./infrastructure-platform.md) | Vercel, Supabase, capacity, DR |
| [caching-auditor-web.md](./caching-auditor-web.md) | RSC cache, client fetch, no Redis MVP |
| [auth-auditor-web.md](./auth-auditor-web.md) | OAuth, JWE session, Supabase optional |
| [backend-auditor-web.md](./backend-auditor-web.md) | API surface, task agent pipeline |
| [frontend-auditor-web.md](./frontend-auditor-web.md) | App Router, polling, UI patterns |
| [database-auditor-web.md](./database-auditor-web.md) | Drizzle schema, migrations |
| [security-auditor-web.md](./security-auditor-web.md) | Secrets, logging, auth boundaries |
| [performance-auditor-web.md](./performance-auditor-web.md) | Latency targets, hot paths |
| [test-auditor-web.md](./test-auditor-web.md) | Test strategy |
| [cdn-delivery-auditor-web.md](./cdn-delivery-auditor-web.md) | Static assets, Edge |
| [platform-cicd.md](./platform-cicd.md) | CI/CD, deploy pipeline |
| [runbooks/](./runbooks/) | Incident response playbooks |

---

## Cross-cutting topics

| Topic | Primary doc | Also see |
|-------|-------------|----------|
| Vercel serverless multi-instance (no shared in-memory state) | [infrastructure §4.1.1](./infrastructure-platform.md#411-vercel-serverless-vs-asumsi-single-instance-mvp) | [rate-limiting § Vercel serverless](./rate-limiting-auditor-web.md#vercel-serverless-vs-single-instance-mvp), [caching §4.1.1](./caching-auditor-web.md) |
| Daily message quota (2 units per task create) | [rate-limiting § Tier S](./rate-limiting-auditor-web.md#tier-s--critical--quota-harian-biaya-dominan) | [reliability §1.2](./reliability-auditor-web.md#12-create-task) |
| Correlation IDs + REL-1 metrics | [observability](./observability-auditor-web.md) | [reliability §3](./reliability-auditor-web.md#3-metrics) |
| UI polling baselines | [rate-limiting baseline](./rate-limiting-auditor-web.md#konteks--baseline-implementasi) | `app-layout.tsx` 5s, `session-provider.tsx` 60s |
