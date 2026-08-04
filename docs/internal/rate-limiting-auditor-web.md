# Dokumen Desain Rate Limiting — ARES Auditor Web

**Scope:** `apps/auditor-web` (Next.js App Router monolith, Drizzle + Postgres, **low-traffic MVP, no Redis**)  
**Audience:** Backend Engineer  
**Status:** Desain target — **bukan** spesifikasi implementasi penuh  
**Versi:** 2026-08-04 (v1.1 — review follow-up 6ee9c4bf: double-count, settings hierarchy, serverless nuance)  
**Related docs:** [infrastructure-platform.md](./infrastructure-platform.md) · [reliability-auditor-web.md](./reliability-auditor-web.md) · [observability-auditor-web.md](./observability-auditor-web.md)

---

## Konteks & Baseline Implementasi

### Yang sudah ada hari ini

| Komponen | Lokasi | Perilaku |
|----------|--------|----------|
| `checkRateLimit(userId)` | `lib/utils/rate-limit.ts` | Hitung kuota **harian** dari Postgres: **`taskMessages` role=`user` hanya** (Opsi B — fixed). **Implementasi saat ini:** `SELECT` rows lalu `.length` — **bukan** `COUNT(*)` (performance debt; lihat §5) |
| Batas default | `lib/constants.ts` → `MAX_MESSAGES_PER_DAY` | **5** (override via `MAX_MESSAGES_PER_DAY` env atau `settings.maxMessagesPerDay` per user) |
| Hierarchy batas | `lib/db/settings.ts` → `getMaxMessagesPerDay` | **`settings.maxMessagesPerDay` (per-user, `userId` NOT NULL) → env `MAX_MESSAGES_PER_DAY`**. Tidak ada tier global di DB — komentar lama "user > global > env" **salah** |
| Endpoint terproteksi | `POST /api/tasks`, `POST /api/tasks/[taskId]/continue` | Return **429** + JSON `{ error, message, remaining, total, resetAt }` |
| Endpoint baca kuota | `GET /api/auth/rate-limit` | Return `{ allowed, remaining, used, total, resetAt }` |
| UI | `components/auth/sign-out.tsx` | Dropdown avatar: `{remaining}/{total} messages remaining today` |

### Yang belum ada

- Tidak ada rate-limit middleware — kuota harian tetap ad hoc per route (`checkRateLimit` inline). **OBS-1 P0** menambahkan `middleware.ts` untuk **correlation ID saja** (bukan pembatasan); file ada secara lokal, **landed on main (2026-08-04)** — lihat [observability-auditor-web.md](./observability-auditor-web.md)
- Tidak ada header standar `X-RateLimit-*` / `Retry-After`
- Tidak ada rate limit per IP, per route, atau burst protection
- Auth routes (`/api/auth/signin/*`, `/api/auth/github/callback`), GitHub proxy, sandbox ops, polling reads — **tidak dibatasi**
- Plan/billing (`lib/mock/usage.ts`) masih mock — tier hanya via `settings` table per user

### Arsitektur MVP

```
[Browser] → [Next.js serverless (N instances)] → [Postgres — shared SoT Tier S]
                ↓
         [Vercel Sandbox / GitHub API / LLM]
```

- ~**50 DAU**, **low-traffic MVP, no Redis**
- **Tier S (kuota harian):** Postgres — **shared** across all Vercel serverless instances; correct source of truth
- **Tier A/B/C (burst/sliding/token bucket, planned):** in-memory `Map` — **per serverless instance**, not shared; deploy/cold-start resets counters; **acceptable at ~50 DAU / low abuse** (known limitation) — monitor 429 bypass via instance fan-out; scale to Redis/Upstash when bypass observable (see § Vercel serverless, §5)
- Polling aktif (verified in code):
  - **Task list:** `components/app-layout.tsx` — **5s** (`setInterval(fetchTasks, 5000)`)
  - **Session + GitHub connection:** `components/auth/session-provider.tsx` — **60s** (`setInterval(fetchAll, 60000)`)
  - Task detail page: messages **3s** (`task-chat.tsx`), sandbox-health **2s** (`task-details.tsx`), task hook **5s** (`use-task.ts`)

---

## Vercel serverless vs "single instance MVP"

> **No Redis MVP** remains correct. Legacy wording "single instance" implied one long-lived Node process with a shared in-memory `Map`. On Vercel, each deployment runs **multiple concurrent serverless function instances** — counters in process memory are **not shared**.

| Assumption (legacy wording) | Reality on Vercel |
|----------------------------|-------------------|
| "Single instance MVP" | Multiple concurrent serverless instances per deployment; no shared process memory |
| In-memory rate-limit Map (Tier A/B/C) | Per-instance only; effective limit ≈ `limit × concurrent_instances` under burst |
| Postgres daily quota (Tier S) | Shared — correct source of truth |
| Deploy counter reset | Still true per instance; cold starts spawn fresh Maps |

**MVP implications:**

- **Tier S (Postgres row count)** — safe cross-instance
- **Tier A/B/C in-memory** — **acceptable at ~50 DAU / low abuse** but document as known limitation; monitor 429 bypass via instance fan-out
- **Scale path unchanged:** Redis/Upstash when 429 abuse or >200 DAU **OR** when multi-instance bypass becomes observable

Platform context (compute autoscale, pooler): [infrastructure-platform.md §4.1.1](./infrastructure-platform.md#411-vercel-serverless-vs-asumsi-single-instance-mvp).

---

## 1. Titik yang Dibatasi (by cost tier)

Endpoint dikelompokkan menurut **biaya marginal** (compute, sandbox vCPU, token LLM, quota GitHub API), bukan semua route diperlakukan sama.

### Tier S — Critical / Quota Harian (biaya dominan)

Operasi yang memicu **sandbox + agent LLM**. Satu request ≈ menit–jam compute + ratusan token.

| Endpoint | Method | Proteksi saat ini | Proteksi target |
|----------|--------|-------------------|-----------------|
| `/api/tasks` | POST | ✅ Kuota harian | Kuota harian + burst hourly |
| `/api/tasks/[taskId]/continue` | POST | ✅ Kuota harian | Kuota harian + burst hourly |

**Catatan semantik kuota (fixed — Opsi B):**

`checkRateLimit` menghitung **hanya** `taskMessages` role=`user` (bukan `tasks`). Satu `POST /api/tasks` sukses = **1 unit** (initial user message). Satu `POST .../continue` = **1 unit** (user follow-up message).

Rate check berjalan **pre-insert** (`app/api/tasks/route.ts` sebelum insert task/message). Off-by-one acceptable: check pakai count existing; insert menambah +1 setelah lolos.

| Messages existing (UTC today) | Rate check | Setelah POST /api/tasks sukses |
|--------------------------------|------------|----------------------------------|
| 0 | allowed (0 < 5) | 1 message |
| 4 | allowed (4 < 5) | 5 messages |
| 5 | **blocked** (5 ≮ 5) | — |

Default limit **5** = hingga **5 user messages/hari** (mix task create + continue).

### Tier A — Expensive (tanpa LLM penuh, tetap mahal)

| Endpoint | Method | Biaya | Proteksi target |
|----------|--------|-------|-----------------|
| `/api/tasks/[taskId]/start-sandbox` | POST | Spin-up Vercel sandbox | Per-user sliding window |
| `/api/tasks/[taskId]/restart-dev` | POST | Command di sandbox | Per-user sliding window |
| `/api/tasks/[taskId]/stop-sandbox` | POST | Shutdown API | Per-user sliding window |
| `/api/auth/signin/github`, `/signin/vercel` | GET | OAuth redirect, state cookie | Per-IP sliding window |
| `/api/auth/github/callback`, `/callback/vercel` | GET | Token exchange + DB writes | Per-IP + per-user |
| `/api/github/repos/create` | POST | GitHub mutation | Per-user sliding window |

### Tier B — Moderate (proxy eksternal / I/O sandbox)

| Endpoint pattern | Biaya | Proteksi target |
|------------------|-------|-----------------|
| `/api/github/*`, `/api/repos/[owner]/[repo]/*` | GitHub REST quota | Per-user token bucket |
| `/api/tasks/[taskId]/file-*`, `/save-file`, `/terminal`, `/lsp`, `/autocomplete` | Sandbox I/O | Per-user token bucket |
| `/api/tasks/[taskId]/pr`, `/merge-pr`, `/sync-pr`, `/sync-changes` | GitHub + git | Per-user token bucket |
| `/api/api-keys` | POST/DELETE | Per-user strict window |

### Tier C — Read / Cheap (DB SELECT, polling UI)

| Endpoint pattern | Pola traffic | Proteksi target |
|------------------|--------------|-----------------|
| `GET /api/tasks`, `GET /api/tasks/[id]` | Poll 5s saat task aktif | Per-user token bucket (long) |
| `GET /api/tasks/[id]/messages` | Poll 3s | Per-user token bucket |
| `GET /api/tasks/[id]/sandbox-health` | Poll 2s | Per-user token bucket |
| `GET /api/auth/rate-limit` | On dropdown open | Per-user fixed (generous) |
| `GET /api/sandboxes` | Dialog sandboxes | Per-user fixed |
| `GET /api/auth/info`, `/api/github/user` | Session bootstrap | Per-user fixed |

### Tier D — Exempt (tidak di-rate-limit normal)

| Endpoint | Alasan |
|----------|--------|
| `GET /api/auth/signout` | Idempotent, harus selalu可用 |
| Static assets / `_next/*` | Diluar scope API |
| Health check (jika ditambah) | Monitoring |

---

## 2. Kunci Pembatasan

Format kunci konsisten: `{namespace}:{dimension}:{identifier}:{window}`

| Tier | Primary key | Secondary key (abuse) | Window |
|------|-------------|----------------------|--------|
| S — message quota | `rl:msg:user:{userId}:day:{YYYY-MM-DD}` | — | Kalender UTC (fixed) |
| S — burst agent | `rl:msg_burst:user:{userId}` | — | 10 menit sliding |
| A — sandbox ops | `rl:sandbox:user:{userId}` | `rl:sandbox:ip:{ip}` | 1 jam sliding |
| A — OAuth | `rl:oauth:ip:{ip}` | `rl:oauth:user:{userId}` | 15 menit sliding |
| B — GitHub proxy | `rl:gh:user:{userId}` | `rl:gh:ip:{ip}` | 1 jam sliding |
| B — sandbox I/O | `rl:sbx_io:user:{userId}:task:{taskId}` | — | 1 menit token bucket |
| C — read/poll | `rl:read:user:{userId}` | `rl:read:ip:{ip}` | 1 menit token bucket |

**Identifier resolution (prioritas):**

1. **Authenticated:** `session.user.id` dari `getServerSession()`
2. **Unauthenticated (OAuth start):** `X-Forwarded-For` first hop / `req.ip` (Vercel)
3. **Fallback anonymous:** IP + route fingerprint

**Plan override:** Jika `settings.key = 'maxMessagesPerDay'` ada untuk user (`settings.userId` NOT NULL — tidak ada baris global), itu menggantikan env default (sudah diimplementasi via `getMaxMessagesPerDay`).

**Hierarchy resolusi batas harian:**

```
settings.maxMessagesPerDay (per userId)
  → MAX_MESSAGES_PER_DAY env (lib/constants.ts, default 5)
```

Tidak ada tier "global" di tabel `settings` — schema `user_id NOT NULL` (`lib/db/schema.ts` L396–398).

---

## 3. Algoritma (token bucket vs sliding window — justify)

### Rekomendasi per tier

| Tier | Algoritma | Justifikasi |
|------|-----------|-------------|
| **S — kuota harian** | **Fixed window counter** (kalender UTC) | Reset prediktif (`resetAt` midnight UTC); counter implicit via row SELECT + `.length` di Postgres (bukan `COUNT(*)`); UX dropdown sudah menampilkan “remaining today” |
| **S — burst hourly** | **Sliding window log** (MVP: counter 10-min sub-window) | Cegah user menghabiskan 5/5 quota dalam 30 detik → 5 sandbox parallel |
| **A — OAuth / sandbox** | **Sliding window** | Serangan brute-force/state replay dan sandbox abuse tidak boleh exploit boundary menit |
| **B — GitHub proxy** | **Token bucket** | UI burst saat browse repo lalu idle; refill gradual menjaga GitHub secondary rate limit |
| **C — polling reads** | **Token bucket** | UI poll burst (mount task page = 3–5 request paralel) lalu steady 12–20 req/min; bucket menampung burst tanpa reject mount |

### Mengapa bukan satu algoritma untuk semua?

- **Fixed window** murah dan natural untuk **billing/quota harian**, tapi rentan “double spend” di boundary (00:00 UTC) — acceptable untuk MVP 50 DAU
- **Sliding window** lebih adil untuk **security** (OAuth) dan **abuse** (rapid sandbox restart)
- **Token bucket** optimal untuk **traffic UI bursty** (polling) tanpa hard reject pada spike legitimate

### Kapasitas vs polling existing

Target **0.05 QPS agregat puncak** ≈ **3 req/detik total** ≈ **180 req/jam** (semua tier).

Dengan polling saat ini (satu user di task page ≈ 0.4–0.7 QPS reads saja), **0.05 QPS tidak achievable tanpa mengubah polling atau menambah instance**. Desain ini:

1. Memisahkan **budget Tier S/A** (writes mahal) dari **Tier C** (reads)
2. Menetapkan Tier C cukup longgar untuk 1–2 concurrent task viewer
3. Mencatat **debt teknis**: naikkan interval poll (5s→10s) atau SSE/WebSocket saat traffic > MVP

---

## 4. Angka Batas (derived from capacity)

### Asumsi kapasitas

| Parameter | Nilai | Herutan |
|-----------|-------|---------|
| DAU | 50 | Given |
| Peak concurrent users | 5 (10% DAU) | Pola SaaS B2B dev tool |
| Peak aggregate QPS | 0.05 | Given → 180 req/jam puncak |
| Per-user share at peak | 180 ÷ 5 = **36 req/jam** ≈ **0.6 req/min** | Mean; bucket allow burst |
| Active agent runs/day (typical) | 50 × 1.2 ≈ **60** | ~60% DAU × 2 msg avg |
| Active agent runs/day (worst) | 50 × 5 = **250** | Semua user max quota (5 user messages/day) |

### Tier S — Message quota (per user / hari)

| Plan | `maxMessagesPerDay` | Derivation |
|------|---------------------|------------|
| **Free (default, current)** | **5** | Env default `5`; 5 user messages/day (creates + continues) |
| **Pro (future, via settings)** | **15** | 3× free; per-user row in `settings` |
| **Team (future)** | **50** | Shared pool per org (future); per-user cap individual |

**Burst supplement (baru, per user):**

| Limit | Nilai | Derivation |
|-------|-------|------------|
| Max agent POST | **2 / 10 menit** | Mencegah >2 sandbox parallel dari satu user; 2 × 5 concurrent users = 10 sandboxes peak << Vercel project limit |

### Tier A — Expensive (per user unless noted)

| Endpoint class | Limit | Window | Derivation |
|----------------|-------|--------|------------|
| Sandbox start/restart | **6** | 1 jam | ≤1 restart/10 min during 60-min task; 6 headroom |
| OAuth sign-in start | **10** | 15 min / **IP** | Legitimate retry ≪ 3; 10 tolerates mis-clicks |
| OAuth callback | **5** | 15 min / **IP** | Token exchange failures rare |
| `repos/create` | **3** | 1 jam | Repo creation infrequent at 50 DAU |

### Tier B — Moderate (per user)

| Endpoint class | Limit | Refill / window | Derivation |
|----------------|-------|-----------------|------------|
| GitHub proxy aggregate | **40** | 1 jam sliding | ~8 repo browse sessions × 5 calls; below GitHub 5000/hr but protects our proxy |
| Sandbox file/terminal/LSP | **120** | 1 jam | ~2/min during 60-min edit session |
| Autocomplete | **30** | 1 min token bucket | ~1 keystroke burst per 2s × 30 = 1 min typing session |
| API keys mutate | **5** | 1 jam | Security-sensitive |

### Tier C — Read (per user)

| Endpoint class | Bucket capacity | Refill rate | Derivation |
|----------------|-----------------|-------------|------------|
| Task + messages poll | **burst 15**, steady **10/min** | 10 token/min | Supports mount burst; steady ≈ poll 6s equivalent |
| sandbox-health poll | **burst 10**, steady **20/min** | 20 token/min | 2s poll = 30/min ideal; 20/min = 33% headroom reduction vs today |
| `GET /api/auth/rate-limit` | **30** | 1 jam | Dropdown open + refresh; cheap |
| Other GET reads | **60** | 1 jam | List tasks, sandboxes dialog |

**Aggregate check:** 2 concurrent task viewers × 10 req/min (post-optimization) = 20 req/min ≈ **0.33 QPS reads** — masih di atas 0.05 QPS total budget, valid hanya jika **≤1 concurrent heavy viewer** atau polling diperlambat. Monitor `429` Tier C untuk trigger SSE migration.

### Ringkasan tabel limit MVP

| Tier | Scope | Limit | Algorithm | Storage MVP |
|------|-------|-------|-----------|-------------|
| S | user/day | 5 msg (free) | Fixed window | Postgres SELECT rows (existing) |
| S | user/10min | 2 agent POST | Sliding | Postgres or memory |
| A | user/hour | 6 sandbox ops | Sliding | In-memory Map |
| A | IP/15min | 10 OAuth start | Sliding | In-memory Map |
| B | user/hour | 40 GitHub | Sliding | In-memory Map |
| B | user/min | 30 autocomplete | Token bucket | In-memory Map |
| C | user/min | 10 task reads | Token bucket | In-memory Map |

---

## 5. Penyimpanan Penghitung (Postgres vs Redis vs in-memory)

### Performance debt — Tier S query shape

`checkRateLimit` (`lib/utils/rate-limit.ts`) menjalankan satu query **`SELECT *`** (joined `taskMessages` + `tasks`) dan menghitung via **`.length`**, bukan `COUNT(*)`. Pada user dengan banyak message historis hari itu, ini membawa lebih banyak row ke app layer daripada agregasi DB. **Planned:** ganti ke `COUNT(*)` atau materialized daily counter; alert jika `rate_limit.check_duration_ms` p95 > 200ms.

### MVP (low-traffic, no Redis) — **recommended now**

| Counter type | Storage | Alasan |
|--------------|---------|--------|
| Daily message quota | **Postgres** (existing) | Source of truth **shared** across serverless instances; audit trail natural; SELECT+length acceptable at 50 DAU (~2 queries × 50 checks/day) |
| Plan override | **Postgres `settings`** (existing) | Per-user only (`userId` NOT NULL); sudah wired |
| Burst / sliding / token bucket | **In-memory `Map`** per serverless instance | Low-traffic MVP; zero infra; TTL via lazy eviction; **not shared** — see § Vercel serverless |
| Abuse IP counters | **In-memory** per instance | Same; reset on deploy/cold start acceptable at ~50 DAU |

**Trade-off MVP:** Deploy/restart/cold start **reset** in-memory counters per instance → briefly more permissive; under burst, effective Tier A/B/C limit ≈ `configured_limit × concurrent_instances` (acceptable at ~50 DAU / low abuse — monitor instance fan-out).

### Scale path (>200 DAU or observable bypass)

| Phase | Trigger | Migration |
|-------|---------|-----------|
| **P1** | 429 abuse, >200 DAU, **or multi-instance bypass observable** | **Redis/Upstash** untuk Tier A/B/C counters; keep Postgres for Tier S daily quota |
| **P2** | Billing live | Postgres `usage_events` table + Redis hot counters; nightly reconcile |
| **P3** | >1000 DAU | Dedicated rate-limit service or API gateway (Cloudflare/Vercel WAF) for IP tier |

**Postgres-only alternative (no Redis):** Table `rate_limit_buckets(user_id, key, window_start, count)` dengan UPSERT — viable sampai ~500 DAU jika indexed `(user_id, key, window_start)`.

---

## 6. Semantik Response (429, Retry-After, X-RateLimit-* headers)

### Status codes

| Kondisi | HTTP | Body |
|---------|------|------|
| Kuota harian habis (Tier S) | **429** | Existing shape + headers (backward compatible). **Planned:** tambah `"code": "DAILY_MESSAGE_QUOTA"` — **belum** di response produksi (`tasks/route.ts`, `continue/route.ts`) |
| Burst/window exceeded (A/B/C) | **429** | `{ error: 'Rate limit exceeded', code: 'RATE_LIMIT_<TIER>', retryAfter: <seconds>, ... }` |
| Unauthenticated | **401** | Unchanged |
| Invalid input | **400** | Unchanged |

### Header standar (tambahan pada response 429 **dan** success untuk Tier S/B/C)

```
HTTP/1.1 429 Too Many Requests
Retry-After: 847
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1725148800
X-RateLimit-Policy: daily;w=86400
```

| Header | Tier S (daily) | Tier A/B/C (window/bucket) |
|--------|----------------|----------------------------|
| `X-RateLimit-Limit` | `total` (5) | Window max atau bucket capacity |
| `X-RateLimit-Remaining` | `remaining` | Tokens/window slots left |
| `X-RateLimit-Reset` | Unix epoch midnight UTC | Epoch when window resets or bucket full |
| `Retry-After` | Seconds until UTC midnight | Seconds until next token/window slot |
| `X-RateLimit-Policy` | `daily;w=86400` | e.g. `sliding;w=600`, `token;r=10;t=60` |

### JSON body (Tier S — align dengan existing + extend)

**Saat ini (produksi):** `{ error, message, remaining, total, resetAt }` — **tanpa** field `code`.

**Target (planned):**

```json
{
  "error": "Rate limit exceeded",
  "code": "DAILY_MESSAGE_QUOTA",
  "message": "You have reached the daily limit of 5 messages (tasks + follow-ups). Your limit will reset at 2026-08-05T00:00:00.000Z",
  "remaining": 0,
  "total": 5,
  "resetAt": "2026-08-05T00:00:00.000Z"
}
```

### `GET /api/auth/rate-limit`

Tetap return JSON body; **tambahkan** headers `X-RateLimit-*` pada response 200 agar UI bisa unify parser.

---

## 7. Pengecualian

| Kategori | Handling |
|----------|----------|
| **Internal/admin users** | Override via `settings.maxMessagesPerDay` = high value; future: `settings.rateLimitExempt = true` |
| **Health checks** | Whitelist path `/api/health` (future) — no limit |
| **Successful reads after 429** | Client should honor `Retry-After`; no penalty |
| **OAuth state mismatch** | Return 400 (not 429) — security, not quota |
| **Task ownership** | 403 before rate check (avoid leaking quota state) |
| **Soft-deleted tasks** | Excluded from count (existing `isNull(tasks.deletedAt)`) |
| **Agent messages (role=agent)** | Not counted toward user quota |
| **Idempotent retries** | Future: idempotency key on `POST /api/tasks` — same key within 24h tidak double-count |
| **Deploy / cold-start counter reset** | In-memory limits briefly relaxed per instance — monitor post-deploy spike and 429 bypass via instance fan-out |
| **Shared IP (corp NAT)** | OAuth limits per-IP more generous (10/15min); escalate to CAPTCHA only if abuse detected |

---

## 8. Pemantauan

### Metrics (minimal MVP)

| Metric | Type | Alert threshold |
|--------|------|-----------------|
| `rate_limit.rejected_total{tier, route}` | Counter | >10/hour Tier S; >50/hour Tier C |
| `rate_limit.check_duration_ms` | Histogram | p95 >200ms (Postgres SELECT+length slow) |
| `rate_limit.remaining_ratio{tier}` | Gauge | p50 remaining <20% before UTC midnight (quota pressure) |
| `api.requests_total{route, status}` | Counter | 429 rate >5% any route |
| `sandbox.starts_total{user}` | Counter | >3/user/hour |

### Logging (comply AGENTS.md)

- Log **static string** only: `'Rate limit exceeded'` — **bukan** userId/IP in user-facing logs (see [observability-auditor-web.md](./observability-auditor-web.md) §7.9)
- Server-side structured log (not UI): `{ tier, route, limit_type }` without PII — `tasks/route.ts` L65–72 uses `logger.warn('Rate limit exceeded', { userIdHash, remaining, total })`

### Reliability cross-ref

429 quota exhaustion is **expected user-facing behavior**, not an SLO violation — see [reliability-auditor-web.md](./reliability-auditor-web.md) §1.2 ("bukan infra failure") and non-alert note §351. Monitor `rate_limited_total` on dashboards, not pages, unless misconfiguration suspected.

### Dashboards

1. **Quota pressure:** % users at 0 remaining before reset  
2. **429 heatmap:** by route + tier  
3. **Capacity:** aggregate QPS vs 0.05 target  
4. **Post-deploy:** counter reset anomaly detection  

### Runbook triggers

| Signal | Action |
|--------|--------|
| Tier C 429 >5% | Increase poll interval in UI; plan SSE |
| Tier S 429 >20% users | Review if `MAX_MESSAGES_PER_DAY=5` too tight for growth |
| Postgres SELECT slow | Materialized daily counter column, `COUNT(*)`, or Redis cache |
| Multi-instance bypass (429 bypass via fan-out) | Migrate Tier A/B/C to Redis/Upstash; keep Postgres Tier S |

---

## Roadmap Implementasi (high-level, bukan kode)

1. **Extract** `checkRateLimit` → unified `RateLimiter` interface (quota + window + bucket strategies)
2. **Add** response helper `withRateLimitHeaders(res, meta)`
3. **Wrap** Tier A/B/C routes via shared middleware helper (route-level config map)
4. **Extend** `GET /api/auth/rate-limit` → multi-tier summary (optional Phase 2)
5. **Wire** usage page mock → real counters when billing lands

---

## Self-Check Checklist

- [x] Baseline existing (`checkRateLimit`, 5/day, Postgres row SELECT + length, 429 on tasks/continue) documented accurately
- [x] **Opsi B (fixed):** 1 POST /api/tasks = 1 quota unit (user message only); pre-insert check documented
- [x] Settings hierarchy: per-user `settings` → env (no global DB tier)
- [x] Vercel multi-instance: Postgres Tier S shared; in-memory A/B/C per instance
- [x] Polling: `app-layout.tsx` 5s, `session-provider.tsx` 60s
- [x] Planned `code: DAILY_MESSAGE_QUOTA` on 429 noted (not yet in production)
- [x] `GET /api/auth/rate-limit` + sign-out dropdown `{remaining}/{total}` referenced
- [x] Endpoint expensive (sandbox, OAuth, GitHub) mapped — currently unprotected
- [x] Limits derived from 50 DAU + 0.05 QPS (180 req/hour aggregate, 5 concurrent, 36 req/hour/user mean) — not round arbitrary numbers
- [x] Default **5 msg/day** matches `MAX_MESSAGES_PER_DAY` env default
- [x] Algorithm justified per tier (fixed / sliding / token bucket)
- [x] MVP storage: Postgres quota (cross-instance) + in-memory burst (per serverless instance); Redis scale path defined
- [x] Vercel multi-instance nuance documented (§ Vercel serverless); cross-linked to infrastructure-platform.md
- [x] 429 + `Retry-After` + `X-RateLimit-*` semantics specified
- [x] Exemptions and monitoring included
- [x] Polling vs 0.05 QPS tension documented honestly
- [x] No full implementation code — design only
- [x] Bahasa Indonesia, istilah teknis English OK

[REDACTED]