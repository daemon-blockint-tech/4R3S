# Desain Caching — ARES auditor-web

**Scope:** `apps/auditor-web`  
**Versi:** MVP (tanpa Redis)  
**Target arsitektur:** eventual consistency usage ≤60s, p95 API <300ms, ~0.05 QPS  
**Tanggal:** 2026-08-04  
**Related:** [infrastructure-platform.md §4.1.1](./infrastructure-platform.md#411-vercel-serverless-vs-asumsi-single-instance-mvp) (in-process cache per serverless instance) · [rate-limiting-auditor-web.md](./rate-limiting-auditor-web.md)

---

## Konteks & State Saat Ini

auditor-web adalah Next.js App Router dengan pola **RSC shell + Client Component interaktif**:

| Lapisan | Pola | Contoh |
|---------|------|--------|
| RSC (`app/*/page.tsx`) | `getServerSession()`, `getGitHubStars()`, `getMaxSandboxDuration()` | `app/page.tsx`, `app/tasks/[taskId]/page.tsx` |
| API Route (`app/api/**`) | Auth via session cookie, query Postgres langsung | `GET /api/tasks`, `GET /api/tasks/[taskId]` |
| Client | `fetch()` ke API, state React/Jotai, localStorage | `AppLayout.fetchTasks()`, `repo-selector.tsx` |

**Caching yang sudah ada:**

```6:10:apps/auditor-web/lib/session/get-server-session.ts
export const getServerSession = cache(async () => {
  const store = await cookies()
  const cookieValue = store.get(SESSION_COOKIE_NAME)?.value
  return getSessionFromCookie(cookieValue)
})
```

- `React.cache()` — deduplikasi **per-request**, bukan cache antar-user/antar-request.
- GitHub stars — `fetch(..., { next: { revalidate: 300 } })` (5 menit, global).
- GitHub owners/repos — `atomWithStorage` → **localStorage** tanpa `userId` di key.
- Task files — `Cache-Control: no-store`.
- Deployment preview — kolom `tasks.previewUrl` di Postgres (write-through app cache).
- Vercel OAuth — `cache: 'no-store'`.
- Usage — mock statis (`MOCK_USAGE_DATA`), belum ada cache layer.

**Kesimpulan jujur:** pada ~0.05 QPS (~4.300 req/hari), sebagian besar caching **opsional**. Yang wajib adalah **isolasi auth** dan **key scoping per user**; optimasi performa minimal sudah cukup.

---

## 1. Kandidat (read freq, recompute cost, change freq)

| Data | Read Freq | Recompute Cost | Change Freq | Rekomendasi Cache |
|------|-----------|----------------|-------------|-------------------|
| **Session / auth** | Setiap request | Rendah (JWE decode) | Rendah (login/logout) | ❌ Jangan cache shared; `React.cache()` per-request saja |
| **Task list** (`GET /api/tasks`) | Tinggi (sidebar mount + refresh) | Rendah (1 query indexed `userId`) | Tinggi (status/progress real-time) | ⚠️ Client stale-while-revalidate opsional; server cache minimal |
| **Task detail** | Sedang | Rendah | Tinggi | ❌ No-store; polling client |
| **Task files / diff** | Sedang–tinggi saat browsing | Tinggi (sandbox I/O) | Sangat tinggi | ❌ Sudah `no-store`; in-memory client ref saat ini |
| **GitHub stars** (footer) | Setiap page load RSC | Rendah (1 GitHub API call) | Sangat rendah | ✅ Data Cache 5 menit (sudah ada) |
| **GitHub owners/repos** | Sedang (form task) | Sedang (2–3 GitHub API calls) | Rendah–sedang | ⚠️ localStorage hari ini; perlu user-scoped key + TTL |
| **Usage / billing** | Rendah | Rendah–sedang (aggregate billing) | Rendah (menit–jam) | ✅ In-memory 60s per `userId` (future) |
| **Rate limit count** | Setiap POST task/message | Sedang (2 COUNT queries) | Tinggi | ❌ Jangan cache; harus akurat |
| **User settings** (`maxSandboxDuration`) | Setiap task create | Rendah (1 query) | Rendah | ⚠️ Optional per-request memo via `React.cache()` keyed by userId |
| **Deployment preview URL** | Sedang | Tinggi (GitHub API) | Rendah setelah set | ✅ DB column `previewUrl` (sudah ada) |
| **Repo commits/issues/PRs** | Rendang | Sedang (GitHub API) | Sedang | ⚠️ Client cache 30–60s opsional; CDN tidak |
| **Connectors list** | Rendah | Rendah | Rendah | `revalidatePath('/')` on mutation (sudah ada) |
| **UI prefs** (agent, sidebar) | Tinggi | Nol | Rendah | ✅ localStorage/cookies (bukan data sensitif) |

---

## 2. Lapisan (in-process, CDN, browser, DB — what goes where)

```
┌─────────────────────────────────────────────────────────────────┐
│ BROWSER                                                         │
│  • UI prefs (agent, prompt draft, sidebar) → localStorage/cookie│
│  • GitHub repo lists → localStorage (HARUS user-scoped)         │
│  • Task list → React state (refetch on mount)                     │
│  • Diff/file cache → useRef in-memory (per tab, per session)    │
└───────────────────────────┬─────────────────────────────────────┘
                            │ fetch (credentials: include)
┌───────────────────────────▼─────────────────────────────────────┐
│ CDN / Vercel Edge                                                 │
│  • Static assets (_next/static, fonts, icons) → default CDN       │
│  • API routes & RSC → BYPASS (auth cookie, no shared cache)     │
│  • GitHub stars fetch cache → Next.js Data Cache (server-side)    │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│ IN-PROCESS (Node.js / serverless instance)                      │
│  • React.cache(getServerSession) → per-request dedup              │
│  • React.cache(getGitHubStars) → Data Cache 300s (global)       │
│  • [Future] Map<userId, UsageSummary> TTL 60s → optional          │
│  • ❌ NO Redis MVP                                              │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│ DATABASE (Postgres / Supabase)                                    │
│  • Source of truth: tasks, messages, accounts, settings           │
│  • Application cache: tasks.previewUrl (denormalized)             │
│  • Index: tasks(userId, deletedAt, createdAt DESC)                │
└─────────────────────────────────────────────────────────────────┘
```

### Aturan penempatan

| Lapisan | Cocok untuk | Tidak cocok untuk |
|---------|-------------|-------------------|
| **CDN** | Static assets, public marketing | Session, task data, GitHub token |
| **Next.js Data Cache** | Data global publik (stars) | Data per-user |
| **In-process Map** | Usage summary 60s, settings hot path | Data yang harus konsisten cross-instance (skip di MVP); **per serverless instance** on Vercel — lihat [infrastructure §4.1.1](./infrastructure-platform.md#411-vercel-serverless-vs-asumsi-single-instance-mvp) |
| **Browser localStorage** | Draft UI, repo list dengan userId+TTL | Token OAuth, task content sensitif |
| **DB denormalized** | Preview URL, computed fields jarang berubah | Task status real-time |

---

## 3. Desain Kunci (include userId in keys)

### Prinsip

Semua cache yang bisa mengekspos data user **wajib** memasukkan identitas stabil:

```
key = f(resourceType, userId, ...scopeParams, version?)
```

**Identitas:** gunakan `session.user.id` (internal DB ID), bukan GitHub login (bisa berubah).

### Skema key yang direkomendasikan

| Resource | Key Format | Contoh |
|----------|------------|--------|
| Session | *(tidak di-cache shared)* | — |
| Task list | Tidak di-cache server; client key: `tasks:${userId}` jika SWR | `tasks:usr_abc123` |
| Task detail | No-store | — |
| Usage summary | `usage:v1:${userId}` | `usage:v1:usr_abc123` |
| User settings | `settings:v1:${userId}:${key}` | `settings:v1:usr_abc123:maxSandboxDuration` |
| GitHub owners | `github-owners:v1:${userId}` | *(ganti key saat ini)* |
| GitHub repos | `github-repos:v1:${userId}:${owner}` | `github-repos:v1:usr_abc123:acme-corp` |
| GitHub stars | `github-stars:global` | Data Cache internal Next.js |
| Agent preference | `last-selected-agent` | OK tanpa userId (non-sensitive, same browser) |
| Task prompt draft | `task-prompt` | OK (draft lokal, bukan data server) |

### Migrasi dari state saat ini

Key localStorage **saat ini tidak memuat userId**:

```19:25:apps/auditor-web/lib/atoms/github-cache.ts
export const githubOwnersAtom = atomWithStorage<GitHubOwner[] | null>('github-owners', null)

export const githubReposAtomFamily = atomFamily((owner: string) =>
  atomWithStorage<GitHubRepo[] | null>(`github-repos-${owner}`, null),
)
```

**Risiko:** user A logout, user B login di browser yang sama → repo list user A bisa terlihat sebelum fetch selesai.

**Fix:** factory atom keyed by userId dari session, e.g. `github-owners:v1:${userId}`.

### Auth boundary

- Session cookie (JWE) → **never** masuk CDN cache header.
- Semua `app/api/**` response: `Cache-Control: private, no-store` (kecuali endpoint publik eksplisit seperti stars jika di-proxy).
- RSC pages yang render data user: default dynamic (cookie-dependent); jangan `export const revalidate = N` di page level untuk data user.

---

## 4. Kedaluwarsa (TTL per data type, jitter)

| Data Type | TTL | Jitter | Catatan |
|-----------|-----|--------|---------|
| GitHub stars (global) | 300s | ±30s (270–330) | Sudah 5 menit; jitter via `revalidate + random(0,60)` jika custom |
| Usage summary | 60s | ±10s (50–70) | Sesuai constraint eventual 60s |
| User settings | 300s | ±30s | Jarang berubah; invalidate on write |
| GitHub owners | 600s | ±60s | Invalidasi on disconnect/reconnect |
| GitHub repos per owner | 300s | ±30s | Invalidasi on repo create / manual refresh |
| Task list (client SWR) | 0s stale, 30s revalidate background | — | Opsional; default tetap fetch fresh |
| Deployment previewUrl (DB) | ∞ until branch deleted | — | Invalidate on branch force-push / redeploy |
| Negative cache (404 task) | 5s | ±2s | Lihat §7 |
| Rate limit | 0 (no cache) | — | Reset midnight UTC |

### Implementasi jitter

```typescript
function ttlWithJitter(baseSeconds: number, jitterSeconds: number): number {
  return baseSeconds + Math.floor(Math.random() * jitterSeconds)
}
// usage: ttlWithJitter(60, 20) → 60–79s
```

Jitter mencegah thundering herd saat TTL batch expire (meski pada 0.05 QPS dampak kecil).

---

## 5. Strategi Invalidasi

| Event | Invalidate |
|-------|------------|
| **Login / logout** | Clear all user-scoped localStorage keys; `React.cache` auto-reset per request |
| **GitHub disconnect** | Remove `github-owners:v1:*`, `github-repos:v1:*` (sudah ada di `home-page-content.tsx`) |
| **GitHub reconnect** | Force refetch owners; clear stale repos |
| **Repo created** | Remove `github-repos:v1:${userId}:${owner}` (sudah di `repos/new/page.tsx`) |
| **Task created/updated/deleted** | Client: `refreshTasks()`; server: no cache to invalidate |
| **Connector CRUD** | `revalidatePath('/')` (sudah di `lib/actions/connectors.ts`) |
| **Settings update** | Delete in-memory `settings:v1:${userId}:*` |
| **Usage consumption** | Lazy TTL expiry; optional explicit bust on task complete (future billing hook) |
| **Manual refresh** | User action → clear localStorage key + reload (sudah ada `handleRefreshOwners/Repos`) |

### Write-through vs write-invalidate

| Pattern | Use Case |
|---------|----------|
| **Write-through** | `previewUrl` disimpan ke DB saat pertama kali ditemukan |
| **Write-invalidate** | Connector mutation → `revalidatePath` |
| **TTL-only** | Usage summary, GitHub stars |
| **Client optimistic + refetch** | Task create (`addTaskOptimistically` + `refreshTasks`) |

---

## 6. Perlindungan Serbuan (stampede)

Pada 0.05 QPS, stampede **hampir tidak mungkin**. Tetap dokumentasikan untuk skala future:

| Teknik | Applicability MVP | Notes |
|--------|-------------------|-------|
| **Jitter TTL** | ✅ Usage, GitHub | Spread expiry |
| **Singleflight / promise coalescing** | ⚠️ Usage fetch | Jika 2 request concurrent same userId, share 1 DB query |
| **Stale-while-revalidate** | ⚠️ GitHub repos client | Tampilkan cache, fetch background |
| **Lock (Redis SETNX)** | ❌ Skip MVP | Butuh Redis |
| **Request dedup** | ✅ `React.cache()` | Hanya per-request |

### Usage summary (future) — minimal singleflight

```typescript
const inflight = new Map<string, Promise<UsageSummary>>()

async function getUsage(userId: string): Promise<UsageSummary> {
  const cached = usageCache.get(userId)
  if (cached && cached.expiresAt > Date.now()) return cached.data

  let p = inflight.get(userId)
  if (!p) {
    p = fetchUsageFromBilling(userId).finally(() => inflight.delete(userId))
    inflight.set(userId, p)
  }
  const data = await p
  usageCache.set(userId, { data, expiresAt: Date.now() + ttlWithJitter(60, 20) * 1000 })
  return data
}
```

---

## 7. Cache Negatif

Cache hasil "tidak ada" untuk mengurangi query berulang:

| Resource | Negative TTL | Key |
|----------|--------------|-----|
| Task not found (404) | 5s | Jangan cache di CDN; client skip retry 5s |
| GitHub not connected | 0s | Return 401, trigger disconnect flow |
| Repo access denied | 60s | `github-repos-deny:v1:${userId}:${owner}` |
| Deployment not found | 300s | Simpan `{ hasDeployment: false }` in-memory per taskId |

**Jangan** cache negative untuk auth failures (401/403) — bisa lock user out setelah reconnect.

Saat ini: `GET /api/tasks/[taskId]` return 404 tanpa negative cache — acceptable at MVP scale.

---

## 8. Perilaku Saat Gagal

| Scenario | Behavior | User Impact |
|----------|----------|-------------|
| **Data Cache miss / GitHub stars down** | Return `0` (sudah ada fallback) | Footer shows 0 stars |
| **Usage cache miss, billing API down** | Serve stale if exists; else mock/empty with banner | "Usage data unavailable" |
| **GitHub repos fetch fail** | Clear connection state, show reconnect | Sudah di `repo-selector.tsx` |
| **Task list fetch fail** | Empty sidebar + toast | Degraded, retry on navigation |
| **Session decode fail** | Treat as anonymous | Redirect if page requires auth |
| **In-memory cache poisoned** | TTL expiry self-heals | Max 60s stale usage |
| **localStorage corrupt JSON** | Catch + remove key | Force refetch |

### Degradation ladder

1. Serve stale (if TTL not expired and origin down)
2. Serve partial (cached repos + loading indicator)
3. Fail open for non-critical (stars = 0)
4. Fail closed for auth (401, no cached session)

---

## 9. Metrik

### SLI / SLO

| Metric | Target | Instrumentation |
|--------|--------|-----------------|
| API p95 latency | <300ms | Vercel Speed Insights, route-level timing |
| Usage data staleness | ≤60s p99 | `cache_age_seconds` histogram |
| Cache hit rate (usage) | >80% at scale | Counter `usage_cache_hit/miss` |
| GitHub stars cache hit | >95% | Next.js fetch cache implicit |
| Task list fetch errors | <0.1% | `fetch /api/tasks` 5xx rate |
| Auth cache violations | 0 | Alert if `Cache-Control: public` on authenticated routes |

### Logging (tanpa PII — sesuai AGENTS.md)

```typescript
// Static strings only
console.error('Usage cache fetch failed')
console.error('GitHub repos cache invalidated')
```

### Dashboard checks (MVP minimal)

- Vercel Analytics: Web Vitals
- Postgres slow query log: `tasks` list by `userId`
- Manual: verify `Cache-Control` headers on `/api/tasks`, `/api/tasks/[id]/files`

---

## Rekomendasi MVP (Minimal Viable Cache)

Given **~0.05 QPS, no Redis, p95 <300ms**:

### Keep (sudah benar)

1. `React.cache(getServerSession)` — per-request dedup
2. GitHub stars `revalidate: 300`
3. `Cache-Control: no-store` on task files
4. DB `previewUrl` write-through
5. `revalidatePath` on connector mutations

### Add (prioritas rendah, high value)

1. **User-scoped localStorage keys** untuk GitHub cache (`userId` in key)
2. **TTL metadata** di localStorage: `{ data, fetchedAt, ttl }` — skip stale >5–10 menit
3. **In-memory usage cache 60s** saat billing API terintegrasi (ganti `MOCK_USAGE_DATA`)
4. **`Cache-Control: private, no-store`** eksplisit di semua authenticated API routes

### Skip (until >1 QPS or multi-instance pain)

- Redis / Upstash
- CDN caching API responses
- Server-side task list cache
- Distributed lock / stampede protection beyond jitter

---

## Risiko localStorage GitHub Cache (dokumentasi wajib)

| Risiko | Severity | Mitigasi |
|--------|----------|----------|
| **Cross-user leakage** (shared browser) | 🔴 High | Key dengan `userId`; clear on logout |
| **Stale private repo visibility** | 🟡 Medium | TTL 5–10 min; background refetch (sudah ada pattern) |
| **XSS → exfiltrate repo list** | 🟡 Medium | Repo metadata bukan token; token tetap server-only (encrypted DB) |
| **Org membership revoked** | 🟡 Medium | Re-validate on task create; doc recommends org-context checks (github-auth.mdx) |
| **Quota exceeded** | 🟢 Low | Repo lists typically <100KB per owner |

Token GitHub **tidak** di localStorage (benar — encrypted di Postgres per `docs/user/guides/github-auth.mdx`).

---

## Self-Check Checklist

- [x] **Session/auth tidak di-cache shared** — `React.cache()` per-request only; cookie-based, no CDN
- [x] **Task list user-specific + object-level auth** — `WHERE userId = session.user.id` di semua task routes
- [x] **Usage eventual 60s** — TTL direkomendasikan; mock saat ini tanpa cache
- [x] **No Redis MVP** — in-process Map + Next.js Data Cache + localStorage saja
- [x] **p95 <300ms** — task list single indexed query; caching opsional
- [x] **userId in cache keys** — direkomendasikan untuk GitHub localStorage; belum diimplementasi
- [x] **GitHub repo localStorage risks** — didokumentasikan dengan mitigasi
- [x] **RSC patterns** — server fetch session/stars/settings → props ke client
- [x] **Jujur tentang 0.05 QPS** — minimal cache recommended
- [x] **Invalidasi** — disconnect, repo create, connector CRUD covered
- [x] **Stampede / negative cache / failure modes** — documented
- [x] **Metrik** — SLI defined, instrumentation path clear

---

*Dokumen ini mencerminkan codebase per 2026-08-04. Update saat billing API (INT) dan user-scoped GitHub cache migration land.*

[REDACTED]