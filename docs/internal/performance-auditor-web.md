# Dokumen Desain Performance Engineer — ARES `auditor-web`

| Field | Value |
|-------|-------|
| **Scope** | `apps/auditor-web` — load & latency |
| **Version** | 2026-08-04 |
| **Status** | Design-only — no production APM; Vercel Analytics/Speed Insights only |
| **Related docs** | [infrastructure-platform.md §4.1.1](./infrastructure-platform.md#411-vercel-serverless-vs-asumsi-single-instance-mvp) · [rate-limiting-auditor-web.md § Vercel serverless](./rate-limiting-auditor-web.md#vercel-serverless-vs-single-instance-mvp) · [caching-auditor-web.md](./caching-auditor-web.md) · [cdn-delivery-auditor-web.md](./cdn-delivery-auditor-web.md) · [reliability-auditor-web.md](./reliability-auditor-web.md) |

---

### 1. Bukti Hambatan

#### 1.1 Status metrik produksi

**Tidak ada metrik produksi yang dapat diverifikasi saat ini.**

Observabilitas yang *sudah terpasang di kode*:
- `@vercel/analytics/react` dan `@vercel/speed-insights/next` di `app/layout.tsx` — memberikan Web Vitals agregat di dashboard Vercel, **bukan** APM server-side (latency per route, error rate per endpoint, query DB time).
- Tidak ada `instrumentation.ts`, OpenTelemetry, Datadog, Sentry Performance, atau middleware timing.
- Tidak ada log terstruktur dengan `duration_ms` per request.

**Kesimpulan:** Semua angka before/after di dokumen ini **sengaja tidak diisi**. Baseline harus dikumpulkan dulu sebelum optimasi infra atau scaling horizontal.

#### 1.2 Data yang harus dikumpulkan terlebih dahulu

| Prioritas | Metrik | Sumber | Alasan |
|-----------|--------|--------|--------|
| P0 | Latency p50/p95/p99 per route (`/api/tasks`, `/`, `/api/auth/*`) | Vercel Observability / log terstruktur | Validasi target p95 < 300 ms |
| P0 | Error rate per status code (401, 500, 429) | Vercel logs + agregasi | Memisahkan config error vs perf error |
| P0 | QPS aktual per endpoint | Vercel / reverse proxy | Bandingkan dengan target 0.05 QPS |
| P1 | Postgres: query duration, connection count, slow queries | Neon/Supabase dashboard atau `pg_stat_statements` | DB adalah shared bottleneck |
| P1 | Cold start / function duration (serverless) | Vercel Functions metrics | Route `tasks` punya `maxDuration: 300` |
| P2 | Client: LCP, INP, bundle size (Monaco, font) | Speed Insights + `next build` analyzer | Frontend weight |
| P2 | External API latency (GitHub, Vercel Sandbox) | Span/trace manual | Dominan untuk POST `/api/tasks` |

#### 1.3 Hambatan dari dev logs (bukan bottleneck infra)

| Issue | Gejala | Root cause (dari kode) | Dampak perf |
|-------|--------|------------------------|-------------|
| **Google Fonts ECONNREFUSED** | Build/dev gagal fetch font | `next/font/google` — `Geist`, `Geist_Mono` di `app/layout.tsx` membutuhkan akses `fonts.googleapis.com` / `fonts.gstatic.com` saat dev/build | Dev experience; build CI bisa gagal di network terisolasi. **Bukan** latency runtime setelah font ter-cache |
| **`GET /api/tasks` → 401** | Polling berulang tanpa session | `AppLayout` fetch `/api/tasks` on mount + `setInterval` 5 detik; `getServerSession()` return null → 401 | **1 user anon = 0.2 QPS** ke endpoint ini saja — **4× target peak 0.05 QPS** |
| **`github_not_configured`** | Redirect `/?error=github_not_configured` | `NEXT_PUBLIC_GITHUB_CLIENT_ID` kosong di `app/api/auth/signin/github/route.ts` | Feature/auth broken; retry OAuth = wasted requests |

#### 1.4 Temuan arsitektur (dari `package.json`, `next.config.ts`, kode)

**`package.json`**
- Dev: `next dev --webpack` · Build: `next build --turbopack` — profil build berbeda dev vs prod.
- Dependensi berat: `@monaco-editor/react`, `@vercel/sandbox`, `@octokit/rest`, `drizzle-orm` + `postgres`.
- Script DB: `db:push`, `db:migrate` — schema harus sinkron sebelum load test.

**`next.config.ts`**
- Hanya `images.remotePatterns` (GitHub avatars). **Tidak ada:** `compress`, `headers` caching, `experimental.optimizePackageImports`, bundle analyzer.

**Polling client-side (beban sintetis tinggi relatif terhadap 0.05 QPS)**

| Komponen | Interval | Endpoint |
|----------|----------|----------|
| `app-layout.tsx` | 5 s | `GET /api/tasks` |
| `use-task.ts` | 5 s | `GET /api/tasks/[id]` |
| `task-details.tsx` | 2 s | sandbox health |
| `task-chat.tsx` | polling messages | `GET /api/tasks/[id]/messages` |
| `session-provider.tsx` | 60 s | auth info |
| `pr-check-status.tsx` | 30 s | check-runs |

**Database (`lib/db/client.ts`)**
- Lazy singleton `postgres(POSTGRES_URL)` tanpa pool limit eksplisit, tanpa prepared statement tuning.
- Throw jika `POSTGRES_URL` missing — semua route DB-dependent → 500.

**Serverless long-running**
- `vercel.json`: `app/api/tasks/route.ts` → `maxDuration: 300` — POST task memicu sandbox + agent; **bukan** request latency-sensitive untuk dashboard read path.

#### 1.5 Diagnosis: bottleneck saat ini

Pada skala **0.05 QPS peak**, **infrastruktur hampir pasti bukan bottleneck**.

Urutan hambatan nyata:
1. **Konfigurasi incomplete** — `POSTGRES_URL`, GitHub OAuth, font network.
2. **Auth/session** — polling tanpa guard → 401 storm.
3. **Desain client polling** — traffic sintetis >> target QPS.
4. **Baru kemudian** — DB query, cold start, bundle size.

---

### 2. Metode Uji Beban (k6 / autocannon)

#### 2.1 Prinsip

- Uji **read path** terpisah dari **write path** (POST task = menit, bukan ms).
- Autentikasi wajib untuk `/api/tasks` — tanpa cookie session, load test hanya mengukur 401 throughput (misleading).
- Target SLO: p95 < 300 ms @ 0.05 QPS sustained; burst test opsional @ 0.5 QPS (10×) untuk headroom.

#### 2.2 Autocannon — smoke test cepat

Cocok untuk endpoint publik / health tanpa auth:

```bash
# Static page (SSR/SSG)
autocannon -c 1 -d 30 -p 1 http://localhost:3000/

# Auth info (tanpa cookie → baseline 401 latency)
autocannon -c 1 -d 30 http://localhost:3000/api/auth/info
```

Flags: `-c` connections, `-d` duration (s), `-p` pipelining.

#### 2.3 k6 — skenario realistis

**Install:** `brew install k6` atau Docker `grafana/k6`.

**File `k6/read-path.js` (template):**

```javascript
import http from 'k6/http'
import { check, sleep } from 'k6'

export const options = {
  scenarios: {
    dashboard_read: {
      executor: 'constant-arrival-rate',
      rate: 0.05,           // target peak QPS
      timeUnit: '1s',
      duration: '10m',
      preAllocatedVUs: 2,
      maxVUs: 5,
    },
    // Simulasi 1 user aktif dengan polling 5s
    task_poll: {
      executor: 'constant-vus',
      vus: 1,
      duration: '5m',
      exec: 'pollTasks',
      startTime: '0s',
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<300'],
    http_req_failed: ['rate<0.01'],
  },
}

const BASE = __ENV.BASE_URL || 'http://localhost:3000'
const SESSION_COOKIE = __ENV.SESSION_COOKIE // wajib untuk test autentik

export default function () {
  const params = SESSION_COOKIE
    ? { headers: { Cookie: `session=${SESSION_COOKIE}` } }
    : {}
  const res = http.get(`${BASE}/api/tasks`, params)
  check(res, { 'status ok': (r) => r.status === 200 })
  sleep(1)
}

export function pollTasks() {
  const params = SESSION_COOKIE
    ? { headers: { Cookie: `session=${SESSION_COOKIE}` } }
    : {}
  http.get(`${BASE}/api/tasks`, params)
  sleep(5)
}
```

**Run:**

```bash
# Production build wajib (bukan dev server)
pnpm build && pnpm start

k6 run -e BASE_URL=http://localhost:3000 \
       -e SESSION_COOKIE="<value-from-browser>" \
       k6/read-path.js
```

**Cara dapat `SESSION_COOKIE`:** login via GitHub OAuth → DevTools → Application → Cookies → `session`.

#### 2.4 Skenario k6 tambahan

| Skenario | Executor | Tujuan |
|----------|----------|--------|
| `home_page` | arrival-rate 0.02/s | TTFB + HTML |
| `tasks_list` | 1 VU, sleep 5s | Replikasi polling nyata |
| `task_detail` | 1 VU, sleep 5s | `GET /api/tasks/{id}` |
| `unauthenticated` | 1 VU, sleep 5s | Baseline 401 rate (document current waste) |
| `db_stress` | ramp 1→5 VU | Temukan connection limit Postgres |

#### 2.5 POST `/api/tasks` — **jangan** dimasukkan load test rutin

- `maxDuration: 300`, Vercel Sandbox, LLM agent — cost tinggi, non-deterministik.
- Uji terpisah: 1 request manual + trace end-to-end.

#### 2.6 Environment uji

```bash
# Pre-req sebelum load test
POSTGRES_URL=postgres://...
pnpm db:push
pnpm build && pnpm start   # port 3000
```

Pastikan `NEXT_PUBLIC_GITHUB_CLIENT_ID` terisi agar auth flow valid.

---

### 3. Urutan Tindakan (8 langkah)

| # | Tindakan | Cost | Risk | Rollback |
|---|----------|------|------|----------|
| **1** | **Baseline observability** — aktifkan Vercel Observability; tambah log `duration_ms` + `route` + `status` di handler `/api/tasks` GET; export ke dashboard | Rendah (waktu eng ~0.5–1 hari) | Rendah | Hapus log fields |
| **2** | **Fix config blockers** — `POSTGRES_URL`, `JWE_SECRET`, `ENCRYPTION_KEY`, `NEXT_PUBLIC_GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`; jalankan `pnpm db:push` | Rendah | Rendah | Revert env vars |
| **3** | **Hentikan 401 polling storm** — di `app-layout.tsx`, skip fetch `/api/tasks` jika session belum initialized / user null; gunakan `sessionAtom` dari `session-provider` | Rendah (~2 jam) | Rendah | Revert guard condition |
| **4** | **Font dev resilience** — opsi A: self-host Geist via `next/font/local`; opsi B: fallback CSS system font jika build offline; opsi C: `npm config set proxy` di CI | Rendah | Rendah (visual drift minimal) | Kembalikan `next/font/google` |
| **5** | **Optimasi read path DB** — index `(user_id, deleted_at, created_at DESC)` pada `tasks`; verifikasi query plan `EXPLAIN ANALYZE`; limit kolom JSONB `logs` di list view | Rendah–Sedang | Sedang (migration) | `DROP INDEX` + revert select |
| **6** | **Kurangi polling agresif** — sandbox health 2s → 5s atau SSE/WebSocket; task list: polling hanya jika ada task `processing`; exponential backoff saat tab hidden (`document.visibilityState`) | Sedang (~1 hari) | Sedang (UX update delay) | Revert interval |
| **7** | **Bundle & caching** — `dynamic(() => import('@monaco-editor/react'), { ssr: false })` di task page saja; `next.config` `optimizePackageImports` untuk `lucide-react`; `Cache-Control` untuk static assets | Sedang | Rendah | Revert dynamic import |
| **8** | **Connection pooling** — Neon `@neondatabase/serverless` atau PgBouncer URL (`?pgbouncer=true`) untuk serverless; set `max` pool di `postgres()` | Sedang (infra) | Sedang (connection bugs) | Kembalikan direct `POSTGRES_URL` |

**Catatan:** Langkah 1–4 adalah prasyarat sebelum langkah 5–8 bermakna. Tanpa baseline, optimasi 5–8 tidak terukur.

---

### 4. Prasyarat Penambahan Instance

Horizontal scaling **belum justified** pada 0.05 QPS. Jika traffic naik 10–100×, penuhi dulu:

| Prasyarat | Status saat ini | Target sebelum scale-out |
|-----------|-----------------|--------------------------|
| Baseline p95 terukur per route | ❌ Tidak ada | ✅ 7 hari data, p95 documented |
| Error budget < 1% (non-401 config) | ❌ Unknown | ✅ |
| DB connection pooling | ❌ Direct postgres-js | ✅ PgBouncer / Neon pooler |
| Stateless session | ⚠️ Cookie JWE — OK untuk multi-instance | ✅ Pastikan `JWE_SECRET` shared |
| Idempotent long jobs | ⚠️ Sandbox registry in-memory? | ✅ Audit `sandbox-registry` — harus external atau sticky |
| Polling → push (SSE/WebSocket) | ❌ Client poll | ✅ Kurangi duplicate read across instances |
| Rate limit tested @ 2× peak | ❌ | ✅ `checkRateLimit` validated |
| Migration strategy | ✅ Drizzle migrations | ✅ Automated di CI/CD |

**Postgres (shared SoT) + Vercel autoscale cukup** — manual scale-out belum perlu sampai (lihat [infrastructure §4.1.1](./infrastructure-platform.md#411-vercel-serverless-vs-asumsi-single-instance-mvp): compute = **banyak instance serverless konkuren**, tanpa shared in-process state; analisis polling/QPS di dokumen ini = **satu viewer aktif per tab**, bukan satu proses long-lived; rate limit in-memory per instance: [rate-limiting § Vercel serverless](./rate-limiting-auditor-web.md#vercel-serverless-vs-single-instance-mvp)):
- p95 read path > 300 ms **setelah** langkah 1–7, **dan**
- CPU/memory Vercel function > 70% sustained, **dan**
- DB CPU > 60% atau connection exhaustion.

---

### 5. Verifikasi (template — tanpa angka palsu)

#### 5.1 Pre-flight checklist

```
[ ] POSTGRES_URL valid, db:push applied
[ ] GitHub OAuth configured, login flow green
[ ] pnpm build && pnpm start (production mode)
[ ] SESSION_COOKIE captured for k6
[ ] Baseline logging enabled (duration_ms)
```

#### 5.2 Hasil load test (isi setelah run)

| Metrik | Target | Baseline (isi) | Post-opt (isi) | Pass? |
|--------|--------|----------------|----------------|-------|
| QPS sustained | 0.05 | ___ | ___ | ☐ |
| p50 latency `GET /api/tasks` | — | ___ ms | ___ ms | ☐ |
| p95 latency `GET /api/tasks` | < 300 ms | ___ ms | ___ ms | ☐ |
| p99 latency `GET /api/tasks` | — | ___ ms | ___ ms | ☐ |
| Error rate (5xx) | < 1% | ___% | ___% | ☐ |
| 401 rate (authenticated test) | ~0% | ___% | ___% | ☐ |
| 401 rate (unauthenticated poll) | document only | ___% | ___% | ☐ |
| Postgres active connections | < limit | ___ | ___ | ☐ |
| Cold start (first request) | — | ___ ms | ___ ms | ☐ |

#### 5.3 Functional verification

```
[ ] Login GitHub → sidebar tasks load
[ ] Create task → status transitions visible ≤ polling interval
[ ] Sign out → no /api/tasks requests in Network tab
[ ] github_not_configured tidak muncul
[ ] Font render correct (Geist / fallback)
[ ] Speed Insights receiving data (Vercel dashboard)
```

#### 5.4 Regression gates (CI)

```bash
pnpm typecheck && pnpm lint && pnpm build
# Optional: k6 smoke @ 0.05 QPS, 2 min, fail on p95 > 300ms
```

---

### 6. Hambatan Berikutnya

Setelah config + polling + baseline selesai, hambatan berikutnya **berdasarkan arsitektur kode** (prioritas perkiraan, **belum divalidasi metrik**):

| Prioritas | Area | Hipotesis |
|-----------|------|-----------|
| 1 | **POST `/api/tasks`** | Dominasi latency external: Vercel Sandbox provision, git clone, agent LLM — bukan Next.js render |
| 2 | **JSONB `logs` column** | `SELECT *` tasks membawa payload besar; list view tidak perlu full logs |
| 3 | **Monaco Editor bundle** | Initial JS parse di task detail page — INP/LCP terdampak |
| 4 | **GitHub API proxy routes** | Rate limit GitHub (5000 req/hr authenticated) saat repo browsing |
| 5 | **Serverless cold start** | First request after idle — `@vercel/sandbox`, `@octokit/rest` import chain |
| 6 | **No edge caching** | Semua API `dynamic` default — tidak ada CDN cache untuk read |
| 7 | **Supabase dual-auth path** | Supabase SSR + custom JWE session — complexity, bukan necessarily perf |

---

### 7. Cadangan Kapasitas

Target arsitektur: **0.05 QPS peak**. Headroom planning (kapasitas per baris = per serverless function instance, bukan satu proses shared-memory — [infrastructure §4.1.1](./infrastructure-platform.md#411-vercel-serverless-vs-asumsi-single-instance-mvp)):

| Layer | Kapasitas nominal (per serverless instance) | Headroom vs 0.05 QPS | Cadangan |
|-------|--------------------------------------|----------------------|----------|
| Next.js serverless | Ratusan req/s (route ringan) | >> 1000× | Scale instance count di Vercel |
| Postgres (small tier) | ~100 concurrent connections | >> dengan pooling | Read replica jika read-heavy |
| Polling 1 user (client-side) | 0.2 QPS `/api/tasks` per tab aktif | **Sudah 4× target** | Fix polling dulu = "free capacity" |
| POST task | 1 concurrent sandbox/user | Bottleneck produk | Queue (Arq/Bull) — align dengan `auditor-api` roadmap |

**Runbook scale-up (jika metrik justify):**
1. Enable PgBouncer / Neon pooler.
2. Vercel Pro — increase function memory (512→1024 MB) jika cold start tinggi.
3. Externalize in-memory state (sandbox registry, rate limit Tier A/B/C) — **hanya** setelah session verified stateless; lihat [rate-limiting § Vercel serverless](./rate-limiting-auditor-web.md#vercel-serverless-vs-single-instance-mvp).
4. Read replica untuk `GET /api/tasks` jika DB CPU bound.

**Runbook scale-down / cost save:**
- Kurangi polling → langsung turunkan function invocations (hemat Vercel bill).
- Disable Speed Insights sampling jika quota concern (trade-off observability).

---

### 8. Biaya per Satuan

Estimasi **order-of-magnitude** untuk perencanaan — **bukan invoice aktual** (isi setelah billing dashboard review).

#### 8.1 Asumsi beban

| Parameter | Nilai |
|-----------|-------|
| Peak QPS (target) | 0.05 |
| Active users (peak concurrent) | ___ (isi) |
| Polling interval | 5 s |
| Task creates / hari | ___ (isi) |
| Avg sandbox duration | ≤ 300 s (`maxDuration`) |

#### 8.2 Unit economics (template)

| Satuan | Driver | Formula | Estimasi/bulan (isi) |
|--------|--------|---------|----------------------|
| **Function invocation** | Polling + page views | `(poll_req/user/s × users × 86400) + pageviews` | $ ___ |
| **Function GB-seconds** | Memory × duration | invocations × avg_duration × memory | $ ___ |
| **Postgres** | Storage + compute | Neon/Supabase tier | $ ___ |
| **Vercel Sandbox** | POST task | tasks/day × sandbox_minutes × rate | $ ___ |
| **LLM API** | Agent execution | tokens/task × tasks | $ ___ |
| **GitHub API** | Repo fetch | requests/user/session | $0 (within limit) |
| **Egress** | Git clone in sandbox | repo_size × tasks | $ ___ |

#### 8.3 Cost driver #1 saat skala rendah

**Bukan infra** — **misconfiguration waste**:
- Anonymous polling → paid function invocations yang return 401.
- Failed builds (font fetch) → CI minutes.
- Sandbox task failures → sunk cost tanpa output.

#### 8.4 Cost optimization (tanpa scale)

1. Guard polling by auth state → ↓ invocations.
2. `visibilityState` pause polling → ↓ idle waste.
3. Self-host fonts → ↓ CI flakiness / rebuild.
4. Selective column fetch di Drizzle → ↓ DB I/O + response bytes.

---

## Self-Check Checklist

```
Dokumen
[✓] Bahasa Indonesia, istilah teknis OK
[✓] Section 1–8 lengkap
[✓] Tidak ada angka before/after palsu
[✓] Section 1 explicitly states: no production metrics
[✓] Section 1 lists data to collect first

Akurasi kode
[✓] package.json: Next 16, dev --webpack, build --turbopack
[✓] next.config.ts: minimal (images only)
[✓] Google Fonts: next/font/google Geist di layout.tsx
[✓] /api/tasks 401: getServerSession + polling 5s di app-layout.tsx
[✓] github_not_configured: missing NEXT_PUBLIC_GITHUB_CLIENT_ID
[✓] vercel.json: tasks maxDuration 300
[✓] DB: postgres-js + POSTGRES_URL lazy singleton

Kejujuran skala
[✓] 0.05 QPS peak acknowledged
[✓] 1 user polling = 0.2 QPS > target — highlighted
[✓] Bottleneck = config/auth/polling, bukan infra
[✓] No production APM — Speed Insights ≠ server APM

Metode uji
[✓] k6 + autocannon examples provided
[✓] Auth cookie requirement documented
[✓] POST /api/tasks excluded from routine load test

Action plan
[✓] 8 steps with cost/risk/rollback
[✓] Prerequisites before horizontal scale
[✓] Verification template without fake numbers
```

---

**Rekomendasi immediate next step:** Jalankan langkah 1–3 (observability + config + polling guard), lalu satu k6 run 10 menit @ 0.05 QPS dengan session valid — isi tabel Section 5.2. Itu akan menjadi **Bukti Hambatan** pertama yang terukur.

[REDACTED]