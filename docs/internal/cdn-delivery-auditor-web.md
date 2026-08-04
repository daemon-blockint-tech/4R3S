# Dokumen Desain Delivery Engineer (CDN) — ARES Auditor Web

| Field | Value |
|-------|-------|
| **Scope** | `apps/auditor-web` — Vercel Edge delivery |
| **Version** | 2026-08-04 |
| **Status** | Partially implemented — Vercel Edge default; custom Cache-Control headers not configured |
| **Related docs** | [infrastructure-platform.md](./infrastructure-platform.md) · [performance-auditor-web.md](./performance-auditor-web.md) |

---

## 0. Ringkasan Eksekutif

| Keputusan | Nilai |
|-----------|-------|
| **Lapisan delivery** | **Vercel Edge Network** (CDN bawaan) — **tanpa CDN eksternal** |
| **Origin compute** | Vercel Functions (Serverless) + Postgres (Neon/Vercel Postgres) |
| **Alasan** | Traffic rendah, stack sudah native Vercel, static assets otomatis di-edge, auth berbasis cookie membuat CDN tambahan berisiko cache poisoning |
| **Aksi wajib** | Dokumentasi header per kelas konten; pastikan route auth/API `private`; monitor `x-vercel-cache` |

---

### 1. Kelayakan

#### 1.1 Pertanyaan Kunci

> **Vercel sudah menyediakan Edge CDN — apakah CDN tambahan diperlukan?**

**Jawaban: TIDAK.** Vercel Edge Network **cukup** sebagai satu-satunya lapisan CDN untuk `auditor-web` pada skala dan arsitektur saat ini.

#### 1.2 Bukti Berbasis Fakta

| # | Bukti | Implikasi untuk `auditor-web` |
|---|-------|-------------------------------|
| 1 | [Vercel CDN docs](https://vercel.com/docs/caching/cdn-cache): *"Static files are automatically cached on Vercel's global network for the lifetime of the deployment"* | Asset `/_next/static/*` dan `/public/*` sudah di-edge tanpa konfigurasi |
| 2 | [Next.js CDN caching guide](https://nextjs.org/docs/app/guides/cdn-caching): `/_next/static/` mendapat `Cache-Control: public, max-age=31536000, immutable` | JS/CSS/font chunks (Geist via `next/font`) aman long-TTL karena content-hash |
| 3 | [How Vercel CDN works](https://vercel.com/docs/how-vercel-cdn-works): 126+ PoP global; request melewati CDN sebelum origin | User `[ASUMSI]` di ap-southeast-1 dilayani dari PoP terdekat (Singapore region `sin1` untuk compute) |
| 4 | Deploy target dokumentasi: [dashboard.mdx](https://github.com/daemon-blockint-tech/4R3S/blob/main/docs/user/guides/dashboard.mdx) — app dari **vercel-labs/coding-agent-template** | Integrasi native: Analytics, Speed Insights, Sandbox SDK sudah Vercel-first |
| 5 | Traffic ~50 DAU / 0,05 QPS | Origin load sangat rendah; CDN eksternal tidak mengurangi biaya/material latency secara signifikan |
| 6 | Semua halaman utama memanggil `cookies()` (SSR dinamis) | HTML tidak cacheable di edge; manfaat CDN eksternal terbatas pada static assets — yang sudah ditangani Vercel |

#### 1.3 Mengapa CDN Eksternal (CloudFront / Cloudflare) Tidak Direkomendasikan

1. **Double-hop latency** — request melewati CDN eksternal → Vercel edge → origin; tambahan hop tidak bermanfaat untuk static yang sudah di Vercel edge.
2. **Cookie / auth complexity** — session JWE (`_user_session_`) dan Supabase auth cookies (`sb-*`) memerlukan `Cache-Control: private` atau `no-store`; CDN eksternal butuh aturan bypass manual per path.
3. **Cache invalidation ganda** — deploy Vercel otomatis invalidasi edge; CDN eksternal perlu purge terpisah → risiko stale content.
4. **Biaya vs manfaat** — pada 0,05 QPS, biaya CloudFront/Cloudflare Pro (~$20–50/bulan) tidak terjustifikasi.
5. **WebSocket / long-running API** — route seperti `/api/tasks/[taskId]/terminal` (ws) dan `maxDuration: 300` di `vercel.json` tidak cocok di-cache CDN eksternal.

#### 1.4 Arsitektur Delivery yang Dipilih

```
[Browser — ap-southeast-1 ASUMSI]
        │
        ▼
┌───────────────────────────────────┐
│   Vercel Edge Network (CDN)       │  ← SATU-SATUNYA lapisan CDN
│   • Static: /_next/static, /public│
│   • Optimized: /_next/image       │
│   • Cacheable API (jika di-set)   │
└───────────────┬───────────────────┘
                │ MISS / dynamic
                ▼
┌───────────────────────────────────┐
│   Vercel Functions (sin1/hkg1)    │  ← Origin compute
│   Next.js SSR + Route Handlers    │
└───────────────┬───────────────────┘
                │
        ┌───────┴────────┐
        ▼                ▼
  [Postgres]      [GitHub/Vercel/Supabase APIs]
  POSTGRES_URL    External origins
```

#### 1.5 Kapan Revisi Diperlukan

Pertimbangkan CDN eksternal **hanya jika**:
- Traffic > 10.000 DAU atau > 50 QPS sustained
- Wajib WAF/DDoS enterprise di depan Vercel (Cloudflare Enterprise)
- Multi-cloud origin (bukan full Vercel deploy)
- Compliance mengharuskan CDN di region/provider tertentu

---

### 2. Klasifikasi Konten

| Kelas | ID | Path / Sumber | Contoh di `auditor-web` | Cacheable Edge? | Catatan |
|-------|----|--------------|-------------------------|-----------------|---------|
| **A — Hashed static** | `STATIC_HASH` | `/_next/static/**` | JS chunks, CSS, Geist font files | ✅ Ya, immutable | Content-hash di filename |
| **B — Public static** | `PUBLIC` | `/public/**`, `/favicon*`, `/site.webmanifest`, `/apple-touch-icon.png` | `logos/ares.png`, `templates/*.svg`, favicon set | ✅ Ya, long-TTL | Tidak di-hash; invalidasi via deploy |
| **C — App metadata icon** | `APP_ICON` | `/icon.png` (dari `app/icon.png`) | Next.js generated favicon route | ✅ Ya | Framework-managed |
| **D — Optimized images** | `NEXT_IMAGE` | `/_next/image?url=...` | GitHub avatars (`avatars.githubusercontent.com`) | ✅ Ya, parameterized | `remotePatterns` di `next.config.ts` |
| **E — SSR HTML (authenticated)** | `HTML_AUTH` | `/`, `/tasks/**`, `/settings`, `/profile`, `/usage`, `/repos/**` | Semua page.tsx yang panggil `cookies()` + `getServerSession()` | ❌ Tidak | Variasi per user/session |
| **F — SSR HTML (public shell)** | `HTML_PUBLIC` | Landing sebelum login | `/` (partial — masih baca cookies prefs) | ❌ Tidak* | *Saat ini dinamis karena cookie prefs |
| **G — Auth / session API** | `API_AUTH` | `/api/auth/**`, `/auth/callback`, `/auth/auth-code-error` | OAuth GitHub/Vercel, Supabase PKCE | ❌ Tidak | Set-Cookie, redirect |
| **H — Task / sandbox API** | `API_DYNAMIC` | `/api/tasks/**`, `/api/sandboxes/**` | Task CRUD, terminal ws, LSP | ❌ Tidak | User-scoped, real-time |
| **I — Semi-static API** | `API_SEMI` | `/api/github-stars` | GitHub star count | ⚠️ Bisa (pendek) | Sudah `revalidate: 300` |
| **J — Third-party static** | `EXT_CDN` | External URLs | `vercel.com/api/www/avatar`, GitHub CDN | ✅ (di provider mereka) | Bukan tanggung jawab origin kita |
| **K — Analytics beacons** | `ANALYTICS` | Vercel Analytics / Speed Insights | `@vercel/analytics`, `@vercel/speed-insights` | N/A | Dilayani Vercel infra |

#### Inventaris Static Asset (`public/`)

| File/Folder | Ukuran relatif | Kelas |
|-------------|----------------|-------|
| `favicon.png`, `favicon-16x16.png`, `favicon-32x32.png` | Kecil | PUBLIC |
| `apple-touch-icon.png`, `android-chrome-*.png` | Kecil | PUBLIC |
| `web-app-manifest-*.png`, `site.webmanifest` | Kecil | PUBLIC |
| `logos/ares.png`, `logos/gemini.svg` | Sedang | PUBLIC |
| `templates/*.svg` (nextjs, hono, svelte, nuxt) | Kecil | PUBLIC |
| `*.svg` (globe, vercel, window, file, next) | Kecil | PUBLIC |

#### Metadata (`app/layout.tsx`)

```typescript
icons: {
  icon: [
    { url: '/favicon.png', type: 'image/png' },
    { url: '/favicon-32x32.png', sizes: '32x32', type: 'image/png' },
    { url: '/favicon-16x16.png', sizes: '16x16', type: 'image/png' },
  ],
  apple: '/apple-touch-icon.png',
},
manifest: '/site.webmanifest',
```

Semua icon → kelas **PUBLIC**, cacheable di edge.

---

### 3. Aturan Header (Cache-Control per Content Class)

#### 3.1 Default Vercel (tidak perlu override)

| Kelas | Cache-Control (expected) | Sumber |
|-------|--------------------------|--------|
| `STATIC_HASH` | `public, max-age=31536000, immutable` | Next.js build + Vercel CDN otomatis |
| `NEXT_IMAGE` | `public, max-age=31536000, immutable` (variant) | Vercel Image Optimization |
| `PUBLIC` (post-first-request) | `public, max-age=31536000, immutable` atau long max-age | Vercel static file caching |

#### 3.2 Header Wajib per Kelas (origin harus set / verify)

| Kelas | Cache-Control | Headers tambahan | Alasan |
|-------|---------------|------------------|--------|
| `HTML_AUTH`, `HTML_PUBLIC` | `private, no-cache, no-store, must-revalidate` | `Vary: Cookie` (implicit via SSR) | Session cookie `_user_session_`, Supabase `sb-*`, UI prefs cookies |
| `API_AUTH` | `private, no-store` | — | Set-Cookie pada login/logout |
| `API_DYNAMIC` | `private, no-store` | — | Task data user-scoped; sudah di-set di `/api/tasks/[taskId]/files` |
| `API_SEMI` (`/api/github-stars`) | `public, s-maxage=300, stale-while-revalidate=60` | — | Data publik, toleransi 5 menit stale |
| `APP_ICON` | `public, max-age=86400, stale-while-revalidate=3600` | — | Jarang berubah |

#### 3.3 Rekomendasi Implementasi (`next.config.ts`)

Tambahkan `headers()` untuk eksplisit dokumentasi dan non-Vercel fallback:

```typescript
// next.config.ts — REKOMENDASI (belum ada di repo saat ini)
async headers() {
  return [
    {
      source: '/api/auth/:path*',
      headers: [{ key: 'Cache-Control', value: 'private, no-store' }],
    },
    {
      source: '/auth/:path*',
      headers: [{ key: 'Cache-Control', value: 'private, no-store' }],
    },
    {
      source: '/api/tasks/:path*',
      headers: [{ key: 'Cache-Control', value: 'private, no-store' }],
    },
    {
      source: '/api/github-stars',
      headers: [
        {
          key: 'Cache-Control',
          value: 'public, s-maxage=300, stale-while-revalidate=60',
        },
      ],
    },
  ]
},
```

#### 3.4 Cookie yang Memaksa `private`

| Cookie | Scope | HttpOnly | Dampak Cache |
|--------|-------|----------|--------------|
| `_user_session_` | `/` | ✅ | Semua halaman authenticated |
| `sb-*-auth-token` (Supabase) | `/` | ✅ | Auth PKCE flow |
| `selected-owner`, `selected-repo` | `/` | ❌ | Home page dinamis |
| `sidebar-width`, `sidebar-open` | `/` | ❌ | Layout wrapper dinamis |
| `install-dependencies`, `keep-alive`, `enable-browser`, `max-duration` | `/` | ❌ | Task form prefs |

**Aturan emas:** Jika response bergantung pada cookie **apapun** → `Cache-Control: private` atau `no-store`. Jangan cache HTML/API auth di edge shared cache.

#### 3.5 Security Headers (bukan cache, tapi delivery layer)

| Header | Nilai | Catatan |
|--------|-------|---------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Vercel otomatis di production |
| `X-Content-Type-Options` | `nosniff` | Vercel default |
| `X-Frame-Options` | `DENY` atau `SAMEORIGIN` | Pertimbangkan untuk dashboard |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Best practice |

---

### 4. Kunci Cache

#### 4.1 Vercel Edge Cache Key (per kelas)

| Kelas | Komponen Cache Key | Cookie di key? |
|-------|-------------------|----------------|
| `STATIC_HASH` | Full URL path (hash unik) | ❌ Tidak |
| `PUBLIC` | Full URL path | ❌ Tidak |
| `NEXT_IMAGE` | `/_next/image?url=&w=&q=` | ❌ Tidak |
| `API_SEMI` | URL path saja | ❌ Tidak (data identik semua user) |
| `HTML_*`, `API_AUTH`, `API_DYNAMIC` | **Tidak di-cache** | N/A |

#### 4.2 Next.js Hashed Assets

Format path build output:
```
/_next/static/chunks/<hash>.js
/_next/static/css/<hash>.css
/_next/static/media/<hash>.woff2   ← Geist fonts
```

- Hash berubah setiap deploy → cache key otomatis invalid
- **Tidak perlu** purge manual untuk `_next/static`
- Cross-deployment: Vercel docs — unchanged hash dapat persist across deployments (aman karena immutable)

#### 4.3 Public Assets (non-hashed)

Cache key = path literal:
```
/favicon.png
/logos/ares.png
/site.webmanifest
```

Invalidasi: **deploy baru** Vercel (asset URL sama, konten baru jika file berubah). Untuk force refresh tanpa deploy → Vercel Dashboard → Deployment → **Invalidate Cache**.

#### 4.4 Auth Routes — Anti-Cache Key Rules

Path yang **harus never-cache** (cookie present = private response):

```
/api/auth/*
/auth/callback
/auth/auth-code-error
/api/tasks/*
/app/api/auth/signin/*
```

Verifikasi: response header `x-vercel-cache: MISS` atau tidak ada header (bypass CDN cache).

#### 4.5 Vary Header

| Scenario | Vary? | Rekomendasi |
|----------|-------|-------------|
| SSR dengan cookie | Implicit (tidak cacheable) | Jangan force-cache HTML |
| API semi-static | Tidak perlu `Vary: Cookie` | Response identik |
| Accept-Encoding | Otomatis (gzip/br) | Vercel handles |

---

### 5. Pembersihan

#### 5.1 Strategi per Kelas

| Kelas | Metode Purge | Trigger |
|-------|--------------|---------|
| `STATIC_HASH` | **Tidak perlu** — hash baru otomatis | Setiap `git push` → deploy |
| `PUBLIC` | Deploy baru ATAU Vercel Invalidate Cache | Update favicon/logo |
| `NEXT_IMAGE` | Otomatis per deployment + parameter change | Avatar URL change |
| `API_SEMI` | TTL expiry (300s) ATAU `revalidatePath('/api/github-stars')` | Manual jika perlu |
| `HTML_*`, `API_*` | N/A (no-store) | — |

#### 5.2 Prosedur Purge Manual

1. **Vercel Dashboard** → Project `ares-auditor-web` → Deployments → [deployment aktif] → **Invalidate Cache**
2. **CLI:** `vercel cache invalidate --yes` (per deployment)
3. **Tidak ada wildcard path purge** di Vercel — cukup untuk skala ini

#### 5.3 Purge yang Dihindari

- ❌ Purge `/_next/static/*` — tidak perlu dan Vercel tidak izinkan bypass
- ❌ CDN eksternal purge — tidak ada CDN eksternal
- ❌ Purge berdasarkan cookie — tidak applicable

#### 5.4 Stale-While-Revalidate

| Endpoint | SWR Window | Perilaku |
|----------|------------|----------|
| `/api/github-stars` | 60 detik | Serve stale dari edge sambil revalidate origin |
| Static assets | N/A (immutable) | Tidak perlu SWR |

---

### 6. Perlindungan Origin

#### 6.1 Origin Architecture

```
Origin = Vercel Serverless Functions (Next.js)
Database = Postgres (POSTGRES_URL — Neon/Vercel Postgres)
External = GitHub API, Vercel API, Supabase Auth, @vercel/sandbox
```

#### 6.2 Mekanisme Perlindungan (Vercel Native)

| Mekanisme | Status | Detail |
|-----------|--------|--------|
| **CDN shielding** | ✅ Aktif | Static served from edge; origin hanya pada MISS |
| **DDoS mitigation** | ✅ Vercel platform | L4/L7 basic protection included |
| **Rate limiting** | ⚠️ Partial | `/api/auth/rate-limit` ada di app; pertimbangkan Vercel Firewall |
| **Request collapsing** | ✅ ISR/SWR | Dedup concurrent requests ke path sama |
| **Function timeout** | ✅ `maxDuration: 300` | `vercel.json` untuk `/api/tasks` |
| **Geographic routing** | ✅ Edge PoP | User ap-southeast-1 → nearest PoP |

#### 6.3 Origin Load Estimation (50 DAU, 0.05 QPS)

| Request type | Est. % traffic | Origin hit? |
|--------------|----------------|-------------|
| Static assets (cached) | ~70% | ❌ Edge HIT |
| HTML SSR (dynamic) | ~20% | ✅ Every request |
| API dynamic | ~8% | ✅ Every request |
| API semi-static | ~2% | ✅ Every 300s per PoP |

**Estimasi origin requests:** ~0.015 QPS effective (~1.300/hari) — sangat rendah.

#### 6.4 Rekomendasi Tambahan (opsional, P2)

| Item | Prioritas | Alasan |
|------|-----------|--------|
| Vercel Firewall rules | P2 | Block abusive `/api/auth/*` |
| Set function region `sin1` | P2 | `[ASUMSI]` primary users di ap-southeast-1 |
| Connection pooling (Neon) | P1 | Kurangi cold DB connection latency |
| `export const preferredRegion = ['sin1', 'hkg1']` | P2 | Fallback Hong Kong |

```typescript
// vercel.json — REKOMENDASI region pinning
{
  "regions": ["sin1"],
  "functions": {
    "app/api/tasks/route.ts": { "maxDuration": 300 }
  }
}
```

#### 6.5 Route yang Tidak Boleh Di-Cache (Origin Protection via no-store)

Semua route berikut **wajib** reach origin setiap request — ini intentional:

- 14 `page.tsx` routes (semua baca cookies)
- 60 API route handlers (majority auth/task scoped)
- WebSocket: `/api/tasks/[taskId]/terminal`

---

### 7. Kompresi dan Format

#### 7.1 Kompresi Transport

| Layer | Algoritma | Status |
|-------|-----------|--------|
| Vercel Edge | **Brotli** (prefer) / **gzip** (fallback) | Otomatis via `Accept-Encoding` |
| Static JS/CSS | Pre-compressed at build | Next.js + Vercel |
| API JSON | Brotli/gzip on-the-fly | Otomatis |

**Tidak perlu** konfigurasi manual.

#### 7.2 Format Asset

| Asset type | Format saat ini | Rekomendasi |
|------------|-----------------|-------------|
| Icons/favicon | PNG | ✅ OK; pertimbangkan WebP/AVIF untuk manifest icons (P3) |
| Logos | PNG + SVG | ✅ SVG sudah optimal untuk templates |
| Fonts | WOFF2 (Geist via next/font) | ✅ Best practice |
| Images (remote) | JPEG/PNG via `/_next/image` | ✅ Auto WebP/AVIF conversion by Vercel |
| JS bundles | ES modules, minified | ✅ Next.js 16 default |

#### 7.3 Font Loading Strategy

```typescript
// app/layout.tsx — sudah optimal
const geistSans = Geist({ variable: '--font-geist-sans', subsets: ['latin'] })
```

- Font self-hosted di `/_next/static/media/` → cacheable immutable
- Tidak ada request ke `fonts.googleapis.com` at runtime → **hemat RTT**

#### 7.4 Content-Encoding Headers (expected)

```
Content-Encoding: br          # untuk teks > 1KB
Content-Type: application/javascript; charset=utf-8
```

---

### 8. Sertifikat dan Domain

#### 8.1 TLS / Sertifikat

| Aspek | Implementasi |
|-------|--------------|
| Provider | **Vercel Automatic SSL** (Let's Encrypt) |
| Renewal | Otomatis |
| Min TLS | TLS 1.2+ |
| HSTS | Enabled di production |
| Certificate scope | `*.vercel.app` + custom domain |

#### 8.2 Domain Strategy (Rekomendasi)

| Domain | Purpose | DNS |
|--------|---------|-----|
| `auditor.ares.dev` `[ASUMSI]` | Production dashboard | CNAME → `cname.vercel-dns.com` |
| `*.vercel.app` | Preview deployments | Otomatis per branch/PR |

#### 8.3 Konfigurasi DNS

```
auditor.ares.dev.  CNAME  cname.vercel-dns.com.
```

- **Tidak perlu** sertifikat terpisah di CDN eksternal
- Vercel handles: cert provisioning, renewal, HTTP→HTTPS redirect

#### 8.4 Cookie Security (Production)

Dari `lib/session/create.ts`:
```
Set-Cookie: _user_session_=...; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000
```

| Flag | Production | Dev |
|------|------------|-----|
| `Secure` | ✅ | ❌ (localhost) |
| `HttpOnly` | ✅ | ✅ |
| `SameSite` | Lax | Lax |

#### 8.5 Redirect Rules

| From | To | Handler |
|------|----|---------|
| `http://` | `https://` | Vercel automatic |
| `www.` | apex (atau sebaliknya) | Vercel domain settings |
| OAuth callback | `/auth/callback` → app route | Supabase PKCE |

---

### 9. Metrik dan Biaya

#### 9.1 Metrik Monitoring

| Metrik | Sumber | Target | Alert Threshold |
|--------|--------|--------|-----------------|
| **Cache Hit Ratio** | `x-vercel-cache` header sampling | ≥ 85% static | < 70% |
| **TTFB (static)** | Speed Insights / RUM | < 100ms `[ASUMSI]` ap-southeast-1 | > 300ms p95 |
| **TTFB (SSR)** | Speed Insights | < 500ms p95 | > 1500ms p95 |
| **Origin invocations** | Vercel Usage dashboard | < 5K/hari | > 50K/hari |
| **Bandwidth** | Vercel Analytics | < 10 GB/bulan | > 50 GB/bulan |
| **4xx/5xx rate** | Vercel Logs | < 1% | > 5% |
| **Function duration p95** | Vercel Observability | < 2s (non-task) | > 10s |

#### 9.2 Header Debug

```bash
# Verifikasi cache status static
curl -sI https://auditor.ares.dev/_next/static/chunks/webpack.js | grep -E 'cache-control|x-vercel-cache'

# Verifikasi auth route tidak di-cache
curl -sI -b "_user_session_=test" https://auditor.ares.dev/ | grep -E 'cache-control|x-vercel-cache'

# Expected auth: cache-control: private/no-store, x-vercel-cache: MISS atau absent
```

#### 9.3 Estimasi Biaya (50 DAU, 0.05 QPS)

| Komponen | Estimasi Bulanan | Catatan |
|----------|------------------|---------|
| **Vercel Pro** (team) | $20/user `[ASUMSI]` | Includes Edge CDN, SSL, Analytics |
| **Vercel Functions** | ~$0–5 | Well within Pro included limits |
| **Bandwidth (Edge)** | ~$0 | < 100 GB included |
| **Speed Insights** | $0 | Included |
| **CDN eksternal** | **$0** | Tidak digunakan |
| **Postgres (Neon)** | $0–19 | Free tier likely sufficient |
| **Total delivery layer** | **~$20–45/bulan** | Dominasi: Vercel Pro seat |

#### 9.4 Traffic Projection

```
50 DAU × ~20 page views/session = 1.000 page views/hari
+ ~500 API calls/hari
+ ~2.000 static asset requests/hari (cached)
≈ 3.500 requests/hari ≈ 0.04 QPS average
Peak (3×): ~0.12 QPS
```

**Kesimpulan biaya:** Vercel Hobby/Pro tier lebih dari cukup; tidak ada ROI untuk CDN berbayar terpisah.

#### 9.5 Dashboard Observability

| Tool | Sudah terpasang? | Use |
|------|------------------|-----|
| `@vercel/analytics` | ✅ `app/layout.tsx` | Page views, Web Vitals |
| `@vercel/speed-insights` | ✅ `app/layout.tsx` | LCP, FID, CLS per route |
| Vercel Logs | ✅ Platform | Function errors, slow queries |
| Custom: cache hit sampler | ❌ Belum | Middleware log `x-vercel-cache` (P3) |

---

## Lampiran A: Matriks Route → Kelas Cache

| Route Pattern | Kelas | Cache-Control |
|---------------|-------|---------------|
| `/_next/static/**` | STATIC_HASH | immutable (auto) |
| `/_next/image/**` | NEXT_IMAGE | immutable variant (auto) |
| `/favicon*.png`, `/logos/**`, `/templates/**` | PUBLIC | long-TTL (auto) |
| `/`, `/tasks/**`, `/settings`, `/profile`, `/usage` | HTML_AUTH | private, no-store |
| `/repos/**`, `/new/**` | HTML_AUTH | private, no-store |
| `/api/auth/**` | API_AUTH | private, no-store |
| `/auth/callback` | API_AUTH | private, no-store |
| `/api/tasks/**` | API_DYNAMIC | private, no-store |
| `/api/github-stars` | API_SEMI | s-maxage=300, swr=60 |
| `/api/connectors`, `/api/sandboxes` | API_DYNAMIC | private, no-store |

---

## Lampiran B: File Konfigurasi Saat Ini

**`next.config.ts`** — hanya image remote patterns:
```typescript
images: {
  remotePatterns: [
    { protocol: 'https', hostname: 'avatars.githubusercontent.com', pathname: '/**' },
    { protocol: 'https', hostname: 'github.com', pathname: '/**' },
  ],
},
```

**`vercel.json`** — function timeout only:
```json
{
  "functions": {
    "app/api/tasks/route.ts": { "maxDuration": 300 }
  }
}
```

**Gap vs rekomendasi dokumen ini:**
1. Belum ada `headers()` cache rules eksplisit
2. Belum ada `regions: ["sin1"]` pinning
3. `/api/github-stars` belum set response `Cache-Control` header (hanya `next.revalidate`)

---

## Self-Check Checklist

| # | Item | Status |
|---|------|--------|
| 1 | Jawaban kelayakan: Vercel Edge cukup, **tanpa CDN eksternal** | ✅ |
| 2 | Bukti berbasis docs Vercel + Next.js + kondisi app aktual | ✅ |
| 3 | Klasifikasi konten mencakup `_next/static`, `/public`, auth, API | ✅ |
| 4 | Cache-Control per kelas; auth/cookie routes = **private/no-store** | ✅ |
| 5 | Kunci cache: hash untuk static, path untuk public, no-cache untuk cookie routes | ✅ |
| 6 | Pembersihan: deploy-based untuk static, TTL untuk semi-static API | ✅ |
| 7 | Perlindungan origin: Vercel CDN shield + no-store dynamic routes | ✅ |
| 8 | Kompresi Brotli/gzip otomatis; WOFF2 fonts; next/image optimization | ✅ |
| 9 | TLS otomatis Vercel; cookie Secure/HttpOnly/SameSite documented | ✅ |
| 10 | Metrik (`x-vercel-cache`, Speed Insights) dan estimasi biaya ~50 DAU | ✅ |
| 11 | Referensi `next.config.ts`, `layout.tsx` metadata, `public/` inventory | ✅ |
| 12 | Asumsi geografi ap-southeast-1 ditandai `[ASUMSI]` | ✅ |
| 13 | Dokumen dalam Bahasa Indonesia, istilah teknis dipertahankan | ✅ |

---

**Keputusan final:** **Vercel Edge Network = lapisan CDN tunggal** untuk ARES Auditor Web. Fokus implementasi berikutnya: (1) tambahkan `headers()` eksplisit di `next.config.ts`, (2) pin region `sin1` di `vercel.json`, (3) set `Cache-Control` response di `/api/github-stars`. **Jangan** menambahkan CloudFront, Cloudflare, atau CDN lain di depan Vercel pada skala traffic saat ini.

[REDACTED]