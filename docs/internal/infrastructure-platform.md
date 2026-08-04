# Dokumen Desain Infrastruktur — ARES Platform
## Fokus: `apps/auditor-web` & Infrastruktur Bersama

**Versi:** 1.1 · **Tanggal:** 4 Agustus 2026  
**Scope:** Deployment dashboard ARES Auditor (`apps/auditor-web`), database aplikasi, Supabase bersama, CI/CD — **bukan provisioning nyata**.  
**Related:** [Rate limiting](./rate-limiting-auditor-web.md) · [Caching](./caching-auditor-web.md) · [Platform CI/CD](./platform-cicd.md)

---

### 1. Profil Beban Kerja

#### 1.1 Karakteristik Aplikasi

| Aspek | Nilai (dari codebase) |
|-------|----------------------|
| Stack | Next.js **16.0.10** monolith (App Router, RSC), Node ≥20 |
| Build | `next build --turbopack`; start via `next start` (Vercel serverless default) |
| DB aplikasi | Drizzle ORM + `postgres` driver via `POSTGRES_URL` |
| Auth (utama) | OAuth GitHub/Vercel → sesi JWE (`JWE_SECRET`, `ENCRYPTION_KEY`) |
| Auth (opsional) | Supabase Auth (GitHub/Web3 PKCE) via `NEXT_PUBLIC_SUPABASE_*` |
| Fitur berat | Vercel Sandbox (`@vercel/sandbox`) — task coding agent, timeout hingga **300s** (`vercel.json`, `MAX_SANDBOX_DURATION`) |
| Knowledge base | Supabase Postgres + pgvector (`db/supabase/*.sql`) — dipakai agent CLI, bukan hot path dashboard |

#### 1.2 Target Beban (constraint yang diberikan)

| Metrik | Target | Implikasi |
|--------|--------|-----------|
| DAU | ~50 | ~500–1.500 page view/hari (asumsi 10–30 halaman/user) |
| Peak QPS | **0.05** (~3 req/menit) | Beban sangat rendah; bottleneck bukan throughput HTTP |
| Availability | **99.5%** | ≈3,6 jam downtime/bulan yang dapat diterima |
| Region | **Single region** — `ap-southeast-1` (Supabase) | Latency ke user SEA; edge Vercel global OK untuk static assets |

#### 1.3 Pola Trafik

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────────┐
│ Browser     │────▶│ Vercel Edge  │────▶│ Serverless Function │
│ (Dashboard) │     │ (CDN/static) │     │ Next.js API Routes  │
└─────────────┘     └──────────────┘     └──────────┬──────────┘
                                                    │
                    ┌───────────────────────────────┼──────────────────────┐
                    ▼                               ▼                      ▼
           Supabase Pooler              Vercel Sandbox API          GitHub OAuth
           (POSTGRES_URL)               (SANDBOX_VERCEL_*)          (OAuth callbacks)
                    │
                    ▼
           Supabase Postgres
           ├── schema Drizzle (users, tasks, connectors)
           └── schema KB (chunks, hybrid_search, RBAC)
```

**Hot paths:**
- **Ringan (<200 ms):** SSR halaman, OAuth redirect, CRUD task metadata
- **Sedang (1–10 s):** GitHub API proxy, file listing sandbox
- **Berat (30–300 s):** `app/api/tasks/route.ts` — sandbox creation, agent execution (`maxDuration: 300` di `vercel.json`)

**Burst pattern:** Trafik terpusat saat jam kerja SEA (UTC+7); sandbox task menambah konkurensi fungsi panjang, bukan QPS.

#### 1.4 Estimasi Kapasitas Harian

| Resource | Perkiraan (50 DAU) |
|----------|-------------------|
| HTTP requests | 2.000–5.000/hari |
| DB queries | 10.000–30.000/hari (≈0,1–0,3 QPS DB) |
| Sandbox hours | 5–20 jam compute/bulan (tergantung adoption coding agent) |
| Storage DB | <1 GB (tahun pertama) |
| Bandwidth | <10 GB/bulan |

---

### 2. Pilihan Platform

#### 2.1 Arsitektur yang Dipilih

| Layer | Platform | Justifikasi |
|-------|----------|-------------|
| **Compute (web)** | **Vercel Pro** | Native Next.js 16; `vercel.json` sudah ada; `@vercel/sandbox`, `@vercel/analytics`, `@vercel/speed-insights` terintegrasi; `scripts/migrate-production.ts` mendeteksi `VERCEL_ENV=production` |
| **Database (app + KB)** | **Supabase Pro — `ap-southeast-1`** | Satu managed Postgres untuk Drizzle schema + `db/supabase/` migrations; Auth + pgvector + pooler (Supavisor); contoh pooler sudah di `.env.example`: `aws-0-ap-southeast-1.pooler.supabase.com` |
| **Local dev** | Docker Compose (root) | `postgres:16-alpine` + `neo4j:5-community` via `npm run db:up` |
| **CI** | GitHub Actions | Root `ci.yml` (npm); `apps/auditor-web/.github/workflows/pr-checks.yml` (pnpm lint/build) — **belum ada deploy workflow** |
| **DNS/TLS** | Vercel (custom domain) | Managed certificates |

**Diagram deployment:**

```
GitHub (4R3S monorepo)
    │
    ├── push main ──▶ GitHub Actions (verify + build)
    │
    └── Vercel Git Integration ──▶ Production Preview
              │
              ├── Edge Network (static/ISR)
              ├── Serverless Functions (sin1 / iad1 fallback)
              └── Build hook: drizzle-kit migrate (production only)

Supabase ap-southeast-1
    ├── Postgres 17 (Pro compute)
    ├── Supavisor pooler (transaction mode, port 6543)
    ├── Auth (GitHub, Web3 Solana — config.toml)
    └── Daily backup + PITR (Pro)
```

#### 2.2 Alternatif yang Ditolak

**A. Railway (monolith container)**

| Pro | Kontra (alasan penolakan) |
|-----|---------------------------|
| Deploy Next.js sebagai single container sederhana | Tidak native untuk Serverless Functions & `@vercel/sandbox`; perlu rewrite timeout handling (300s tasks) |
| Managed Postgres included | Region SEA terbatas vs Supabase `ap-southeast-1` eksplisit |
| Harga prediktif | Kehilangan edge CDN Vercel; cold start container vs function isolation |

**B. AWS ECS Fargate + RDS (self-managed)**

| Pro | Kontra |
|-----|--------|
| Kontrol penuh, multi-AZ native | Over-engineering untuk 0.05 QPS / 50 DAU |
| Compliance enterprise | Biaya baseline ~$150+/bulan (ALB + Fargate + RDS) vs ~$50–80 managed |
| | Tim kecil menanggung patching, scaling, IaC Terraform penuh |

**Catatan Neon:** `vercel-template.json` mereferensikan integrasi Neon, dan `@neondatabase/serverless` ada di `package.json`, tetapi runtime saat ini memakai `postgres` (postgres-js) via `POSTGRES_URL`. Neon tetap viable sebagai **DB aplikasi terpisah** jika Supabase dipakai hanya untuk KB — ditolak demi **satu vendor DB** dan simplifikasi operasi.

---

### 3. Wilayah dan Jaringan

#### 3.1 Region

| Komponen | Region | Catatan |
|----------|--------|---------|
| Supabase Postgres | **ap-southeast-1** (Singapore) | Align dengan user base SEA; pooler hostname pattern dari `.env.example` |
| Vercel Functions | **sin1** (Singapore) preferred | Set di Project Settings → Functions Region |
| Vercel Edge | Global | Static assets, `@vercel/analytics` |
| GitHub Actions | `ubuntu-latest` (US) | CI only; bukan runtime user-facing |
| Neo4j (opsional, agent CLI) | Neo4j Aura `ap-southeast-1` atau local Docker | **Tidak** di hot path `auditor-web` |

#### 3.2 Jaringan & Keamanan

```
Internet
   │
   ▼
[Vercel Edge] ──HTTPS──▶ [Serverless Functions]
                              │
                              ├── TLS ──▶ Supabase Pooler (6543, transaction mode)
                              │           └── IP allowlist: Vercel egress (optional Pro)
                              │
                              ├── TLS ──▶ api.github.com (OAuth)
                              │
                              └── TLS ──▶ api.vercel.com (Sandbox API)
```

**Aturan:**
- **Tidak** expose Postgres port 5432 langsung ke internet; gunakan Supavisor pooler
- Env secrets hanya di Vercel Environment Variables (Production / Preview / Development terpisah)
- `NEXT_PUBLIC_*` hanya untuk: `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `GITHUB_CLIENT_ID`, `VERCEL_CLIENT_ID`, `AUTH_PROVIDERS`
- **Jangan** commit `.env.local`; `.env.example` (root) dan README sebagai referensi

**Redirect URLs (production):**
- OAuth GitHub: `https://<domain>/api/auth/github/callback`
- OAuth Vercel: `https://<domain>/api/auth/callback/vercel`
- Supabase Auth: `https://<domain>/auth/callback` (+ Supabase Dashboard allow-list)

#### 3.3 Multi-AZ / Multi-Region

**Tidak diimplementasikan** pada fase ini.

| Requirement | Status | Justifikasi |
|-------------|--------|-------------|
| Multi-AZ Postgres | ✅ Included (Supabase Pro managed) | Cukup untuk 99.5% |
| Multi-region active-active | ❌ | 50 DAU tidak membenarkan kompleksitas + biaya 2× |
| CDN | ✅ Vercel Edge | Static/asset caching global tanpa multi-region compute |

Failover cross-region hanya dipertimbangkan jika DAU >500 **dan** availability target naik ke 99.9%.

---

### 4. Konfigurasi Sumber Daya

#### 4.1 Vercel (Compute)

| Setting | Nilai Produksi | Alasan |
|---------|----------------|--------|
| Plan | **Pro** ($20/user/bulan) | `maxDuration: 300`, team env vars, analytics |
| Framework Preset | Next.js | Auto-detect dari `apps/auditor-web` |
| Root Directory | `apps/auditor-web` | Monorepo |
| Node.js Version | **22.x** | Align CI matrix (`pr-checks.yml` uses 20; root CI tests 20+22) |
| Function Region | **sin1** | Dekat Supabase ap-southeast-1 |
| `maxDuration` | **300s** | Sudah di `vercel.json` untuk `app/api/tasks/route.ts` |

**Autoscale thresholds (Vercel Serverless):**

| Signal | Threshold | Action |
|--------|-----------|--------|
| Concurrent executions (project) | > **5** sustained 5 min | Alert Slack/email (unusual at 0.05 QPS; indikasi bug/retry loop) |
| Concurrent executions | > **20** | Page ops; review sandbox leak / missing `stop-sandbox` |
| Function duration p95 | > **120s** (non-task routes) | Investigate; normal for task routes up to 300s |
| Function duration p95 | > **280s** (task routes) | Review sandbox timeout config |
| Error rate (5xx) | > **1%** over 15 min | Alert; rollback deployment |
| Build time | > **10 min** | Optimize dependencies / turbopack cache |

**Scaling behavior:** Vercel auto-scales per invocation; pada 0.05 QPS tidak perlu konfigurasi manual instance count. Ini **bukan** satu proses long-lived — lihat §4.1.1 untuk implikasi state in-process (rate limit, cache).

#### 4.1.1 Vercel serverless vs asumsi "single instance MVP"

> **Koreksi arsitektural (2026-08-04):** **No Redis MVP** tetap benar. Yang perlu nuance: wording legacy "single instance" menyarankan satu proses dengan memori bersama; pada Vercel, compute = **banyak instance serverless konkuren** per deployment, **tanpa shared in-process state**.

| Asumsi (wording legacy) | Realitas di Vercel |
|----------------------------|-------------------|
| "Single instance MVP" | Multiple concurrent serverless instances per deployment; no shared process memory |
| In-memory rate-limit `Map` (Tier A/B/C) | Per-instance only; effective limit ≈ `limit × concurrent_instances` under burst |
| Postgres daily quota (Tier S) | Shared — correct source of truth |
| Deploy counter reset | Still true per instance; cold starts spawn fresh Maps |

**Implikasi MVP:**

- **Tier S (Postgres COUNT)** — aman cross-instance (kuota harian agent).
- **Tier A/B/C in-memory** — acceptable at ~50 DAU / low abuse, tetapi **known limitation**; monitor 429 bypass via instance fan-out.
- **In-process usage cache** (60s) — eventual consistency per instance; lihat [caching-auditor-web.md](./caching-auditor-web.md).
- **Scale path unchanged:** Redis/Upstash when 429 abuse or >200 DAU **OR** when multi-instance bypass becomes observable.

Detail tier, algoritma, dan monitoring: [rate-limiting-auditor-web.md § Vercel serverless](./rate-limiting-auditor-web.md#vercel-serverless-vs-single-instance-mvp).

#### 4.2 Supabase (Database)

| Setting | Nilai Produksi | Alasan |
|---------|----------------|--------|
| Plan | **Pro** ($25/bulan) | PITR, daily backup, pgvector, Auth hooks |
| Postgres version | **17** | Match `supabase/config.toml` (`major_version = 17`) |
| Compute | **Micro** (2 vCPU, 1 GB RAM) | Cukup untuk <1 GB data, 0.05 QPS |
| Pooler mode | **Transaction** | Serverless-friendly (Drizzle short queries) |
| `default_pool_size` | **15** | Match config local reference; adjust via dashboard |
| `max_client_conn` (pooler) | **100** | Headroom untuk burst Vercel functions |
| Connection string (app) | Port **6543** (pooler) | Hindari connection exhaustion serverless |

**Autoscale / upgrade thresholds (Supabase):**

| Signal | Threshold | Action |
|--------|-----------|--------|
| CPU utilization | > **70%** avg 15 min | Upgrade ke Small (2 vCPU, 2 GB) |
| Active connections | > **80%** of pool max | Increase pool size or review connection leaks |
| Disk usage | > **70%** of quota | Archive old task logs; upgrade storage |
| Query latency p95 | > **500ms** (non-sandbox) | EXPLAIN ANALYZE; index review |
| Replication lag | > **30s** | Supabase support ticket |

#### 4.3 Vercel Sandbox (On-demand Compute)

| Setting | Nilai | Catatan |
|---------|-------|---------|
| `resources.vcpus` | **4** (default di `lib/sandbox/config.ts`) | Per sandbox instance |
| `timeout` | **20m** default | Override via task config |
| Env required | `SANDBOX_VERCEL_TEAM_ID`, `SANDBOX_VERCEL_PROJECT_ID`, `SANDBOX_VERCEL_TOKEN` | Wajib untuk fitur coding agent |

**Budget guard:** Alert jika sandbox compute > **$50/bulan** (usage-based, di luar prediksi 50 DAU).

#### 4.4 Local Development (Referensi)

Dari `docker-compose.yml`:

| Service | Image | Port |
|---------|-------|------|
| Postgres | `postgres:16-alpine` | 5432 |
| Neo4j | `neo4j:5-community` | 7474, 7687 |

Local Supabase CLI (`supabase/config.toml`): API 54321, DB 54322, Studio 54323.

---

### 5. Infrastruktur sebagai Kode

#### 5.1 State Saat Ini

| Asset | Status | Lokasi |
|-------|--------|--------|
| Docker Compose (local) | ✅ | `/docker-compose.yml` |
| Supabase local config | ✅ | `/supabase/config.toml` |
| Vercel project config | ✅ | `/apps/auditor-web/vercel.json` |
| DB migrations (app) | ✅ | `/apps/auditor-web/lib/db/migrations/` (Drizzle) |
| DB migrations (KB) | ✅ | `/db/supabase/0001–0003_*.sql` |
| CI verify | ✅ | `/.github/workflows/ci.yml` |
| CI auditor-web | ✅ | `/apps/auditor-web/.github/workflows/pr-checks.yml` |
| **Deploy workflow** | ❌ Belum ada | Perlu ditambahkan |
| Terraform/Pulumi | ❌ Tidak ada | Managed services → minimal IaC |

#### 5.2 Target IaC Layout (dokumen saja)

```
infra/
├── vercel/
│   └── project.env.example      # Non-secret reference
├── supabase/
│   ├── config.toml              # (existing, symlink/copy)
│   └── migrations/              # (existing db/supabase/)
├── github/
│   └── workflows/
│       └── deploy-auditor-web.yml   # NEW — proposed
└── scripts/
    ├── migrate-production.ts    # (existing)
    └── seed-staging.sh
```

#### 5.3 Deploy Pipeline (Proposed)

```yaml
# .github/workflows/deploy-auditor-web.yml (PROPOSED — not provisioned)
name: Deploy Auditor Web

on:
  push:
    branches: [main]
    paths:
      - 'apps/auditor-web/**'
      - 'pnpm-lock.yaml'

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: pnpm/action-setup@v4
        with:
          version: 9

      - name: Install & verify
        working-directory: apps/auditor-web
        run: |
          pnpm install --frozen-lockfile
          pnpm typecheck
          pnpm lint
          pnpm build

      # Vercel Git Integration handles deploy on push;
      # alternatively: vercel deploy --prod --token ${{ secrets.VERCEL_TOKEN }}

      - name: Apply Supabase KB migrations (manual gate)
        if: github.ref == 'refs/heads/main'
        run: |
          # supabase db push --linked (requires SUPABASE_ACCESS_TOKEN secret)
          echo "KB migrations applied via Supabase CLI or Dashboard"
```

**Migration strategy:**

| Schema | Tool | When |
|--------|------|------|
| App (Drizzle) | `drizzle-kit migrate` | Vercel build → `scripts/migrate-production.ts` jika `VERCEL_ENV=production` |
| KB (Supabase SQL) | `supabase db push` / Dashboard SQL | Manual atau CI gated step |
| Local | `pnpm db:push` / `npm run db:up` | Developer machine |

**Build command (Vercel):**
```bash
cd apps/auditor-web && pnpm install && pnpm build && node scripts/migrate-production.ts
```

#### 5.4 Version Pinning

| Component | Pin |
|-----------|-----|
| Node.js (Vercel) | 22.x |
| Postgres (prod) | 17 (Supabase) |
| Postgres (local Docker) | 16 (compose) — **dev-only drift acceptable** |
| Next.js | 16.0.10 (`package.json`) |

---

### 6. Environment

#### 6.1 Environment Tiers

| Tier | Trigger | Database | Secrets |
|------|---------|----------|---------|
| **Local** | `pnpm dev` | Docker Postgres / Supabase local CLI | `.env.local` (gitignored) |
| **Preview** | Vercel PR deploy | Supabase branch atau staging project | Vercel Preview env |
| **Production** | Push `main` | Supabase Pro ap-southeast-1 | Vercel Production env |

#### 6.2 Variabel Environment (`apps/auditor-web`)

**Wajib (core dashboard):**

| Variable | Scope | Purpose |
|----------|-------|---------|
| `POSTGRES_URL` | Server | Drizzle — gunakan pooler URL (`?pgbouncer=true` atau port 6543) |
| `JWE_SECRET` | Server | Enkripsi sesi OAuth (≥32 char random) |
| `ENCRYPTION_KEY` | Server | Enkripsi API key user |
| `NEXT_PUBLIC_AUTH_PROVIDERS` | Client | `github`, `vercel`, comma-separated |
| `NEXT_PUBLIC_GITHUB_CLIENT_ID` | Client | GitHub OAuth app |
| `GITHUB_CLIENT_SECRET` | Server | GitHub OAuth |
| `NEXT_PUBLIC_VERCEL_CLIENT_ID` | Client | Vercel OAuth (jika enabled) |
| `VERCEL_CLIENT_SECRET` | Server | Vercel OAuth |

**Wajib (coding agent / sandbox):**

| Variable | Purpose |
|----------|---------|
| `SANDBOX_VERCEL_TEAM_ID` | Vercel Sandbox team |
| `SANDBOX_VERCEL_PROJECT_ID` | Vercel Sandbox project |
| `SANDBOX_VERCEL_TOKEN` | Vercel API token (scoped) |

**Opsional (Supabase Auth + KB browser):**

| Variable | Purpose |
|----------|---------|
| `NEXT_PUBLIC_SUPABASE_URL` | Supabase project URL |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Browser client (never service role) |

**Opsional (AI agents):**

| Variable | Purpose |
|----------|---------|
| `AI_GATEWAY_API_KEY` | Claude/Codex via gateway |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `CURSOR_API_KEY` | Per-agent fallback |

**Vercel-managed (auto-injected):**

| Variable | Purpose |
|----------|---------|
| `VERCEL_ENV` | `production` / `preview` / `development` |
| `VERCEL_URL` | Deployment URL |

#### 6.3 Root `.env` (Agent CLI — terpisah dari web)

Root `.env.example` mendefinisikan env untuk LangGraph auditor (`src/`):
- `OPENROUTER_*`, `POSTGRES_*`, `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `NEO4J_*`, `EMBEDDINGS_*`

Dashboard dan agent CLI **bisa share** Supabase project yang sama tetapi **service role key tidak pernah** masuk ke `auditor-web`.

#### 6.4 Secret Rotation

| Secret | Cadence | Method |
|--------|---------|--------|
| `JWE_SECRET` | 90 hari | Rotate → invalidate all sessions (maintenance window) |
| `ENCRYPTION_KEY` | 180 hari | Re-encrypt user keys (migration script) |
| `SANDBOX_VERCEL_TOKEN` | 90 hari | Vercel dashboard → update env |
| OAuth client secrets | On compromise | GitHub/Vercel app settings |
| Supabase service role | 180 hari | Supabase dashboard (CLI agent only) |

---

### 7. Model Biaya

#### 7.1 Estimasi Bulanan — **Sekarang (~50 DAU)**

| Item | Platform | Estimasi USD/bulan |
|------|----------|---------------------|
| Next.js hosting | Vercel Pro (1 seat) | $20 |
| Managed Postgres + Auth + Storage | Supabase Pro | $25 |
| Vercel Sandbox compute | Usage-based | $10–30 |
| Domain + DNS | Vercel / registrar | $1–2 |
| GitHub Actions | Free tier | $0 |
| Monitoring (Vercel Analytics/Speed Insights) | Included Pro | $0 |
| **Total** | | **~$56–77/bulan** |

#### 7.2 Estimasi Bulanan — **10× Scale (~500 DAU, ~0.5 QPS)**

| Item | Perubahan | Estimasi USD/bulan |
|------|-----------|---------------------|
| Vercel Pro | Same plan; monitor function invocations | $20–40 |
| Supabase | Upgrade **Small** compute + 8 GB storage | $25 → **$50** |
| Vercel Sandbox | 10× sandbox usage | $100–300 |
| Neo4j Aura (jika agent KB aktif) | Professional | $65+ |
| **Total** | | **~$185–455/bulan** |

#### 7.3 Budget Alerts (Recommended)

| Alert | Threshold | Channel |
|-------|-----------|---------|
| Total infra spend | > **$100/bulan** | Email + Slack |
| Total infra spend | > **$200/bulan** (10× prep) | Escalate to eng lead |
| Vercel Sandbox | > **$50/bulan** | Slack #infra |
| Supabase compute | > **80% CPU** sustained | Supabase dashboard |
| Vercel function invocations | > **500K/bulan** | Vercel usage dashboard |
| OpenRouter/LLM (agent, bukan web) | > **$100/bulan** | Separate billing alert |

#### 7.4 Cost Optimization (50 DAU)

- Gunakan **Supabase pooler** — hindari connection churn serverless
- Preview deployments: auto-delete after 7 hari (Vercel default)
- Sandbox: enforce `stop-sandbox` route; TTL default 20m
- Neo4j: tetap local/Docker sampai KB graph benar-benar dipakai production

---

### 8. Pemulihan Bencana

#### 8.1 Target RPO/RTO per Skenario

| Skenario | RPO | RTO | Prosedur |
|----------|-----|-----|----------|
| **Vercel deployment gagal / bad release** | 0 (stateless) | **15 menit** | Rollback ke deployment sebelumnya (Vercel dashboard → Promote) |
| **Supabase Postgres corrupt / accidental DROP** | **1 jam** (PITR Pro) | **2–4 jam** | Restore PITR ke timestamp; re-run Drizzle migrate jika perlu |
| **Supabase region outage (ap-southeast-1)** | **24 jam** (daily backup) | **8–24 jam** | Wait for Supabase recovery OR restore backup ke project baru + update `POSTGRES_URL` + redeploy |
| **Vercel platform outage** | 0 | **4–8 jam** | Monitor status.vercel.com; komunikasi ke user; no action unless >4h |
| **Secret compromise (OAuth/token leak)** | N/A | **1 jam** | Rotate secrets → redeploy → force logout (clear JWE sessions) |
| **GitHub unavailable (OAuth)** | N/A | **0** (degraded) | Existing sessions tetap; sign-in baru blocked |
| **Kehilangan seluruh Vercel project config** | 0 (git is SoT) | **2 jam** | Re-link repo; restore env vars dari secret manager backup |

#### 8.2 Backup Strategy

| Data | Method | Retention | Lokasi |
|------|--------|-----------|--------|
| Postgres (app + KB) | Supabase automated daily + **PITR 7 hari** (Pro) | 7 hari PITR, 30 hari daily | Supabase managed |
| Drizzle migrations | Git | Indefinite | GitHub `4R3S` |
| Supabase KB SQL | Git (`db/supabase/`) | Indefinite | GitHub |
| Env secrets | Vercel env + offline vault (1Password/etc.) | Last 3 rotations | Encrypted backup |
| Vercel deployment artifacts | Vercel retention | 30 hari | Vercel |

#### 8.3 DR Drill (Recommended Cadence)

| Drill | Frequency | Success Criteria |
|-------|-----------|----------------|
| Vercel rollback | Quarterly | <15 min to previous deployment |
| Supabase PITR restore to staging | Semi-annual | Data integrity verified |
| Secret rotation | Quarterly | Zero downtime sign-in |
| Full redeploy from scratch | Annual | <2h to production |

**Tidak perlu** warm standby multi-region pada fase 50 DAU / 99.5% SLA.

---

### 9. Ketergantungan Vendor

#### 9.1 Dependency Matrix

| Vendor | Komponen | Lock-in Level | Mitigasi |
|--------|----------|---------------|----------|
| **Vercel** | Next.js hosting, Sandbox, Analytics | **Tinggi** (Sandbox) | Sandbox fitur spesifik Vercel; migrasi ke Codespaces/Fly Machines butuh rewrite `lib/sandbox/*` |
| **Supabase** | Postgres, Auth, pgvector, pooler | **Sedang** | Postgres standard + Drizzle; export via `pg_dump`; Auth migrasi ke Auth0/Clerk |
| **GitHub** | OAuth, repo access, CI | **Sedang** | OAuth provider swappable (`lib/auth/providers.ts`) |
| **Neon** (dependency declared, unused runtime) | — | **Rendah** | `@neondatabase/serverless` di package.json; driver aktual `postgres` — portable |
| **OpenRouter/OpenAI** (agent) | LLM inference | **Rendah** | Abstraksi di root `src/` |

#### 9.2 Portability Assessment

| Komponen | Migrasi ke | Effort |
|----------|-----------|--------|
| Next.js app (tanpa sandbox) | Railway, Fly.io, AWS Amplify | **1–2 minggu** |
| Postgres (Drizzle) | Neon, RDS, Railway Postgres | **2–3 hari** (connection string + pooler config) |
| Supabase Auth | Auth0, Clerk, NextAuth | **2–4 minggu** (RBAC hooks, JWT claims) |
| Vercel Sandbox | GitHub Codespaces API, custom VM | **4–8 minggu** (rewrite sandbox layer) |
| CI/CD | GitHub Actions portable | **1 hari** |

#### 9.3 SLA Vendor (Referensi)

| Vendor | SLA Published | Notes |
|--------|---------------|-------|
| Vercel Pro | 99.99% (Enterprise); Pro best-effort | Cukup untuk target 99.5% platform |
| Supabase Pro | 99.9% | Align dengan target |
| GitHub | 99.9%+ | OAuth dependency |

**Composite availability estimate:** ~99.5–99.7% (single region, no redundant compute).

#### 9.4 Exit Strategy (Worst Case)

1. **Export DB:** `pg_dump` dari Supabase → import ke Neon/RDS
2. **Deploy app:** Dockerize Next.js (`next build && next start`) → Railway/Fly
3. **Disable sandbox features** sementara (feature flag) jika Vercel Sandbox unavailable
4. **Auth fallback:** GitHub OAuth via NextAuth (sudah ada pola serupa di codebase)

---

## Self-Check Checklist

- [x] Profil beban selaras constraint: ~50 DAU, 0.05 QPS, 99.5% availability
- [x] Monolith Next.js + managed Postgres (Supabase) — bukan microservices
- [x] Single region `ap-southeast-1` — multi-AZ via managed Supabase, multi-region ditolak
- [x] Managed services default (Vercel, Supabase) — ECS/Railway ditolak dengan justifikasi
- [x] Membaca `docker-compose.yml` (Postgres 16 + Neo4j local)
- [x] Membaca `apps/auditor-web/package.json` (Next 16, Drizzle, Supabase SSR, Vercel Sandbox)
- [x] Membaca `next.config.ts` (minimal — image remote patterns)
- [x] Membaca `vercel.json` (`maxDuration: 300` untuk tasks API)
- [x] Membaca `.github/workflows` — CI ada, deploy workflow belum ada (didokumentasikan)
- [x] Membaca `supabase/config.toml` (PG 17, auth Web3 Solana, project_id 4R3S)
- [x] Membaca `.env.example` (root) + README/dashboard.mdx untuk env auditor-web
- [x] Tidak kontradiksi CLAUDE.md (monorepo, managed optional DB, no GPL)
- [x] **Tidak ada provisioning nyata** — dokumen desain saja
- [x] 2 alternatif ditolak: Railway, AWS ECS Fargate (+ RDS)
- [x] Autoscale thresholds konkret (Vercel concurrent, Supabase CPU/connections)
- [x] Model biaya now (~$56–77) + 10× (~$185–455) dengan budget alerts
- [x] RPO/RTO per skenario disaster
- [x] Analisis vendor lock-in dengan exit strategy
- [x] Output dalam Bahasa Indonesia, istilah teknis diperbolehkan

---

**Catatan implementasi berikutnya (di luar scope dokumen):**
1. Buat `.env.local.example` di `apps/auditor-web` (direferensikan README tapi belum ada di repo)
2. Tambah `deploy-auditor-web.yml` GitHub Actions
3. Link Supabase project ap-southeast-1 + set Vercel env vars
4. Konfigurasi Supabase redirect URLs untuk production domain
5. Wire `migrate-production.ts` ke Vercel build command

[REDACTED]