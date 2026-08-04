# Dokumen Desain CI/CD — ARES Monorepo (Platform Engineer)

**Repositori:** `/Users/macbook/4R3S`  
**Backlog referensi:** PLAT-1 (monorepo shell), PLAT-2 (license gate), ENG-1 (core Rust)  
**Tanggal:** 4 Agustus 2026  
**Audience:** Platform Engineer, Release Manager, Tech Lead

---

## Ringkasan Eksekutif

Monorepo ARES menjalankan **empat pipeline independen** dengan package manager berbeda:

| Area | Package manager | Workflow | Trigger |
|------|-----------------|----------|---------|
| Root auditor (`src/`) | **npm** (authoritative) | `.github/workflows/ci.yml` | Semua PR/push ke `main` |
| Rust engine (`core/`) | **cargo** | `.github/workflows/core-ci.yml` | Path-filter `core/**` |
| Dashboard (`apps/auditor-web/`) | **pnpm** | ⚠️ `apps/auditor-web/.github/workflows/pr-checks.yml` **tidak dieksekusi** oleh GitHub (bukan di root `.github/workflows/`) | — |
| Offensive framework (`apps/ares-sec/`) | **npm** (isolasi) | `.github/workflows/ares-sec-ci.yml` | PR path-filter saja; **bukan** push `main` |

**Deploy target dashboard:** Vercel (`apps/auditor-web/`, `vercel.json` ada).  
**Database:** Postgres via Drizzle ORM; migrasi di `lib/db/migrations/`.  
**Railway:** Tidak ada konfigurasi di repo saat ini.

---

## 1. Strategi Cabang

### 1.1 Model Branching

```
main ────────────────────────────────────► Production (Vercel Production)
  ▲
  │ PR (required checks, squash merge preferred)
  │
feat/<BACKLOG-ID>-short-desc ─────────────► Preview (Vercel Preview per PR)
fix/<BACKLOG-ID>-short-desc
chore/<BACKLOG-ID>-short-desc
```

| Cabang | Tujuan | Deploy otomatis | CI wajib |
|--------|--------|-----------------|----------|
| `main` | Production canonical | Vercel Production + migrasi DB prod | Semua blocking gates |
| `feat/*`, `fix/*` | Feature/fix work | Vercel Preview (opsional, recommended) | Path-filtered PR checks |
| Tag `v*.*.*` | Rust binary release | GitHub Release + crates.io | `core-release.yml` + verify-claims release gate |
| `hotfix/*` | Emergency prod fix | Vercel Production (fast-track) | Minimal gate + post-merge full CI |

### 1.2 Konvensi (dari CLAUDE.md)

- **Branch:** `feat/<ID>-short-desc` (contoh: `feat/UI-3-supabase-auth`)
- **Commit:** `<ID>: <what changed>`
- **PR title:** diawali backlog ID

### 1.3 Path-Based CI (hemat waktu PR)

Hanya jalankan job yang relevan dengan diff:

| Path yang berubah | Pipeline yang jalan |
|-------------------|---------------------|
| `src/**`, `package.json`, `package-lock.json` | Root `ci.yml` → `verify`, `audit` |
| `core/**` | `core-ci.yml` (test, lint, cargo-audit) |
| `apps/auditor-web/**`, `pnpm-lock.yaml` | `auditor-web-ci.yml` (baru, di root) |
| `apps/ares-sec/**` | `ares-sec-ci.yml` |
| `eval/**` | `eval-scorer`, `verify-claims` |
| `scripts/check-*.mjs`, `core/deny.toml` | `audit` job (license + boundary) |
| Docs-only (`docs/**`, `*.md`) | Lint docs saja atau skip build (opsional) |

### 1.4 Concurrency

Semua workflow memakai pola yang sudah ada di `ci.yml`:

```yaml
concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

Push cepat ke PR yang sama membatalkan run sebelumnya — mengurangi antrian dan biaya.

---

## 2. Tahapan Pipeline

Target: **PR pipeline kritikal < 10 menit** (p95). Full audit gate boleh paralel, total wall-clock ≤ 10 menit dengan path-filter.

### 2.1 Root Auditor CI (`ci.yml`) — npm, authoritative

| Job | Langkah | Durasi target | Blocking? | Catatan |
|-----|---------|---------------|-----------|---------|
| **verify** | `npm ci` → typecheck → lint → build → test | **4–6 min** (Node 20 saja di PR) | ✅ Block | Matrix Node 20+22 hanya di push `main` |
| **audit** | npm audit, pip-audit, license npm, cargo-deny, import-boundary | **3–5 min** | ✅ Block | Golden Rule 1; jangan dilemahkan |
| **eval-scorer** | `pytest eval` | **1–2 min** | ✅ Block | Hermetic, no external services |
| **verify-claims** | fetch datasets, gate selftest, check_published_claims | **2–4 min** | ⚠️ Mixed | Missing `ares-latest.csv` = **warning**; release = **block** |

**Optimasi PR (< 10 min):**

```yaml
# PR: single Node version
strategy:
  matrix:
    node: ${{ github.event_name == 'pull_request' && fromJSON('[20]') || fromJSON('[20, 22]') }}
```

Jalankan `verify`, `audit`, `eval-scorer`, `verify-claims` **paralel** (sudah terpisah job).

### 2.2 Core CI (`core-ci.yml`) — Rust

| Job | Langkah | Durasi target | Blocking? |
|-----|---------|---------------|-------------|
| **test** | `cargo test --workspace` | **3–8 min** (cache hit: ~2 min) | ✅ Block |
| **lint** | `cargo fmt --check`, `clippy -D warnings` | **2–4 min** | ✅ Block |
| **audit** | `cargo audit` (4 ignored RUSTSEC) | **1–2 min** | ✅ Block |

Path-filter sudah benar — commit TS-only tidak memicu Rust toolchain.

### 2.3 Auditor Web CI (target: pindah ke root)

| Langkah | Script | Durasi target | Blocking? |
|---------|--------|---------------|-------------|
| Install | `pnpm install --frozen-lockfile` (filter workspace) | **1–2 min** | ✅ |
| Format | `pnpm format:check` | **~30s** | ✅ |
| Lint | `pnpm lint` | **~1 min** | ✅ |
| Typecheck | `pnpm typecheck` | **~1 min** | ✅ Block (saat ini **absent** di pr-checks lokal) |
| Build | `pnpm build` | **2–4 min** | ✅ |
| Import boundary | `node scripts/check-import-boundary.mjs` | **~10s** | ✅ (sudah di root audit) |

**Gap saat ini:** workflow di `apps/auditor-web/.github/workflows/` tidak dieksekusi GitHub Actions pada monorepo. Harus dipindah ke `.github/workflows/auditor-web-ci.yml`.

### 2.4 ares-sec CI (`ares-sec-ci.yml`)

| Langkah | Durasi | Blocking? | Catatan |
|---------|--------|-----------|---------|
| lint → typecheck → test → doctor → verify-claims → smoke | **5–10 min** | ✅ (PR saja) | Import incomplete; **tidak** di push `main` |

### 2.5 Vercel Deploy (di luar GitHub Actions)

| Tahap | Trigger | Durasi | Blocking? |
|-------|---------|--------|-------------|
| Preview build | PR open/sync | **2–5 min** | ⚠️ Warn (GitHub check via Vercel integration) |
| Production build | merge ke `main` | **3–6 min** | ✅ Block release jika build fail |
| DB migrate | post-build hook / CI step | **~30s–2 min** | ✅ Block jika migrasi gagal |

### 2.6 Diagram Alur PR (target)

```mermaid
flowchart LR
  subgraph PR["PR opened / updated"]
    PF[Path filter]
  end

  PF --> RW[Root verify npm]
  PF --> AU[Audit gates]
  PF --> EV[Eval pytest]
  PF --> VC[Verify-claims]
  PF --> AW[Auditor-web pnpm]
  PF --> CR[Core cargo - if core/**]

  RW & AU & EV & VC & AW & CR --> MERGE{All required green?}
  MERGE -->|Yes| PREV[Vercel Preview]
  MERGE -->|No| BLOCK[Block merge]
```

---

## 3. Gerbang Wajib (Mandatory Gates)

### 3.1 Daftar Gerbang — tidak boleh dilemahkan

| Gate | Implementasi | Golden Rule | Bypass? |
|------|--------------|-------------|---------|
| **License npm** | `node scripts/check-licenses.mjs` | GR-1 (copyleft) | ❌ Tidak |
| **License cargo** | `cargo-deny check licenses bans sources` | GR-1 | ❌ Tidak |
| **Import boundary** | `node scripts/check-import-boundary.mjs` | GR-1 (product safety) | ❌ Tidak |
| **npm audit high+** | `npm audit --audit-level=high` | Security | ❌ Tidak (fix atau justify) |
| **cargo audit vuln** | `cargo audit` (ignore list terdokumentasi) | Security | ❌ Tidak |
| **Core determinism** | No LLM/network/randomness in detection path | GR-2 | ❌ Code review |
| **Verify-claims README** | `check_published_claims.py` | GR-3 | ❌ Tidak |
| **Release F1 score** | `ares-latest.csv` required on release | GR-3 | ❌ Tidak |

### 3.2 Gerbang Warning (non-blocking di PR, blocking di release)

| Gate | Kondisi | PR | Release |
|------|---------|-----|---------|
| Missing eval predictions | No `eval/predictions/ares-latest.csv` | ⚠️ Warning | 🔴 Block |
| cargo-deny multiple-versions | Duplicate transitive versions | ⚠️ Warn | ⚠️ Warn |
| UNKNOWN license packages | Reported, not failed | ℹ️ Info | ℹ️ Info |

### 3.3 Siapa Bisa Bypass

| Role | Bypass mechanism | Scope | Audit trail |
|------|----------------|-------|-------------|
| **Tidak ada individu** | — | — | — |
| **Repo admin** | GitHub "bypass branch protection" | Emergency only | GitHub audit log |
| **Platform team** | Temporary workflow_dispatch dengan label `emergency-merge` | Hotfix prod down | Post-incident review wajib ≤ 24 jam |
| **Exception file** | `license-exceptions.json` (PLAT-2) | Per-package license | PR + `approvedBy` + `date` |

### 3.4 Prosedur Emergency

1. **Declare incident** — channel `#ares-incidents`, assign Incident Commander.
2. **Minimal merge path:** hotfix branch → PR dengan label `emergency` → hanya `verify` (npm) + `auditor-web build` jalan.
3. **Admin bypass** branch protection jika SLA prod terancam (> 15 menit downtime).
4. **Post-merge ≤ 4 jam:** full CI di `main` harus green; jika red, revert atau forward-fix.
5. **Post-mortem ≤ 48 jam:** dokumentasi root cause + apakah gate perlu diperketat.

---

## 4. Manajemen Artefak

### 4.1 Artefak CI (GitHub Actions)

| Artefak | Sumber | Retention | Konsumen |
|---------|--------|-----------|----------|
| `ares-eval-score` | `eval/data/score.json`, `manifest.json` | 90 hari | Release notes, compliance |
| Rust binaries | `core-release.yml` per OS/arch | GitHub Release permanent | CLI users, on-prem |
| Next.js build output | Vercel (bukan GHA artifact) | Vercel retention policy | Runtime |
| Test coverage (future) | vitest/cargo-tarpaulin | 30 hari | Dev review |

### 4.2 Cache Strategy

| Layer | Key | Path |
|-------|-----|------|
| npm | `cache: npm` di setup-node | `~/.npm` |
| pnpm | `pnpm store path` + actions/cache | `~/.pnpm-store` |
| pip | `cache: pip` | eval requirements |
| cargo | `Swatinem/rust-cache@v2` workspaces: core | `target/` |

### 4.3 Registry & Lockfiles

| Package manager | Lockfile | CI command | Catatan |
|-----------------|----------|------------|---------|
| Root auditor | `package-lock.json` | `npm ci` | **Authoritative** untuk TS agent |
| auditor-web | `pnpm-lock.yaml` (root) | `pnpm install --frozen-lockfile` | Workspace monorepo |
| ares-sec | `apps/ares-sec/package-lock.json` | `npm ci` | Isolated, own cache path |

**Jangan** campur `npm install` dan `pnpm install` di direktori yang sama.

---

## 5. Promosi Environment

### 5.1 Environment Matrix

| Environment | Branch/Trigger | Vercel | Database | URL pattern |
|-------------|----------------|--------|----------|-------------|
| **Local** | dev machine | — | Docker Compose (`npm run db:up`) | `localhost:3000` |
| **Preview** | PR → Vercel | Preview deployment | Neon/Supabase branch DB (recommended) atau shared staging | `*.vercel.app` |
| **Staging** | `main` (opsional dedicated) | Production project, staging domain | Staging Postgres | `staging.auditor.example.com` |
| **Production** | merge `main` | Production | Production Postgres | `app.auditor.example.com` |

### 5.2 Promosi Flow

```
Local dev
  │  pnpm db:push (dev only) / db:generate + commit migration
  ▼
PR Preview (Vercel)
  │  db:migrate against preview/staging DB (via CI or Vercel build command)
  ▼
Merge main
  │  db:migrate against production DB (blocking step)
  ▼
Production live
```

### 5.3 Konfigurasi Vercel Monorepo

**Project Settings (dashboard Vercel):**

- **Root Directory:** `apps/auditor-web`
- **Framework:** Next.js
- **Build Command:** `pnpm build` (dari root: `cd ../.. && pnpm --filter ares-auditor-web build`)
- **Install Command:** `pnpm install --frozen-lockfile` (dari monorepo root)
- **Node.js Version:** 20.x

**`vercel.json` (sudah ada):**

```json
{
  "functions": {
    "app/api/tasks/route.ts": { "maxDuration": 300 }
  }
}
```

### 5.4 Environment Variables per Tier

| Variable | Preview | Staging | Production |
|----------|---------|---------|------------|
| `POSTGRES_URL` | Preview DB URL | Staging URL | Prod URL (encrypted) |
| `JWE_SECRET` | Staging secret | Staging secret | Unique prod secret |
| `ENCRYPTION_KEY` | Staging | Staging | Unique prod |
| `GITHUB_CLIENT_SECRET` | OAuth app preview | Staging app | Prod OAuth app |
| `NEXT_PUBLIC_*` | Preview values | Staging | Production |

---

## 6. Migrasi Database dalam Pipeline

### 6.1 Toolchain

- **ORM:** Drizzle (`drizzle-orm` + `drizzle-kit`)
- **Config:** `apps/auditor-web/drizzle.config.ts`
- **Schema:** `apps/auditor-web/lib/db/schema.ts`
- **Migrations:** `apps/auditor-web/lib/db/migrations/` (22+ migration files)
- **Env var wajib:** `POSTGRES_URL`

```typescript
// drizzle.config.ts — ringkasan
config({ path: '.env.local' })
config({ path: '.env' })
// POSTGRES_URL required; throws if missing
```

### 6.2 Scripts

| Script | Perintah | Kapan dipakai |
|--------|----------|---------------|
| Generate | `pnpm db:generate` | Developer lokal setelah schema change |
| Migrate | `pnpm db:migrate` | CI deploy + production |
| Push | `pnpm db:push` | **Hanya local dev** — jangan di CI/prod |
| Studio | `pnpm db:studio` | Local debug |

### 6.3 Pipeline Integration

**PR CI (validasi, tanpa DB live):**

```yaml
- name: Validate migration SQL syntax
  working-directory: apps/auditor-web
  run: |
    # Pastikan migration files ada dan journal konsisten
    test -f lib/db/migrations/meta/_journal.json
    pnpm exec drizzle-kit check  # jika tersedia di versi drizzle-kit
```

**Preview deploy:**

```bash
# Vercel Build Command (append) atau GitHub Actions pre-deploy
export POSTGRES_URL="$PREVIEW_POSTGRES_URL"
pnpm --filter ares-auditor-web db:migrate
pnpm --filter ares-auditor-web build
```

**Production deploy (blocking):**

```yaml
- name: Run database migrations
  working-directory: apps/auditor-web
  env:
    POSTGRES_URL: ${{ secrets.PRODUCTION_POSTGRES_URL }}
  run: pnpm db:migrate

- name: Deploy to Vercel
  # Hanya jalan jika migrate sukses
```

### 6.4 Aturan Keamanan Migrasi

1. **Forward-only** di production — no `db:push`, no manual DDL.
2. **Backward-compatible migrations** — expand/contract pattern untuk zero-downtime.
3. **Migration review** — PR yang menyentuh `lib/db/migrations/**` wajib review Platform Engineer.
4. **Rollback DB** — restore dari backup + deploy commit sebelumnya (bukan `drizzle down` otomatis).
5. **Preview DB isolation** — gunakan Neon branch atau schema-per-PR; jangan share prod URL ke preview.

---

## 7. Secret dalam CI

### 7.1 GitHub Secrets (repository / environment)

| Secret | Environment | Digunakan oleh |
|--------|-------------|----------------|
| `PRODUCTION_POSTGRES_URL` | `production` | db:migrate prod |
| `PREVIEW_POSTGRES_URL` | `preview` | db:migrate preview |
| `CARGO_REGISTRY_TOKEN` | release | `core-release.yml` → crates.io |
| `VERCEL_TOKEN` | deploy | Vercel CLI / GitHub integration |
| `VERCEL_ORG_ID` | deploy | Vercel project linking |
| `VERCEL_PROJECT_ID` | deploy | auditor-web project |

### 7.2 Vercel Environment Variables

Disimpan di Vercel dashboard per environment (Production / Preview / Development):

```
POSTGRES_URL
JWE_SECRET
ENCRYPTION_KEY
GITHUB_CLIENT_SECRET
NEXT_PUBLIC_GITHUB_CLIENT_ID
NEXT_PUBLIC_AUTH_PROVIDERS
NEXT_PUBLIC_SUPABASE_URL      # optional
NEXT_PUBLIC_SUPABASE_ANON_KEY # optional
SANDBOX_VERCEL_TOKEN          # optional, task sandbox
SANDBOX_VERCEL_TEAM_ID
SANDBOX_VERCEL_PROJECT_ID
```

### 7.3 Prinsip Keamanan

| Prinsip | Implementasi |
|---------|--------------|
| Least privilege | GitHub environments: `preview` vs `production` dengan approval gate |
| No secrets in logs | AGENTS.md: static log strings only; redact di `lib/utils/logging.ts` |
| No `.env.local` in git | `.gitignore`; CI inject via secrets |
| Rotation | OAuth secrets + JWE quarterly; POSTGRES creds on incident |
| Fork PR safety | Secrets tidak exposed ke fork PR (GitHub default) |

### 7.4 Local vs CI

```bash
# Local (apps/auditor-web/.env.local — NEVER commit)
POSTGRES_URL=postgres://ares:ares_dev_password@localhost:5432/ares
JWE_SECRET=<random-32+-chars>
ENCRYPTION_KEY=<random-32+-chars>
```

Docker Postgres dari root: `npm run db:up`

---

## 8. Rollback

### 8.1 Application Rollback (Vercel)

| Metode | Kecepatan | Kapan |
|--------|-----------|-------|
| **Instant Rollback** (Vercel dashboard) | < 1 menit | Build/runtime error post-deploy |
| **Redeploy previous commit** | 3–6 menit | Rollback ke known-good SHA |
| **Revert PR di GitHub** | 5–10 menit | Fix forward tidak feasible |

**Prosedur:**

1. Identifikasi last-known-good deployment di Vercel.
2. Klik **Promote to Production** pada deployment tersebut.
3. Jika DB schema berubah: lihat §8.2 sebelum promote.

### 8.2 Database Rollback

| Scenario | Action |
|----------|--------|
| Migrasi gagal mid-deploy | Deploy **tidak dilanjutkan**; fix migration, re-run |
| Migrasi sukses, app broken | App rollback Vercel; DB **tetap** (backward-compatible migration) |
| Breaking migration deployed | Restore DB dari snapshot pre-migrate + app rollback |

**Backup policy (recommended):**

- Neon/Supabase: point-in-time recovery (PITR) enabled
- Pre-migrate snapshot hook di production pipeline

### 8.3 Rust Release Rollback

- GitHub Release artifacts immutable — yank crate di crates.io jika publish salah
- Tag deletion discouraged; gunakan patch tag `vX.Y.Z+1`

### 8.4 Rollback Decision Matrix

```
App broken + DB unchanged     → Vercel instant rollback
App broken + DB expanded only   → Vercel rollback (old app still compatible)
App broken + DB breaking      → PITR restore + rollback + incident review
```

---

## 9. Definisi Pipeline (YAML Skeleton)

### 9.1 Auditor Web CI — `.github/workflows/auditor-web-ci.yml` (BARU, pindah dari subdirectory)

```yaml
name: Auditor Web CI

on:
  pull_request:
    branches: [main]
    paths:
      - 'apps/auditor-web/**'
      - 'pnpm-lock.yaml'
      - 'pnpm-workspace.yaml'
      - '.github/workflows/auditor-web-ci.yml'
  push:
    branches: [main]
    paths:
      - 'apps/auditor-web/**'
      - 'pnpm-lock.yaml'

concurrency:
  group: auditor-web-${{ github.ref }}
  cancel-in-progress: true

permissions:
  contents: read

defaults:
  run:
    working-directory: apps/auditor-web

jobs:
  checks:
    name: lint · typecheck · build
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4

      - uses: pnpm/action-setup@v4
        with:
          version: 9

      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: pnpm

      - name: Install dependencies
        run: pnpm install --frozen-lockfile
        working-directory: ${{ github.workspace }}

      - name: Format check
        run: pnpm format:check

      - name: Lint
        run: pnpm lint

      - name: Typecheck
        run: pnpm typecheck

      - name: Build
        run: pnpm build
        env:
          # Build-time placeholders — no real secrets needed for compile
          POSTGRES_URL: postgres://ci:ci@localhost:5432/ci
          JWE_SECRET: ci-jwe-secret-minimum-32-characters
          ENCRYPTION_KEY: ci-encryption-key-min-32-chars

  boundary:
    name: import-boundary (auditor-web scope)
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - name: Import-boundary check
        run: node scripts/check-import-boundary.mjs
```

### 9.2 Auditor Web Deploy + Migrate — `.github/workflows/auditor-web-deploy.yml`

```yaml
name: Auditor Web Deploy

on:
  push:
    branches: [main]
    paths:
      - 'apps/auditor-web/**'
      - 'pnpm-lock.yaml'

concurrency:
  group: auditor-web-deploy-production
  cancel-in-progress: false  # jangan cancel deploy prod

jobs:
  migrate-and-deploy:
    name: migrate → deploy production
    runs-on: ubuntu-latest
    environment: production  # GitHub environment dengan approval optional
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4

      - uses: pnpm/action-setup@v4
        with:
          version: 9

      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: pnpm

      - name: Install
        run: pnpm install --frozen-lockfile

      - name: Run database migrations
        working-directory: apps/auditor-web
        env:
          POSTGRES_URL: ${{ secrets.PRODUCTION_POSTGRES_URL }}
        run: pnpm db:migrate

      - name: Deploy to Vercel
        uses: amondnet/vercel-action@v25  # atau official Vercel GitHub integration
        with:
          vercel-token: ${{ secrets.VERCEL_TOKEN }}
          vercel-org-id: ${{ secrets.VERCEL_ORG_ID }}
          vercel-project-id: ${{ secrets.VERCEL_PROJECT_ID }}
          working-directory: apps/auditor-web
          vercel-args: '--prod'
```

> **Alternatif recommended:** biarkan Vercel GitHub Integration handle deploy otomatis; jalankan `db:migrate` sebagai step terpisah di GHA **sebelum** merge (via required check) atau via Vercel `buildCommand` hook.

### 9.3 Root CI — catatan perbaikan (`ci.yml`)

Tidak perlu rewrite penuh. Tambahkan path-filter opsional untuk PR:

```yaml
# Tambahan opsional di ci.yml — job verify
on:
  pull_request:
    paths-ignore:
      - 'apps/ares-sec/**'
      - 'docs/**'
      - '**.md'
```

Dan single-node matrix di PR (lihat §2.1).

### 9.4 Core CI — sudah production-ready

Tetap di `.github/workflows/core-ci.yml` — path-filter `core/**` sudah optimal.

### 9.5 Branch Protection Rules (GitHub Settings)

**Required checks untuk merge ke `main`:**

| Check name | Source workflow |
|------------|-----------------|
| `verify (node 20)` | `ci.yml` |
| `dependency audit` | `ci.yml` |
| `eval scorer (python)` | `ci.yml` |
| `Verify-Claims release gate` | `ci.yml` |
| `lint · typecheck · build` | `auditor-web-ci.yml` (baru) |
| `Test` / `Lint and Format` | `core-ci.yml` (jika core changed — via ruleset opsional) |

---

## Self-Check Checklist

### Akurasi terhadap repo saat ini

- [x] Root CI memakai **npm** (`npm ci`, `npm run typecheck/lint/build/test`) — authoritative per CLAUDE.md
- [x] `apps/auditor-web` memakai **pnpm** (`pnpm install`, scripts di `package.json`)
- [x] Golden Rule gates: `check-licenses.mjs`, `cargo-deny`, `check-import-boundary.mjs` sudah di `ci.yml` audit job
- [x] `core-ci.yml` path-filtered; `ares-sec-ci.yml` PR-only, no main push
- [x] `drizzle.config.ts` requires `POSTGRES_URL`; migrations di `lib/db/migrations/`
- [x] `vercel.json` exists (function timeout 300s); no Railway config
- [x] Gap documented: `apps/auditor-web/.github/workflows/pr-checks.yml` **tidak jalan** di monorepo GitHub

### Target PR < 10 menit

- [x] Path-filter per area codebase
- [x] Parallel jobs (verify || audit || eval || verify-claims)
- [x] Single Node matrix di PR (20 only); dual (20+22) di push main
- [x] Rust CI skipped untuk non-core PRs
- [x] pnpm/npm/cargo cache configured
- [x] `cancel-in-progress: true` untuk dedup runs

### Keamanan & compliance

- [x] No bypass individual untuk license/import-boundary gates
- [x] Emergency procedure documented
- [x] Secrets scoped per environment
- [x] `db:push` forbidden in prod pipeline
- [x] AGENTS.md log redaction policy referenced

### Action items untuk Platform Engineer

1. **Pindahkan** `apps/auditor-web/.github/workflows/pr-checks.yml` → `.github/workflows/auditor-web-ci.yml` + tambah `typecheck` + path-filter
2. **Konfigurasi Vercel** monorepo root directory = `apps/auditor-web`
3. **Setup GitHub Environment** `production` dengan `PRODUCTION_POSTGRES_URL`
4. **Branch protection** — wire required checks setelah auditor-web-ci green
5. **Neon/Supabase branch DB** untuk preview migrations
6. **Re-enable** `ares-sec-ci.yml` push main setelah import SEC-1 complete

---

*Dokumen ini mencerminkan state repo per 4 Agustus 2026. Update saat PLAT-1 migration (`src/` → `packages/*`) selesai dan turbo pipeline aktif.*

[REDACTED]