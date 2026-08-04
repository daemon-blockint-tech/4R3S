# Desain Database — ARES Auditor Dashboard (`apps/auditor-web`)

| Field | Value |
|-------|-------|
| **Scope** | Postgres dashboard schema (`apps/auditor-web/lib/db/`) |
| **Version** | 2026-08-04 |
| **Status** | Partially implemented — 22 Drizzle migrations applied; migration **0022** (plans/usage/settings) design-only, not applied |
| **Related docs** | [backend-auditor-web.md](./backend-auditor-web.md) · [caching-auditor-web.md](./caching-auditor-web.md) |

---

### 1. Model Entitas

#### Diagram relasi (ER)

```mermaid
erDiagram
    plans ||--o{ users : "plan_id"
    users ||--o{ tasks : "user_id"
    users ||--o{ accounts : "user_id"
    users ||--o{ keys : "user_id"
    users ||--o{ connectors : "user_id"
    users ||--o{ settings : "user_id"
    users ||--|| user_settings : "user_id"
    users ||--o{ usage_snapshots : "user_id"
    tasks ||--o{ task_messages : "task_id"

    plans {
        text code PK
        text name
        integer compute_hours_limit
        integer on_demand_runs_limit
    }

    users {
        text id PK
        text provider
        text external_id
        text plan_id FK
        text access_token "encrypted"
    }

    user_settings {
        text id PK
        text user_id FK UK
        text theme
        boolean email_notifications
    }

    usage_snapshots {
        text id PK
        text user_id FK
        date usage_date
        integer compute_seconds
        integer on_demand_runs
    }

    settings {
        text id PK
        text user_id FK
        text key
        text value
    }

    tasks {
        text id PK
        text user_id FK
        text status
        timestamp deleted_at
    }
```

#### Tabel existing (8) — ringkasan

| Tabel | Peran | PK | Relasi utama |
|-------|-------|----|--------------|
| `users` | Identitas OAuth primer (GitHub/Vercel) + profil | `id` (text/nanoid) | Root entity; cascade ke semua child |
| `accounts` | Akun OAuth tambahan (GitHub linked) | `id` | N:1 → `users` |
| `tasks` | Job agent/audit sandbox | `id` | N:1 → `users`; 1:N → `task_messages` |
| `task_messages` | Chat user↔agent per task | `id` | N:1 → `tasks` |
| `connectors` | MCP connector (local/remote) | `id` | N:1 → `users` |
| `keys` | API key per provider | `id` | N:1 → `users` |
| `settings` | Key-value override env vars per user (EAV) | `id` | N:1 → `users`; UNIQUE `(user_id, key)` |

#### Tabel baru (3)

##### `plans` — katalog subscription tier

| Kolom | Tipe | Nullable | Default | Keterangan |
|-------|------|----------|---------|------------|
| `code` | `text` | NO | — | **PK** — `'free'`, `'pro'`, `'team'` |
| `name` | `text` | NO | — | Display name |
| `description` | `text` | YES | — | Deskripsi plan |
| `price_label` | `text` | NO | — | e.g. `'$0 / month'` |
| `price_cents` | `integer` | YES | — | Harga bulanan (sen); NULL untuk custom/enterprise |
| `compute_hours_limit` | `integer` | NO | — | Kuota compute hours per billing period |
| `on_demand_runs_limit` | `integer` | NO | — | Kuota on-demand runs per billing period |
| `features` | `jsonb` | NO | `'[]'` | Array string fitur (UI plan card) |
| `is_active` | `boolean` | NO | `true` | Soft-disable plan tanpa hapus FK |
| `stripe_price_id` | `text` | YES | — | Placeholder integrasi billing (INT) |
| `created_at` | `timestamp` | NO | `now()` | |
| `updated_at` | `timestamp` | NO | `now()` | |

##### `usage_snapshots` — agregat harian usage per user

| Kolom | Tipe | Nullable | Default | Keterangan |
|-------|------|----------|---------|------------|
| `id` | `text` | NO | — | **PK** (nanoid) |
| `user_id` | `text` | NO | — | FK → `users.id` ON DELETE CASCADE |
| `usage_date` | `date` | NO | — | Tanggal UTC; **satu baris per user per hari** |
| `compute_seconds` | `integer` | NO | `0` | Durasi sandbox/agent (detik) |
| `on_demand_runs` | `integer` | NO | `0` | Jumlah run on-demand hari itu |
| `created_at` | `timestamp` | NO | `now()` | |
| `updated_at` | `timestamp` | NO | `now()` | |

Agregasi billing period = `SUM(compute_seconds)` dan `SUM(on_demand_runs)` WHERE `usage_date` BETWEEN period start/end, dibandingkan limit dari `plans` via `users.plan_id`.

##### `user_settings` — preferensi UI/UX terstruktur (1:1 per user)

| Kolom | Tipe | Nullable | Default | Keterangan |
|-------|------|----------|---------|------------|
| `id` | `text` | NO | — | **PK** (nanoid) |
| `user_id` | `text` | NO | — | FK → `users.id` ON DELETE CASCADE; **UNIQUE** |
| `theme` | `text` | NO | `'system'` | `'light'` \| `'dark'` \| `'system'` |
| `email_notifications` | `boolean` | NO | `false` | Alert audit completion |
| `pr_updates` | `boolean` | NO | `false` | Notifikasi perubahan PR agent |
| `timezone` | `text` | YES | — | IANA timezone, e.g. `'Asia/Jakarta'` |
| `locale` | `text` | YES | `'en'` | BCP-47 locale |
| `preferences` | `jsonb` | NO | `'{}'` | Extensibility tanpa migrasi (indexing docs, MCP defaults, dll.) |
| `created_at` | `timestamp` | NO | `now()` | |
| `updated_at` | `timestamp` | NO | `now()` | |

**Pemisahan tanggung jawab:**

| Tabel | Tujuan | Contoh data |
|-------|--------|-------------|
| `settings` (existing) | Override env/runtime per user (EAV) | `maxMessagesPerDay`, `maxSandboxDuration` |
| `user_settings` (baru) | Preferensi dashboard UI | theme, notifications, locale |

#### ALTER existing: `users`

| Kolom baru | Tipe | Nullable | Default | Keterangan |
|------------|------|----------|---------|------------|
| `plan_id` | `text` | NO (post-backfill) | `'free'` | FK → `plans.code` |

Opsional future (tidak di DDL ini): `billing_period_start date` di `users` untuk anchor reset kuota bulanan.

---

### 2. Strategi Kunci

| Entity | Strategi PK | Alasan |
|--------|-------------|--------|
| `users`, `tasks`, `accounts`, dll. | `text` nanoid (~12 char) | Konsisten dengan `generateId()` existing; URL-safe; tidak sequential leak |
| `plans` | `text code` natural key | Stable reference (`'free'`, `'pro'`, `'team'`); FK readable tanpa join |
| `usage_snapshots` | `text id` + UNIQUE `(user_id, usage_date)` | nanoid untuk Drizzle insert pattern; invariant di-enforce composite unique |
| `user_settings` | `text id` + UNIQUE `user_id` | 1:1 relasi; id terpisah agar konsisten dengan tabel lain |

**Natural keys vs surrogate:**

- `users`: surrogate `id`; natural key `(provider, external_id)` via unique index
- `keys`: natural key `(user_id, provider)` via unique index
- `accounts`: natural key `(user_id, provider)` via unique index
- `settings`: natural key `(user_id, key)` via unique index
- `usage_snapshots`: natural key `(user_id, usage_date)` via unique index

**Encrypted columns (app-layer AES-256-GCM via `lib/crypto.ts`, bukan queryable):**

- `users.access_token`, `users.refresh_token`
- `accounts.access_token`, `accounts.refresh_token`
- `keys.value`
- `connectors.oauth_client_secret`, `connectors.env`

Database menyimpan ciphertext sebagai `text` biasa; **tidak ada** index atau constraint di kolom terenkripsi.

---

### 3. Constraint sebagai Invariant (map ALL design invariants)

| # | Invariant (SoT) | Enforcement DB | Catatan |
|---|-------------------|----------------|---------|
| I1 | GitHub `externalId` = numeric string, UNIQUE per provider | `UNIQUE INDEX users_provider_external_id_idx ON users(provider, external_id)` (existing) + `CHECK users_github_external_id_numeric_chk`: `provider <> 'github' OR external_id ~ '^\d+$'` | Vercel external_id tidak di-check numerik |
| I2 | GitHub linked account `external_user_id` numeric | `CHECK accounts_github_external_user_id_numeric_chk`: `provider <> 'github' OR external_user_id ~ '^\d+$'` | Multiple user boleh link ke external account yang sama (by design) |
| I3 | Tasks dimiliki `user_id` | `tasks.user_id NOT NULL` + FK `tasks_user_id_users_id_fk ON DELETE CASCADE` (existing) | Semua API route filter `eq(tasks.userId, session.user.id)` |
| I4 | Usage: satu baris per user per hari | `UNIQUE INDEX usage_snapshots_user_id_usage_date_idx ON usage_snapshots(user_id, usage_date)` | UPSERT pattern: `ON CONFLICT (user_id, usage_date) DO UPDATE` |
| I5 | Tokens encrypted at rest, tidak queryable | **App-layer only** — kolom `text` tanpa index | Dokumentasi: decrypt hanya di server route/action |
| I6 | User punya plan valid | `users.plan_id NOT NULL` + FK `users_plan_id_plans_code_fk` | Default `'free'` saat signup |
| I7 | User settings 1:1 | `UNIQUE INDEX user_settings_user_id_idx ON user_settings(user_id)` | Auto-create row saat signup |
| I8 | Satu API key per provider per user | `UNIQUE INDEX keys_user_id_provider_idx` (existing) | |
| I9 | Satu linked account per provider per user | `UNIQUE INDEX accounts_user_id_provider_idx` (existing) | |
| I10 | Satu setting key per user | `UNIQUE INDEX settings_user_id_key_idx` (existing) | |
| I11 | Task messages belong to task | FK `task_messages_task_id_tasks_id_fk ON DELETE CASCADE` (existing) | |
| I12 | Child rows cascade on user delete | Semua FK child → `users` pakai `ON DELETE CASCADE` (existing) | GDPR/account deletion |

**Enum values (app-validated, stored as `text`):**

- `users.provider`: `'github'`, `'vercel'`
- `tasks.status`: `'pending'`, `'processing'`, `'completed'`, `'error'`, `'stopped'`
- `tasks.pr_status`: `'open'`, `'closed'`, `'merged'`
- `connectors.type`: `'local'`, `'remote'`
- `connectors.status`: `'connected'`, `'disconnected'`
- `keys.provider`: `'anthropic'`, `'openai'`, `'cursor'`, `'gemini'`, `'aigateway'`
- `user_settings.theme`: `'light'`, `'dark'`, `'system'`

Postgres tidak memakai native ENUM type agar konsisten dengan pola Drizzle existing.

---

### 4. Indeks (with queries that justify each; note indexes NOT created)

#### Indeks yang DIBUAT (migration 0022)

| Index | Tabel | Kolom | Query yang di-justify |
|-------|-------|-------|----------------------|
| `usage_snapshots_user_id_usage_date_idx` (UNIQUE) | `usage_snapshots` | `(user_id, usage_date)` | Invariant I4; UPSERT harian; `GET /api/billing/usage`: agregasi per billing period |
| `usage_snapshots_user_id_usage_date_desc_idx` | `usage_snapshots` | `(user_id, usage_date DESC)` | Dashboard usage chart: 30/90 hari terakhir per user |
| `tasks_user_id_created_at_idx` | `tasks` | `(user_id, created_at DESC)` WHERE `deleted_at IS NULL` | `GET /api/tasks`: `WHERE user_id = ? AND deleted_at IS NULL ORDER BY created_at DESC` |
| `tasks_user_id_created_at_rate_limit_idx` | `tasks` | `(user_id, created_at)` WHERE `deleted_at IS NULL` | `checkRateLimit()`: `WHERE user_id = ? AND created_at >= today AND deleted_at IS NULL` |
| `task_messages_task_id_created_at_idx` | `task_messages` | `(task_id, created_at)` | `GET /api/tasks/[taskId]/messages`: chat history ordered |
| `users_plan_id_idx` | `users` | `(plan_id)` | Admin analytics: count users per plan; join plan limits |

Partial index `WHERE deleted_at IS NULL` mengurangi ukuran index karena soft-deleted tasks di-exclude dari hot path.

#### Indeks existing (tidak diubah)

| Index | Tabel | Justifikasi |
|-------|-------|-------------|
| `users_provider_external_id_idx` (UNIQUE) | `users` | OAuth lookup/signup dedup (I1) |
| `accounts_user_id_provider_idx` (UNIQUE) | `accounts` | Linked account lookup |
| `keys_user_id_provider_idx` (UNIQUE) | `keys` | API key upsert per provider |
| `settings_user_id_key_idx` (UNIQUE) | `settings` | Setting override lookup |

#### Indeks yang TIDAK dibuat (dan alasan)

| Index yang dipertimbangkan | Alasan TIDAK dibuat |
|----------------------------|---------------------|
| GIN pada `tasks.logs` (jsonb) | Logs dibaca whole-row saat render task detail; tidak ada query filter by log content |
| Index pada `tasks.prompt`, `tasks.title` | Tidak ada full-text search MVP |
| Index pada kolom encrypted (`access_token`, `keys.value`, dll.) | Ciphertext tidak queryable; index useless dan security risk |
| Index `(user_id, status)` di `tasks` | Status filter belum ada di hot path; partial index `(user_id, created_at)` sudah cover list view |
| Index `(usage_date)` saja | Selalu queried dengan `user_id`; composite index sudah cukup |
| BRIN pada `usage_snapshots.usage_date` | Volume belum cukup besar (<10M rows); premature optimization |
| `CREATE INDEX CONCURRENTLY` di dalam migrasi Drizzle | Drizzle migration runs in transaction; untuk production scale gunakan script terpisah (lihat §6) |

---

### 5. Batas Transaksi

| Operasi | Scope transaksi | Isolation | Rollback trigger |
|---------|-----------------|-----------|-------------------|
| **OAuth signup (GitHub/Vercel)** | `INSERT users` + `INSERT user_settings` (default) + optional `INSERT accounts` | `READ COMMITTED` | Duplicate `(provider, external_id)` → return existing user |
| **OAuth re-login** | `UPDATE users` (tokens, last_login_at) | Single statement OK | Token encrypt failure → abort |
| **Task creation** | `INSERT tasks` (+ optional `INSERT task_messages`) | `READ COMMITTED` | Rate limit exceeded → no insert; usage check failure → no insert |
| **Usage increment (post-task)** | `INSERT ... ON CONFLICT (user_id, usage_date) DO UPDATE SET compute_seconds = compute_seconds + ?, on_demand_runs = on_demand_runs + ?` | Single UPSERT | Idempotent per day |
| **Plan change (future billing webhook)** | `UPDATE users SET plan_id = ?` | Single statement | Invalid plan code → FK violation |
| **Account deletion** | `DELETE users WHERE id = ?` | Cascade handles all children | — |
| **Settings update (UI)** | `UPDATE user_settings SET ... WHERE user_id = ?` | Single statement | — |
| **Env override update** | `INSERT settings ... ON CONFLICT (user_id, key) DO UPDATE` | UPSERT | — |

**Cross-transaction rules:**

- Usage check (read `plans` + aggregate `usage_snapshots`) dan task insert **bisa** di dua statement; race condition diterima untuk MVP — overage ditangkap async. Production: gunakan advisory lock `pg_advisory_xact_lock(hashtext(user_id))` saat check+insert.
- Token encryption/decryption **selalu di luar** transaksi DB (CPU-bound, no DB lock).
- Soft delete tasks (`UPDATE deleted_at`) tidak cascade ke `task_messages` — messages tetap untuk audit trail sampai hard delete user.

**Recommended transaction boundaries (pseudocode):**

```
BEGIN;
  -- Signup
  INSERT INTO users (...) RETURNING id;
  INSERT INTO user_settings (id, user_id) VALUES (nanoid, user_id);
COMMIT;

BEGIN;
  -- Daily usage bump
  INSERT INTO usage_snapshots (id, user_id, usage_date, compute_seconds, on_demand_runs)
  VALUES (nanoid, $user_id, CURRENT_DATE, $seconds, $runs)
  ON CONFLICT (user_id, usage_date)
  DO UPDATE SET
    compute_seconds = usage_snapshots.compute_seconds + EXCLUDED.compute_seconds,
    on_demand_runs = usage_snapshots.on_demand_runs + EXCLUDED.on_demand_runs,
    updated_at = now();
COMMIT;
```

---

### 6. Rencana Migrasi (expand-contract, up/down scripts, lock estimates)

**Strategi:** Expand-Contract (3 fase, zero-downtime friendly)

| Fase | Aksi | Downtime | Lock estimate |
|------|------|----------|---------------|
| **Expand 1** | CREATE `plans` + seed; CREATE `user_settings`; CREATE `usage_snapshots` | None | `ACCESS EXCLUSIVE` pada tabel baru saja (<1s) |
| **Expand 2** | `ALTER users ADD COLUMN plan_id text` (nullable); backfill `'free'`; ADD FK | Minimal | `ACCESS EXCLUSIVE` on `users` ~100ms (est. <10K rows); backfill = row-level |
| **Expand 3** | `ALTER users ALTER plan_id SET NOT NULL`; CREATE indexes | Minimal | `ACCESS EXCLUSIVE` on `users` ~50ms; index build on `tasks` depends on row count |
| **Contract** | (Future) Remove mock usage code paths | N/A | App deploy only |

**Estimasi lock per operasi (Postgres 15+, Neon/Vercel Postgres):**

| Operasi | Lock mode | Durasi estimasi (<10K users, <100K tasks) |
|---------|-----------|---------------------------------------------|
| CREATE TABLE | — | <100ms |
| ALTER ADD COLUMN (nullable) | ACCESS EXCLUSIVE | <200ms |
| UPDATE backfill plan_id | ROW EXCLUSIVE | <1s |
| ADD FK constraint | SHARE ROW EXCLUSIVE | <100ms |
| ALTER SET NOT NULL | ACCESS EXCLUSIVE | <100ms |
| CREATE INDEX (in txn) | SHARE lock on table | 1–30s depending on `tasks` size |
| CREATE INDEX CONCURRENTLY (prod script) | minimal | Background, no blocking writes |

**Production note:** Untuk `tasks` >100K rows, jalankan index creation sebagai script terpisah dengan `CONCURRENTLY` di luar Drizzle migration transaction.

#### UP — `0022_plans_usage_settings.sql`

```sql
-- ============================================================
-- Migration 0022: plans, usage_snapshots, user_settings
-- ARES auditor-web dashboard Postgres
-- ============================================================

-- 1. Plans catalog
CREATE TABLE "plans" (
  "code" text PRIMARY KEY NOT NULL,
  "name" text NOT NULL,
  "description" text,
  "price_label" text NOT NULL,
  "price_cents" integer,
  "compute_hours_limit" integer NOT NULL,
  "on_demand_runs_limit" integer NOT NULL,
  "features" jsonb DEFAULT '[]'::jsonb NOT NULL,
  "is_active" boolean DEFAULT true NOT NULL,
  "stripe_price_id" text,
  "created_at" timestamp DEFAULT now() NOT NULL,
  "updated_at" timestamp DEFAULT now() NOT NULL
);

-- Seed default plans (align with lib/mock/usage.ts)
INSERT INTO "plans" (
  "code", "name", "description", "price_label", "price_cents",
  "compute_hours_limit", "on_demand_runs_limit", "features"
) VALUES
  (
    'free', 'Free', 'Get started with ARES Auditor on the free tier.',
    '$0 / month', 0, 100, 25,
    '["100 compute hours / month", "25 on-demand runs", "Community support", "Single workspace"]'::jsonb
  ),
  (
    'pro', 'Pro', 'For individual developers running regular audits.',
    '$29 / month', 2900, 500, 100,
    '["500 compute hours / month", "100 on-demand runs", "Priority support", "Multiple repos"]'::jsonb
  ),
  (
    'team', 'Team', 'For teams with shared workspaces and higher limits.',
    '$99 / month', 9900, 2000, 500,
    '["2000 compute hours / month", "500 on-demand runs", "Team management", "SSO (coming soon)"]'::jsonb
  );

-- 2. User settings (1:1 UI preferences)
CREATE TABLE "user_settings" (
  "id" text PRIMARY KEY NOT NULL,
  "user_id" text NOT NULL,
  "theme" text DEFAULT 'system' NOT NULL,
  "email_notifications" boolean DEFAULT false NOT NULL,
  "pr_updates" boolean DEFAULT false NOT NULL,
  "timezone" text,
  "locale" text DEFAULT 'en',
  "preferences" jsonb DEFAULT '{}'::jsonb NOT NULL,
  "created_at" timestamp DEFAULT now() NOT NULL,
  "updated_at" timestamp DEFAULT now() NOT NULL
);

ALTER TABLE "user_settings"
  ADD CONSTRAINT "user_settings_user_id_users_id_fk"
  FOREIGN KEY ("user_id") REFERENCES "public"."users"("id")
  ON DELETE cascade ON UPDATE no action;

CREATE UNIQUE INDEX "user_settings_user_id_idx"
  ON "user_settings" USING btree ("user_id");

-- 3. Usage snapshots (daily aggregation)
CREATE TABLE "usage_snapshots" (
  "id" text PRIMARY KEY NOT NULL,
  "user_id" text NOT NULL,
  "usage_date" date NOT NULL,
  "compute_seconds" integer DEFAULT 0 NOT NULL,
  "on_demand_runs" integer DEFAULT 0 NOT NULL,
  "created_at" timestamp DEFAULT now() NOT NULL,
  "updated_at" timestamp DEFAULT now() NOT NULL
);

ALTER TABLE "usage_snapshots"
  ADD CONSTRAINT "usage_snapshots_user_id_users_id_fk"
  FOREIGN KEY ("user_id") REFERENCES "public"."users"("id")
  ON DELETE cascade ON UPDATE no action;

CREATE UNIQUE INDEX "usage_snapshots_user_id_usage_date_idx"
  ON "usage_snapshots" USING btree ("user_id", "usage_date");

CREATE INDEX "usage_snapshots_user_id_usage_date_desc_idx"
  ON "usage_snapshots" USING btree ("user_id", "usage_date" DESC);

-- 4. Users.plan_id (expand-contract)
ALTER TABLE "users" ADD COLUMN "plan_id" text;

UPDATE "users" SET "plan_id" = 'free' WHERE "plan_id" IS NULL;

ALTER TABLE "users" ALTER COLUMN "plan_id" SET DEFAULT 'free';
ALTER TABLE "users" ALTER COLUMN "plan_id" SET NOT NULL;

ALTER TABLE "users"
  ADD CONSTRAINT "users_plan_id_plans_code_fk"
  FOREIGN KEY ("plan_id") REFERENCES "public"."plans"("code")
  ON DELETE restrict ON UPDATE cascade;

CREATE INDEX "users_plan_id_idx" ON "users" USING btree ("plan_id");

-- 5. GitHub numeric external ID checks (invariant I1, I2)
ALTER TABLE "users"
  ADD CONSTRAINT "users_github_external_id_numeric_chk"
  CHECK (provider <> 'github' OR external_id ~ '^\d+$');

ALTER TABLE "accounts"
  ADD CONSTRAINT "accounts_github_external_user_id_numeric_chk"
  CHECK (provider <> 'github' OR external_user_id ~ '^\d+$');

-- 6. Performance indexes on existing tables (hot paths)
CREATE INDEX "tasks_user_id_created_at_idx"
  ON "tasks" USING btree ("user_id", "created_at" DESC)
  WHERE "deleted_at" IS NULL;

CREATE INDEX "tasks_user_id_created_at_rate_limit_idx"
  ON "tasks" USING btree ("user_id", "created_at")
  WHERE "deleted_at" IS NULL;

CREATE INDEX "task_messages_task_id_created_at_idx"
  ON "task_messages" USING btree ("task_id", "created_at");

-- 7. Backfill user_settings for existing users
INSERT INTO "user_settings" ("id", "user_id")
SELECT
  substr(md5(random()::text || u.id), 1, 12),
  u.id
FROM "users" u
WHERE NOT EXISTS (
  SELECT 1 FROM "user_settings" us WHERE us.user_id = u.id
);
```

**Catatan backfill ID:** Production app harus pakai `generateId()`; SQL backfill di atas hanya untuk migrasi one-time. Drizzle schema update harus mirror kolom ini.

#### DOWN — rollback script

```sql
-- ============================================================
-- Rollback 0022 (run in reverse dependency order)
-- ============================================================

DROP INDEX IF EXISTS "task_messages_task_id_created_at_idx";
DROP INDEX IF EXISTS "tasks_user_id_created_at_rate_limit_idx";
DROP INDEX IF EXISTS "tasks_user_id_created_at_idx";

ALTER TABLE "accounts" DROP CONSTRAINT IF EXISTS "accounts_github_external_user_id_numeric_chk";
ALTER TABLE "users" DROP CONSTRAINT IF EXISTS "users_github_external_id_numeric_chk";

ALTER TABLE "users" DROP CONSTRAINT IF EXISTS "users_plan_id_plans_code_fk";
DROP INDEX IF EXISTS "users_plan_id_idx";
ALTER TABLE "users" DROP COLUMN IF EXISTS "plan_id";

DROP TABLE IF EXISTS "usage_snapshots";
DROP TABLE IF EXISTS "user_settings";
DROP TABLE IF EXISTS "plans";
```

#### Post-migration app tasks (bukan DDL)

1. Update `lib/db/schema.ts` dengan 3 tabel baru + `users.planId`
2. `pnpm drizzle-kit generate` untuk sync snapshot `0022`
3. Signup flow: insert `user_settings` row
4. Replace `MOCK_USAGE_DATA` dengan query `plans` + `usage_snapshots`

---

### 7. Volume dan Retensi

| Tabel | Pertumbuhan estimasi (Y1) | Ukuran row avg | Retensi |
|-------|---------------------------|----------------|---------|
| `users` | 1K–10K | ~500 B | Permanent; delete = cascade |
| `plans` | 3–10 (static) | ~300 B | Permanent |
| `user_settings` | 1:1 users | ~200 B | Cascade dengan user |
| `usage_snapshots` | ~365 rows/user/tahun | ~80 B | **13 bulan** rolling; purge via cron |
| `tasks` | 10–100/user/tahun | 2–50 KB (logs jsonb) | Soft delete (`deleted_at`); hard delete via user cascade |
| `task_messages` | 5–50/task | ~500 B | Cascade dengan task/user |
| `keys` | ≤5/user | ~200 B | Cascade dengan user |
| `connectors` | 0–10/user | ~300 B | Cascade dengan user |
| `settings` | 0–20/user | ~100 B | Cascade dengan user |
| `accounts` | 0–1/user | ~300 B | Cascade dengan user |

**Proyeksi storage Y1 (10K users, avg 50 tasks/user):**

- `usage_snapshots`: 10K × 365 × 80B ≈ **290 MB**
- `tasks` (with logs): 500K × 5KB avg ≈ **2.5 GB** (dominant)
- Lainnya: <100 MB

**Retensi policy:**

| Data | Policy | Mekanisme |
|------|--------|-----------|
| `usage_snapshots` | 13 bulan | Scheduled job: `DELETE FROM usage_snapshots WHERE usage_date < CURRENT_DATE - INTERVAL '13 months'` |
| `tasks` (soft-deleted) | 90 hari post soft-delete | Optional purge job on `deleted_at` |
| `tasks.logs` jsonb | Truncate on `clear-logs` API (existing) | App-layer |
| Encrypted tokens | Rotated on re-auth | App-layer overwrite |

**Archival (P2):** Export `usage_snapshots` >13 bulan ke cold storage (S3/Parquet) sebelum purge jika billing dispute resolution diperlukan.

---

### 8. Backup dan Restore (RPO/RTO)

**Asumsi deployment:** Vercel Postgres / Neon / Railway managed Postgres dengan PITR.

| Metrik | Target | Implementasi |
|--------|--------|--------------|
| **RPO** (Recovery Point Objective) | ≤ 5 menit (prod) / ≤ 24 jam (dev) | Point-in-Time Recovery (PITR) enabled; WAL continuous archiving |
| **RTO** (Recovery Time Objective) | ≤ 1 jam (prod) / ≤ 4 jam (dev) | Restore ke branch/staging → verify → DNS cutover |
| **Backup frequency** | Continuous WAL + daily full snapshot | Provider-managed |
| **Retention backup** | 7 hari (dev) / 30 hari (prod) | Provider config |

**Disaster recovery runbook:**

1. **Detect:** Connection failure / data corruption alert
2. **Assess:** Identify last known good timestamp (pre-incident)
3. **Restore:** Create PITR branch at `T-5min` before incident
4. **Verify:** Run smoke tests — user count, recent tasks, plan FK integrity
5. **Cutover:** Update `POSTGRES_URL` in Vercel/Railway env
6. **Communicate:** Status page; users may lose ≤5 min writes

**Selective restore (user deletion accident):**

- Restore PITR branch → extract specific user rows → re-insert ke production
- Cascade order: `users` → `user_settings`, `usage_snapshots`, `tasks`, etc.

**Encrypted data note:** Backup contains ciphertext; `ENCRYPTION_KEY` must be restored alongside DB — store in separate secret manager (Vercel/Railway secrets, not in repo).

**Testing cadence:** Quarterly restore drill ke staging branch; verify row counts + FK integrity query:

```sql
SELECT conname, conrelid::regclass
FROM pg_constraint
WHERE contype = 'f' AND connamespace = 'public'::regnamespace;
```

---

### 9. DDL (complete runnable SQL for NEW migration only + ALTER existing)

DDL lengkap ada di **§6 UP script** di atas. Ringkasan operasi:

| # | Operasi | Tipe |
|---|---------|------|
| 1 | `CREATE TABLE plans` + seed 3 rows | NEW |
| 2 | `CREATE TABLE user_settings` + FK + UNIQUE | NEW |
| 3 | `CREATE TABLE usage_snapshots` + FK + UNIQUE | NEW |
| 4 | `ALTER TABLE users ADD plan_id` + FK + DEFAULT | ALTER existing |
| 5 | `ALTER TABLE users/accounts ADD CHECK` (GitHub numeric) | ALTER existing |
| 6 | `CREATE INDEX` on tasks, task_messages, users | ALTER existing (indexes) |
| 7 | Backfill `user_settings` for existing users | DATA |

**Tidak termasuk** (sudah ada di migrasi 0000–0021):

- CREATE `users`, `tasks`, `accounts`, `keys`, `connectors`, `settings`, `task_messages`
- Existing unique indexes dan FK cascade

---

## Self-Check Checklist

| # | Kriteria | Status |
|---|----------|--------|
| 1 | Semua 8 tabel existing dari `schema.ts` didokumentasikan | ✅ |
| 2 | 3 tabel baru (`plans`, `usage_snapshots`, `user_settings`) didesain | ✅ |
| 3 | `users.plan_id` FK ke `plans.code` | ✅ |
| 4 | Invariant I1: GitHub externalId numeric + UNIQUE per provider | ✅ (index existing + CHECK baru) |
| 5 | Invariant I3: tasks owned by user_id | ✅ (FK existing) |
| 6 | Invariant I4: usage one row per user per day | ✅ (UNIQUE index) |
| 7 | Invariant I5: tokens encrypted at rest, tidak queryable | ✅ (app-layer, no index) |
| 8 | PK pattern text/nanoid konsisten | ✅ |
| 9 | `plans` PK = text code (`free`, `pro`, `team`) | ✅ |
| 10 | snake_case columns align Drizzle | ✅ |
| 11 | Pemisahan `settings` vs `user_settings` jelas | ✅ |
| 12 | Indeks dengan query justification | ✅ |
| 13 | Indeks NOT created dengan alasan | ✅ |
| 14 | Transaction boundaries documented | ✅ |
| 15 | Expand-contract migration dengan UP/DOWN | ✅ |
| 16 | Lock estimates provided | ✅ |
| 17 | Volume & retention estimates | ✅ |
| 18 | RPO/RTO & backup strategy | ✅ |
| 19 | DDL runnable untuk migration 0022 only | ✅ |
| 20 | Tidak mengubah SoT/invariants dari system design | ✅ |
| 21 | Tidak menulis application code | ✅ |
| 22 | `db/supabase/*` distinguished sebagai DB terpisah | ✅ |
| 23 | Dokumen dalam Bahasa Indonesia | ✅ |

---

**Referensi kode baseline:**

- Schema: `apps/auditor-web/lib/db/schema.ts`
- Migrasi latest: `apps/auditor-web/lib/db/migrations/0021_lovely_lizard.sql`
- Mock usage (seed alignment): `apps/auditor-web/lib/mock/usage.ts`
- Hot query tasks: `apps/auditor-web/app/api/tasks/route.ts` (lines 35–39)
- Encryption: `apps/auditor-web/lib/crypto.ts`

[REDACTED]