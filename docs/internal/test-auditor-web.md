# Dokumen Desain Test Engineer — ARES `auditor-web`

| Field | Value |
|-------|-------|
| **Scope** | `apps/auditor-web` + monorepo test patterns |
| **Version** | 2026-08-04 |
| **Status** | Design-only — 0 tests in auditor-web; Vitest rollout not started |
| **Related docs** | [backend-auditor-web.md](./backend-auditor-web.md) · [platform-cicd.md](./platform-cicd.md) |

---

## Rekomendasi Runner: **Vitest** (bukan Jest)

| Kriteria | Vitest | Jest |
|---|---|---|
| Konsistensi monorepo | Root `src/` sudah pakai Vitest (`vitest.config.ts`, `npm test`) | Tidak dipakai |
| `apps/ares-sec` | `vitest run src` | — |
| ESM / TypeScript | Native, minimal config | Perlu transform tambahan |
| Kecepatan | Cepat, watch mode | Lebih berat |
| Next.js 16 | Didukung via `vitest.config.ts` + path alias `@/` | Didukung via `next/jest` |

**Kesimpulan:** Tambahkan `vitest`, `@vitejs/plugin-react` (jika test komponen), dan `vitest.config.ts` di `apps/auditor-web`. Jangan perkenalkan Jest — fragmentasi runner monorepo.

---

## 1. Apa yang Diuji di Mana

| Layer | Lokasi kode | Jenis test | File test (usulan) | Runner / DB |
|---|---|---|---|---|
| **Crypto** | `lib/crypto.ts` | Unit | `lib/crypto.test.ts` | Vitest, hermetic (`ENCRYPTION_KEY` dummy) |
| **JWE session** | `lib/jwe/encrypt.ts`, `lib/jwe/decrypt.ts` | Unit | `lib/jwe/session.test.ts` | Vitest, `JWE_SECRET` dummy |
| **Redaksi log** | `lib/utils/logging.ts` | Unit | `lib/utils/logging.test.ts` | Vitest |
| **Usage UI helper** | `lib/mock/usage.ts` → `usagePercent()` | Unit | `lib/mock/usage.test.ts` | Vitest |
| **Zod schema** | `lib/db/schema.ts` | Unit | `lib/db/schema.test.ts` | Vitest |
| **User upsert / dedup** | `lib/db/users.ts` | Integration | `lib/db/users.integration.test.ts` | Vitest + Postgres test |
| **Rate limit harian** | `lib/utils/rate-limit.ts` | Integration | `lib/utils/rate-limit.integration.test.ts` | Vitest + Postgres + fake timers |
| **Settings per user** | `lib/db/settings.ts` | Integration | `lib/db/settings.integration.test.ts` | Vitest + Postgres |
| **API keys decrypt** | `lib/api-keys/user-keys.ts` | Integration | `lib/api-keys/user-keys.integration.test.ts` | Vitest + mock session + Postgres |
| **OAuth session GitHub** | `lib/session/create-github.ts` | Integration (mock fetch) | `lib/session/create-github.integration.test.ts` | Vitest + MSW/nock |
| **Task ownership** | `app/api/tasks/**/route.ts` (~30 route) | Contract | `__tests__/contract/tasks-ownership.test.ts` | Vitest + mock `getServerSession` + mock `db` |
| **Auth routes** | `app/api/auth/**` | Contract | `__tests__/contract/auth.test.ts` | Vitest + mock cookies/fetch |
| **Connectors / keys API** | `app/api/connectors/route.ts`, `app/api/api-keys/route.ts` | Contract | `__tests__/contract/user-scoped-resources.test.ts` | Vitest |
| **Import boundary** | seluruh `apps/auditor-web` | Static (monorepo) | Sudah ada: `scripts/check-import-boundary.mjs` | Node, CI root |
| **Usage page** | `components/usage-page-client.tsx` | Component (rendah) | `components/usage-page-client.test.tsx` | Vitest + RTL (opsional P2) |
| **E2E smoke** | Login → buat task → logout | E2E | `e2e/smoke.spec.ts` | Playwright, scheduled |
| **Monorepo agent** | Root `src/` | Regression | Tetap `src/**/*.test.ts` | Root Vitest, CI `ci.yml` |
| **Rust engine** | `core/` | Cargo test | `cargo test --workspace` | `core-ci.yml` |
| **Eval harness** | `eval/` | Pytest | `python -m pytest eval -q` | `ci.yml` |

**Gap CI saat ini:**

- Root `.github/workflows/ci.yml` → `npm test` hanya `src/**/*.test.ts` (auditor-web **tidak** tercakup).
- `apps/auditor-web/.github/workflows/pr-checks.yml` → lint, format:check, build — **tanpa test**.

---

## 2. Prioritas berdasarkan Risiko

| Prioritas | Area | Risiko jika gagal | Alasan |
|---|---|---|---|
| **P0 — Kritis** | Enkripsi token (`lib/crypto.ts`) | Kebocoran OAuth/API key plaintext di DB | Data sensitif; invariant desain |
| **P0 — Kritis** | Task `userId` ownership (semua route task) | IDOR — user A akses sandbox/task user B | ~30 route dengan pola `eq(tasks.userId, session.user.id)` |
| **P0 — Kritis** | GitHub `externalId` dedup (`upsertUser`) | Duplikat akun, kehilangan data task saat merge | Logika multi-path (users + accounts) |
| **P0 — Kritis** | Redaksi log (`redactSensitiveInfo`) | Token/credential tampil di UI log | AGENTS.md: log statis wajib; redaksi backup |
| **P1 — Tinggi** | Rate limit harian (`checkRateLimit`) | Abuse quota, bypass limit | Menghitung task + follow-up message per UTC day |
| **P1 — Tinggi** | Auth OAuth state validation | CSRF OAuth, session hijack | Callback GitHub/Vercel |
| **P1 — Tinggi** | JWE session cookie | Session forgery / expiry bypass | `encryptJWE` + cookie flags |
| **P1 — Tinggi** | API keys user-scoped | Key user A dipakai user B | `keys.userId` + decrypt |
| **P2 — Sedang** | Zod schema validation | Bad input corrupt DB | `insertTaskSchema`, dll. |
| **P2 — Sedang** | `usagePercent()` | UI progress bar salah | Pure function, mudah |
| **P2 — Sedang** | Usage UNIQUE per day (billing future) | Double-count usage | Belum ada tabel; desain forward |
| **P3 — Rendah** | Component rendering (usage, settings) | UI regression kosmetik | Mock data saat ini |
| **P3 — Rendah** | E2E full flow | Regresi integrasi end-to-end | Lambat, flaky; scheduled saja |

---

## 3. Kasus Uji Invariant (per design invariant)

### Invariant A: GitHub `externalId`

**Aturan desain:** `externalId` = GitHub numeric ID sebagai string (`"${githubUser.id}"`); unique index `(provider, externalId)`; linked account via `accounts.externalUserId`.

| # | Kasus | Deskripsi test | Ekspektasi |
|---|---|---|---|
| A1 | Sign-in GitHub pertama kali | `upsertUser({ provider: 'github', externalId: '12345', ... })` pada DB kosong | Insert user baru, return `nanoid` internal ID |
| A2 | Sign-in ulang same externalId | Panggil `upsertUser` dua kali dengan `externalId` sama | Return ID yang sama; **tidak** insert baris kedua |
| A3 | Vercel → connect GitHub → sign-in GitHub | User Vercel punya row di `accounts`; sign-in GitHub dengan `externalUserId` sama | Return userId Vercel; update token di `accounts`; **tidak** buat user baru |
| A4 | Violation unique index | Insert manual dua user `(github, '999')` | DB reject (unique constraint) |
| A5 | `getUserByGitHubConnection` | Query via `accounts.externalUserId` | Return parent user, bukan duplicate |
| A6 | Token refresh on re-login | Sign-in ulang dengan access token baru | `users.accessToken` ter-update (encrypted) |
| A7 | Primary provider preserved | Scenario A3 | `users.provider` tetap `'vercel'`, tidak berubah ke `'github'` |

### Invariant B: Encrypted tokens

**Aturan desain:** Semua token sensitif di-encrypt sebelum persist (`encrypt()`); decrypt saat baca (`decrypt()`).

| # | Kasus | Deskripsi test | Ekspektasi |
|---|---|---|---|
| B1 | Round-trip encrypt/decrypt | `decrypt(encrypt('ghp_abc123'))` | Plaintext identik |
| B2 | Ciphertext ≠ plaintext | Simpan token via `createGitHubSession` mock | Value di DB **bukan** raw token |
| B3 | Format ciphertext | Output `encrypt()` | Pola `{iv_hex}:{cipher_hex}` |
| B4 | Missing `ENCRYPTION_KEY` | Panggil `encrypt('x')` tanpa env | Throw error eksplisit |
| B5 | Invalid key length | `ENCRYPTION_KEY` bukan 64 hex char | Throw error validasi 32-byte |
| B6 | Empty string passthrough | `encrypt('')`, `decrypt('')` | Return empty tanpa throw |
| B7 | Invalid ciphertext | `decrypt('not-valid')` | Throw "Invalid encrypted text format" |
| B8 | API key storage | Insert ke `keys.value` via flow API | Encrypted at rest; decrypt hanya server-side |
| B9 | Connector env encrypted | Insert connector dengan env vars | Kolom `env` encrypted string, bukan JSON plaintext |
| B10 | Response tidak expose token | GET task / GET user (contract) | Response JSON **tidak** mengandung `accessToken`, `refreshToken` |

### Invariant C: Task `userId` ownership

**Aturan desain:** Setiap operasi task wajib filter `tasks.userId === session.user.id`.

| # | Kasus | Deskripsi test | Ekspektasi |
|---|---|---|---|
| C1 | GET task milik sendiri | Session user A, task.userId = A | 200 + task data |
| C2 | GET task milik orang lain | Session user A, task.userId = B | **404** (bukan 403 — tidak leak existence) |
| C3 | PATCH/DELETE cross-user | User A coba modifikasi task B | 404 |
| C4 | POST task | Body berisi `userId` berbeda dari session | Server **override** dengan `session.user.id` |
| C5 | List tasks | GET `/api/tasks` | Hanya task `userId = session.user.id` |
| C6 | Soft-deleted excluded | Task dengan `deletedAt != null` | Tidak muncul di list; GET return 404 |
| C7 | Sub-resource ownership | `/api/tasks/[id]/messages`, `/file-content`, `/sandbox-health`, dll. | Semua route dalam grep ownership — test parametrized |
| C8 | Unauthenticated | Tanpa session cookie | 401 `{ error: 'Unauthorized' }` |
| C9 | GitHub connect merge | Callback connect migrates tasks | Task `userId` di-update ke stored user (regression) |

**Pendekatan parametrized:** Satu test matrix dengan daftar ~30 route dari grep `eq(tasks.userId, session.user.id)`.

### Invariant D: Usage UNIQUE per day

**Aturan desain (forward):** Satu baris usage per `(userId, date)` — UNIQUE constraint harian.  
**Implementasi saat ini:** Rate limit via agregasi `tasks.createdAt` + `taskMessages` (UTC day); halaman usage masih mock (`MOCK_USAGE_DATA`).

| # | Kasus | Deskripsi test | Ekspektasi |
|---|---|---|---|
| D1 | Satu increment per hari (future table) | Dua kali `recordUsage(userId, 'compute', 1)` same UTC date | Upsert satu baris; `used` += 2 |
| D2 | UNIQUE violation | Insert manual dua row `(userId, '2026-08-04')` | DB reject |
| D3 | Rate limit — task count | 3 task dibuat hari ini, limit 5 | `remaining = 2`, `allowed = true` |
| D4 | Rate limit — follow-up messages | 2 user messages hari ini | Menghitung ke quota (tasks + messages) |
| D5 | UTC boundary | Task dibuat 23:59 UTC vs 00:01 UTC next day | Counter reset di boundary UTC |
| D6 | User-specific limit | Setting `maxMessagesPerDay` per user | Override env default |
| D7 | Soft-deleted tasks excluded | Task deleted hari ini | Tidak dihitung quota |
| D8 | `usagePercent(42, 100)` | Pure function | Return `42` |
| D9 | `usagePercent(150, 100)` | Over limit | Cap at `100` |
| D10 | `usagePercent(x, 0)` | Limit nol | Return `0` (guard divide-by-zero) |

---

## 4. Kasus Batas

| Kategori | Kasus batas | Harapan |
|---|---|---|
| **Crypto** | Plaintext 1 char vs 10 KB | Round-trip sukses |
| **Crypto** | Ciphertext dengan IV corrupt (1 nibble salah) | Decrypt throw |
| **Crypto** | Key rotation (future) | Dokumentasikan: ciphertext lama tidak decryptable dengan key baru |
| **OAuth** | State cookie mismatch | 400 "Invalid OAuth state" |
| **OAuth** | Missing `code` query param | 400 |
| **OAuth** | GitHub token exchange failure | 400, tidak buat session |
| **Session** | Expired JWE cookie | Treat as unauthenticated |
| **Session** | Cookie tampered | Decrypt fail → 401 |
| **Tasks** | `taskId` nonexistent | 404 |
| **Tasks** | `taskId` empty / malformed | 404 atau 400 |
| **Tasks** | Body POST invalid (missing prompt) | 400 Zod validation error |
| **Tasks** | Rate limit exact boundary | Count = limit → `allowed = false`, 429 |
| **Users** | Concurrent `upsertUser` same externalId | Satu user created (transaction/unique handle) |
| **Settings** | Duplicate key per user | Unique index reject |
| **Keys** | Duplicate provider per user | Unique index reject |
| **Logging** | Message dengan embedded GitHub token di URL | `redactSensitiveInfo` mask token |
| **Logging** | Template literal di logger (static audit) | Grep CI: **0** match `logger.*\`.*\$\{` |
| **DB** | Missing `POSTGRES_URL` | Proxy throw on first access |
| **Usage page** | Signed out user | Tampil mock + banner "Sign in" |

---

## 5. Data Uji (factories, isolation, cleanup)

### Struktur direktori

```
apps/auditor-web/
├── vitest.config.ts
├── vitest.setup.ts              # env dummy, fake timers hook
├── test/
│   ├── factories/
│   │   ├── user.factory.ts
│   │   ├── task.factory.ts
│   │   ├── account.factory.ts
│   │   └── session.factory.ts
│   ├── helpers/
│   │   ├── db-test-client.ts    # Postgres test instance
│   │   ├── mock-session.ts
│   │   └── mock-github-api.ts
│   └── fixtures/
│       ├── encryption-key.env   # openssl rand -hex 32 (NOT real)
│       └── github-user.json
└── lib/
    └── crypto.test.ts           # co-located unit tests OK
```

### Factory pattern (mengikuti root `src/billing/account-store.test.ts`)

```typescript
// test/factories/user.factory.ts — konsep, bukan implementasi penuh
function buildUser(over: Partial<InsertUser> = {}): InsertUser {
  return {
    provider: 'github',
    externalId: '12345678',
    accessToken: encrypt('ghp_test_token_placeholder'),
    username: 'test-user',
    ...over,
  }
}
```

### Isolation strategy

| Layer | Isolation | Cleanup |
|---|---|---|
| Unit (crypto, usagePercent, logging, zod) | Tidak perlu DB | Reset `process.env` per test (`vi.stubEnv`) |
| Integration (users, rate-limit) | Postgres dedicated: `POSTGRES_URL_TEST` atau Testcontainers | `TRUNCATE` semua tabel dalam `afterEach` / transaction rollback |
| Contract (API routes) | Mock `db` Proxy + mock `getServerSession` | Stateless — no cleanup |
| E2E | Staging DB / ephemeral branch Supabase | Seed + teardown script |

### Environment test (hermetic — mirror root `vitest.config.ts`)

```typescript
// vitest.config.ts — env block
env: {
  ENCRYPTION_KEY: 'a'.repeat(64),           // 32-byte hex dummy
  JWE_SECRET: '<base64url-32-byte-dummy>',
  POSTGRES_URL: 'postgres://test:test@localhost:5433/auditor_web_test',
  OPENAI_API_KEY: 'test-key-not-used',
  // Jangan set GITHUB_CLIENT_SECRET nyata
}
```

### Seed data minimal

| Entity | ID / key | Relasi |
|---|---|---|
| User A | `user-a` | provider github, externalId `111` |
| User B | `user-b` | provider vercel, externalId `vercel-1` |
| Account linked | user-b → github `222` | accounts row |
| Task A1 | userId = user-a | status pending |
| Task B1 | userId = user-b | untuk IDOR test |
| Key A | user-a, provider anthropic | encrypted dummy |

---

## 6. Determinisme

| Sumber non-determinisme | Mitigasi test |
|---|---|
| `crypto.randomBytes(IV_LENGTH)` di `encrypt()` | Assert round-trip & format, **bukan** snapshot ciphertext |
| `nanoid()` user/task ID | Mock `nanoid` return fixed `'test-id-1'` di integration |
| `new Date()` di upsertUser / rate-limit | `vi.useFakeTimers({ now: new Date('2026-08-04T12:00:00Z') })` |
| UTC midnight boundary rate limit | Test eksplisit dengan fake timer di 23:59:59 dan 00:00:01 UTC |
| Fetch GitHub API | MSW / `vi.stubGlobal('fetch', ...)` dengan fixture JSON statis |
| Vercel Sandbox | **Jangan** panggil di unit/contract — mock `createSandbox` |
| Postgres auto `defaultNow()` | Accept atau freeze timer sebelum insert |
| Parallel test file | DB isolation per worker (`schema test_${workerId}`) atau serial integration suite |

**Prinsip:** Suite P0/P1 harus green tanpa network, tanpa `.env.local` produksi, tanpa Supabase/GitHub/Vercel live — sama seperti komentar hermetic di root `vitest.config.ts`.

---

## 7. Test Kontrak (API contract tests)

### Setup kontrak

- Framework: Vitest + helper `invokeRoute(handler, { method, url, body, cookies })`
- Mock: `@/lib/session/get-server-session`, `@/lib/db/client`
- Assert: HTTP status, shape JSON (bukan snapshot penuh), **absence** field sensitif

### Route matrix prioritas

| Route | Method | Auth | Kontrak kunci |
|---|---|---|---|
| `/api/tasks` | GET | Required | `{ tasks: Task[] }`, no cross-user |
| `/api/tasks` | POST | Required | 201/200, `userId` dari session, 429 jika rate limited |
| `/api/tasks/[taskId]` | GET/PATCH/DELETE | Required | 404 cross-user |
| `/api/auth/info` | GET | Optional | Shape session info, no token |
| `/api/auth/signout` | POST | Required | Clear cookie header |
| `/api/auth/github/status` | GET | Required | `{ connected: boolean }` |
| `/api/auth/rate-limit` | GET | Required | `{ remaining, total, resetAt }` |
| `/api/api-keys` | GET/POST | Required | Never return decrypted key in response |
| `/api/connectors` | GET | Required | Scoped `userId` |
| `/api/tasks/[taskId]/messages` | GET/POST | Required | Ownership + rate limit on POST |

### Response invariants (semua route)

1. Error shape konsisten: `{ error: string }` (+ optional `message`)
2. **Never** expose: `accessToken`, `refreshToken`, `ENCRYPTION_KEY`, raw API keys
3. 401 untuk unauthenticated (kecuali public routes)
4. 404 (bukan 403) untuk resource owned by other user

### Static contract (tanpa runtime)

- Grep test: semua file `app/api/tasks/**/route.ts` mengandung ownership check **ata** explicit guard
- Import boundary: `node scripts/check-import-boundary.mjs` (sudah di CI root)

---

## 8. Anggaran Waktu (per layer, CI strategy)

| Layer | Test count (est.) | Durasi lokal | CI trigger | Job |
|---|---|---|---|---|
| **Unit** (crypto, logging, zod, usagePercent, jwe) | ~40 cases | < 15 detik | **Every commit / PR** | `auditor-web-test-unit` |
| **Contract** (API mocks) | ~60 cases | < 30 detik | **Every commit / PR** | Same job |
| **Integration** (Postgres) | ~35 cases | 1–3 menit | **Every PR** (+ main push) | `auditor-web-test-integration` dengan Postgres service |
| **Static audit** (grep logs, import boundary) | ~5 checks | < 10 detik | **Every commit** | Extend root `ci.yml` atau PR checks |
| **Component** (RTL, optional) | ~15 cases | 30–60 detik | PR only | Same unit job |
| **E2E** (Playwright) | ~5 flows | 5–15 menit | **Scheduled nightly** + pre-release | `auditor-web-e2e` |
| **Monorepo root `src/`** | 65 files existing | ~2 menit | Every commit (existing) | `ci.yml` verify job |
| **Eval pytest** | existing | ~1 menit | Every commit (existing) | `eval-scorer` job |

### Usulan update CI

**`apps/auditor-web/.github/workflows/pr-checks.yml`** — tambah:

```yaml
- name: Unit & contract tests
  run: pnpm test:unit

- name: Integration tests
  run: pnpm test:integration
  env:
    POSTGRES_URL: postgres://postgres:postgres@localhost:5432/test
  services:
    postgres: ...
```

**Root `.github/workflows/ci.yml`** — tambah matrix job atau step:

```yaml
- name: auditor-web tests
  working-directory: apps/auditor-web
  run: pnpm test
```

### Script usulan `package.json`

```json
{
  "test": "vitest run",
  "test:unit": "vitest run --project unit",
  "test:integration": "vitest run --project integration",
  "test:watch": "vitest",
  "test:coverage": "vitest run --coverage"
}
```

**Target SLA:**

- PR gate (unit + contract): **< 2 menit**
- PR gate (+ integration): **< 5 menit**
- Nightly E2E: **< 20 menit**, allowed flaky retry ×1

---

## 9. Cakupan sebagai Sinyal

Coverage **bukan** target KPI; dipakai sebagai **radar regresi**.

| Metrik | Target awal | Interpretasi |
|---|---|---|
| Line coverage `lib/crypto.ts`, `lib/db/users.ts` | ≥ 95% | Invariant keamanan |
| Line coverage `lib/utils/rate-limit.ts` | ≥ 90% | Quota abuse |
| Route ownership (`app/api/tasks/**`) | 100% route ter-cover contract test | IDOR prevention |
| Branch coverage OAuth callback | ≥ 80% | CSRF / error paths |
| Overall `apps/auditor-web` | ≥ 60% (fase 1) → 75% (fase 2) | Jangan kejar 100% di UI/mock |
| Mutation testing | Tidak (fase 1) | Pertimbangkan P3 untuk crypto |

**Yang tidak perlu dikejar coverage-nya:**

- `components/ui/*` (shadcn generated)
- Mock pages (`usage-page-client` sampai billing API live)
- Vercel Sandbox orchestration (mock di unit, E2E terbatas)

**Sinyal alternatif lebih kuat dari coverage:**

1. Invariant test suite (Section 3) — **wajib green**
2. Static grep: no dynamic logs, no import ares-sec
3. Contract test matrix ownership — **100% route task**
4. CI time regression: alert jika unit suite > 3 menit

---

## Struktur Implementasi (fase rollout)

### Fase 1 — Foundation (1–2 hari dev)

1. Install Vitest + config + env hermetic
2. `lib/crypto.test.ts` (B1–B7)
3. `lib/utils/logging.test.ts` (redaction)
4. `lib/mock/usage.test.ts` (D8–D10)
5. Tambah `pnpm test` ke PR checks

### Fase 2 — Security invariants (2–3 hari dev)

1. Postgres test container + factories
2. `lib/db/users.integration.test.ts` (A1–A7)
3. `lib/utils/rate-limit.integration.test.ts` (D3–D7)
4. Contract ownership matrix (C1–C9)

### Fase 3 — Auth & billing readiness (2 hari dev)

1. OAuth callback contract tests
2. Usage table tests (D1–D2) saat schema billing land
3. Playwright smoke (scheduled)

---

## Self-check Checklist

- [x] Baca `apps/auditor-web/package.json` — **tidak ada script `test`**, hanya `typecheck`/`type-check`
- [x] Cari `*.test.ts` / `*.spec.ts` di auditor-web — **0 file**
- [x] Pola root `src/` — Vitest, co-located `*.test.ts`, factory helpers, hermetic env
- [x] CI root — `npm test` → Vitest `src/**/*.test.ts` only
- [x] CI auditor-web — lint/format/build, **no test**
- [x] `lib/db/users.ts` — dedup GitHub via accounts, encrypt path di caller
- [x] `lib/crypto.ts` — AES-256-CBC, IV random, ENCRYPTION_KEY validation
- [x] Invariant GitHub externalId — documented dengan 7 cases
- [x] Invariant encrypted tokens — documented dengan 10 cases
- [x] Invariant task userId ownership — documented dengan 9 cases + parametrized route matrix
- [x] Invariant usage UNIQUE per day — documented (forward + rate-limit proxy)
- [x] Rekomendasi Vitest (bukan Jest) dengan justifikasi monorepo
- [x] **Tidak** menyertakan implementasi test penuh — hanya desain kasus & struktur
- [x] Bahasa Indonesia, istilah teknis English where appropriate

---

**Catatan implementer:** Sebelum menulis test pertama, tambahkan `"test": "vitest run"` ke `apps/auditor-web/package.json` dan wire ke `pr-checks.yml`. Tanpa langkah ini, desain ini tidak ter-enforce di CI meskipun test file sudah ada.

[REDACTED]