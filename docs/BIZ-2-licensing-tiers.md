# BIZ-2 — Licensing tiers: what's built, and the real tier structure

For whoever builds the pricing/landing page, and for reference on how
tier-gating actually works in the codebase.

## The real tiers, from `core/Resources.md` (confirmed with senior directly)

| Plan code | Display name | Price | Target |
|---|---|---|---|
| `free` | ARES Dev (Free) | Free | Solo dev, OSS |
| `pro` | ARES Dev | $29/month | Solo dev, private use |
| `team` | ARES Audit-Assist | $499/month per repo | Team of 2–10, pre-launch protocol |
| `enterprise` | ARES Enterprise | Custom, min $15K/year | Large protocols, audit firms |

**Note on `free`/`pro`:** `core/Resources.md` describes "ARES Dev" as having
two price points ("Free atau $29/mo") without specifying an exact feature
difference between them. Interpreted here as: `free` is public/OSS-only
(matching the doc's own "public PR comments" description), `pro` unlocks
private personal repos at the same usage limits. Worth confirming this
specific split is right before it goes live anywhere customer-facing.

**Note on `team`/`enterprise` codes:** kept the existing database codes
(`free`, `pro`, `team`) rather than renaming them, since `users.plan_id`
already defaults to `'free'` at the schema level, and renaming a
`PRIMARY KEY`/foreign-key value carries real migration risk for no
functional benefit. `team` now displays as "ARES Audit-Assist" — the
rename is intentional, not a mismatch to fix.

## Auth: no new system — uses what already exists

Per direct confirmation: `auditor-web` already has a working login system
(GitHub/Vercel OAuth, Drizzle + Postgres, JWE-encrypted sessions). This
work adds tier data to the *existing* `users`/`plans` tables — no new
auth provider, no license-key system, nothing parallel.

## What was already there, and what's new

**Already existed (migration 0022):** the `plans` table itself, and a
`features: string[]` column — but seeded with **generic SaaS placeholder
data** (free/pro/team at $0/$29/$99, "aligned with lib/mock/usage.ts" per
its own comment), not any real pricing decision, and used only for
**display** (the usage page) — nothing anywhere actually gated a feature
by plan.

**New in this work:**
- `scripts/seed-pricing-tiers.ts` — updates the 4 plans with the real
  tier data above (safe to re-run; upserts by code, doesn't append)
- A new `capabilities: string[]` column on `plans`, **deliberately
  separate** from `features`. `features` stays human-readable display
  copy, free to reword for the pricing page at any time.
  `capabilities` is a stable set of machine-checkable keys
  (`lib/billing/capabilities.ts`'s `Capability` type) that gating logic
  actually checks — so rewording a feature's display text can never
  accidentally change who has access to what
- `lib/billing/capabilities.ts` — `userHasCapability(userId, capability)`,
  the actual gating check, plus `cheapestPlanFor(capability)` for
  upgrade-prompt copy
- Applied to one real, concrete feature as proof-of-concept: private
  repository creation (`app/api/github/repos/create/route.ts`) now
  requires the `private-repo` capability, checked **server-side** (not
  just hidden in the UI, which could be bypassed by calling the API
  directly)

## How to gate a new feature

```ts
import { userHasCapability, cheapestPlanFor } from '@/lib/billing/capabilities'

if (!(await userHasCapability(session.user.id, 'poc-generation'))) {
  const upgradeTo = await cheapestPlanFor('poc-generation')
  return NextResponse.json(
    { error: `This feature requires the ${upgradeTo} plan or above.` },
    { status: 403 },
  )
}
```

Add new capability keys to the `Capability` type in
`lib/billing/capabilities.ts`, and to the relevant plans' `capabilities`
arrays in `scripts/seed-pricing-tiers.ts` — keep both in sync by hand,
there's no shared source of truth enforcing it automatically yet.

## To apply and verify

```bash
cd apps/auditor-web
npm run db:generate   # drizzle-kit diffs schema.ts, generates the
                       # capabilities-column migration properly
npm run db:migrate    # applies it
npx tsx scripts/seed-pricing-tiers.ts
```

## Verified

- `npx tsc --noEmit`: zero errors in any file this work touched
  (`lib/billing/capabilities.ts`, `scripts/seed-pricing-tiers.ts`,
  `lib/db/schema.ts`, `app/api/github/repos/create/route.ts`)
- The 45 pre-existing type errors elsewhere in the codebase (unrelated
  `sandboxId`/markdown-component typing issues) confirmed identical and
  unaffected — checked directly via `git stash`, not assumed

**Not verified: an actual database migration + seed run.** No Postgres
instance available here. The schema change and seed script are correct
TypeScript, checked directly, but `npm run db:generate`/`db:migrate` and
the seed script itself need a real run against a real database before
merging.
