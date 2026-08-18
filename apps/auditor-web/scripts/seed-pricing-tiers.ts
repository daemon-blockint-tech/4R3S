#!/usr/bin/env node

import { config } from 'dotenv'

// Runs standalone via tsx, outside Next.js — Next.js auto-loads .env.local
// for its own dev/build process, but a standalone script needs to load it
// explicitly, the same way drizzle.config.ts already does for drizzle-kit.
// Missing this caused a real, confirmed failure: "POSTGRES_URL environment
// variable is required" even with a correct .env.local sitting right there.
config({ path: '.env.local' })
config({ path: '.env' })

/**
 * Seed real ARES pricing tiers — BIZ-2.
 *
 * Migration 0022 seeded generic placeholder plans (free/pro/team at
 * $0/$29/$99, "aligned with lib/mock/usage.ts" per its own comment — not
 * any real pricing decision). The real tiers are documented in
 * core/Resources.md: ARES Dev (free or $29/mo), ARES Audit-Assist
 * ($499/mo per repo), ARES Enterprise (custom, min $15K/yr).
 *
 * A standalone seed script rather than a hand-crafted drizzle-kit
 * migration: schema changes (the new `capabilities` column) should go
 * through `npm run db:generate` so drizzle-kit diffs schema.ts against
 * the real database itself, rather than a hand-written migration +
 * journal entry risking a mismatch with no database available to verify
 * it against directly.
 *
 * Run after `npm run db:generate && npm run db:migrate` have applied the
 * new `capabilities` column:
 *
 *   npx tsx scripts/seed-pricing-tiers.ts
 *
 * Safe to re-run — every plan is fully upserted (updates existing rows
 * by code, inserts if missing), not appended.
 */

import { db } from '../lib/db/client'
import { plans } from '../lib/db/schema'
import { eq } from 'drizzle-orm'

interface PlanSeed {
  code: string
  name: string
  description: string
  priceLabel: string
  priceCents: number | null
  computeHoursLimit: number
  onDemandRunsLimit: number
  features: string[]
  capabilities: string[]
}

// 'free' and 'pro' both represent ARES Dev's own two price points
// (core/Resources.md: "Free atau $29/mo") — kept as two separate codes
// since users.plan_id already defaults to 'free' and changing that
// default is out of scope here. 'team' is repurposed to ARES
// Audit-Assist — core/Resources.md's own target for this tier is "Tim
// 2-10" (teams of 2-10), so the rename is conceptually consistent with
// the existing code, not arbitrary. 'enterprise' is genuinely new — no
// existing code mapped to it at all.
const REAL_TIERS: PlanSeed[] = [
  {
    code: 'free',
    name: 'ARES Dev (Free)',
    description: 'Solo dev, OSS. CLI-native scanning with public PR comments.',
    priceLabel: 'Free',
    priceCents: 0,
    computeHoursLimit: 100,
    onDemandRunsLimit: 50,
    features: ['CLI-native', '50 runs / month', 'Basic invariant checks', 'Public PR comments'],
    capabilities: [],
  },
  {
    code: 'pro',
    name: 'ARES Dev',
    description: 'Solo dev, OSS. Same as the free tier, for private personal use.',
    priceLabel: '$29 / month',
    priceCents: 2900,
    computeHoursLimit: 100,
    onDemandRunsLimit: 50,
    features: ['CLI-native', '50 runs / month', 'Basic invariant checks', 'Private personal repos'],
    capabilities: ['private-repo'],
  },
  {
    code: 'team',
    name: 'ARES Audit-Assist',
    description: 'Team of 2-10, pre-launch protocol. Full multi-agent pipeline.',
    priceLabel: '$499 / month per repo',
    priceCents: 49900,
    computeHoursLimit: 2000,
    onDemandRunsLimit: 500,
    features: ['Full multi-agent pipeline', 'Web dashboard', 'PoC generation', 'CI hooks', 'Private repo support'],
    capabilities: ['private-repo', 'poc-generation', 'ci-hooks', 'web-dashboard'],
  },
  {
    code: 'enterprise',
    name: 'ARES Enterprise',
    description: 'Large protocols, audit firms. Custom pricing, minimum $15K/year.',
    priceLabel: 'Custom',
    priceCents: null,
    // No real usage ceiling for a custom, negotiated-contract tier —
    // documented here rather than left as an unexplained magic number.
    computeHoursLimit: 999_999,
    onDemandRunsLimit: 999_999,
    features: ['SDK / API access', 'On-prem deployment', 'Custom rules engine', 'White-label', 'Dedicated engineer'],
    capabilities: [
      'private-repo',
      'poc-generation',
      'ci-hooks',
      'web-dashboard',
      'sdk-api',
      'on-prem',
      'custom-rules',
      'white-label',
    ],
  },
]

async function main() {
  for (const tier of REAL_TIERS) {
    const existing = await db.select({ code: plans.code }).from(plans).where(eq(plans.code, tier.code)).limit(1)

    if (existing.length > 0) {
      await db
        .update(plans)
        .set({
          name: tier.name,
          description: tier.description,
          priceLabel: tier.priceLabel,
          priceCents: tier.priceCents,
          computeHoursLimit: tier.computeHoursLimit,
          onDemandRunsLimit: tier.onDemandRunsLimit,
          features: tier.features,
          capabilities: tier.capabilities,
          updatedAt: new Date(),
        })
        .where(eq(plans.code, tier.code))
      console.log(`updated: ${tier.code} -> ${tier.name}`)
    } else {
      await db.insert(plans).values(tier)
      console.log(`inserted: ${tier.code} -> ${tier.name}`)
    }
  }

  console.log('\nDone. Real ARES pricing tiers seeded.')
  process.exit(0)
}

main().catch((err) => {
  console.error('Seed failed:', err)
  process.exit(1)
})
