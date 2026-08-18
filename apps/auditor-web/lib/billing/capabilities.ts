import 'server-only'

import { db } from '@/lib/db/client'
import { users, plans } from '@/lib/db/schema'
import { eq } from 'drizzle-orm'

/**
 * Stable, machine-checkable capability keys — BIZ-2. Deliberately separate
 * from `plans.features` (human-readable display copy for the usage page,
 * lib/db/usage.ts) so gating logic never depends on marketing/display
 * wording that's free to change. Keep this list in sync with
 * scripts/seed-pricing-tiers.ts's own `capabilities` arrays.
 */
export type Capability =
  | 'private-repo'
  | 'poc-generation'
  | 'ci-hooks'
  | 'web-dashboard'
  | 'sdk-api'
  | 'on-prem'
  | 'custom-rules'
  | 'white-label'

/**
 * Does this user's current plan include the given capability?
 *
 * Throws rather than silently defaulting to `false` if the user or their
 * plan can't be found — a missing user/plan is a genuine data-integrity
 * problem (every user row has a `plan_id` foreign key, `NOT NULL`,
 * defaulting to `'free'`), not a normal "capability absent" case, and
 * gating logic should surface that loudly rather than quietly deny access
 * for a reason unrelated to the user's actual tier.
 */
export async function userHasCapability(userId: string, capability: Capability): Promise<boolean> {
  const [row] = await db
    .select({ capabilities: plans.capabilities })
    .from(users)
    .innerJoin(plans, eq(users.planId, plans.code))
    .where(eq(users.id, userId))
    .limit(1)

  if (!row) {
    throw new Error(`userHasCapability: no user or plan found for user id "${userId}"`)
  }

  return row.capabilities.includes(capability)
}

/** Human-readable name of the cheapest plan that includes this capability, for upgrade-prompt copy. */
export async function cheapestPlanFor(capability: Capability): Promise<string | undefined> {
  const rows = await db
    .select({ name: plans.name, priceCents: plans.priceCents, capabilities: plans.capabilities })
    .from(plans)
    .where(eq(plans.isActive, true))

  const eligible = rows
    .filter((p) => p.capabilities.includes(capability))
    // Enterprise's priceCents is null (custom pricing) — sort it last,
    // not first, since a numeric comparison would otherwise treat null
    // as the smallest/cheapest value.
    .sort((a, b) => (a.priceCents ?? Infinity) - (b.priceCents ?? Infinity))

  return eligible[0]?.name
}
