import 'server-only'

import { db } from './client'
import { plans, usageSnapshots, users, tasks } from './schema'
import { and, eq, gte, lte, sql } from 'drizzle-orm'
import { nanoid } from 'nanoid'
import type { MockUsageData } from '@/lib/mock/usage'

export function usagePercent(used: number, limit: number): number {
  if (limit <= 0) return 0
  return Math.min(100, Math.round((used / limit) * 100))
}

export function getBillingPeriodBounds(date: Date = new Date()): { start: Date; end: Date } {
  const start = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), 1))
  const end = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 0))
  return { start, end }
}

function formatUsageDate(date: Date): string {
  return date.toISOString().slice(0, 10)
}

function getBillingPeriodEndIso(date: Date = new Date()): string {
  return formatUsageDate(new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 1)))
}

export function computeTaskComputeSeconds(
  maxDurationMinutes: number | null | undefined,
  startTime: Date,
  endTime: Date = new Date(),
): number {
  const maxSeconds = (maxDurationMinutes ?? 300) * 60
  const elapsedSeconds = Math.floor((endTime.getTime() - startTime.getTime()) / 1000)
  return Math.min(maxSeconds, Math.max(0, elapsedSeconds))
}

export async function recordTaskUsage(
  userId: string,
  { computeSeconds, onDemandRun = true }: { computeSeconds: number; onDemandRun?: boolean },
): Promise<void> {
  if (computeSeconds <= 0 && !onDemandRun) return

  const usageDate = formatUsageDate(new Date())
  const onDemandIncrement = onDemandRun ? 1 : 0

  await db
    .insert(usageSnapshots)
    .values({
      id: nanoid(),
      userId,
      usageDate,
      computeSeconds: Math.max(0, computeSeconds),
      onDemandRuns: onDemandIncrement,
    })
    .onConflictDoUpdate({
      target: [usageSnapshots.userId, usageSnapshots.usageDate],
      set: {
        computeSeconds: sql`${usageSnapshots.computeSeconds} + ${Math.max(0, computeSeconds)}`,
        onDemandRuns: sql`${usageSnapshots.onDemandRuns} + ${onDemandIncrement}`,
        updatedAt: new Date(),
      },
    })
}

export async function recordTaskUsageForTask(taskId: string, options?: { startTime?: Date }): Promise<void> {
  try {
    const [task] = await db.select().from(tasks).where(eq(tasks.id, taskId)).limit(1)
    if (!task) return

    const startTime = options?.startTime ?? task.createdAt
    const computeSeconds = computeTaskComputeSeconds(task.maxDuration, startTime)

    await recordTaskUsage(task.userId, { computeSeconds, onDemandRun: true })
  } catch (error) {
    console.error('Failed to record task usage:', error)
  }
}

export async function getUserUsageSummary(userId: string): Promise<MockUsageData> {
  const now = new Date()
  const { start, end } = getBillingPeriodBounds(now)
  const startDate = formatUsageDate(start)
  const endDate = formatUsageDate(end)

  const [userPlan] = await db
    .select({
      planCode: plans.code,
      planName: plans.name,
      planDescription: plans.description,
      priceLabel: plans.priceLabel,
      computeHoursLimit: plans.computeHoursLimit,
      onDemandRunsLimit: plans.onDemandRunsLimit,
      features: plans.features,
    })
    .from(users)
    .innerJoin(plans, eq(users.planId, plans.code))
    .where(eq(users.id, userId))
    .limit(1)

  if (!userPlan) {
    throw new Error('User or plan not found')
  }

  const [aggregates] = await db
    .select({
      totalComputeSeconds: sql<number>`coalesce(sum(${usageSnapshots.computeSeconds}), 0)::int`,
      totalOnDemandRuns: sql<number>`coalesce(sum(${usageSnapshots.onDemandRuns}), 0)::int`,
    })
    .from(usageSnapshots)
    .where(
      and(
        eq(usageSnapshots.userId, userId),
        gte(usageSnapshots.usageDate, startDate),
        lte(usageSnapshots.usageDate, endDate),
      ),
    )

  const totalComputeSeconds = Number(aggregates?.totalComputeSeconds ?? 0)
  const totalOnDemandRuns = Number(aggregates?.totalOnDemandRuns ?? 0)
  const computeHoursUsed = Math.round((totalComputeSeconds / 3600) * 10) / 10

  return {
    compute: {
      used: computeHoursUsed,
      limit: userPlan.computeHoursLimit,
      unit: 'compute hours',
    },
    onDemand: {
      used: totalOnDemandRuns,
      limit: userPlan.onDemandRunsLimit,
      unit: 'on-demand runs',
    },
    plan: {
      id: userPlan.planCode,
      name: userPlan.planName,
      priceLabel: userPlan.priceLabel,
      description: userPlan.planDescription ?? '',
      features: userPlan.features ?? [],
    },
    billingPeriodEnd: getBillingPeriodEndIso(now),
  }
}
