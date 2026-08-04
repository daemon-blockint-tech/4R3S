import { db } from '@/lib/db/client'
import { tasks, taskMessages } from '@/lib/db/schema'
import { eq, gte, and, isNull } from 'drizzle-orm'
import { getMaxMessagesPerDay } from '@/lib/db/settings'

export async function checkRateLimit(
  userId: string,
): Promise<{ allowed: boolean; remaining: number; total: number; resetAt: Date }> {
  // Per-user settings.maxMessagesPerDay, else env MAX_MESSAGES_PER_DAY (no global DB tier)
  const maxMessagesPerDay = await getMaxMessagesPerDay(userId)

  // Get start of today (UTC)
  const today = new Date()
  today.setUTCHours(0, 0, 0, 0)

  // Get end of today (UTC)
  const tomorrow = new Date(today)
  tomorrow.setUTCDate(tomorrow.getUTCDate() + 1)

  // Daily quota: taskMessages role=user only (non-deleted tasks).
  // Pre-insert check: allowed when count < maxMessagesPerDay.
  const userMessagesToday = await db
    .select()
    .from(taskMessages)
    .innerJoin(tasks, eq(taskMessages.taskId, tasks.id))
    .where(
      and(
        eq(tasks.userId, userId),
        eq(taskMessages.role, 'user'),
        gte(taskMessages.createdAt, today),
        isNull(tasks.deletedAt),
      ),
    )

  const count = userMessagesToday.length
  const remaining = Math.max(0, maxMessagesPerDay - count)
  const allowed = count < maxMessagesPerDay

  return {
    allowed,
    remaining,
    total: maxMessagesPerDay,
    resetAt: tomorrow,
  }
}
