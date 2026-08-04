/**
 * Placeholder usage and plan data for the Plan & Usage page.
 * TODO(INT): Replace with billing API integration when subscription backend lands.
 */

export interface UsageMetric {
  used: number
  limit: number
  unit: string
}

export interface PlanInfo {
  id: string
  name: string
  priceLabel: string
  description: string
  features: string[]
}

export interface MockUsageData {
  compute: UsageMetric
  onDemand: UsageMetric
  plan: PlanInfo
  billingPeriodEnd: string
}

export const MOCK_USAGE_DATA: MockUsageData = {
  compute: {
    used: 42,
    limit: 100,
    unit: 'compute hours',
  },
  onDemand: {
    used: 8,
    limit: 25,
    unit: 'on-demand runs',
  },
  plan: {
    id: 'free',
    name: 'Free',
    priceLabel: '$0 / month',
    description: 'Get started with ARES Auditor on the free tier.',
    features: ['100 compute hours / month', '25 on-demand runs', 'Community support', 'Single workspace'],
  },
  billingPeriodEnd: '2026-09-01',
}

export function usagePercent(used: number, limit: number): number {
  if (limit <= 0) return 0
  return Math.min(100, Math.round((used / limit) * 100))
}
