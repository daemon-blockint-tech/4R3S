import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { api } from '@/lib/api'
import { useEvents } from '@/hooks/useEvents'

export interface ApprovalRequest {
  id: string
  action: string
  target: string
  reason: string
  status: 'pending' | 'approved' | 'rejected' | 'expired'
  requestedBy?: string
  createdAt?: string
  updatedAt?: string
  expiresAt?: string
}

export function useApprovals(status = 'pending') {
  const qc = useQueryClient()
  const { events } = useEvents(50, ['approval.'])

  const query = useQuery({
    queryKey: ['approvals', status],
    queryFn: () => api.get<{ approvals: ApprovalRequest[] }>(`/api/approvals?status=${status}`),
    refetchInterval: 5_000,
  })

  useEffect(() => {
    const last = events[events.length - 1]
    if (last?.type.startsWith('approval.')) {
      qc.invalidateQueries({ queryKey: ['approvals'] })
    }
  }, [events, qc])

  return {
    approvals: query.data?.approvals ?? [],
    isLoading: query.isLoading,
    refetch: query.refetch,
  }
}
