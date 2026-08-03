import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '@/lib/api'
import { useApprovalGate } from '@/contexts/ApprovalContext'

export interface MissionStatus {
  active: boolean
  paused?: boolean
  name?: string
  tickCount?: number
  mission?: {
    currentPhase?: string
    progress?: number
    status?: string
  } | null
  findings?: Array<{
    id: string
    title: string
    severity: string
    phase?: string
  }>
}

export interface StartMissionParams {
  name: string
  targets: Array<{ host: string }>
  operators: string[]
  opsecLevel?: string
  autonomous?: boolean
  approvalId?: string
  repoPath?: string
}

export function useMissionStatus() {
  return useQuery({
    queryKey: ['mission-status'],
    queryFn: () => api.get<MissionStatus>('/api/mission/status'),
    refetchInterval: 3_000,
  })
}

export function useMissionMutations() {
  const qc = useQueryClient()
  const { showApproval } = useApprovalGate()

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['mission-status'] })
    qc.invalidateQueries({ queryKey: ['findings'] })
  }

  const handleApprovalError = (e: unknown) => {
    if (e instanceof ApiError && e.approval) showApproval(e.approval)
    throw e
  }

  const start = useMutation({
    mutationFn: (body: StartMissionParams) => api.post('/api/mission/start', body),
    onSuccess: invalidate,
    onError: handleApprovalError,
  })

  const stop = useMutation({
    mutationFn: () => api.post('/api/mission/stop'),
    onSuccess: invalidate,
  })

  const pause = useMutation({
    mutationFn: () => api.post('/api/mission/pause'),
    onSuccess: invalidate,
  })

  const resume = useMutation({
    mutationFn: () => api.post('/api/mission/resume'),
    onSuccess: invalidate,
  })

  return { start, stop, pause, resume }
}
