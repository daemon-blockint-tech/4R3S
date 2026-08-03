import { useQuery } from '@tanstack/react-query'
import { api, healthToState, type HealthResponse } from '@/lib/api'

export function useHealth() {
  const query = useQuery({
    queryKey: ['health'],
    queryFn: () => api.get<HealthResponse>('/api/health'),
    refetchInterval: 10_000,
    retry: false,
  })
  const state = query.isLoading ? 'checking' : healthToState(query.data ?? null)
  return { ...query, state }
}
