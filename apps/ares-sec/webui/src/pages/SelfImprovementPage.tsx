import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Brain, Check, X, RefreshCw, BookOpen, TrendingUp } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { PageHeader, EmptyState, LoadingState, Field } from '@/components/common'
import { cn } from '@/lib/utils'

interface ImprovementProposal {
  id: string
  routeId: string
  baseConfigId: string
  status: string
  rationale: string
  risks: string[]
  requiredReplaySuites: string[]
  rollbackTarget: string
}

interface MemoryProposal {
  id: string
  type: string
  content: string
  status: string
  observationCount?: number
  createdAt?: string
}

interface LedgerGen {
  generation?: number
  score?: number
  timestamp?: string
}

export function SelfImprovementPage() {
  const qc = useQueryClient()

  const ledger = useQuery({
    queryKey: ['selfimprove-ledger'],
    queryFn: () =>
      api.get<{
        available: boolean
        generations: LedgerGen[]
        tactics: string
      }>('/api/selfimprove/ledger'),
  })

  const proposals = useQuery({
    queryKey: ['memory-proposals'],
    queryFn: () => api.get<{ proposals: MemoryProposal[] }>('/api/memory/proposals'),
    refetchInterval: 10_000,
  })

  const learning = useQuery({
    queryKey: ['learning-status'],
    queryFn: () => api.get<Record<string, unknown>>('/api/learning/status'),
  })

  const capsule = useQuery({
    queryKey: ['memory-capsule'],
    queryFn: () => api.get<{ entries?: unknown[] }>('/api/memory/capsule'),
  })

  const runReview = useMutation({
    mutationFn: () => api.post('/api/learning/run-review', {}),
    onSuccess: () => {
      toast.success('Review run complete')
      qc.invalidateQueries({ queryKey: ['memory-proposals'] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const accept = useMutation({
    mutationFn: (id: string) => api.post(`/api/memory/proposals/${id}/accept`, {}),
    onSuccess: () => {
      toast.success('Proposal accepted')
      qc.invalidateQueries({ queryKey: ['memory-proposals'] })
      qc.invalidateQueries({ queryKey: ['memory-capsule'] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const reject = useMutation({
    mutationFn: (id: string) => api.post(`/api/memory/proposals/${id}/reject`, {}),
    onSuccess: () => {
      toast.success('Proposal rejected')
      qc.invalidateQueries({ queryKey: ['memory-proposals'] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const improvements = useQuery({
    queryKey: ['improvement-proposals'],
    queryFn: () => api.get<{ proposals: ImprovementProposal[] }>('/api/improvement/proposals'),
    refetchInterval: 15_000,
  })

  const [routeId, setRouteId] = useState('web_api')
  const [rationale, setRationale] = useState('')
  const [evalResult, setEvalResult] = useState<Record<string, unknown> | null>(null)

  const createImprovement = useMutation({
    mutationFn: () =>
      api.post('/api/improvement/proposals', { routeId: routeId.trim() || 'web_api', rationale: rationale.trim() || undefined }),
    onSuccess: () => {
      toast.success('Improvement proposed')
      setRationale('')
      qc.invalidateQueries({ queryKey: ['improvement-proposals'] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const evaluatePromotion = useMutation({
    mutationFn: (proposalId: string) =>
      api.post<Record<string, unknown>>('/api/promotion/evaluate', { proposalId }),
    onSuccess: (r) => {
      setEvalResult(r)
      toast.success('Promotion evaluated')
      qc.invalidateQueries({ queryKey: ['improvement-proposals'] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const pending = (proposals.data?.proposals ?? []).filter((p) => p.status === 'pending')

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="Self-Improvement"
        description="Review what ARES learned from past runs. Accept memory proposals to promote them into the active capsule."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => runReview.mutate()}
            disabled={runReview.isPending}
          >
            <RefreshCw className={cn('size-3.5', runReview.isPending && 'animate-spin')} />
            Run review
          </Button>
        }
      />

      <Tabs defaultValue="proposals">
        <TabsList>
          <TabsTrigger value="proposals">
            <Brain className="size-3.5" />
            Memory proposals ({pending.length})
          </TabsTrigger>
          <TabsTrigger value="improvements">
            <TrendingUp className="size-3.5" />
            Improvements
          </TabsTrigger>
          <TabsTrigger value="ledger">Evolve ledger</TabsTrigger>
          <TabsTrigger value="learning">Learning status</TabsTrigger>
          <TabsTrigger value="capsule">
            <BookOpen className="size-3.5" />
            Capsule
          </TabsTrigger>
        </TabsList>

        <TabsContent value="proposals" className="mt-4">
          {proposals.isLoading ? (
            <LoadingState />
          ) : pending.length === 0 ? (
            <EmptyState icon={Brain} title="No pending proposals" hint="Run a review to generate new memory proposals." />
          ) : (
            <div className="flex flex-col gap-2">
              {pending.map((p) => (
                <Card key={p.id}>
                  <CardContent className="flex flex-wrap items-start gap-3 py-4">
                    <div className="min-w-0 flex-1">
                      <div className="mb-1 flex gap-2">
                        <Badge variant="outline" className="font-mono text-[10px]">
                          {p.type}
                        </Badge>
                        {(p.observationCount ?? 1) > 1 && (
                          <Badge variant="secondary" className="text-[10px]">
                            ×{p.observationCount} observed
                          </Badge>
                        )}
                      </div>
                      <p className="text-sm leading-relaxed">{p.content}</p>
                    </div>
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" onClick={() => reject.mutate(p.id)}>
                        <X className="size-3.5" />
                      </Button>
                      <Button size="sm" onClick={() => accept.mutate(p.id)}>
                        <Check className="size-3.5" />
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="improvements" className="mt-4 space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Propose an improvement</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid gap-3 sm:grid-cols-[12rem_1fr]">
                <Field label="Route">
                  <Input value={routeId} onChange={(e) => setRouteId(e.target.value)} className="font-mono text-sm" />
                </Field>
                <Field label="Rationale">
                  <Textarea
                    value={rationale}
                    onChange={(e) => setRationale(e.target.value)}
                    rows={2}
                    placeholder="Why this candidate improves the route; must pass replay validation before promotion."
                  />
                </Field>
              </div>
              <Button size="sm" onClick={() => createImprovement.mutate()} disabled={createImprovement.isPending}>
                Propose
              </Button>
            </CardContent>
          </Card>

          {improvements.isLoading ? (
            <LoadingState />
          ) : (improvements.data?.proposals ?? []).length === 0 ? (
            <EmptyState icon={TrendingUp} title="No improvement proposals" hint="Propose one above; each is replay-validated before promotion." />
          ) : (
            <div className="flex flex-col gap-2">
              {improvements.data!.proposals.map((p) => (
                <Card key={p.id}>
                  <CardContent className="space-y-2 py-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="outline" className="font-mono text-[10px]">
                        {p.routeId}
                      </Badge>
                      <Badge
                        variant="secondary"
                        className={cn(
                          'font-mono text-[10px]',
                          p.status === 'promoted' && 'text-[var(--color-success)]',
                          p.status === 'rejected' && 'text-destructive',
                        )}
                      >
                        {p.status}
                      </Badge>
                      <code className="font-mono text-[10px] text-muted-foreground">{p.id}</code>
                    </div>
                    <p className="text-sm text-muted-foreground">{p.rationale}</p>
                    {p.requiredReplaySuites?.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {p.requiredReplaySuites.map((s, i) => (
                          <Badge key={i} variant="outline" className="text-[9px]">
                            {s}
                          </Badge>
                        ))}
                      </div>
                    )}
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => evaluatePromotion.mutate(p.id)}
                      disabled={evaluatePromotion.isPending}
                    >
                      Evaluate promotion
                    </Button>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
          {evalResult && (
            <pre className="max-h-64 overflow-auto rounded-lg border border-border p-4 text-xs">
              {JSON.stringify(evalResult, null, 2)}
            </pre>
          )}
        </TabsContent>

        <TabsContent value="ledger" className="mt-4">
          {ledger.isLoading ? (
            <LoadingState />
          ) : !ledger.data?.available ? (
            <EmptyState icon={Brain} title="No evolve ledger" hint="Run obsidivm:evolve to populate bench/obsidivm-evolution." />
          ) : (
            <div className="space-y-4">
              <div className="flex flex-col gap-2">
                {(ledger.data.generations ?? []).map((g, i) => (
                  <div key={i} className="flex items-center gap-3 rounded-md border border-border px-3 py-2 text-sm">
                    <span className="font-mono text-muted-foreground">gen {g.generation ?? i}</span>
                    <span className="font-mono">{g.score ?? '—'}</span>
                    <span className="text-xs text-muted-foreground">{g.timestamp}</span>
                  </div>
                ))}
              </div>
              {ledger.data.tactics && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Current tactics</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <pre className="max-h-64 overflow-auto whitespace-pre-wrap text-xs text-muted-foreground">
                      {ledger.data.tactics}
                    </pre>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </TabsContent>

        <TabsContent value="learning" className="mt-4">
          {learning.isLoading ? (
            <LoadingState />
          ) : (
            <pre className="overflow-x-auto rounded-lg border border-border p-4 text-xs">
              {JSON.stringify(learning.data, null, 2)}
            </pre>
          )}
        </TabsContent>

        <TabsContent value="capsule" className="mt-4">
          {capsule.isLoading ? (
            <LoadingState />
          ) : (
            <pre className="max-h-96 overflow-auto rounded-lg border border-border p-4 text-xs">
              {JSON.stringify(capsule.data, null, 2)}
            </pre>
          )}
        </TabsContent>
      </Tabs>
    </div>
  )
}
