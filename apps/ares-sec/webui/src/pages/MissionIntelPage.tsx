import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Activity, GitBranch, ListChecks, ShieldAlert, Waypoints } from 'lucide-react'
import { api } from '@/lib/api'
import { PageHeader, EmptyState, LoadingState, ErrorState } from '@/components/common'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { ScrollArea } from '@/components/ui/scroll-area'
import { cn } from '@/lib/utils'

interface Hypothesis {
  id: string
  claim: string
  rationale: string
  status: string
  confidence: number
  evidenceForIds: string[]
  evidenceAgainstIds: string[]
  findingIds: string[]
  nextTests: string[]
}

interface WorkOrder {
  id: string
  hypothesisId: string
  squad: string
  title: string
  objective: string
  kind?: string
  status: string
  requiresReceipt?: boolean
  resultSummary?: string
}

const STATUS_TONE: Record<string, string> = {
  open: 'bg-muted text-muted-foreground border-border',
  testing: 'bg-primary/15 text-primary border-primary/30',
  supported: 'bg-[var(--color-success)]/15 text-[var(--color-success)] border-[var(--color-success)]/30',
  promoted: 'bg-[var(--color-success)]/15 text-[var(--color-success)] border-[var(--color-success)]/30',
  weakened: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  rejected: 'bg-destructive/15 text-destructive border-destructive/30',
  completed: 'bg-[var(--color-success)]/15 text-[var(--color-success)] border-[var(--color-success)]/30',
  needs_receipt: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
}

function tone(status: string) {
  return STATUS_TONE[status] ?? STATUS_TONE.open
}

export function MissionIntelPage() {
  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader
        title="Mission Intel"
        description="Everything between a hunch and an evidence-backed finding: hypotheses, work orders, the watch loop, self-heal, and pressure paths."
      />
      <Tabs defaultValue="hypotheses">
        <TabsList className="mb-4 flex-wrap">
          <TabsTrigger value="hypotheses">
            <GitBranch className="size-4" /> Hypotheses
          </TabsTrigger>
          <TabsTrigger value="work-orders">
            <ListChecks className="size-4" /> Work Orders
          </TabsTrigger>
          <TabsTrigger value="watch-loop">
            <Activity className="size-4" /> Watch Loop
          </TabsTrigger>
          <TabsTrigger value="self-heal">
            <ShieldAlert className="size-4" /> Self-Heal
          </TabsTrigger>
          <TabsTrigger value="pressure">
            <Waypoints className="size-4" /> Pressure Paths
          </TabsTrigger>
        </TabsList>

        <TabsContent value="hypotheses">
          <HypothesesTab />
        </TabsContent>
        <TabsContent value="work-orders">
          <WorkOrdersTab />
        </TabsContent>
        <TabsContent value="watch-loop">
          <WatchLoopTab />
        </TabsContent>
        <TabsContent value="self-heal">
          <SelfHealTab />
        </TabsContent>
        <TabsContent value="pressure">
          <PressurePathsTab />
        </TabsContent>
      </Tabs>
    </div>
  )
}

function HypothesesTab() {
  const qc = useQueryClient()
  const q = useQuery({
    queryKey: ['hypotheses'],
    queryFn: () => api.get<{ hypotheses: Hypothesis[] }>('/api/hypotheses'),
  })
  const decompose = useMutation({
    mutationFn: (id: string) => api.post(`/api/hypotheses/${id}/work-orders`, {}),
    onSuccess: () => {
      toast.success('Decomposed into work orders')
      qc.invalidateQueries({ queryKey: ['work-orders'] })
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Decompose failed'),
  })
  const promote = useMutation({
    mutationFn: (id: string) => api.post(`/api/hypotheses/${id}/promote`, {}),
    onSuccess: () => {
      toast.success('Promoted to finding')
      q.refetch()
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Promote failed'),
  })

  if (q.isLoading) return <LoadingState />
  if (q.error) return <ErrorState error={q.error} />
  const hypotheses = q.data?.hypotheses ?? []
  if (hypotheses.length === 0) {
    return (
      <EmptyState
        icon={GitBranch}
        title="No hypotheses staged"
        hint="Hypotheses appear as operators reason about the target. Each must be hardened with evidence before promotion to a finding."
      />
    )
  }

  return (
    <div className="grid gap-3">
      {hypotheses.map((h) => (
        <Card key={h.id}>
          <CardHeader className="pb-2">
            <div className="flex items-start justify-between gap-3">
              <CardTitle className="text-sm font-medium leading-snug">{h.claim}</CardTitle>
              <Badge variant="outline" className={cn('shrink-0 font-mono text-[10px]', tone(h.status))}>
                {h.status}
              </Badge>
            </div>
            <CardDescription className="text-xs">{h.rationale}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex flex-wrap gap-3 font-mono text-[11px] text-muted-foreground">
              <span>confidence {(h.confidence * 100).toFixed(0)}%</span>
              <span className="text-[var(--color-success)]">for {h.evidenceForIds.length}</span>
              <span className="text-amber-400">against {h.evidenceAgainstIds.length}</span>
              <span>findings {h.findingIds.length}</span>
            </div>
            {h.nextTests.length > 0 && (
              <ul className="space-y-1 text-xs text-muted-foreground">
                {h.nextTests.map((t, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="text-primary">›</span>
                    {t}
                  </li>
                ))}
              </ul>
            )}
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="secondary"
                onClick={() => decompose.mutate(h.id)}
                disabled={decompose.isPending}
              >
                Decompose
              </Button>
              <Button
                size="sm"
                onClick={() => promote.mutate(h.id)}
                disabled={promote.isPending || h.evidenceForIds.length === 0}
              >
                Promote to finding
              </Button>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

function WorkOrdersTab() {
  const qc = useQueryClient()
  const q = useQuery({
    queryKey: ['work-orders'],
    queryFn: () => api.get<{ workOrders: WorkOrder[] }>('/api/work-orders'),
  })
  const complete = useMutation({
    mutationFn: (id: string) => api.post(`/api/work-orders/${id}/complete`, {}),
    onSuccess: () => {
      toast.success('Work order completed')
      qc.invalidateQueries({ queryKey: ['work-orders'] })
      qc.invalidateQueries({ queryKey: ['hypotheses'] })
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Complete failed'),
  })

  if (q.isLoading) return <LoadingState />
  if (q.error) return <ErrorState error={q.error} />
  const orders = q.data?.workOrders ?? []
  if (orders.length === 0) {
    return (
      <EmptyState
        icon={ListChecks}
        title="No work orders"
        hint="Decompose a hypothesis to generate bounded prove/disprove work orders."
      />
    )
  }

  return (
    <div className="grid gap-3">
      {orders.map((o) => (
        <Card key={o.id}>
          <CardHeader className="pb-2">
            <div className="flex items-start justify-between gap-3">
              <CardTitle className="text-sm font-medium leading-snug">{o.title}</CardTitle>
              <div className="flex shrink-0 items-center gap-1">
                {o.kind && (
                  <Badge variant="outline" className="font-mono text-[10px] capitalize">
                    {o.kind}
                  </Badge>
                )}
                <Badge variant="outline" className={cn('font-mono text-[10px]', tone(o.status))}>
                  {o.status}
                </Badge>
              </div>
            </div>
            <CardDescription className="text-xs">{o.objective}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex flex-wrap gap-3 font-mono text-[11px] text-muted-foreground">
              <span>squad {o.squad}</span>
              {o.requiresReceipt && <span className="text-orange-400">receipt required</span>}
            </div>
            {o.resultSummary && <p className="text-xs text-muted-foreground">{o.resultSummary}</p>}
            {o.status !== 'completed' && (
              <Button
                size="sm"
                variant="secondary"
                onClick={() => complete.mutate(o.id)}
                disabled={complete.isPending}
              >
                Mark complete + attach evidence
              </Button>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

function WatchLoopTab() {
  const q = useQuery({
    queryKey: ['watch-loop'],
    queryFn: () => api.get<Record<string, unknown>>('/api/watch-loop/status'),
  })
  const run = useMutation({
    mutationFn: () => api.post('/api/watch-loop/run', {}),
    onSuccess: () => {
      toast.success('Watch cycle executed')
      q.refetch()
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Watch loop failed'),
  })
  const summary = (q.data?.summary ?? {}) as Record<string, number>
  const signals = (q.data?.signals ?? []) as Array<Record<string, unknown>>

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="grid grid-cols-4 gap-2 text-xs">
          <Stat label="Cycles" value={String(summary.cycles ?? 0)} />
          <Stat label="Blocks" value={String(summary.blocks ?? 0)} tone="danger" />
          <Stat label="Actions" value={String(summary.actions ?? 0)} tone="warning" />
          <Stat label="Watches" value={String(summary.watches ?? 0)} />
        </div>
        <Button size="sm" onClick={() => run.mutate()} disabled={run.isPending}>
          Run watch cycle
        </Button>
      </div>
      {signals.length === 0 ? (
        <EmptyState icon={Activity} title="No signals" hint="Run a watch cycle to evaluate mission drift, coverage, and OPSEC pressure." />
      ) : (
        <div className="grid gap-2">
          {signals.map((s, i) => (
            <div
              key={i}
              className="flex items-start gap-2 rounded-md border border-border bg-background/50 px-3 py-2 text-xs"
            >
              <Badge
                variant="outline"
                className={cn(
                  'shrink-0 font-mono text-[10px]',
                  s.severity === 'block' && 'border-destructive/30 text-destructive',
                  s.severity === 'action' && 'border-amber-500/30 text-amber-400',
                )}
              >
                {String(s.severity ?? 'watch')}
              </Badge>
              <span className="leading-snug">
                <span className="font-medium">{String(s.title ?? s.message ?? 'Signal')}</span>
                {s.detail != null && (
                  <span className="mt-0.5 block text-muted-foreground">{String(s.detail)}</span>
                )}
                {s.recommendedAction != null && (
                  <span className="mt-0.5 block text-primary/80">→ {String(s.recommendedAction)}</span>
                )}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function SelfHealTab() {
  const run = useMutation({
    mutationFn: () => api.post<Record<string, unknown>>('/api/self-heal/run', {}),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Self-heal failed'),
  })

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Self-heal report</CardTitle>
          <CardDescription className="text-xs">
            Diagnose stalled mission state and propose recovery actions — read-only until you apply them.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button size="sm" onClick={() => run.mutate()} disabled={run.isPending}>
            Run self-heal
          </Button>
        </CardContent>
      </Card>
      {run.data && (
        <ScrollArea className="h-80 rounded-md border border-border bg-background/40 p-3">
          <pre className="font-mono text-[11px] leading-relaxed text-foreground/90">
            {JSON.stringify(run.data, null, 2)}
          </pre>
        </ScrollArea>
      )}
    </div>
  )
}

function PressurePathsTab() {
  const [target, setTarget] = useState('')
  const q = useQuery({
    queryKey: ['pressure-paths'],
    queryFn: () => api.get<Record<string, unknown>>('/api/pressure-paths'),
  })
  const [result, setResult] = useState<Record<string, unknown> | null>(null)

  function runPath(kind: 'canary' | 'duel' | 'mutate' | 'chains') {
    api
      .post<Record<string, unknown>>(`/api/pressure-paths/${kind}`, { target: target.trim() || undefined })
      .then((r) => {
        setResult(r)
        toast.success(`${kind} pressure path executed`)
      })
      .catch((e) => toast.error(e instanceof Error ? e.message : 'Pressure path failed'))
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Adversarial pressure paths</CardTitle>
          <CardDescription className="text-xs">
            Canary probes, duels, mutations, and chained pressure, all inside mission authority and containment.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Target (optional — defaults to active mission scope)"
            className="font-mono text-sm"
          />
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="secondary" onClick={() => runPath('canary')}>
              Canary
            </Button>
            <Button size="sm" variant="secondary" onClick={() => runPath('duel')}>
              Duel
            </Button>
            <Button size="sm" variant="secondary" onClick={() => runPath('mutate')}>
              Mutate
            </Button>
            <Button size="sm" variant="secondary" onClick={() => runPath('chains')}>
              Chains
            </Button>
          </div>
        </CardContent>
      </Card>
      {(result || q.data) && (
        <ScrollArea className="h-80 rounded-md border border-border bg-background/40 p-3">
          <pre className="font-mono text-[11px] leading-relaxed text-foreground/90">
            {JSON.stringify(result ?? q.data, null, 2)}
          </pre>
        </ScrollArea>
      )}
    </div>
  )
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: 'danger' | 'warning' }) {
  return (
    <div className="rounded-md border border-border bg-background/50 px-3 py-2 text-center">
      <p className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</p>
      <p
        className={cn(
          'mt-0.5 font-mono text-base',
          tone === 'danger' && 'text-destructive',
          tone === 'warning' && 'text-amber-400',
        )}
      >
        {value}
      </p>
    </div>
  )
}
