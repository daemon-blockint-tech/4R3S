import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Crosshair, Search, CheckCircle2, XCircle, ShieldQuestion, Package, Check, X, Bot } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useApprovals } from '@/hooks/useApprovals'
import { useEvents } from '@/hooks/useEvents'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { PageHeader, EmptyState, ErrorState, LoadingState, riskClass } from '@/components/common'
import { cn } from '@/lib/utils'

const LOADOUT_KEY = 'ares_loadout'

interface Adapter {
  id: string
  binary: string
  name: string
  category: string
  risk: string
  execution: string
  networked: boolean
  status: string
  available: boolean
  notes: string
  installHint: string
}

interface ArsenalStatus {
  summary: {
    total: number
    commandReady: number
    installedCommandReady: number
    readiness: number
    adapterCoverage: number | null
  }
  tools: Adapter[]
}

interface ApprovalsState {
  active: boolean
  approvedTools: string[]
  preAuthorized: string[]
  audit: { tool?: string; decision?: string; at?: string; action?: string }[]
  note: string
}

interface PlanStep {
  step: number
  adapterId: string
  tool: string
  category: string
  gate: string
}

interface RedTeamTechnique {
  id: string
  category: string
  principle: string
  redteamUse: string
  defense: string
}

interface ActivationItem {
  id: string
  binary: string
  name: string
  category: string
  execution: string
  installHint: string
}

interface ActivationPlan {
  groups?: Record<string, ActivationItem[]>
  summary?: Record<string, unknown>
  policy?: Record<string, unknown>
}

export function ArsenalPage() {
  const [q, setQ] = useState('')
  const [category, setCategory] = useState('')
  const [loadout, setLoadout] = useState<string[]>(() => {
    try {
      return JSON.parse(localStorage.getItem(LOADOUT_KEY) ?? '[]')
    } catch {
      return []
    }
  })
  const qc = useQueryClient()
  const { events } = useEvents(30, ['approval.', 'arsenal'])
  const { approvals: pendingApprovals } = useApprovals('pending')

  const status = useQuery({
    queryKey: ['arsenal-status'],
    queryFn: () => api.get<ArsenalStatus>('/api/arsenal/status'),
    refetchInterval: 30_000,
  })

  const catalog = useQuery({
    queryKey: ['arsenal-catalog', category],
    queryFn: () =>
      api.get<{ adapters: Adapter[] }>(
        `/api/arsenal/catalog${category ? `?category=${encodeURIComponent(category)}` : ''}`,
      ),
  })

  const approvals = useQuery({
    queryKey: ['arsenal-approvals'],
    queryFn: () => api.get<ApprovalsState>('/api/arsenal/approvals'),
    refetchInterval: 15_000,
  })

  const activation = useQuery({
    queryKey: ['arsenal-activation'],
    queryFn: () => api.get<ActivationPlan>('/api/arsenal/activation'),
    enabled: loadout.length > 0,
  })

  const playbook = useQuery({
    queryKey: ['ai-redteam-playbook'],
    queryFn: () =>
      api.get<{ techniques: RedTeamTechnique[]; count: number; source: string }>(
        '/api/ai-redteam/playbook',
      ),
  })

  const plan = useMutation({
    mutationFn: () => api.post<{ steps?: PlanStep[] }>('/api/arsenal/plan', { tools: loadout }),
    onSuccess: () => toast.success('Plan generated'),
    onError: (e: Error) => toast.error(e.message),
  })

  useEffect(() => {
    const last = events[events.length - 1]
    if (last?.type.startsWith('approval.')) {
      qc.invalidateQueries({ queryKey: ['arsenal-approvals'] })
      qc.invalidateQueries({ queryKey: ['approvals'] })
    }
  }, [events, qc])

  useEffect(() => {
    localStorage.setItem(LOADOUT_KEY, JSON.stringify(loadout))
  }, [loadout])

  const categories = useMemo(() => {
    const all = status.data?.tools ?? catalog.data?.adapters ?? []
    return [...new Set(all.map((t) => t.category))].sort()
  }, [status.data, catalog.data])

  const tools = useMemo(() => {
    const all = catalog.data?.adapters ?? status.data?.tools ?? []
    const needle = q.trim().toLowerCase()
    return all.filter(
      (t) =>
        (!needle ||
          t.name.toLowerCase().includes(needle) ||
          t.binary.toLowerCase().includes(needle) ||
          t.category.toLowerCase().includes(needle)) &&
        (!category || t.category === category),
    )
  }, [catalog.data, status.data, q, category])

  function toggleLoadout(id: string) {
    setLoadout((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]))
  }

  async function resolveApproval(id: string, action: 'approve' | 'reject') {
    try {
      await api.post(`/api/approvals/${id}/${action}`)
      toast.success(action === 'approve' ? 'Approved' : 'Rejected')
      qc.invalidateQueries({ queryKey: ['approvals'] })
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed')
    }
  }

  const s = status.data?.summary

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="Arsenal"
        description="The tool catalog ARES reasons over. Command-ready adapters can run behind approval gates; catalog-only entries inform planning but never auto-execute."
      />

      {s && (
        <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Summary label="Adapters" value={s.total} />
          <Summary label="Command-ready" value={s.commandReady} />
          <Summary label="Installed" value={s.installedCommandReady} tone="good" />
          <Summary label="Readiness" value={`${s.readiness}%`} />
        </div>
      )}

      <Tabs defaultValue="catalog">
        <TabsList>
          <TabsTrigger value="catalog">
            <Crosshair className="size-3.5" />
            Catalog
          </TabsTrigger>
          <TabsTrigger value="loadout">
            <Package className="size-3.5" />
            Loadout ({loadout.length})
          </TabsTrigger>
          <TabsTrigger value="redteam">
            <Bot className="size-3.5" />
            AI Red-team
          </TabsTrigger>
          <TabsTrigger value="approvals">
            <ShieldQuestion className="size-3.5" />
            Approvals
          </TabsTrigger>
        </TabsList>

        <TabsContent value="catalog" className="mt-4">
          <div className="mb-3 flex flex-wrap gap-2">
            <div className="relative min-w-48 flex-1">
              <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Filter by name, binary, or category…"
                className="pl-9"
              />
            </div>
            <select
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              className="h-9 rounded-md border border-input bg-transparent px-3 text-sm"
            >
              <option value="">All categories</option>
              {categories.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>

          {status.isLoading ? (
            <LoadingState label="Inspecting toolchain…" />
          ) : status.error ? (
            <ErrorState error={status.error} />
          ) : tools.length === 0 ? (
            <EmptyState icon={Crosshair} title="No adapters match" />
          ) : (
            <div className="flex flex-col gap-2">
              {tools.map((t) => (
                <div
                  key={t.id}
                  className="flex items-start gap-3 rounded-lg border border-border px-4 py-3"
                >
                  <button
                    type="button"
                    onClick={() => toggleLoadout(t.id)}
                    className={cn(
                      'mt-0.5 flex size-5 shrink-0 items-center justify-center rounded border',
                      loadout.includes(t.id)
                        ? 'border-primary bg-primary text-primary-foreground'
                        : 'border-border',
                    )}
                  >
                    {loadout.includes(t.id) && <Check className="size-3" />}
                  </button>
                  <div className="mt-0.5 shrink-0">
                    {t.available ? (
                      <CheckCircle2 className="size-4 text-[var(--color-success)]" />
                    ) : (
                      <XCircle className="size-4 text-muted-foreground" />
                    )}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-medium">{t.name}</span>
                      <code className="font-mono text-xs text-muted-foreground">{t.binary}</code>
                    </div>
                    {t.notes && <p className="mt-0.5 text-xs text-muted-foreground">{t.notes}</p>}
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {t.category}
                    </Badge>
                    <span className={cn('font-mono text-[10px] uppercase', riskClass(t.risk))}>
                      {t.risk}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="loadout" className="mt-4 space-y-4">
          {loadout.length === 0 ? (
            <EmptyState icon={Package} title="Loadout empty" hint="Select tools from the Catalog tab." />
          ) : (
            <>
              <div className="flex flex-wrap gap-1.5">
                {loadout.map((id) => (
                  <Badge key={id} variant="secondary" className="font-mono text-[10px]">
                    {id}
                    <button type="button" className="ml-1" onClick={() => toggleLoadout(id)}>
                      ×
                    </button>
                  </Badge>
                ))}
              </div>
              <Button onClick={() => plan.mutate()} disabled={plan.isPending}>
                Generate plan
              </Button>
              {plan.data?.steps && (
                <div className="flex flex-col gap-2">
                  {plan.data.steps.map((step) => (
                    <div key={step.step} className="rounded-md border border-border px-3 py-2 text-xs">
                      <span className="font-mono text-muted-foreground">#{step.step}</span>{' '}
                      <span className="font-medium">{step.tool}</span>
                      <Badge variant="outline" className="ml-2 font-mono text-[9px]">
                        {step.gate}
                      </Badge>
                    </div>
                  ))}
                </div>
              )}
              {activation.data?.groups && Object.keys(activation.data.groups).length > 0 && (
                <div className="space-y-3">
                  <p className="text-xs uppercase tracking-wider text-muted-foreground">
                    Activation plan
                  </p>
                  {Object.entries(activation.data.groups).map(([group, items]) =>
                    items.length === 0 ? null : (
                      <div key={group} className="space-y-1.5">
                        <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                          {group}
                        </p>
                        {items.map((item) => (
                          <div
                            key={item.id}
                            className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2 text-xs"
                          >
                            <span className="font-medium">{item.name}</span>
                            <code className="font-mono text-[10px] text-muted-foreground">{item.binary}</code>
                            <Badge variant="outline" className="font-mono text-[9px]">
                              {item.category}
                            </Badge>
                            <Badge variant="secondary" className="font-mono text-[9px]">
                              {item.execution}
                            </Badge>
                            <span className="flex-1 truncate text-muted-foreground">{item.installHint}</span>
                          </div>
                        ))}
                      </div>
                    ),
                  )}
                </div>
              )}
            </>
          )}
        </TabsContent>

        <TabsContent value="redteam" className="mt-4 space-y-4">
          {playbook.isLoading ? (
            <LoadingState label="Loading playbook…" />
          ) : playbook.error ? (
            <ErrorState error={playbook.error} />
          ) : (
            <>
              <p className="text-xs text-muted-foreground">
                {playbook.data?.count} defanged techniques · {playbook.data?.source}
              </p>
              <div className="flex flex-col gap-3">
                {(playbook.data?.techniques ?? []).map((t) => (
                  <Card key={t.id}>
                    <CardContent className="space-y-2 py-4">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-sm font-medium">{t.category}</p>
                        <code className="font-mono text-[10px] text-muted-foreground">{t.id}</code>
                      </div>
                      <p className="text-xs text-muted-foreground">{t.principle}</p>
                      <div className="rounded-md border border-primary/20 bg-primary/5 px-3 py-2 text-xs">
                        <span className="font-medium text-primary">Red-team use: </span>
                        {t.redteamUse}
                      </div>
                      <div className="rounded-md border border-[var(--color-success)]/20 bg-[var(--color-success)]/5 px-3 py-2 text-xs">
                        <span className="font-medium text-[var(--color-success)]">Defense: </span>
                        {t.defense}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </>
          )}
        </TabsContent>

        <TabsContent value="approvals" className="mt-4 space-y-4">
          {pendingApprovals.length > 0 && (
            <div>
              <p className="mb-2 text-xs uppercase tracking-wider text-muted-foreground">
                Pending action approvals
              </p>
              <div className="flex flex-col gap-2">
                {pendingApprovals.map((a) => (
                  <div
                    key={a.id}
                    className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2 text-xs"
                  >
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {a.action}
                    </Badge>
                    <span className="font-mono">{a.target}</span>
                    <span className="flex-1 truncate text-muted-foreground">{a.reason}</span>
                    <Button size="sm" variant="outline" onClick={() => resolveApproval(a.id, 'reject')}>
                      <X className="size-3" />
                    </Button>
                    <Button size="sm" onClick={() => resolveApproval(a.id, 'approve')}>
                      <Check className="size-3" />
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {approvals.isLoading ? (
            <LoadingState />
          ) : approvals.error ? (
            <ErrorState error={approvals.error} />
          ) : (
            <>
              <p className="text-sm text-muted-foreground">{approvals.data?.note}</p>
              <Card>
                <CardContent className="py-4">
                  <p className="mb-2 text-xs uppercase tracking-wider text-muted-foreground">
                    Approved tools
                  </p>
                  {(approvals.data?.approvedTools ?? []).length === 0 ? (
                    <p className="text-sm text-muted-foreground">None approved this session.</p>
                  ) : (
                    <div className="flex flex-wrap gap-1.5">
                      {approvals.data?.approvedTools.map((t) => (
                        <Badge key={t} variant="secondary" className="font-mono text-[10px]">
                          {t}
                        </Badge>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
              <div>
                <p className="mb-2 text-xs uppercase tracking-wider text-muted-foreground">
                  Audit trail
                </p>
                {(approvals.data?.audit ?? []).length === 0 ? (
                  <EmptyState icon={ShieldQuestion} title="No gated decisions logged" />
                ) : (
                  <div className="flex flex-col gap-1.5">
                    {approvals.data?.audit.map((a, i) => (
                      <div
                        key={i}
                        className="flex items-center gap-2 rounded-md border border-border px-3 py-2 text-xs"
                      >
                        <Badge
                          variant="outline"
                          className={cn(
                            'font-mono text-[10px]',
                            a.decision === 'approved'
                              ? 'border-[var(--color-success)]/30 text-[var(--color-success)]'
                              : 'border-destructive/30 text-destructive',
                          )}
                        >
                          {a.decision}
                        </Badge>
                        <span className="font-mono">{a.tool}</span>
                        <span className="flex-1 truncate text-muted-foreground">{a.action}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </TabsContent>
      </Tabs>
    </div>
  )
}

function Summary({ label, value, tone }: { label: string; value: number | string; tone?: 'good' }) {
  return (
    <div className="rounded-lg border border-border bg-background/50 px-4 py-3">
      <p className={cn('font-mono text-2xl font-semibold', tone === 'good' && 'text-[var(--color-success)]')}>
        {value}
      </p>
      <p className="mt-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">{label}</p>
    </div>
  )
}
