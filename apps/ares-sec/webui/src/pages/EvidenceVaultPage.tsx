import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ShieldAlert, RefreshCw, RotateCcw, ChevronDown, Plus, Download, Network, FileText, KeyRound } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { PageHeader, EmptyState, ErrorState, LoadingState, severityClass, Field } from '@/components/common'
import { cn } from '@/lib/utils'

interface Finding {
  id: string
  family: string
  title: string
  target: string
  claim: string
  impact: string
  severity: string
  confidence: number
  status: string
  recommendedFix: string
  acceptanceCriteria: string[]
  updatedAt: string
  evidenceIds?: string[]
}

interface EvidenceItem {
  id: string
  kind: string
  type?: string
  title?: string
  summary: string
  source?: string
  findingId?: string
  createdAt?: string
}

interface RetestRecord {
  id: string
  findingId: string
  status: string
  method: string
  resultSummary?: string
  acceptanceCriteria?: string[]
  updatedAt: string
}

interface GraphNode {
  id: string
  type: string
  label: string
  status?: string
}

interface GraphEdge {
  from: string
  to: string
  type: string
}

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info']
const STATUSES = ['', 'open', 'confirmed', 'triaged', 'remediated', 'false_positive']
const NEXT_STATUS: Record<string, string> = {
  open: 'confirmed',
  confirmed: 'remediated',
  triaged: 'confirmed',
  remediated: 'open',
  false_positive: 'open',
}
const RETEST_STATUSES = ['queued', 'passed', 'failed', 'blocked'] as const

export function EvidenceVaultPage() {
  const qc = useQueryClient()
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [newTitle, setNewTitle] = useState('')
  const [newTarget, setNewTarget] = useState('')
  const [newClaim, setNewClaim] = useState('')
  const [newSeverity, setNewSeverity] = useState('medium')
  const [evidenceOpen, setEvidenceOpen] = useState(false)
  const [evTitle, setEvTitle] = useState('')
  const [evSummary, setEvSummary] = useState('')
  const [evType, setEvType] = useState('note')

  const query = useQuery({
    queryKey: ['findings', status],
    queryFn: () => api.get<{ findings: Finding[] }>(`/api/findings${status ? `?status=${status}` : ''}`),
    refetchInterval: 12_000,
  })

  const graph = useQuery({
    queryKey: ['evidence-graph'],
    queryFn: () =>
      api.get<{ nodes: GraphNode[]; edges: GraphEdge[] }>('/api/evidence-graph'),
  })

  const evidenceList = useQuery({
    queryKey: ['evidence-all'],
    queryFn: () => api.get<{ evidence: EvidenceItem[] }>('/api/evidence'),
  })

  const retests = useQuery({
    queryKey: ['retests'],
    queryFn: () => api.get<{ retests: RetestRecord[] }>('/api/retests'),
    refetchInterval: 15_000,
  })

  const operators = useQuery({
    queryKey: ['operators'],
    queryFn: () => api.get<{ operators: Array<{ credentials?: number }> }>('/api/operators/list'),
    refetchInterval: 20_000,
  })

  const createEvidence = useMutation({
    mutationFn: () =>
      api.post('/api/evidence', {
        title: evTitle.trim() || 'Untitled evidence',
        summary: evSummary.trim(),
        type: evType,
        source: 'human',
      }),
    onSuccess: () => {
      toast.success('Evidence added')
      setEvidenceOpen(false)
      setEvTitle('')
      setEvSummary('')
      qc.invalidateQueries({ queryKey: ['evidence-all'] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const patchRetest = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      api.patch(`/api/retests/${id}`, { status }),
    onSuccess: () => {
      toast.success('Retest updated')
      qc.invalidateQueries({ queryKey: ['retests'] })
      qc.invalidateQueries({ queryKey: ['findings'] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const credentialsCaptured = useMemo(
    () => (operators.data?.operators ?? []).reduce((sum, o) => sum + (o.credentials ?? 0), 0),
    [operators.data],
  )

  const patch = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      api.patch(`/api/findings/${id}`, { status }),
    onSuccess: () => {
      toast.success('Finding updated')
      qc.invalidateQueries({ queryKey: ['findings'] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const retest = useMutation({
    mutationFn: (id: string) => api.post(`/api/findings/${id}/retest`, {}),
    onSuccess: () => {
      toast.success('Retest queued')
      qc.invalidateQueries({ queryKey: ['findings'] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const create = useMutation({
    mutationFn: () =>
      api.post('/api/findings', {
        title: newTitle.trim(),
        target: newTarget.trim() || 'local-lab',
        claim: newClaim.trim() || 'Manual finding',
        severity: newSeverity,
      }),
    onSuccess: () => {
      toast.success('Finding created')
      setCreateOpen(false)
      setNewTitle('')
      setNewTarget('')
      setNewClaim('')
      qc.invalidateQueries({ queryKey: ['findings'] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const findings = useMemo(() => {
    const all = query.data?.findings ?? []
    return severity ? all.filter((f) => f.severity === severity) : all
  }, [query.data, severity])

  const stats = useMemo(() => {
    const all = query.data?.findings ?? []
    const counts: Record<string, number> = {}
    for (const f of all) counts[f.severity] = (counts[f.severity] ?? 0) + 1
    return counts
  }, [query.data])

  function exportJson() {
    const blob = new Blob([JSON.stringify(findings, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `ares-findings-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="Evidence Vault"
        description="Every claim ARES makes lands here with its evidence attached. Confirm it, mark it remediated, or queue a retest."
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="size-3.5" />
              Finding
            </Button>
            <Button variant="outline" size="sm" onClick={() => setEvidenceOpen(true)}>
              <FileText className="size-3.5" />
              Evidence
            </Button>
            <Button variant="outline" size="sm" onClick={exportJson} disabled={findings.length === 0}>
              <Download className="size-3.5" />
              Export
            </Button>
            <Button variant="outline" size="sm" onClick={() => query.refetch()} disabled={query.isFetching}>
              <RefreshCw className={cn('size-3.5', query.isFetching && 'animate-spin')} />
              Refresh
            </Button>
          </div>
        }
      />

      <div className="mb-4 grid grid-cols-3 gap-2 sm:grid-cols-6">
        {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
          <div key={s} className="rounded-md border border-border px-3 py-2 text-center">
            <p className={cn('font-mono text-lg font-semibold capitalize', severityClass(s))}>
              {stats[s] ?? 0}
            </p>
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground">{s}</p>
          </div>
        ))}
        <div className="rounded-md border border-border px-3 py-2 text-center">
          <p className="flex items-center justify-center gap-1 font-mono text-lg font-semibold text-orange-400">
            <KeyRound className="size-3.5" />
            {credentialsCaptured}
          </p>
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground">creds</p>
        </div>
      </div>

      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="evidence">
            <FileText className="size-3.5" />
            Evidence
          </TabsTrigger>
          <TabsTrigger value="retests">
            <RotateCcw className="size-3.5" />
            Retests
          </TabsTrigger>
          <TabsTrigger value="graph">
            <Network className="size-3.5" />
            Evidence graph
          </TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="mt-4">
          <div className="mb-4 flex flex-wrap gap-2">
            <Select value={severity || 'all'} onValueChange={(v) => setSeverity(v === 'all' ? '' : v)}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                {SEVERITIES.map((s) => (
                  <SelectItem key={s || 'all'} value={s || 'all'}>
                    {s ? s : 'All severities'}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={status || 'all'} onValueChange={(v) => setStatus(v === 'all' ? '' : v)}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                {STATUSES.map((s) => (
                  <SelectItem key={s || 'all'} value={s || 'all'}>
                    {s ? s.replace(/_/g, ' ') : 'All statuses'}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {query.isLoading ? (
            <LoadingState label="Loading ledger…" />
          ) : query.error ? (
            <ErrorState error={query.error} />
          ) : findings.length === 0 ? (
            <EmptyState
              icon={ShieldAlert}
              title="No findings yet"
              hint="Operators write findings as they validate claims mid-mission. Start a hunt in the War Room."
            />
          ) : (
            <div className="flex flex-col gap-2">
              {findings.map((f) => (
                <FindingRow
                  key={f.id}
                  finding={f}
                  open={expanded === f.id}
                  onToggle={() => setExpanded(expanded === f.id ? null : f.id)}
                  onPatch={(status) => patch.mutate({ id: f.id, status })}
                  onRetest={() => retest.mutate(f.id)}
                  patchPending={patch.isPending}
                  retestPending={retest.isPending}
                />
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="evidence" className="mt-4">
          {evidenceList.isLoading ? (
            <LoadingState />
          ) : evidenceList.error ? (
            <ErrorState error={evidenceList.error} />
          ) : (evidenceList.data?.evidence ?? []).length === 0 ? (
            <EmptyState icon={FileText} title="No evidence entries" hint="Add evidence manually or let operators capture it mid-mission." />
          ) : (
            <div className="flex flex-col gap-2">
              {evidenceList.data!.evidence.map((e) => (
                <div key={e.id} className="rounded-md border border-border px-4 py-3 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {e.type ?? e.kind}
                    </Badge>
                    {e.source && (
                      <Badge variant="secondary" className="font-mono text-[10px]">
                        {e.source}
                      </Badge>
                    )}
                    <span className="font-medium">{e.title ?? 'Untitled'}</span>
                    {e.findingId && (
                      <code className="font-mono text-[10px] text-muted-foreground">→ {e.findingId}</code>
                    )}
                  </div>
                  {e.summary && <p className="mt-1 text-xs text-muted-foreground">{e.summary}</p>}
                </div>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="retests" className="mt-4">
          {retests.isLoading ? (
            <LoadingState />
          ) : retests.error ? (
            <ErrorState error={retests.error} />
          ) : (retests.data?.retests ?? []).length === 0 ? (
            <EmptyState icon={RotateCcw} title="No retests queued" hint="Queue a retest from any finding to track remediation verification here." />
          ) : (
            <div className="flex flex-col gap-2">
              {retests.data!.retests.map((r) => (
                <div key={r.id} className="rounded-md border border-border px-4 py-3 text-sm">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge
                      variant="outline"
                      className={cn(
                        'font-mono text-[10px]',
                        r.status === 'passed' && 'border-[var(--color-success)]/30 text-[var(--color-success)]',
                        r.status === 'failed' && 'border-destructive/30 text-destructive',
                      )}
                    >
                      {r.status}
                    </Badge>
                    <code className="font-mono text-[10px] text-muted-foreground">{r.findingId}</code>
                    <span className="flex-1 truncate text-muted-foreground">{r.method}</span>
                    <Select value={r.status} onValueChange={(v) => patchRetest.mutate({ id: r.id, status: v })}>
                      <SelectTrigger className="h-7 w-32 text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {RETEST_STATUSES.map((s) => (
                          <SelectItem key={s} value={s}>
                            {s}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  {r.resultSummary && <p className="mt-1 text-xs text-muted-foreground">{r.resultSummary}</p>}
                </div>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="graph" className="mt-4">
          {graph.isLoading ? (
            <LoadingState label="Building graph…" />
          ) : graph.error ? (
            <ErrorState error={graph.error} />
          ) : (
            <div className="rounded-lg border border-border p-4 font-mono text-xs">
              <p className="mb-3 text-muted-foreground">
                {(graph.data?.nodes ?? []).length} nodes · {(graph.data?.edges ?? []).length} edges
              </p>
              <div className="max-h-96 space-y-1 overflow-y-auto">
                {(graph.data?.nodes ?? []).map((n) => (
                  <div key={n.id} className="flex gap-2">
                    <Badge variant="outline" className="shrink-0 text-[9px]">
                      {n.type}
                    </Badge>
                    <span className="truncate">{n.label}</span>
                    {n.status && (
                      <span className="text-muted-foreground">({n.status})</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </TabsContent>
      </Tabs>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create finding</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <Field label="Title">
              <Input value={newTitle} onChange={(e) => setNewTitle(e.target.value)} />
            </Field>
            <Field label="Target">
              <Input value={newTarget} onChange={(e) => setNewTarget(e.target.value)} placeholder="host or repo" />
            </Field>
            <Field label="Claim">
              <Textarea value={newClaim} onChange={(e) => setNewClaim(e.target.value)} rows={3} />
            </Field>
            <Field label="Severity">
              <Select value={newSeverity} onValueChange={setNewSeverity}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SEVERITIES.filter(Boolean).map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
          </div>
          <DialogFooter>
            <Button onClick={() => create.mutate()} disabled={create.isPending || !newTitle.trim()}>
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={evidenceOpen} onOpenChange={setEvidenceOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add evidence</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <Field label="Title">
              <Input value={evTitle} onChange={(e) => setEvTitle(e.target.value)} />
            </Field>
            <Field label="Type">
              <Select value={evType} onValueChange={setEvType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {['note', 'screenshot', 'log', 'command', 'artifact', 'http'].map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            <Field label="Summary">
              <Textarea value={evSummary} onChange={(e) => setEvSummary(e.target.value)} rows={3} />
            </Field>
          </div>
          <DialogFooter>
            <Button onClick={() => createEvidence.mutate()} disabled={createEvidence.isPending || !evTitle.trim()}>
              Add
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function FindingRow({
  finding: f,
  open,
  onToggle,
  onPatch,
  onRetest,
  patchPending,
  retestPending,
}: {
  finding: Finding
  open: boolean
  onToggle: () => void
  onPatch: (status: string) => void
  onRetest: () => void
  patchPending: boolean
  retestPending: boolean
}) {
  const evidence = useQuery({
    queryKey: ['evidence', f.id],
    queryFn: () => api.get<{ evidence: EvidenceItem[] }>('/api/evidence'),
    enabled: open,
  })

  const linked = (evidence.data?.evidence ?? []).filter(
    (e) => e.findingId === f.id || f.evidenceIds?.includes(e.id),
  )

  return (
    <div className="overflow-hidden rounded-lg border border-border">
      <button
        className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-muted/40"
        onClick={onToggle}
      >
        <Badge variant="outline" className={cn('shrink-0 font-mono text-[10px] uppercase', severityClass(f.severity))}>
          {f.severity}
        </Badge>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium">{f.title}</p>
          <p className="truncate text-xs text-muted-foreground">
            {f.target} · {f.family}
          </p>
        </div>
        <Badge variant="secondary" className="shrink-0 font-mono text-[10px]">
          {f.status?.replace(/_/g, ' ')}
        </Badge>
        <ChevronDown className={cn('size-4 shrink-0 text-muted-foreground transition-transform', open && 'rotate-180')} />
      </button>

      {open && (
        <div className="border-t border-border bg-background/40 px-4 py-3 text-sm">
          <Detail label="Claim">{f.claim}</Detail>
          {f.impact && <Detail label="Impact">{f.impact}</Detail>}
          {f.recommendedFix && <Detail label="Recommended fix">{f.recommendedFix}</Detail>}
          {linked.length > 0 && (
            <Detail label="Evidence">
              <ul className="space-y-1">
                {linked.map((e) => (
                  <li key={e.id} className="font-mono text-xs">
                    [{e.kind}] {e.summary}
                  </li>
                ))}
              </ul>
            </Detail>
          )}
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <span className="text-xs text-muted-foreground">
              Confidence {Math.round((f.confidence ?? 0) * 100)}%
            </span>
            <div className="flex-1" />
            <Button
              variant="outline"
              size="sm"
              onClick={() => onPatch(NEXT_STATUS[f.status] ?? 'confirmed')}
              disabled={patchPending}
            >
              Mark {NEXT_STATUS[f.status] ?? 'confirmed'}
            </Button>
            <Button variant="outline" size="sm" onClick={onRetest} disabled={retestPending}>
              <RotateCcw className="size-3.5" />
              Retest
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

function Detail({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="mb-2">
      <p className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</p>
      <div className="mt-0.5 text-sm">{children}</div>
    </div>
  )
}
