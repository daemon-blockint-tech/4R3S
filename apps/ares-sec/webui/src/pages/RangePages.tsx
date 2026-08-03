import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Copy,
  Check,
  LineChart,
  Flag,
  Terminal,
  Play,
  Square,
  RefreshCw,
  Loader2,
  Server,
  Layers,
  FileJson,
} from 'lucide-react'
import { toast } from 'sonner'
import { api, ApiError } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { PageHeader, EmptyState, ErrorState, LoadingState, Field } from '@/components/common'
import { cn } from '@/lib/utils'

// =============================================================================
// Shared range-job plumbing
// =============================================================================

interface RangeJobStatus {
  id: string
  status: 'running' | 'completed' | 'failed'
  exitCode?: number
  startedAt: string
  finishedAt?: string
  stdoutTail: string
  stderrTail: string
  meta?: Record<string, unknown>
}

/** Polls a range job every 1.5s while it's running, then stops. */
function useRangeJob(base: string, jobId: string | null) {
  return useQuery({
    queryKey: ['range-job', base, jobId],
    queryFn: () => api.get<RangeJobStatus>(`${base}/${jobId}`),
    enabled: !!jobId,
    refetchInterval: (query) => (query.state.data?.status === 'running' ? 1500 : false),
  })
}

function JobStatusBadge({ status }: { status: RangeJobStatus['status'] }) {
  if (status === 'running') {
    return (
      <Badge variant="secondary" className="gap-1">
        <Loader2 className="size-3 animate-spin" />
        running
      </Badge>
    )
  }
  if (status === 'completed') {
    return (
      <Badge variant="outline" className="gap-1 border-[var(--color-success)]/40 text-[var(--color-success)]">
        <Check className="size-3" />
        completed
      </Badge>
    )
  }
  return (
    <Badge variant="outline" className="gap-1 border-destructive/40 text-destructive">
      failed
    </Badge>
  )
}

function JobPanel({ job, title = 'Run output' }: { job: RangeJobStatus; title?: string }) {
  const output = [job.stdoutTail, job.stderrTail].filter(Boolean).join('\n').trim()
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          <Terminal className="size-4" />
          {title}
        </CardTitle>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {typeof job.exitCode === 'number' && job.status !== 'running' && (
            <span className="font-mono">exit {job.exitCode}</span>
          )}
          <JobStatusBadge status={job.status} />
        </div>
      </CardHeader>
      <CardContent>
        <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-md border border-border bg-background/60 p-3 font-mono text-xs leading-relaxed">
          {output || 'Waiting for output…'}
        </pre>
      </CardContent>
    </Card>
  )
}

function CommandBlock({ commands }: { commands: { label: string; cmd: string }[] }) {
  const [copied, setCopied] = useState<string | null>(null)
  function copy(cmd: string) {
    navigator.clipboard.writeText(cmd)
    setCopied(cmd)
    setTimeout(() => setCopied(null), 1500)
  }
  return (
    <div className="flex flex-col gap-2">
      {commands.map(({ label, cmd }) => (
        <div key={cmd} className="overflow-hidden rounded-lg border border-border">
          <div className="border-b border-border bg-muted/40 px-3 py-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">
            {label}
          </div>
          <div className="flex items-center gap-2 bg-background/60 px-3 py-2">
            <span className="font-mono text-xs text-primary">$</span>
            <code className="flex-1 font-mono text-xs">{cmd}</code>
            <button
              onClick={() => copy(cmd)}
              className="text-muted-foreground hover:text-foreground"
              aria-label="Copy command"
            >
              {copied === cmd ? <Check className="size-3.5 text-[var(--color-success)]" /> : <Copy className="size-3.5" />}
            </button>
          </div>
        </div>
      ))}
    </div>
  )
}

// =============================================================================
// OBSIDIVM — blockchain-intelligence range
// =============================================================================

const HUNTERS: { value: string; label: string; hint: string }[] = [
  { value: 'stub', label: 'stub', hint: 'Deterministic offline hunter — no keys, no network.' },
  { value: 'live', label: 'live', hint: 'Real chain-intel API; needs a key in .env.' },
  { value: 'ares', label: 'ares', hint: 'Full ARES agent driving the investigation.' },
]

interface LedgerGeneration {
  generation?: number
  score?: number
  timestamp?: string
}

function ObsidivmRunTab() {
  const [hunter, setHunter] = useState('stub')
  const [target, setTarget] = useState('')
  const [jobId, setJobId] = useState<string | null>(null)

  const job = useRangeJob('/api/obsidivm/bench', jobId)
  const running = job.data?.status === 'running'

  const bench = useMutation({
    mutationFn: () =>
      api.post<{ jobId: string; status: string }>('/api/obsidivm/bench', {
        hunter,
        target: target.trim(),
      }),
    onSuccess: (data) => {
      setJobId(data.jobId)
      toast.success(`Benchmark started (${hunter})`)
    },
    onError: (e: Error) =>
      toast.error(e instanceof ApiError && e.status === 429 ? 'Too many concurrent range jobs (max 2)' : e.message),
  })

  const activeHunter = HUNTERS.find((h) => h.value === hunter)

  return (
    <div className="mt-4 grid gap-4">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Benchmark configuration</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-[200px_1fr]">
          <Field label="Hunter" hint={activeHunter?.hint}>
            <Select value={hunter} onValueChange={setHunter}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {HUNTERS.map((h) => (
                  <SelectItem key={h.value} value={h.value}>
                    {h.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field label="Target" hint="Optional — leave blank to run the full suite.">
            <Input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="all targets"
              className="font-mono"
            />
          </Field>
          <div className="sm:col-span-2">
            <Button onClick={() => bench.mutate()} disabled={bench.isPending || running}>
              {bench.isPending || running ? <Loader2 className="size-4 animate-spin" /> : <Play className="size-4" />}
              {running ? 'Running…' : 'Run benchmark'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {jobId && job.data && <JobPanel job={job.data} />}
      {jobId && job.isLoading && !job.data && <LoadingState label="Starting job…" />}

      <details className="rounded-lg border border-border">
        <summary className="cursor-pointer px-3 py-2 text-xs uppercase tracking-wider text-muted-foreground">
          Run from the CLI instead
        </summary>
        <div className="p-3 pt-0">
          <CommandBlock
            commands={[
              { label: 'Benchmark (stub — no keys)', cmd: 'npm run obsidivm:bench:stub' },
              { label: 'Benchmark (ARES agent)', cmd: 'npm run obsidivm:bench:ares' },
              { label: 'Evolve loop', cmd: 'npm run obsidivm:evolve' },
              { label: 'Replay a recorded run', cmd: 'npm run obsidivm:replay' },
            ]}
          />
        </div>
      </details>
    </div>
  )
}

function ObsidivmSpecTab() {
  const spec = useQuery({
    queryKey: ['obsidivm-spec'],
    queryFn: () => api.get<Record<string, unknown>>('/api/obsidivm/spec'),
    retry: 0,
  })

  if (spec.isLoading) return <LoadingState label="Fetching spec…" />
  if (spec.isError) {
    return (
      <div className="mt-4 space-y-3">
        <ErrorState error={spec.error} />
        <p className="text-xs text-muted-foreground">
          The spec is served by the OBSIDIVM bridge. Make sure the OBSIDIVM API is reachable
          (see <code className="font-mono">docs/OBSIDIVM.md</code>), then retry.
        </p>
      </div>
    )
  }

  const raw = spec.data && typeof spec.data.raw === 'string' ? spec.data.raw : null
  return (
    <div className="mt-4">
      <pre className="max-h-[32rem] overflow-auto whitespace-pre-wrap rounded-lg border border-border p-4 font-mono text-xs">
        {raw ?? JSON.stringify(spec.data, null, 2)}
      </pre>
    </div>
  )
}

function ObsidivmLedgerTab() {
  const ledger = useQuery({
    queryKey: ['obsidivm-ledger'],
    queryFn: () =>
      api.get<{ ledger: { generations?: LedgerGeneration[] } | null; proposals: unknown }>('/api/obsidivm/ledger'),
  })

  if (ledger.isLoading) return <LoadingState />
  const generations = ledger.data?.ledger?.generations ?? []
  if (generations.length === 0) {
    return (
      <div className="mt-4">
        <EmptyState
          icon={LineChart}
          title="No evolution ledger yet"
          hint="Run the evolve loop (npm run obsidivm:evolve) to populate bench/obsidivm-evolution."
        />
      </div>
    )
  }

  return (
    <div className="mt-4 flex flex-col gap-2">
      {generations.map((g, i) => (
        <div key={i} className="flex items-center gap-3 rounded-md border border-border px-3 py-2 text-sm">
          <span className="font-mono text-muted-foreground">gen {g.generation ?? i}</span>
          <span className="font-mono">{g.score ?? '—'}</span>
          <span className="ml-auto text-xs text-muted-foreground">{g.timestamp}</span>
        </div>
      ))}
    </div>
  )
}

export function ObsidivmPage() {
  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        title="OBSIDIVM"
        description="The blockchain-intelligence range. Benchmark ARES on wallet-tracing and on-chain investigation tasks, then track run-over-run improvement in the evolve ledger."
      />
      <Tabs defaultValue="run">
        <TabsList>
          <TabsTrigger value="run">
            <Play className="size-3.5" />
            Run
          </TabsTrigger>
          <TabsTrigger value="spec">
            <FileJson className="size-3.5" />
            Spec
          </TabsTrigger>
          <TabsTrigger value="ledger">
            <LineChart className="size-3.5" />
            Evolve ledger
          </TabsTrigger>
        </TabsList>
        <TabsContent value="run">
          <ObsidivmRunTab />
        </TabsContent>
        <TabsContent value="spec">
          <ObsidivmSpecTab />
        </TabsContent>
        <TabsContent value="ledger">
          <ObsidivmLedgerTab />
        </TabsContent>
      </Tabs>
    </div>
  )
}

// =============================================================================
// CTF Range — dockerized capture-the-flag lab
// =============================================================================

interface CtfChallenge {
  id: string
  name: string
  category: string
  difficulty?: number
  points?: number
  source?: string
  target?: { host?: string; port?: number; protocol?: string }
  time_limit_seconds?: number
}

interface CtfManifest {
  version?: string
  description?: string
  challenges: CtfChallenge[]
}

interface DockerService {
  Name?: string
  Service?: string
  State?: string
  Status?: string
  raw?: string
}

interface DockerStatus {
  running: boolean
  services: DockerService[]
  error?: string
}

function categoryLabel(category: string): string {
  return category.replace(/_/g, ' ')
}

export function CtfRangePage() {
  const qc = useQueryClient()
  const [selected, setSelected] = useState<string | null>(null)
  const [runJobId, setRunJobId] = useState<string | null>(null)

  const manifest = useQuery({
    queryKey: ['ctf-manifest'],
    queryFn: () => api.get<CtfManifest>('/api/ctf/manifest'),
  })

  const docker = useQuery({
    queryKey: ['ctf-docker-status'],
    queryFn: () => api.get<DockerStatus>('/api/ctf/docker/status'),
    refetchInterval: 5000,
  })

  const runJob = useRangeJob('/api/ctf/run', runJobId)
  const runActive = runJob.data?.status === 'running'

  const up = useMutation({
    mutationFn: () => api.post<{ jobId: string }>('/api/ctf/docker/up', {}),
    onSuccess: () => {
      toast.success('Bringing the lab up…')
      setTimeout(() => qc.invalidateQueries({ queryKey: ['ctf-docker-status'] }), 2000)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const down = useMutation({
    mutationFn: () => api.post<{ jobId: string }>('/api/ctf/docker/down', {}),
    onSuccess: () => {
      toast.success('Tearing the lab down…')
      setTimeout(() => qc.invalidateQueries({ queryKey: ['ctf-docker-status'] }), 2000)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const run = useMutation({
    mutationFn: () =>
      api.post<{ jobId: string; status: string }>('/api/ctf/run', { challenge: selected ?? '' }),
    onSuccess: (data) => {
      setRunJobId(data.jobId)
      toast.success(selected ? `Running ${selected}` : 'Running all challenges')
    },
    onError: (e: Error) =>
      toast.error(e instanceof ApiError && e.status === 429 ? 'Too many concurrent range jobs (max 2)' : e.message),
  })

  const dockerRunning = docker.data?.running
  const challenges = manifest.data?.challenges ?? []

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        title="CTF Range"
        description="A local, dockerized capture-the-flag lab. Bring up the vulnerable targets, then point ARES at them. Everything runs on loopback and is in-scope, so you can validate the whole chain safely."
        actions={
          <div className="flex items-center gap-2">
            <Badge
              variant="outline"
              className={cn(
                'gap-1.5',
                dockerRunning
                  ? 'border-[var(--color-success)]/40 text-[var(--color-success)]'
                  : 'text-muted-foreground',
              )}
            >
              <Server className="size-3" />
              {docker.isLoading ? 'checking…' : dockerRunning ? 'lab up' : 'lab down'}
            </Badge>
            <Button
              size="sm"
              variant="outline"
              onClick={() => docker.refetch()}
              aria-label="Refresh docker status"
            >
              <RefreshCw className={cn('size-3.5', docker.isFetching && 'animate-spin')} />
            </Button>
            {dockerRunning ? (
              <Button size="sm" variant="outline" onClick={() => down.mutate()} disabled={down.isPending}>
                <Square className="size-3.5" />
                Tear down
              </Button>
            ) : (
              <Button size="sm" onClick={() => up.mutate()} disabled={up.isPending}>
                <Play className="size-3.5" />
                Bring up
              </Button>
            )}
          </div>
        }
      />

      {docker.data?.error && (
        <p className="mb-4 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-400">
          Docker not reachable: {docker.data.error}
        </p>
      )}

      <div className="grid gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium">
              <Layers className="size-4" />
              Challenges
            </CardTitle>
            <Button size="sm" onClick={() => run.mutate()} disabled={run.isPending || runActive}>
              {run.isPending || runActive ? <Loader2 className="size-3.5 animate-spin" /> : <Flag className="size-3.5" />}
              {runActive ? 'Running…' : selected ? `Run ${selected}` : 'Run all'}
            </Button>
          </CardHeader>
          <CardContent>
            {manifest.isLoading ? (
              <LoadingState />
            ) : manifest.isError ? (
              <ErrorState error={manifest.error} />
            ) : challenges.length === 0 ? (
              <EmptyState icon={Flag} title="No challenges" hint="ctf/challenges/manifest.json is empty." />
            ) : (
              <div className="grid gap-2 sm:grid-cols-2">
                {challenges.map((c) => {
                  const isSelected = selected === c.id
                  return (
                    <button
                      key={c.id}
                      onClick={() => setSelected(isSelected ? null : c.id)}
                      className={cn(
                        'flex flex-col gap-1.5 rounded-lg border p-3 text-left transition-colors',
                        isSelected
                          ? 'border-primary bg-primary/5'
                          : 'border-border hover:border-primary/40 hover:bg-muted/40',
                      )}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <span className="text-sm font-medium leading-tight">{c.name}</span>
                        {isSelected && <Check className="mt-0.5 size-3.5 shrink-0 text-primary" />}
                      </div>
                      <div className="flex flex-wrap items-center gap-1.5">
                        <Badge variant="secondary" className="text-[10px]">
                          {categoryLabel(c.category)}
                        </Badge>
                        {typeof c.difficulty === 'number' && (
                          <Badge variant="outline" className="text-[10px]">
                            lvl {c.difficulty}
                          </Badge>
                        )}
                        {typeof c.points === 'number' && (
                          <Badge variant="outline" className="text-[10px]">
                            {c.points} pts
                          </Badge>
                        )}
                      </div>
                      {c.target?.port && (
                        <span className="font-mono text-[10px] text-muted-foreground">
                          {c.target.protocol ?? 'tcp'}://{c.target.host ?? 'localhost'}:{c.target.port}
                        </span>
                      )}
                    </button>
                  )
                })}
              </div>
            )}
          </CardContent>
        </Card>

        {runJobId && runJob.data && <JobPanel job={runJob.data} title="Executor output" />}
        {runJobId && runJob.isLoading && !runJob.data && <LoadingState label="Starting executor…" />}

        <details className="rounded-lg border border-border">
          <summary className="cursor-pointer px-3 py-2 text-xs uppercase tracking-wider text-muted-foreground">
            Run from the CLI instead
          </summary>
          <div className="p-3 pt-0">
            <CommandBlock
              commands={[
                { label: 'Start all challenge containers', cmd: 'docker compose -f ctf/docker-compose.yml up -d' },
                { label: 'Run the executor', cmd: 'python ctf/executor/ctf_executor.py' },
                { label: 'Tear down', cmd: 'docker compose -f ctf/docker-compose.yml down' },
              ]}
            />
          </div>
        </details>
      </div>
    </div>
  )
}
