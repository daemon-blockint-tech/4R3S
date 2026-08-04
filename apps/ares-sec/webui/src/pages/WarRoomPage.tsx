import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router'
import { Pause, Play, Square, Crosshair, FolderGit2, FileText } from 'lucide-react'
import { toast } from 'sonner'
import { api, ApiError } from '@/lib/api'
import { useEvents } from '@/hooks/useEvents'
import { useMissionMutations, useMissionStatus } from '@/hooks/useMission'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { cn } from '@/lib/utils'

const EXAMPLES = ['github.com/expressjs/express', 'lodash', '10.0.0.5']
const DEFAULT_OPERATORS = ['recon', 'scanner', 'analyst']

const SEVERITY: Record<string, string> = {
  critical: 'bg-destructive/15 text-destructive border-destructive/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  low: 'bg-primary/15 text-primary border-primary/30',
  info: 'bg-muted text-muted-foreground border-border',
}

interface OperatorPrompt {
  archetype: string
  name: string
  description: string
}

export function WarRoomPage() {
  const [target, setTarget] = useState('')
  const [selectedOps, setSelectedOps] = useState<string[]>(DEFAULT_OPERATORS)
  const [opsecLevel, setOpsecLevel] = useState('standard')
  const [autonomous, setAutonomous] = useState(false)
  const [repoPath, setRepoPath] = useState('')
  const [showRepo, setShowRepo] = useState(false)
  const { events, live } = useEvents(150)
  const status = useMissionStatus()
  const { start, stop, pause, resume } = useMissionMutations()

  async function exportReport() {
    try {
      const res = await api.get<{ report: string; missionId: string | null }>('/api/mission/report')
      const blob = new Blob([res.report], { type: 'text/markdown' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `ares-mission-report-${Date.now()}.md`
      a.click()
      URL.revokeObjectURL(url)
      toast.success('Report exported')
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'No report available')
    }
  }

  const operatorPrompts = useQuery({
    queryKey: ['operator-prompts'],
    queryFn: () => api.get<{ operators: OperatorPrompt[] }>('/api/operators/prompts'),
  })

  const active = status.data?.active
  const paused = status.data?.paused
  const findings = status.data?.findings ?? []

  useEffect(() => {
    const last = events[events.length - 1]
    if (!last) return
    if (
      last.type.startsWith('finding.') ||
      last.type.startsWith('mission:') ||
      last.type.startsWith('task:')
    ) {
      status.refetch()
    }
  }, [events, status])

  function toggleOperator(archetype: string) {
    setSelectedOps((prev) =>
      prev.includes(archetype) ? prev.filter((a) => a !== archetype) : [...prev, archetype],
    )
  }

  function launch() {
    const host = target.trim()
    if (!host) {
      toast.error('Enter a target')
      return
    }
    if (selectedOps.length === 0) {
      toast.error('Select at least one operative')
      return
    }
    start.mutate(
      {
        name: `Hunt ${host}`,
        targets: [{ host }],
        operators: selectedOps,
        opsecLevel,
        autonomous,
        ...(repoPath.trim() ? { repoPath: repoPath.trim() } : {}),
      },
      {
        onSuccess: () => toast.success('Mission started'),
        onError: (e) => {
          // A 403 with an approval payload is handled by the approval gate
          // (modal pops up) — don't also fire an error toast for it.
          if (e instanceof ApiError && e.approval) return
          toast.error(e instanceof Error ? e.message : 'Start failed')
        },
      },
    )
  }

  const archetypes = operatorPrompts.data?.operators ?? []

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-6">
      <Card className="border-primary/25 bg-gradient-to-br from-primary/5 to-transparent">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-lg font-semibold text-primary">
            <Crosshair className="size-5" />
            Start a hunt
          </CardTitle>
          <CardDescription className="max-w-3xl text-sm leading-relaxed">
            Set a target you own or have written permission to test. ARES runs live recon
            (nmap, DNS, HTTP probes) and links each finding to the command that produced it.
            Post-recon kill-chain stages are labeled as-is — no staged shells, no phantom flags.
            Run <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">npm run verify-claims</code>{' '}
            to re-check the numbers yourself.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-xs text-muted-foreground">
            No API key if you connect Claude Code, Codex, or Hermes — the agent uses your existing
            login. Otherwise add a key in{' '}
            <Link to="/settings" className="text-primary underline-offset-2 hover:underline">
              Settings
            </Link>
            .
          </p>
          <div className="flex flex-col gap-2 sm:flex-row">
            <Input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && !active && launch()}
              placeholder="github.com/org/repo · npm package · host or IP"
              className="font-mono text-sm"
              disabled={active}
            />
            {active ? (
              <div className="flex shrink-0 gap-2">
                {paused ? (
                  <Button
                    variant="secondary"
                    onClick={() => resume.mutate()}
                    disabled={resume.isPending}
                  >
                    <Play className="size-4" />
                    Resume
                  </Button>
                ) : (
                  <Button
                    variant="secondary"
                    onClick={() => pause.mutate()}
                    disabled={pause.isPending}
                  >
                    <Pause className="size-4" />
                    Pause
                  </Button>
                )}
                <Button
                  variant="destructive"
                  onClick={() => stop.mutate()}
                  disabled={stop.isPending}
                >
                  <Square className="size-4" />
                  Stop
                </Button>
                <Button variant="outline" onClick={exportReport}>
                  <FileText className="size-4" />
                  Report
                </Button>
              </div>
            ) : (
              <Button onClick={launch} disabled={start.isPending} className="shrink-0">
                <Play className="size-4" />
                Hunt
              </Button>
            )}
          </div>
          {!active && (
            <>
              <div className="space-y-2">
                <p className="text-xs font-medium text-muted-foreground">Operatives</p>
                <div className="flex flex-wrap gap-2">
                  {archetypes.length === 0 ? (
                    DEFAULT_OPERATORS.map((a) => (
                      <OpChip
                        key={a}
                        archetype={a}
                        selected={selectedOps.includes(a)}
                        onToggle={() => toggleOperator(a)}
                      />
                    ))
                  ) : (
                    archetypes.map((op) => (
                      <OpChip
                        key={op.archetype}
                        archetype={op.archetype}
                        label={op.name}
                        selected={selectedOps.includes(op.archetype)}
                        onToggle={() => toggleOperator(op.archetype)}
                      />
                    ))
                  )}
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-3 text-xs">
                <span className="text-muted-foreground">OPSEC:</span>
                {(['stealth', 'standard', 'aggressive'] as const).map((level) => (
                  <button
                    key={level}
                    type="button"
                    onClick={() => setOpsecLevel(level)}
                    className={cn(
                      'rounded-md border px-2 py-1 capitalize transition-colors',
                      opsecLevel === level
                        ? 'border-primary bg-primary/10 text-primary'
                        : 'border-border text-muted-foreground hover:border-primary/50',
                    )}
                  >
                    {level}
                  </button>
                ))}
                <span className="ml-2 text-muted-foreground">Mode:</span>
                <button
                  type="button"
                  onClick={() => setAutonomous((v) => !v)}
                  className={cn(
                    'rounded-md border px-2 py-1 transition-colors',
                    autonomous
                      ? 'border-orange-500/50 bg-orange-500/10 text-orange-400'
                      : 'border-border text-muted-foreground hover:border-primary/50',
                  )}
                >
                  {autonomous ? 'Autonomous' : 'Approval-gated'}
                </button>
                <button
                  type="button"
                  onClick={() => setShowRepo((v) => !v)}
                  className={cn(
                    'ml-auto flex items-center gap-1 rounded-md border px-2 py-1 transition-colors',
                    showRepo
                      ? 'border-primary bg-primary/10 text-primary'
                      : 'border-border text-muted-foreground hover:border-primary/50',
                  )}
                >
                  <FolderGit2 className="size-3" />
                  White-box repo
                </button>
              </div>
              {showRepo && (
                <Input
                  value={repoPath}
                  onChange={(e) => setRepoPath(e.target.value)}
                  placeholder="Local repo path for white-box source analysis (optional)"
                  className="font-mono text-sm"
                />
              )}
            </>
          )}
          <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
            <span>Examples:</span>
            {EXAMPLES.map((ex) => (
              <button
                key={ex}
                type="button"
                onClick={() => setTarget(ex)}
                className="font-mono text-primary underline-offset-2 hover:underline"
              >
                {ex}
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-[1fr_1.2fr]">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">SITREP</CardTitle>
            <CardDescription className="text-xs">Live mission state</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 font-mono text-xs">
            <div className="grid grid-cols-2 gap-3">
              <Stat
                label="Status"
                value={active ? (paused ? 'Paused' : 'Running') : 'Idle'}
              />
              <Stat label="Phase" value={status.data?.mission?.currentPhase ?? '—'} />
              <Stat label="Ticks" value={String(status.data?.tickCount ?? 0)} />
              <Stat label="Findings" value={String(findings.length)} />
            </div>
            {status.data?.name && (
              <p className="truncate text-muted-foreground">{status.data.name}</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium">Findings</CardTitle>
              <Badge variant="outline" className="font-mono text-[10px]">
                {findings.length}
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            {findings.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">
                No findings yet. Start a hunt against an authorized target.
              </p>
            ) : (
              <ScrollArea className="h-48">
                <ul className="space-y-2 pr-3">
                  {findings.map((f) => (
                    <li
                      key={f.id}
                      className="flex items-start justify-between gap-2 rounded-md border border-border bg-background/50 px-3 py-2"
                    >
                      <span className="text-sm leading-snug">{f.title}</span>
                      <Badge
                        variant="outline"
                        className={cn(
                          'shrink-0 font-mono text-[10px] capitalize',
                          SEVERITY[f.severity] ?? SEVERITY.info,
                        )}
                      >
                        {f.severity}
                      </Badge>
                    </li>
                  ))}
                </ul>
              </ScrollArea>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-medium">Event stream</CardTitle>
            <Badge variant={live ? 'default' : 'secondary'} className="font-mono text-[10px]">
              {live ? 'LIVE' : 'OFFLINE'}
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-56 rounded-md border border-border bg-background/40 p-3 font-mono text-xs">
            {events.length === 0 ? (
              <p className="text-muted-foreground">Waiting for events from /api/events…</p>
            ) : (
              <ul className="space-y-1">
                {events.map((e) => (
                  <li key={e.id} className="flex gap-2">
                    <span className="shrink-0 text-muted-foreground">
                      {new Date(e.ts).toLocaleTimeString()}
                    </span>
                    <span
                      className={cn(
                        'shrink-0 uppercase',
                        e.level === 'danger' && 'text-destructive',
                        e.level === 'warning' && 'text-amber-400',
                        e.level === 'success' && 'text-[var(--color-success)]',
                      )}
                    >
                      [{e.source}]
                    </span>
                    <span className="text-foreground/90">{e.message}</span>
                  </li>
                ))}
              </ul>
            )}
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  )
}

function OpChip({
  archetype,
  label,
  selected,
  onToggle,
}: {
  archetype: string
  label?: string
  selected: boolean
  onToggle: () => void
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      className={cn(
        'rounded-md border px-2.5 py-1 text-xs font-mono transition-colors',
        selected
          ? 'border-primary bg-primary/15 text-primary'
          : 'border-border text-muted-foreground hover:border-primary/40',
      )}
    >
      {label ?? archetype}
    </button>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-background/50 px-3 py-2">
      <p className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</p>
      <p className="mt-0.5 text-sm text-foreground">{value}</p>
    </div>
  )
}
