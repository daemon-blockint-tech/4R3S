import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { UserPlus, Skull, RefreshCw, Users, SlidersHorizontal, RotateCcw, Send, Wand2 } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { PageHeader, EmptyState, ErrorState, LoadingState, Field } from '@/components/common'
import { cn } from '@/lib/utils'

interface Operator {
  id: string
  callsign: string
  archetype: string
  status: string
  completedTasks: number
  failedTasks: number
  findings: number
  credentials: number
  detectionRisk: number
}

interface CellStatus {
  operators: Operator[]
  cell: { active?: number; total?: number } | null
}

interface OperatorParams {
  temperature: number
  maxTokens: number
  topP: number
}

interface OperatorPrompt {
  archetype: string
  name: string
  description: string
  defaultTools: string[]
  toolCategories: string[]
  capabilities: string[]
  techniques: string[]
  systemPrompt: string
  defaultSystemPrompt: string
  params: OperatorParams
  overridden: boolean
}

const ARCHETYPES = [
  'recon_specialist',
  'exploit_developer',
  'web_operator',
  'cloud_operator',
  'ai_red_teamer',
  'crypto_analyst',
  'osint_investigator',
  'reporter',
]

const STATUS_COLOR: Record<string, string> = {
  active: 'text-[var(--color-success)]',
  idle: 'text-muted-foreground',
  working: 'text-primary',
  terminated: 'text-destructive',
}

export function OperativesPage() {
  const qc = useQueryClient()
  const [archetype, setArchetype] = useState(ARCHETYPES[0])
  const [callsign, setCallsign] = useState('')
  const [editing, setEditing] = useState<OperatorPrompt | null>(null)

  const list = useQuery({
    queryKey: ['operators'],
    queryFn: () => api.get<CellStatus>('/api/operators/list'),
    refetchInterval: 10_000,
  })

  const prompts = useQuery({
    queryKey: ['operator-prompts'],
    queryFn: () => api.get<{ operators: OperatorPrompt[] }>('/api/operators/prompts'),
  })

  const spawn = useMutation({
    mutationFn: () =>
      api.post('/api/operators/spawn', {
        archetype,
        callsign: callsign.trim() || undefined,
      }),
    onSuccess: () => {
      toast.success('Operative spawned')
      setCallsign('')
      qc.invalidateQueries({ queryKey: ['operators'] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const terminate = useMutation({
    mutationFn: (id: string) => api.post('/api/operators/terminate', { id }),
    onSuccess: () => {
      toast.success('Operative terminated')
      qc.invalidateQueries({ queryKey: ['operators'] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const operators = list.data?.operators ?? []
  const promptList = prompts.data?.operators ?? []

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="Operatives"
        description="The active cell plus the archetype playbook behind it. Spawn operators, dispatch tasks, and tune the system prompt and sampling params each archetype runs with."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => list.refetch()}
            disabled={list.isFetching}
          >
            <RefreshCw className={cn('size-3.5', list.isFetching && 'animate-spin')} />
            Refresh
          </Button>
        }
      />

      <Tabs defaultValue="cell">
        <TabsList>
          <TabsTrigger value="cell">
            <Users className="size-4" />
            Cell
          </TabsTrigger>
          <TabsTrigger value="prompts">
            <Wand2 className="size-4" />
            Archetype prompts
          </TabsTrigger>
        </TabsList>

        <TabsContent value="cell" className="mt-4">
          <Card className="mb-6">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-sm font-medium">
                <UserPlus className="size-4" />
                Spawn operative
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap items-end gap-3">
                <Field label="Archetype" className="min-w-52">
                  <Select value={archetype} onValueChange={setArchetype}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {ARCHETYPES.map((a) => (
                        <SelectItem key={a} value={a} className="font-mono text-xs">
                          {a}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>
                <Field label="Callsign (optional)" className="min-w-48">
                  <input
                    value={callsign}
                    onChange={(e) => setCallsign(e.target.value)}
                    placeholder="auto"
                    className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 font-mono text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50"
                  />
                </Field>
                <Button onClick={() => spawn.mutate()} disabled={spawn.isPending}>
                  <UserPlus className="size-4" />
                  Spawn
                </Button>
              </div>
            </CardContent>
          </Card>

          {list.isLoading ? (
            <LoadingState label="Loading cell…" />
          ) : list.error ? (
            <ErrorState error={list.error} />
          ) : operators.length === 0 ? (
            <EmptyState
              icon={Users}
              title="No operatives active"
              hint="Spawn one above, or start a mission in the War Room; it assembles a cell automatically."
            />
          ) : (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {operators.map((op) => (
                <OperatorCard
                  key={op.id}
                  op={op}
                  onTerminate={() => terminate.mutate(op.id)}
                  terminating={terminate.isPending}
                />
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="prompts" className="mt-4">
          {prompts.isLoading ? (
            <LoadingState label="Loading prompts…" />
          ) : prompts.error ? (
            <ErrorState error={prompts.error} />
          ) : (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {promptList.map((p) => (
                <Card key={p.archetype} className="gap-0">
                  <CardHeader className="pb-2">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <CardTitle className="text-sm">{p.name}</CardTitle>
                        <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                          {p.archetype}
                        </p>
                      </div>
                      {p.overridden && (
                        <Badge variant="outline" className="shrink-0 font-mono text-[10px] text-primary">
                          custom
                        </Badge>
                      )}
                    </div>
                  </CardHeader>
                  <CardContent className="pt-2">
                    <p className="line-clamp-2 text-xs text-muted-foreground">{p.description}</p>
                    <div className="mt-3 flex items-center gap-3 font-mono text-[10px] text-muted-foreground">
                      <span>temp {p.params.temperature}</span>
                      <span>tok {p.params.maxTokens}</span>
                      <span>topP {p.params.topP}</span>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      className="mt-3 w-full"
                      onClick={() => setEditing(p)}
                    >
                      <SlidersHorizontal className="size-3.5" />
                      Edit prompt & params
                    </Button>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>

      <PromptEditorDialog prompt={editing} onClose={() => setEditing(null)} />
    </div>
  )
}

function OperatorCard({
  op,
  onTerminate,
  terminating,
}: {
  op: Operator
  onTerminate: () => void
  terminating: boolean
}) {
  const qc = useQueryClient()
  const [taskName, setTaskName] = useState('')
  const [taskDescription, setTaskDescription] = useState('')

  const dispatch = useMutation({
    mutationFn: () =>
      api.post(`/api/operators/${op.id}/task`, {
        taskName: taskName.trim() || 'Manual Task',
        taskDescription: taskDescription.trim(),
      }),
    onSuccess: () => {
      toast.success('Task dispatched')
      setTaskName('')
      setTaskDescription('')
      qc.invalidateQueries({ queryKey: ['operators'] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const canDispatch = op.status !== 'terminated'

  return (
    <Card className="gap-0">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between">
          <div>
            <CardTitle className="font-mono text-sm">{op.callsign}</CardTitle>
            <p className="mt-0.5 text-xs text-muted-foreground">{op.archetype}</p>
          </div>
          <Badge
            variant="outline"
            className={cn('font-mono text-[10px]', STATUS_COLOR[op.status] ?? '')}
          >
            {op.status}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="pt-2">
        <div className="grid grid-cols-3 gap-2 text-center">
          <Metric label="done" value={op.completedTasks} />
          <Metric label="failed" value={op.failedTasks} tone={op.failedTasks ? 'warn' : undefined} />
          <Metric label="findings" value={op.findings} tone={op.findings ? 'good' : undefined} />
        </div>
        <div className="mt-3">
          <div className="mb-1 flex items-center justify-between text-[10px] uppercase tracking-wider text-muted-foreground">
            <span>Detection risk</span>
            <span>{Math.round((op.detectionRisk ?? 0) * 100)}%</span>
          </div>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
            <div
              className={cn(
                'h-full rounded-full',
                op.detectionRisk > 0.66
                  ? 'bg-destructive'
                  : op.detectionRisk > 0.33
                    ? 'bg-amber-500'
                    : 'bg-[var(--color-success)]',
              )}
              style={{ width: `${Math.min(100, (op.detectionRisk ?? 0) * 100)}%` }}
            />
          </div>
        </div>

        {canDispatch && (
          <div className="mt-3 space-y-2 rounded-md border border-border bg-background/50 p-2">
            <Input
              value={taskName}
              onChange={(e) => setTaskName(e.target.value)}
              placeholder="Task name"
              className="h-8 text-xs"
            />
            <Textarea
              value={taskDescription}
              onChange={(e) => setTaskDescription(e.target.value)}
              placeholder="What should this operative do?"
              className="min-h-14 text-xs"
            />
            <Button
              variant="secondary"
              size="sm"
              className="w-full"
              onClick={() => dispatch.mutate()}
              disabled={dispatch.isPending}
            >
              <Send className="size-3.5" />
              {dispatch.isPending ? 'Dispatching…' : 'Dispatch task'}
            </Button>
          </div>
        )}

        <Button
          variant="ghost"
          size="sm"
          className="mt-3 w-full text-destructive hover:bg-destructive/10 hover:text-destructive"
          onClick={onTerminate}
          disabled={terminating || op.status === 'terminated'}
        >
          <Skull className="size-3.5" />
          Terminate
        </Button>
      </CardContent>
    </Card>
  )
}

function PromptEditorDialog({
  prompt,
  onClose,
}: {
  prompt: OperatorPrompt | null
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [systemPrompt, setSystemPrompt] = useState('')
  const [temperature, setTemperature] = useState('0.4')
  const [maxTokens, setMaxTokens] = useState('4096')
  const [topP, setTopP] = useState('1')

  useEffect(() => {
    if (prompt) {
      setSystemPrompt(prompt.systemPrompt)
      setTemperature(String(prompt.params.temperature))
      setMaxTokens(String(prompt.params.maxTokens))
      setTopP(String(prompt.params.topP))
    }
  }, [prompt])

  const save = useMutation({
    mutationFn: () =>
      api.post('/api/operators/prompt', {
        archetype: prompt!.archetype,
        systemPrompt,
        params: {
          temperature: Number(temperature),
          maxTokens: Number(maxTokens),
          topP: Number(topP),
        },
      }),
    onSuccess: () => {
      toast.success('Prompt saved')
      qc.invalidateQueries({ queryKey: ['operator-prompts'] })
      onClose()
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const reset = useMutation({
    mutationFn: () => api.post('/api/operators/prompt/reset', { archetype: prompt!.archetype }),
    onSuccess: () => {
      toast.success('Prompt reset to default')
      qc.invalidateQueries({ queryKey: ['operator-prompts'] })
      onClose()
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const [failureSignal, setFailureSignal] = useState('')
  const coach = useMutation({
    mutationFn: () =>
      api.post<Record<string, unknown>>('/api/admiral/suggest', {
        operatorPrompt: systemPrompt,
        archetype: prompt!.archetype,
        failureSignal: failureSignal.trim() || undefined,
      }),
    onSuccess: () => toast.success('Admiral returned suggestions'),
    onError: (e: Error) => toast.error(e.message),
  })

  const busy = save.isPending || reset.isPending

  return (
    <Dialog open={!!prompt} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Wand2 className="size-5 text-primary" />
            {prompt?.name}
          </DialogTitle>
          <DialogDescription>
            Runtime override for the{' '}
            <code className="font-mono">{prompt?.archetype}</code> archetype. Applies to every
            operator spawned from it; reset restores the built-in default.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <Field label="System prompt">
            <Textarea
              value={systemPrompt}
              onChange={(e) => setSystemPrompt(e.target.value)}
              className="min-h-48 font-mono text-xs"
            />
          </Field>
          <div className="grid grid-cols-3 gap-3">
            <Field label="Temperature">
              <Input
                type="number"
                step="0.1"
                min="0"
                max="2"
                value={temperature}
                onChange={(e) => setTemperature(e.target.value)}
                className="font-mono text-sm"
              />
            </Field>
            <Field label="Max tokens">
              <Input
                type="number"
                step="256"
                min="1"
                value={maxTokens}
                onChange={(e) => setMaxTokens(e.target.value)}
                className="font-mono text-sm"
              />
            </Field>
            <Field label="Top P">
              <Input
                type="number"
                step="0.05"
                min="0"
                max="1"
                value={topP}
                onChange={(e) => setTopP(e.target.value)}
                className="font-mono text-sm"
              />
            </Field>
          </div>

          <div className="rounded-md border border-border bg-muted/20 p-3">
            <div className="mb-2 flex items-center justify-between gap-2">
              <p className="text-xs font-medium">Admiral prompt coach</p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => coach.mutate()}
                disabled={coach.isPending || systemPrompt.trim().length < 20}
              >
                <Wand2 className="size-3.5" />
                {coach.isPending ? 'Thinking…' : 'Ask Admiral to improve'}
              </Button>
            </div>
            <Input
              value={failureSignal}
              onChange={(e) => setFailureSignal(e.target.value)}
              placeholder="Failure signal (optional) — e.g. keeps hallucinating findings"
              className="mb-2 text-xs"
            />
            {coach.data != null && (
              <pre className="max-h-40 overflow-auto whitespace-pre-wrap rounded bg-background/50 p-2 font-mono text-[10px] text-muted-foreground">
                {JSON.stringify(coach.data, null, 2)}
              </pre>
            )}
            <p className="mt-1 text-[10px] text-muted-foreground">
              Suggestions are general improvements only; challenge-specific tells are flagged and never auto-applied.
            </p>
          </div>
        </div>

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => reset.mutate()}
            disabled={busy || !prompt?.overridden}
          >
            <RotateCcw className="size-3.5" />
            {reset.isPending ? 'Resetting…' : 'Reset to default'}
          </Button>
          <Button onClick={() => save.mutate()} disabled={busy}>
            {save.isPending ? 'Saving…' : 'Save'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function Metric({
  label,
  value,
  tone,
}: {
  label: string
  value: number
  tone?: 'good' | 'warn'
}) {
  return (
    <div className="rounded-md border border-border bg-background/50 py-1.5">
      <p
        className={cn(
          'font-mono text-base font-semibold',
          tone === 'good' && 'text-[var(--color-success)]',
          tone === 'warn' && 'text-amber-400',
        )}
      >
        {value}
      </p>
      <p className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</p>
    </div>
  )
}
