import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plug, RefreshCw, Cpu, KeyRound, Server, Activity, Unplug, PlugZap } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { PageHeader, Field, ErrorState, LoadingState } from '@/components/common'
import { cn } from '@/lib/utils'

interface LlmStatus {
  connected: boolean
  provider: string
  model: string
  hasApiKey: boolean
}

interface AgentDetection {
  id: string
  label: string
  vendor?: string
  blurb?: string
  installed: boolean
  version?: string
  authed: boolean
  authMethod?: string
  ready: boolean
}

interface PingResult {
  ok: boolean
  latencyMs: number
  output: string
  error?: string
}

interface ConnectedAgent {
  id: string
  label?: string
  version?: string
  connectedAt?: number
  lastPing?: PingResult | null
}

const API_KEY = 'ares_api_url'

export function SettingsPage() {
  const qc = useQueryClient()
  const [apiUrl, setApiUrl] = useState(() => localStorage.getItem(API_KEY) ?? '')
  const [detected, setDetected] = useState<AgentDetection[] | null>(null)

  const llm = useQuery({
    queryKey: ['llm-status'],
    queryFn: () => api.get<LlmStatus>('/api/llm/status'),
    refetchInterval: 15_000,
  })

  const agents = useQuery({
    queryKey: ['local-agents'],
    queryFn: () => api.get<{ connected: ConnectedAgent[] }>('/api/agents/local/status'),
    refetchInterval: 15_000,
  })

  const detect = useMutation({
    mutationFn: () => api.get<{ agents?: AgentDetection[]; connected?: string[] }>('/api/agents/local/detect'),
    onSuccess: (data) => {
      const found = data.agents ?? []
      setDetected(found)
      const installed = found.filter((a) => a.installed)
      toast.success(installed.length ? `Found ${installed.length} installed agent(s)` : 'No local agents found')
      qc.invalidateQueries({ queryKey: ['local-agents'] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const connect = useMutation({
    mutationFn: (id: string) => api.post('/api/agents/local/connect', { id, ping: true }),
    onSuccess: (_data, id) => {
      toast.success(`Connected ${id}`)
      qc.invalidateQueries({ queryKey: ['local-agents'] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const ping = useMutation({
    mutationFn: (id: string) => api.post<PingResult>('/api/agents/local/ping', { id }),
    onSuccess: (data, id) => {
      toast[data.ok ? 'success' : 'error'](
        data.ok ? `${id}: PONG in ${data.latencyMs}ms` : `${id}: ${data.error ?? 'ping failed'}`,
      )
      qc.invalidateQueries({ queryKey: ['local-agents'] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const disconnect = useMutation({
    mutationFn: (id: string) => api.post('/api/agents/local/disconnect', { id }),
    onSuccess: (_data, id) => {
      toast.success(`Disconnected ${id}`)
      qc.invalidateQueries({ queryKey: ['local-agents'] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  function saveApiUrl() {
    const trimmed = apiUrl.trim()
    if (trimmed) localStorage.setItem(API_KEY, trimmed)
    else localStorage.removeItem(API_KEY)
    toast.success('Saved. Reloading to apply…')
    setTimeout(() => window.location.reload(), 600)
  }

  const connected = agents.data?.connected ?? []
  const connectedById = new Map(connected.map((a) => [a.id, a]))
  const busyId = connect.variables ?? ping.variables ?? disconnect.variables

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        title="Settings"
        description="Wire up a model backend. An already-authenticated local agent (Claude Code, Codex, Hermes) runs keyless; otherwise point ARES at a remote server."
      />

      <div className="grid gap-6">
        {/* LLM backend */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm font-medium">
              <Cpu className="size-4" />
              Model backend
            </CardTitle>
          </CardHeader>
          <CardContent>
            {llm.isLoading ? (
              <LoadingState />
            ) : llm.error ? (
              <ErrorState error={llm.error} />
            ) : (
              <div className="grid gap-3 sm:grid-cols-3">
                <Stat label="Status">
                  <Badge
                    variant="outline"
                    className={cn(
                      'font-mono text-[10px]',
                      llm.data?.connected
                        ? 'border-[var(--color-success)]/30 text-[var(--color-success)]'
                        : 'border-destructive/30 text-destructive',
                    )}
                  >
                    {llm.data?.connected ? 'Connected' : 'Not configured'}
                  </Badge>
                </Stat>
                <Stat label="Provider">
                  <span className="block truncate font-mono text-sm" title={llm.data?.provider}>
                    {llm.data?.provider ?? '—'}
                  </span>
                </Stat>
                <Stat label="Model">
                  <span className="block truncate font-mono text-sm" title={llm.data?.model}>
                    {llm.data?.model ?? '—'}
                  </span>
                </Stat>
                <Stat label="API key">
                  <span className="flex items-center gap-1.5 text-sm">
                    <KeyRound className="size-3.5 text-muted-foreground" />
                    {llm.data?.hasApiKey ? 'Present' : 'None (agent/keyless)'}
                  </span>
                </Stat>
              </div>
            )}
            <p className="mt-4 text-xs text-muted-foreground">
              Provider and key are read from the server's <code className="font-mono">.env</code> and{' '}
              <code className="font-mono">config</code>. Change them there, then refresh.
            </p>
          </CardContent>
        </Card>

        {/* Local agents */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2 text-sm font-medium">
                <Plug className="size-4" />
                Local agents
              </CardTitle>
              <Button
                variant="outline"
                size="sm"
                onClick={() => detect.mutate()}
                disabled={detect.isPending}
              >
                <RefreshCw className={cn('size-3.5', detect.isPending && 'animate-spin')} />
                Detect
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {detected === null && connected.length === 0 ? (
              <p className="py-4 text-sm text-muted-foreground">
                No agent connected. If Claude Code, Codex, or Hermes is logged in on this machine,
                hit Detect. ARES borrows the agent's own session, so no API key is needed.
              </p>
            ) : detected !== null && detected.length === 0 ? (
              <p className="py-4 text-sm text-muted-foreground">
                No supported agent CLIs found on this machine.
              </p>
            ) : (
              <ul className="divide-y divide-border">
                {(detected ?? []).map((a) => {
                  const conn = connectedById.get(a.id)
                  return (
                    <AgentRow
                      key={a.id}
                      agent={a}
                      connected={conn}
                      busy={busyId === a.id}
                      onConnect={() => connect.mutate(a.id)}
                      onPing={() => ping.mutate(a.id)}
                      onDisconnect={() => disconnect.mutate(a.id)}
                    />
                  )
                })}
                {/* Connected agents that weren't in the latest detect sweep */}
                {connected
                  .filter((c) => !(detected ?? []).some((d) => d.id === c.id))
                  .map((c) => (
                    <AgentRow
                      key={c.id}
                      agent={{
                        id: c.id,
                        label: c.label ?? c.id,
                        installed: true,
                        authed: true,
                        ready: true,
                        version: c.version,
                      }}
                      connected={c}
                      busy={busyId === c.id}
                      onConnect={() => connect.mutate(c.id)}
                      onPing={() => ping.mutate(c.id)}
                      onDisconnect={() => disconnect.mutate(c.id)}
                    />
                  ))}
              </ul>
            )}
          </CardContent>
        </Card>

        {/* API base URL */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm font-medium">
              <Server className="size-4" />
              API server
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Field
              label="Base URL override"
              hint="Blank uses this origin (the server serving the UI). Set it to reach a remote ARES server, e.g. http://10.0.0.5:3333"
            >
              <div className="flex gap-2">
                <Input
                  value={apiUrl}
                  onChange={(e) => setApiUrl(e.target.value)}
                  placeholder="http://localhost:3333"
                  className="font-mono text-sm"
                />
                <Button onClick={saveApiUrl}>Save</Button>
              </div>
            </Field>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

function AgentRow({
  agent,
  connected,
  busy,
  onConnect,
  onPing,
  onDisconnect,
}: {
  agent: AgentDetection
  connected?: ConnectedAgent
  busy: boolean
  onConnect: () => void
  onPing: () => void
  onDisconnect: () => void
}) {
  const isConnected = !!connected
  const status: { label: string; className: string } = isConnected
    ? { label: 'connected', className: 'border-[var(--color-success)]/30 text-[var(--color-success)]' }
    : !agent.installed
      ? { label: 'not-installed', className: 'text-muted-foreground' }
      : agent.authed
        ? { label: 'ready', className: 'border-primary/30 text-primary' }
        : { label: 'not-authed', className: 'border-amber-500/30 text-amber-400' }

  const lastPing = connected?.lastPing

  return (
    <li className="py-3">
      <div className="flex items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2">
          <span
            className={cn(
              'size-2 shrink-0 rounded-full',
              isConnected ? 'bg-[var(--color-success)]' : agent.ready ? 'bg-primary/60' : 'bg-muted-foreground/40',
            )}
          />
          <div className="min-w-0">
            <p className="truncate text-sm">{agent.label}</p>
            {agent.version && (
              <p className="truncate font-mono text-[10px] text-muted-foreground">v{agent.version}</p>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className={cn('font-mono text-[10px]', status.className)}>
            {status.label}
          </Badge>
          {isConnected ? (
            <>
              <Button variant="outline" size="sm" onClick={onPing} disabled={busy}>
                <Activity className="size-3.5" />
                Ping
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                onClick={onDisconnect}
                disabled={busy}
              >
                <Unplug className="size-3.5" />
                Disconnect
              </Button>
            </>
          ) : (
            <Button
              variant="secondary"
              size="sm"
              onClick={onConnect}
              disabled={busy || !agent.ready}
              title={!agent.ready ? 'Agent must be installed and logged in' : undefined}
            >
              <PlugZap className="size-3.5" />
              Connect
            </Button>
          )}
        </div>
      </div>
      {lastPing && (
        <div
          className={cn(
            'mt-2 rounded-md border px-2.5 py-1.5 font-mono text-[11px]',
            lastPing.ok
              ? 'border-[var(--color-success)]/20 bg-[var(--color-success)]/5 text-muted-foreground'
              : 'border-destructive/20 bg-destructive/5 text-destructive',
          )}
        >
          {lastPing.ok
            ? `↳ ${lastPing.output || 'ok'} (${lastPing.latencyMs}ms)`
            : `↳ ${lastPing.error ?? 'ping failed'}`}
        </div>
      )}
    </li>
  )
}

function Stat({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 rounded-md border border-border bg-background/50 px-3 py-2">
      <p className="mb-1 text-[10px] uppercase tracking-wider text-muted-foreground">{label}</p>
      {children}
    </div>
  )
}
