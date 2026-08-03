import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Workflow, BookOpen, MessageSquareText, ListChecks, ExternalLink, Radar, Scale, Search } from 'lucide-react'
import { api } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { ScrollArea } from '@/components/ui/scroll-area'
import { PageHeader, EmptyState, ErrorState, LoadingState } from '@/components/common'

interface WorkflowPreset {
  id: string
  label: string
  plainLanguage: string
  family: string
  route: string
  directive: string
  expectedOutputs: string[]
}
interface ResourcePack {
  id: string
  title: string
  authority: string
  url: string
  sourceType: string
  useWhen: string
}
interface PromptPack {
  id: string
  title: string
  family: string
  roleFrame: string
  operatingRules: string[]
}
interface Runbook {
  family: string
  title: string
  operatorPromise: string
  defaultRoute: string
  phases: { id: string; label: string }[]
}

export function ConfigLibraryPage() {
  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="Config Library"
        description="The reference material ARES ships with: workflow presets, resource packs, agent prompt packs, and per-family runbooks. Read-only. It's what the operators pull from."
      />
      <Tabs defaultValue="presets">
        <TabsList>
          <TabsTrigger value="presets">
            <Workflow className="size-3.5" />
            Presets
          </TabsTrigger>
          <TabsTrigger value="resources">
            <BookOpen className="size-3.5" />
            Resources
          </TabsTrigger>
          <TabsTrigger value="prompts">
            <MessageSquareText className="size-3.5" />
            Prompt packs
          </TabsTrigger>
          <TabsTrigger value="runbooks">
            <ListChecks className="size-3.5" />
            Runbooks
          </TabsTrigger>
          <TabsTrigger value="radar">
            <Radar className="size-3.5" />
            Forefront radar
          </TabsTrigger>
          <TabsTrigger value="doctrine">
            <Scale className="size-3.5" />
            Doctrine
          </TabsTrigger>
        </TabsList>

        <TabsContent value="presets" className="mt-4">
          <Presets />
        </TabsContent>
        <TabsContent value="resources" className="mt-4">
          <Resources />
        </TabsContent>
        <TabsContent value="prompts" className="mt-4">
          <Prompts />
        </TabsContent>
        <TabsContent value="runbooks" className="mt-4">
          <Runbooks />
        </TabsContent>
        <TabsContent value="radar" className="mt-4">
          <ForefrontRadar />
        </TabsContent>
        <TabsContent value="doctrine" className="mt-4">
          <Doctrine />
        </TabsContent>
      </Tabs>
    </div>
  )
}

function useList<T>(key: string, path: string, pick: (d: any) => T[]) {
  const q = useQuery({ queryKey: [key], queryFn: () => api.get<any>(path) })
  return { ...q, items: q.data ? pick(q.data) : [] }
}

function Presets() {
  const q = useList<WorkflowPreset>('presets', '/api/workflow-presets', (d) => d.presets ?? [])
  if (q.isLoading) return <LoadingState />
  if (q.error) return <ErrorState error={q.error} />
  if (!q.items.length) return <EmptyState icon={Workflow} title="No presets" />
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {q.items.map((p) => (
        <Card key={p.id}>
          <CardHeader className="pb-2">
            <div className="flex items-start justify-between gap-2">
              <CardTitle className="text-sm">{p.label}</CardTitle>
              <Badge variant="outline" className="shrink-0 font-mono text-[10px]">
                {p.route}
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground">{p.family}</p>
          </CardHeader>
          <CardContent className="pt-0">
            <p className="text-sm">{p.plainLanguage}</p>
            {p.expectedOutputs?.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {p.expectedOutputs.slice(0, 4).map((o, i) => (
                  <Badge key={i} variant="secondary" className="text-[10px]">
                    {o}
                  </Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

function Resources() {
  const [search, setSearch] = useState('')
  const all = useList<ResourcePack>('resources', '/api/resource-packs', (d) => d.resources ?? [])
  const found = useQuery({
    queryKey: ['resource-search', search],
    queryFn: () => api.post<{ resources: ResourcePack[] }>('/api/resource-packs/search', { query: search }),
    enabled: search.trim().length > 1,
  })
  const items = search.trim().length > 1 ? (found.data?.resources ?? []) : all.items

  if (all.isLoading) return <LoadingState />
  if (all.error) return <ErrorState error={all.error} />
  return (
    <div className="flex flex-col gap-2">
      <div className="relative">
        <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search resource packs by topic, authority, or use-case…"
          className="pl-9"
        />
      </div>
      {items.length === 0 ? (
        <EmptyState icon={BookOpen} title="No resource packs match" />
      ) : (
        items.map((r) => (
        <div key={r.id} className="rounded-lg border border-border px-4 py-3">
          <div className="flex flex-wrap items-center gap-2">
            <a
              href={r.url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-sm font-medium hover:text-primary"
            >
              {r.title}
              <ExternalLink className="size-3" />
            </a>
            <Badge variant="outline" className="font-mono text-[10px]">
              {r.sourceType}
            </Badge>
            <span className="text-xs text-muted-foreground">{r.authority}</span>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">{r.useWhen}</p>
        </div>
        ))
      )}
    </div>
  )
}

function Prompts() {
  const q = useList<PromptPack>('prompts', '/api/agent-prompt-packs', (d) => d.promptPacks ?? [])
  if (q.isLoading) return <LoadingState />
  if (q.error) return <ErrorState error={q.error} />
  if (!q.items.length) return <EmptyState icon={MessageSquareText} title="No prompt packs" />
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {q.items.map((p) => (
        <Card key={p.id}>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">{p.title}</CardTitle>
            <p className="text-xs text-muted-foreground">{p.family}</p>
          </CardHeader>
          <CardContent className="pt-0">
            <p className="text-sm text-muted-foreground">{p.roleFrame}</p>
            {p.operatingRules?.length > 0 && (
              <ul className="mt-2 list-inside list-disc space-y-0.5 text-xs text-muted-foreground">
                {p.operatingRules.slice(0, 3).map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

function ForefrontRadar() {
  const q = useQuery({
    queryKey: ['forefront-radar'],
    queryFn: () => api.get<{ lanes: Record<string, unknown>[]; mandate: Record<string, unknown> }>('/api/forefront-radar'),
  })
  if (q.isLoading) return <LoadingState />
  if (q.error) return <ErrorState error={q.error} />
  const lanes = q.data?.lanes ?? []
  const mandate = q.data?.mandate ?? {}
  if (!lanes.length) return <EmptyState icon={Radar} title="No pressure lanes" />
  return (
    <div className="space-y-4">
      {mandate.purpose != null && (
        <Card>
          <CardContent className="py-4 text-xs text-muted-foreground">
            <p className="font-medium text-foreground">Mandate</p>
            <p className="mt-1">{String(mandate.purpose)}</p>
            {Array.isArray(mandate.pressureModel) && (
              <div className="mt-2 flex flex-wrap gap-1">
                {(mandate.pressureModel as string[]).map((m, i) => (
                  <Badge key={i} variant="secondary" className="text-[10px]">
                    {m}
                  </Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
      <div className="grid gap-3 sm:grid-cols-2">
        {lanes.map((lane, i) => {
          const label = String(lane.label ?? lane.title ?? lane.name ?? lane.id ?? `lane ${i + 1}`)
          const detail = lane.purpose ?? lane.summary ?? lane.description ?? lane.mandate
          return (
            <Card key={String(lane.id ?? i)}>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">{label}</CardTitle>
                {lane.id != null && (
                  <p className="font-mono text-[10px] text-muted-foreground">{String(lane.id)}</p>
                )}
              </CardHeader>
              <CardContent className="pt-0">
                {detail != null ? (
                  <p className="text-xs text-muted-foreground">{String(detail)}</p>
                ) : (
                  <pre className="max-h-40 overflow-auto whitespace-pre-wrap font-mono text-[10px] text-muted-foreground">
                    {JSON.stringify(lane, null, 2)}
                  </pre>
                )}
              </CardContent>
            </Card>
          )
        })}
      </div>
    </div>
  )
}

function Doctrine() {
  const q = useQuery({
    queryKey: ['operator-doctrine'],
    queryFn: () => api.get<Record<string, unknown>>('/api/operator-doctrine'),
  })
  if (q.isLoading) return <LoadingState />
  if (q.error) return <ErrorState error={q.error} />
  const data = q.data ?? {}
  const operators = Array.isArray(data.operators) ? (data.operators as string[]) : []
  return (
    <div className="space-y-4">
      {data.doctrine != null && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Plinian operator doctrine</CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <p className="whitespace-pre-wrap text-xs text-muted-foreground">{String(data.doctrine)}</p>
          </CardContent>
        </Card>
      )}
      {operators.length > 0 && (
        <div>
          <p className="mb-2 text-xs uppercase tracking-wider text-muted-foreground">Operators</p>
          <div className="flex flex-wrap gap-1.5">
            {operators.map((o) => (
              <Badge key={o} variant="secondary" className="font-mono text-[10px]">
                {o}
              </Badge>
            ))}
          </div>
        </div>
      )}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Authority & output contract</CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <ScrollArea className="h-64 rounded-md border border-border bg-background/40 p-3">
            <pre className="whitespace-pre-wrap font-mono text-[10px] text-muted-foreground">
              {JSON.stringify(
                { authorityModel: data.authorityModel, outputContract: data.outputContract, reflexAgents: data.reflexAgents },
                null,
                2,
              )}
            </pre>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  )
}

function Runbooks() {
  const q = useList<Runbook>('runbooks', '/api/operator-runbooks', (d) => d.runbooks ?? [])
  if (q.isLoading) return <LoadingState />
  if (q.error) return <ErrorState error={q.error} />
  if (!q.items.length) return <EmptyState icon={ListChecks} title="No runbooks" />
  return (
    <div className="flex flex-col gap-3">
      {q.items.map((r) => (
        <Card key={r.family}>
          <CardHeader className="pb-2">
            <div className="flex items-start justify-between gap-2">
              <CardTitle className="text-sm">{r.title}</CardTitle>
              <Badge variant="outline" className="shrink-0 font-mono text-[10px]">
                {r.defaultRoute}
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground">{r.operatorPromise}</p>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="flex flex-wrap gap-1.5">
              {r.phases?.map((phase, i) => (
                <span
                  key={phase.id}
                  className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-[10px] text-muted-foreground"
                >
                  <span className="font-mono text-primary">{i + 1}</span>
                  {phase.label}
                </span>
              ))}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
