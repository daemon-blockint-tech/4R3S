import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Network } from 'lucide-react'
import { api } from '@/lib/api'
import { PageHeader, EmptyState } from '@/components/common'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'

interface GraphNode {
  id: string
  label: string
  phase: string
  kind: string
  status?: string
}
interface GraphEdge {
  from: string
  to: string
  kind: string
}
interface AttackGraph {
  target: string
  family: string
  phases: string[]
  nodes: GraphNode[]
  edges: GraphEdge[]
  source: string
}

const FAMILIES = ['default', 'web_api', 'network', 'cloud', 'mobile', 'source_code']

const KIND_TONE: Record<string, string> = {
  target_root: 'border-primary/40 bg-primary/10 text-primary',
  sink: 'border-destructive/30 bg-destructive/10 text-destructive',
  service: 'border-border bg-background/60',
}

export function AttackGraphPage() {
  const [target, setTarget] = useState('')
  const [family, setFamily] = useState('default')

  const build = useMutation({
    mutationFn: () =>
      api.post<{ graph: AttackGraph }>('/api/attack-graph', { target: target.trim(), family }),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Graph failed'),
  })

  const graph = build.data?.graph

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader
        title="Attack Graph"
        description="A recon-generated kill-chain scaffold. Scaffold nodes are recon-pending candidates, not findings — agents replace and extend them as they map the real surface."
      />

      <Card className="mb-6">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Scaffold a target</CardTitle>
          <CardDescription className="text-xs">Structure varies by target and mission family.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3 sm:flex-row">
          <Input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && target.trim() && build.mutate()}
            placeholder="Target host, domain, or repo"
            className="font-mono text-sm"
          />
          <Select value={family} onValueChange={setFamily}>
            <SelectTrigger className="sm:w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {FAMILIES.map((f) => (
                <SelectItem key={f} value={f}>
                  {f}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button onClick={() => build.mutate()} disabled={!target.trim() || build.isPending} className="shrink-0">
            <Network className="size-4" />
            Build graph
          </Button>
        </CardContent>
      </Card>

      {!graph ? (
        <EmptyState icon={Network} title="No graph yet" hint="Enter a target to scaffold the attack surface across kill-chain phases." />
      ) : (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <Badge variant="outline" className="font-mono text-[10px]">{graph.source}</Badge>
            <span className="font-mono">{graph.target}</span>
            <span>·</span>
            <span>{graph.nodes.length} nodes</span>
            <span>·</span>
            <span>{graph.edges.length} edges</span>
          </div>
          <div className="grid gap-3 overflow-x-auto" style={{ gridTemplateColumns: `repeat(${graph.phases.length}, minmax(11rem, 1fr))` }}>
            {graph.phases.map((phase) => (
              <div key={phase} className="flex flex-col gap-2">
                <div className="rounded-md border border-border bg-muted/40 px-2 py-1 text-center text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  {phase}
                </div>
                {graph.nodes
                  .filter((n) => n.phase === phase)
                  .map((n) => (
                    <div
                      key={n.id}
                      className={cn(
                        'rounded-md border px-3 py-2 text-xs',
                        KIND_TONE[n.kind] ?? KIND_TONE.service,
                      )}
                    >
                      <p className="font-medium leading-snug">{n.label}</p>
                      <p className="mt-0.5 font-mono text-[10px] opacity-70">
                        {n.kind}
                        {n.status ? ` · ${n.status}` : ''}
                      </p>
                    </div>
                  ))}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
