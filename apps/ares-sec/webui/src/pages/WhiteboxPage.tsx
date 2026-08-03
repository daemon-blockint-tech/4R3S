import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { toast } from 'sonner'
import { FolderGit2, ScanSearch } from 'lucide-react'
import { api } from '@/lib/api'
import { PageHeader, EmptyState, Field } from '@/components/common'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { ScrollArea } from '@/components/ui/scroll-area'

export function WhiteboxPage() {
  const [repoPath, setRepoPath] = useState('')
  const [objective, setObjective] = useState('')
  const [maxRounds, setMaxRounds] = useState('3')

  const analyze = useMutation({
    mutationFn: () =>
      api.post<Record<string, unknown>>('/api/whitebox/analyze', {
        repoPath: repoPath.trim(),
        objective: objective.trim(),
        maxRounds: Number(maxRounds) || undefined,
      }),
    onSuccess: () => toast.success('Analysis complete'),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Analysis failed'),
  })

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="White-box Analysis"
        description="Multi-model source decomposition against a local repository. Paths are canonicalized and confined to the allowed root before any read."
      />

      <div className="grid gap-6 lg:grid-cols-[1fr_1.3fr]">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Analysis brief</CardTitle>
            <CardDescription className="text-xs">Point at a local repo and state the security objective.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Field label="Repository path">
              <Input
                value={repoPath}
                onChange={(e) => setRepoPath(e.target.value)}
                placeholder="/path/to/local/repo"
                className="font-mono text-sm"
              />
            </Field>
            <Field label="Objective">
              <Textarea
                value={objective}
                onChange={(e) => setObjective(e.target.value)}
                placeholder="e.g. Find authentication bypasses and unsafe deserialization in the API layer."
                rows={4}
              />
            </Field>
            <Field label="Max rounds" hint="How many decomposition/analysis passes to run.">
              <Input
                type="number"
                min={1}
                max={10}
                value={maxRounds}
                onChange={(e) => setMaxRounds(e.target.value)}
                className="font-mono text-sm w-24"
              />
            </Field>
            <Button
              onClick={() => analyze.mutate()}
              disabled={!repoPath.trim() || !objective.trim() || analyze.isPending}
            >
              <ScanSearch className="size-4" />
              {analyze.isPending ? 'Analyzing…' : 'Run analysis'}
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Result</CardTitle>
          </CardHeader>
          <CardContent>
            {analyze.data ? (
              <ScrollArea className="h-[28rem] rounded-md border border-border bg-background/40 p-3">
                <pre className="whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-foreground/90">
                  {JSON.stringify(analyze.data, null, 2)}
                </pre>
              </ScrollArea>
            ) : (
              <EmptyState
                icon={FolderGit2}
                title="No analysis yet"
                hint="Provide a repo path and objective, then run the analysis."
              />
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
