import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Bug, Send } from 'lucide-react'
import { api } from '@/lib/api'
import { PageHeader, EmptyState, LoadingState, ErrorState, severityClass } from '@/components/common'
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
import { ScrollArea } from '@/components/ui/scroll-area'
import { cn } from '@/lib/utils'

interface Platform {
  id: string
  name: string
  apiSubmit: boolean
  portalOnly: boolean
}

interface Finding {
  id: string
  title: string
  severity: string
  claim?: string
  impact?: string
  recommendedFix?: string
  target?: string
}

/** Map UI finding (camelCase) to keys findingToBountyFinding() reads on the server. */
function toBountyFindingPayload(finding: Finding): Record<string, string> {
  return {
    id: finding.id,
    slug: finding.id,
    title: finding.title,
    summary: finding.claim || finding.title,
    severity_self: finding.severity,
    impact: finding.impact || '',
    root_cause: finding.claim || finding.title,
    remediation: finding.recommendedFix || '',
    component: finding.target || '',
  }
}

interface BountyReportPayload {
  body?: string
  title?: string
  severity?: string
  checklist?: string[]
}

function bountyReportText(report: string | BountyReportPayload): string {
  if (typeof report === 'string') return report
  if (report.body) return report.body
  return JSON.stringify(report, null, 2)
}

export function BountyPage() {
  const [platform, setPlatform] = useState('')
  const [programHandle, setProgramHandle] = useState('')
  const [findingId, setFindingId] = useState('')
  const [report, setReport] = useState('')

  const platforms = useQuery({
    queryKey: ['bounty-platforms'],
    queryFn: () => api.get<{ platforms: Platform[] }>('/api/bounty/platforms'),
  })
  const creds = useQuery({
    queryKey: ['bounty-credentials'],
    queryFn: () => api.get<{ credentials: Record<string, { platform: string; configured: boolean }> }>('/api/bounty/credentials'),
  })
  const findings = useQuery({
    queryKey: ['findings'],
    queryFn: () => api.get<{ findings: Finding[] }>('/api/findings'),
  })

  const selectedFinding = findings.data?.findings.find((f) => f.id === findingId)

  const format = useMutation({
    mutationFn: () =>
      api.post<{ report: string | BountyReportPayload }>('/api/bounty/format', {
        platform,
        programHandle: programHandle.trim(),
        finding: toBountyFindingPayload(selectedFinding!),
      }),
    onSuccess: (r) => {
      setReport(bountyReportText(r.report))
      toast.success('Report formatted')
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Format failed'),
  })

  const submit = useMutation({
    mutationFn: () =>
      api.post<{ result: unknown }>('/api/bounty/submit', {
        platform,
        programHandle: programHandle.trim(),
        finding: toBountyFindingPayload(selectedFinding!),
        dryRun: true,
      }),
    onSuccess: () => toast.success('Dry-run submission validated'),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Submit failed'),
  })

  const canFormat = platform && programHandle.trim() && selectedFinding

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="Bounty Submission"
        description="Turn a validated finding into a platform-ready report, then dry-run the submission before anything leaves your machine."
      />

      {platforms.isLoading ? (
        <LoadingState />
      ) : platforms.error ? (
        <ErrorState error={platforms.error} />
      ) : (
        <div className="grid gap-6 lg:grid-cols-[1fr_1.3fr]">
          <div className="space-y-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Platforms</CardTitle>
                <CardDescription className="text-xs">Configured credentials are detected locally.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                {(platforms.data?.platforms ?? []).map((p) => {
                  const configured = creds.data?.credentials[p.id]?.configured
                  return (
                    <div
                      key={p.id}
                      className="flex items-center justify-between rounded-md border border-border bg-background/50 px-3 py-2 text-xs"
                    >
                      <div>
                        <p className="font-medium">{p.name}</p>
                        <p className="text-[10px] text-muted-foreground">
                          {p.apiSubmit ? 'API submit' : 'Portal only'}
                        </p>
                      </div>
                      <Badge
                        variant="outline"
                        className={cn(
                          'font-mono text-[10px]',
                          configured
                            ? 'border-[var(--color-success)]/30 text-[var(--color-success)]'
                            : 'text-muted-foreground',
                        )}
                      >
                        {configured ? 'creds set' : 'no creds'}
                      </Badge>
                    </div>
                  )
                })}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Submission</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <Select value={platform} onValueChange={setPlatform}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select platform" />
                  </SelectTrigger>
                  <SelectContent>
                    {(platforms.data?.platforms ?? []).map((p) => (
                      <SelectItem key={p.id} value={p.id}>
                        {p.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input
                  value={programHandle}
                  onChange={(e) => setProgramHandle(e.target.value)}
                  placeholder="Program handle (e.g. acme-corp)"
                  className="font-mono text-sm"
                />
                <Select value={findingId} onValueChange={setFindingId}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select a finding" />
                  </SelectTrigger>
                  <SelectContent>
                    {(findings.data?.findings ?? []).map((f) => (
                      <SelectItem key={f.id} value={f.id}>
                        {f.title}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {selectedFinding && (
                  <Badge variant="outline" className={cn('font-mono text-[10px] capitalize', severityClass(selectedFinding.severity))}>
                    {selectedFinding.severity}
                  </Badge>
                )}
                <div className="flex gap-2">
                  <Button size="sm" onClick={() => format.mutate()} disabled={!canFormat || format.isPending}>
                    <Bug className="size-4" />
                    Format
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => submit.mutate()}
                    disabled={!canFormat || submit.isPending}
                  >
                    <Send className="size-4" />
                    Dry-run submit
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Formatted report</CardTitle>
            </CardHeader>
            <CardContent>
              {report ? (
                <ScrollArea className="h-[28rem] rounded-md border border-border bg-background/40 p-3">
                  <pre className="whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-foreground/90">
                    {report}
                  </pre>
                </ScrollArea>
              ) : (
                <EmptyState
                  icon={Bug}
                  title="No report yet"
                  hint="Pick a platform, program handle, and finding, then format the report."
                />
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}
