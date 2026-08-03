import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Crown, Send, Rocket, ScrollText } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { useEvents } from '@/hooks/useEvents'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { PageHeader } from '@/components/common'
import { cn } from '@/lib/utils'

interface ChatMsg {
  role: 'user' | 'assistant'
  content: string
}

interface MissionBrief {
  objective: string
  target: string | { host?: string }
  scope?: string
  fidelity?: 'dry_run' | 'live'
  constraints?: string[]
}

interface ConverseTurn {
  reply: string
  brief?: MissionBrief
  missing?: string[]
  ready?: boolean
}

type Step = 'brief' | 'review' | 'launch' | 'sitrep'

export function AdmiralPage() {
  const [step, setStep] = useState<Step>('brief')
  const [messages, setMessages] = useState<ChatMsg[]>([])
  const [input, setInput] = useState('')
  const [brief, setBrief] = useState<MissionBrief | null>(null)
  const [confirmed, setConfirmed] = useState(false)
  const { events } = useEvents(80, ['general:', 'admiral:'])

  const sitreps = useQuery({
    queryKey: ['general-sitreps'],
    queryFn: () => api.get<{ sitreps?: Array<{ message?: string; ts?: string }> }>('/api/general/sitreps'),
    refetchInterval: step === 'sitrep' ? 5_000 : false,
    enabled: step === 'sitrep',
  })

  const converse = useMutation({
    mutationFn: (msgs: ChatMsg[]) =>
      api.post<ConverseTurn>('/api/admiral/converse', { messages: msgs }),
    onSuccess: (data) => {
      setMessages((prev) => [...prev, { role: 'assistant', content: data.reply }])
      if (data.brief) setBrief(data.brief)
      if (data.ready) setStep('review')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const plan = useMutation({
    mutationFn: () => {
      if (!brief) throw new Error('No brief')
      const target =
        typeof brief.target === 'string' ? brief.target : brief.target?.host ?? 'local-lab'
      return api.post('/api/general/plan', {
        directive: `${brief.objective}\nTarget: ${target}\nScope: ${brief.scope ?? 'authorized testing only'}`,
      })
    },
    onSuccess: () => {
      toast.success('Plan ready')
      setStep('launch')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const launch = useMutation({
    mutationFn: () =>
      api.post('/api/admiral/launch', {
        brief: { ...brief, fidelity: confirmed ? 'live' : 'dry_run' },
        confirmed,
      }),
    onSuccess: () => {
      toast.success(confirmed ? 'Mission launched' : 'Dry-run plan returned')
      setStep('sitrep')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const execute = useMutation({
    mutationFn: () => api.post('/api/general/execute', {}),
    onSuccess: () => {
      toast.success('Op General executing plan')
      setStep('sitrep')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const auto = useMutation({
    mutationFn: () => {
      if (!brief) throw new Error('No brief')
      const target = typeof brief.target === 'string' ? brief.target : brief.target?.host ?? 'local-lab'
      return api.post('/api/general/auto', {
        objective: `${brief.objective}\nTarget: ${target}\nScope: ${brief.scope ?? 'authorized testing only'}`,
      })
    },
    onSuccess: () => {
      toast.success('Autonomous mission dispatched')
      setStep('sitrep')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const forceSitrep = useMutation({
    mutationFn: () => api.post('/api/general/sitrep', {}),
    onSuccess: () => {
      toast.success('Sitrep requested')
      sitreps.refetch()
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const assess = useMutation({
    mutationFn: () => api.post<{ assessment: unknown }>('/api/general/assess', {}),
    onSuccess: () => toast.success('Assessment produced'),
    onError: (e: Error) => toast.error(e.message),
  })

  function send() {
    const text = input.trim()
    if (!text) return
    const next = [...messages, { role: 'user' as const, content: text }]
    setMessages(next)
    setInput('')
    converse.mutate(next)
  }

  const sseFeed = events.filter((e) => e.type.startsWith('general:') || e.type.startsWith('admiral:'))

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        title="Op Admiral"
        description="Guided mission intake. Refine your objective with the Admiral, review the plan, then hand off to Op General."
      />

      <div className="mb-4 flex flex-wrap gap-2">
        {(['brief', 'review', 'launch', 'sitrep'] as Step[]).map((s) => (
          <Badge
            key={s}
            variant={step === s ? 'default' : 'outline'}
            className="cursor-pointer font-mono text-[10px] capitalize"
            onClick={() => setStep(s)}
          >
            {s}
          </Badge>
        ))}
      </div>

      {step === 'brief' && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <Crown className="size-4 text-amber-400" />
              Mission brief
            </CardTitle>
            <CardDescription>
              Describe what you want tested. The Admiral fills gaps before launch.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <ScrollArea className="h-48 rounded-md border border-border p-3">
              {messages.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  Example: "Assess github.com/myorg/api for auth bypass and IDOR on user endpoints."
                </p>
              ) : (
                <ul className="space-y-2 text-sm">
                  {messages.map((m, i) => (
                    <li key={i} className={cn(m.role === 'user' ? 'text-foreground' : 'text-muted-foreground')}>
                      <span className="font-mono text-[10px] uppercase">{m.role}</span>
                      <p className="mt-0.5 whitespace-pre-wrap">{m.content}</p>
                    </li>
                  ))}
                </ul>
              )}
            </ScrollArea>
            <div className="flex gap-2">
              <Textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Your objective, target, and constraints…"
                rows={3}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault()
                    send()
                  }
                }}
              />
              <Button onClick={send} disabled={converse.isPending} className="shrink-0 self-end">
                <Send className="size-4" />
              </Button>
            </div>
            {brief && (
              <div className="rounded-md border border-border bg-muted/30 p-3 text-xs font-mono">
                <p>Objective: {brief.objective}</p>
                <p>Target: {typeof brief.target === 'string' ? brief.target : brief.target?.host}</p>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {step === 'review' && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <ScrollText className="size-4" />
              Review plan
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {brief ? (
              <pre className="overflow-x-auto rounded-md border border-border bg-background/50 p-3 text-xs">
                {JSON.stringify(brief, null, 2)}
              </pre>
            ) : (
              <p className="text-sm text-muted-foreground">Complete the brief step first.</p>
            )}
            <Button onClick={() => plan.mutate()} disabled={plan.isPending || !brief}>
              Generate plan via Op General
            </Button>
          </CardContent>
        </Card>
      )}

      {step === 'launch' && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <Rocket className="size-4" />
              Launch
            </CardTitle>
            <CardDescription>
              Dry-run returns a plan only. Live execution requires explicit confirmation.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
              />
              I confirm authorized testing and want live execution
            </label>
            <div className="flex flex-wrap gap-2">
              <Button onClick={() => launch.mutate()} disabled={launch.isPending}>
                {confirmed ? 'Launch live' : 'Dry-run launch'}
              </Button>
              <Button variant="secondary" onClick={() => execute.mutate()} disabled={execute.isPending}>
                Execute via Op General
              </Button>
              <Button
                variant="outline"
                onClick={() => auto.mutate()}
                disabled={auto.isPending || !brief}
              >
                Autonomous (plan + execute)
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Execute runs the plan already staged by Op General. Autonomous plans and executes in one
              shot — both still pass approval gates for sensitive actions.
            </p>
          </CardContent>
        </Card>
      )}

      {step === 'sitrep' && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm">Sitrep feed</CardTitle>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => forceSitrep.mutate()}
                  disabled={forceSitrep.isPending}
                >
                  Force sitrep
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => assess.mutate()}
                  disabled={assess.isPending}
                >
                  Assess
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <ScrollArea className="h-64 rounded-md border border-border p-3 font-mono text-xs">
              {sitreps.data?.sitreps?.map((s, i) => (
                <p key={i} className="mb-1 text-muted-foreground">
                  {s.message ?? JSON.stringify(s)}
                </p>
              ))}
              {sseFeed.map((e) => (
                <p key={e.id} className="mb-1">
                  [{e.type}] {e.message}
                </p>
              ))}
              {!sitreps.data?.sitreps?.length && sseFeed.length === 0 && (
                <p className="text-muted-foreground">Waiting for sitreps…</p>
              )}
            </ScrollArea>
            {assess.data != null && (
              <ScrollArea className="h-48 rounded-md border border-border bg-background/40 p-3">
                <pre className="whitespace-pre-wrap font-mono text-[11px] leading-relaxed text-foreground/90">
                  {JSON.stringify(assess.data.assessment, null, 2)}
                </pre>
              </ScrollArea>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
