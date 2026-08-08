'use client'

import { useEffect, useState } from 'react'
import { PageShell } from '@/components/page-shell'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Progress, ProgressIndicator, ProgressLabel, ProgressTrack, ProgressValue } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { GitBranch, BookOpen, Wrench, FileSearch, Sparkles, ArrowUpRight } from 'lucide-react'
import Link from 'next/link'
import { toast } from 'sonner'
import { MOCK_USAGE_DATA, usagePercent, type MockUsageData } from '@/lib/mock/usage'
import type { Session } from '@/lib/session/types'

interface UsagePageClientProps {
  user: Session['user'] | null
  initialStars?: number
}

const PLAN_SECTIONS = [
  {
    title: 'Git & PRs to repo',
    description: 'Connect repositories and manage pull request workflows for audit findings.',
    icon: GitBranch,
    href: '/repos/new',
  },
  {
    title: 'Rules & Skills',
    description: 'Configure audit rules, custom skills, and agent behavior for your workspace.',
    icon: Sparkles,
    href: '/settings',
  },
  {
    title: 'Tools & MCPs',
    description: 'Manage MCP connectors and external tools available to audit agents.',
    icon: Wrench,
    href: '/settings',
  },
  {
    title: 'Indexing & Docs',
    description: 'Control documentation indexing and knowledge base sources for analysis.',
    icon: FileSearch,
    href: '/settings',
  },
] as const

function UsageBar({ label, used, limit, unit }: { label: string; used: number; limit: number; unit: string }) {
  const percent = usagePercent(used, limit)

  return (
    <Progress value={percent}>
      <div className="flex items-center justify-between gap-2">
        <ProgressLabel>{label}</ProgressLabel>
        <ProgressValue>{`${used} / ${limit} ${unit}`}</ProgressValue>
      </div>
      <ProgressTrack>
        <ProgressIndicator />
      </ProgressTrack>
      <p className="text-xs text-muted-foreground">{percent}% of monthly allowance used</p>
    </Progress>
  )
}

export function UsagePageClient({ user, initialStars }: UsagePageClientProps) {
  const [usageState, setUsageState] = useState<{ userId: string; data: MockUsageData } | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [reloadKey, setReloadKey] = useState(0)

  useEffect(() => {
    if (!user?.id) return

    let cancelled = false

    fetch('/api/billing/usage')
      .then(async (res) => {
        if (!res.ok) throw new Error(`Request failed with status ${res.status}`)
        return res.json() as Promise<MockUsageData>
      })
      .then((data) => {
        if (cancelled) return
        setLoadError(null)
        setUsageState({ userId: user.id, data })
      })
      .catch((error: unknown) => {
        if (cancelled) return
        // Never fall back to mock numbers for a signed-in user: a failed fetch must
        // not be indistinguishable from real billing data.
        setLoadError(error instanceof Error ? error.message : 'Could not load usage data')
        toast.error('Could not load usage data')
      })

    return () => {
      cancelled = true
    }
  }, [user?.id, reloadKey])

  const loading = Boolean(user?.id) && usageState?.userId !== user?.id && !loadError
  const displayData = user?.id && usageState?.userId === user.id ? usageState.data : MOCK_USAGE_DATA
  const { compute, onDemand, plan, billingPeriodEnd } = displayData
  const isLiveData = Boolean(user?.id && usageState?.userId === user.id && !loading)
  // Signed out, mock data is honest sample content and is labelled as such. Signed in,
  // it would masquerade as this account's real plan — so suppress it instead.
  const showsMockToSignedInUser = Boolean(user?.id) && !isLiveData

  const handlePlanAction = (action: 'adjust' | 'upgrade') => {
    toast.info(
      action === 'upgrade'
        ? 'Upgrade plans will be available once billing is connected.'
        : 'Plan adjustments will be available once billing is connected.',
    )
  }

  return (
    <PageShell initialStars={initialStars}>
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Plan &amp; Usage</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Review your current plan and monitor compute usage for this billing period.
        </p>
      </div>

      {!user && (
        <Card className="border-primary/30 bg-primary/5">
          <CardContent className="pt-6">
            <p className="text-sm">Sign in to track usage against your account. Sample data is shown below.</p>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <div className="flex items-start justify-between gap-4">
            <div>
              <CardTitle className="text-base">Current plan</CardTitle>
              <CardDescription>
                {/* Plan facts are billing facts. For a signed-in user we say nothing rather
                    than print sample numbers that read as their real plan. */}
                {showsMockToSignedInUser
                  ? 'Plan details unavailable.'
                  : `Billing period resets on ${billingPeriodEnd}.`}
              </CardDescription>
            </div>
            {!showsMockToSignedInUser && <Badge variant="secondary">{plan.name}</Badge>}
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {showsMockToSignedInUser ? (
            <div className="space-y-2">
              <Skeleton className="h-8 w-32" />
              <Skeleton className="h-4 w-full max-w-sm" />
            </div>
          ) : (
            <>
              <div>
                <p className="text-2xl font-semibold">{plan.priceLabel}</p>
                <p className="text-sm text-muted-foreground mt-1">{plan.description}</p>
              </div>
              <ul className="text-sm text-muted-foreground space-y-1">
                {plan.features.map((feature) => (
                  <li key={feature} className="flex items-center gap-2">
                    <BookOpen className="h-3.5 w-3.5 shrink-0" />
                    {feature}
                  </li>
                ))}
              </ul>
            </>
          )}
          <div className="flex flex-wrap gap-2 pt-2">
            <Button variant="outline" size="sm" onClick={() => handlePlanAction('adjust')}>
              Adjust plan
            </Button>
            <Button size="sm" onClick={() => handlePlanAction('upgrade')}>
              Upgrade plans
              <ArrowUpRight className="h-3.5 w-3.5 ml-1" />
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            {/* TODO(INT): Wire Adjust plan / Upgrade plans to billing checkout when subscription API is ready. */}
            Plan changes require billing integration (future INT work).
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Usage this period</CardTitle>
          <CardDescription>
            {loadError
              ? 'Usage data unavailable.'
              : loading
                ? 'Loading usage data…'
                : isLiveData
                  ? 'Usage for the current billing period.'
                  : 'Sample usage data for guests.'}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {loadError ? (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                We couldn&apos;t load your usage. No numbers are shown rather than showing numbers that might be wrong.
              </p>
              <p className="text-xs text-muted-foreground">{loadError}</p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setLoadError(null)
                  setReloadKey((k) => k + 1)
                }}
              >
                Retry
              </Button>
            </div>
          ) : loading ? (
            <div className="space-y-6">
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
            </div>
          ) : (
            <>
              <UsageBar label="Compute usage" used={compute.used} limit={compute.limit} unit={compute.unit} />
              <UsageBar label="On-demand usage" used={onDemand.used} limit={onDemand.limit} unit={onDemand.unit} />
            </>
          )}
        </CardContent>
      </Card>

      <div>
        <h2 className="text-lg font-medium mb-3">Workspace features</h2>
        <div className="grid gap-3 sm:grid-cols-2">
          {PLAN_SECTIONS.map(({ title, description, icon: Icon, href }) => (
            <Link key={title} href={href} className="block group">
              <Card className="h-full transition-colors hover:bg-accent/50">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Icon className="h-4 w-4 text-muted-foreground group-hover:text-foreground" />
                    {title}
                  </CardTitle>
                  <CardDescription className="text-xs">{description}</CardDescription>
                </CardHeader>
                <CardContent className="pt-0">
                  <span className="text-xs text-primary inline-flex items-center gap-1">
                    Manage
                    <ArrowUpRight className="h-3 w-3" />
                  </span>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      </div>
    </PageShell>
  )
}
