'use client'

import { SharedHeader } from '@/components/shared-header'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Progress, ProgressIndicator, ProgressLabel, ProgressTrack, ProgressValue } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { GitBranch, BookOpen, Wrench, FileSearch, Sparkles, ArrowUpRight } from 'lucide-react'
import Link from 'next/link'
import { toast } from 'sonner'
import { MOCK_USAGE_DATA, usagePercent } from '@/lib/mock/usage'
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
  const { compute, onDemand, plan, billingPeriodEnd } = MOCK_USAGE_DATA

  const handlePlanAction = (action: 'adjust' | 'upgrade') => {
    toast.info(
      action === 'upgrade'
        ? 'Upgrade plans will be available once billing is connected.'
        : 'Plan adjustments will be available once billing is connected.',
    )
  }

  return (
    <div className="flex-1 bg-background flex flex-col h-full overflow-hidden">
      <div className="flex-shrink-0 p-3">
        <SharedHeader initialStars={initialStars} />
      </div>

      <div className="flex-1 overflow-auto px-4 pb-6">
        <div className="max-w-3xl mx-auto space-y-6">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Plan &amp; Usage</h1>
            <p className="text-sm text-muted-foreground mt-1">
              Review your current plan and monitor compute usage for this billing period.
            </p>
          </div>

          {!user && (
            <Card className="border-primary/30 bg-primary/5">
              <CardContent className="pt-6">
                <p className="text-sm">
                  Sign in to track usage against your account. Sample data is shown below.
                </p>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <CardTitle className="text-base">Current plan</CardTitle>
                  <CardDescription>Billing period resets on {billingPeriodEnd}.</CardDescription>
                </div>
                <Badge variant="secondary">{plan.name}</Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
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
                {/* TODO(INT): Replace MOCK_USAGE_DATA with GET /api/billing/usage response. */}
                Mock usage data — billing API not yet connected.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <UsageBar label="Compute usage" used={compute.used} limit={compute.limit} unit={compute.unit} />
              <UsageBar label="On-demand usage" used={onDemand.used} limit={onDemand.limit} unit={onDemand.unit} />
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
        </div>
      </div>
    </div>
  )
}
