import { useLocation } from 'react-router'
import { RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { useHealth } from '@/hooks/useHealth'
import type { ConnState } from '@/lib/api'
import { NAV } from '@/components/layout/nav'

const LABELS: Record<ConnState, string> = {
  checking: 'Checking…',
  llm: 'API + LLM ready',
  connected: 'API connected',
  offline: 'Offline',
}

const DOT: Record<ConnState, string> = {
  checking: 'bg-muted-foreground animate-pulse',
  llm: 'bg-[var(--color-success)]',
  connected: 'bg-primary',
  offline: 'bg-destructive',
}

const PAGE_TITLES = new Map(
  NAV.flatMap((group) => group.items.map((item) => [item.to, item.label] as const)),
)

function titleFromPath(path: string): string {
  const normalized = path === '' || path === '/' ? '/' : `/${path.replace(/^\/+/, '').split('/')[0]}`
  const fromNav = PAGE_TITLES.get(normalized)
  if (fromNav) return fromNav

  const segment = normalized.slice(1)
  return segment
    .split('-')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ')
}

export function Header() {
  const { pathname } = useLocation()
  const { state, refetch, isFetching } = useHealth()

  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-border bg-card px-5">
      <h1 className="text-sm font-semibold tracking-tight">{titleFromPath(pathname)}</h1>

      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 rounded-md border border-border bg-background px-2.5 py-1.5">
          <span className={cn('size-2 rounded-full', DOT[state])} />
          <span className="font-mono text-xs text-muted-foreground">{LABELS[state]}</span>
        </div>
        <Button
          variant="ghost"
          size="icon-sm"
          onClick={() => refetch()}
          disabled={isFetching}
          aria-label="Refresh connection"
        >
          <RefreshCw className={cn('size-4', isFetching && 'animate-spin')} />
        </Button>
      </div>
    </header>
  )
}
