'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { FileKey2, FlaskConical, LayoutDashboard, ShieldAlert, FileText } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { Session } from '@/lib/session/types'

type NavItem = {
  href: string
  label: string
  icon: typeof LayoutDashboard
  /** Real page exists. false = intentionally rendered as disabled "Coming soon" -- data wiring to apps/auditor-api is separate scope (INT-4 follow-up), not silently omitted. */
  enabled: boolean
}

const NAV: NavItem[] = [
  { href: '/dashboard', label: 'Overview', icon: LayoutDashboard, enabled: true },
  { href: '/dashboard/findings', label: 'Findings', icon: ShieldAlert, enabled: false },
  { href: '/dashboard/risk', label: 'Risk', icon: FlaskConical, enabled: false },
  { href: '/dashboard/reports', label: 'Reports', icon: FileText, enabled: false },
  { href: '/dashboard/license', label: 'License', icon: FileKey2, enabled: true },
]

function isActive(pathname: string, href: string): boolean {
  if (href === '/dashboard') return pathname === '/dashboard' || pathname === '/dashboard/'
  return pathname === href || pathname.startsWith(`${href}/`)
}

export function DashboardShell({
  user,
  children,
}: {
  user: Session['user'] | null
  children: React.ReactNode
}) {
  const pathname = usePathname()

  return (
    <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6">
      <div className="mb-6 flex items-center justify-between gap-4 border-b border-border pb-4">
        <nav aria-label="Dashboard sections" className="flex flex-wrap gap-1">
          {NAV.map((item) => {
            const active = isActive(pathname, item.href)
            const Icon = item.icon
            if (!item.enabled) {
              return (
                <span
                  key={item.href}
                  title="Coming soon"
                  aria-disabled="true"
                  className="inline-flex cursor-not-allowed items-center gap-2 rounded-md px-3 py-2 text-sm font-medium text-muted-foreground/50"
                >
                  <Icon className="h-4 w-4" aria-hidden />
                  {item.label}
                  <span className="rounded-full bg-muted px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                    Soon
                  </span>
                </span>
              )
            }
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? 'page' : undefined}
                className={cn(
                  'inline-flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors',
                  active
                    ? 'bg-accent text-accent-foreground'
                    : 'text-muted-foreground hover:bg-accent/50 hover:text-accent-foreground',
                )}
              >
                <Icon className="h-4 w-4" aria-hidden />
                {item.label}
              </Link>
            )
          })}
        </nav>
        {user ? (
          <p className="shrink-0 text-sm text-muted-foreground">{user.username}</p>
        ) : (
          <Link href="/" className="shrink-0 text-sm font-medium text-primary hover:underline">
            Sign in
          </Link>
        )}
      </div>
      {children}
    </div>
  )
}
