'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Settings, BarChart3, User } from 'lucide-react'
import { cn } from '@/lib/utils'

interface SidebarNavProps {
  isSignedIn: boolean
  onLinkClick?: () => void
}

const NAV_ITEMS = [
  { href: '/settings', label: 'Settings', icon: Settings, signedInOnly: false },
  { href: '/usage', label: 'Usage', icon: BarChart3, signedInOnly: false },
  { href: '/profile', label: 'Profile', icon: User, signedInOnly: true },
] as const

export function SidebarNav({ isSignedIn, onLinkClick }: SidebarNavProps) {
  const pathname = usePathname()

  const visibleItems = NAV_ITEMS.filter((item) => !item.signedInOnly || isSignedIn)

  return (
    <nav className="mt-auto pt-3 border-t border-border/60 space-y-0.5">
      {visibleItems.map(({ href, label, icon: Icon }) => {
        const isActive = pathname === href || pathname.startsWith(`${href}/`)

        return (
          <Link
            key={href}
            href={href}
            onClick={onLinkClick}
            className={cn(
              'flex items-center gap-2 rounded-lg px-2 py-1.5 text-xs font-medium transition-colors',
              isActive
                ? 'bg-accent text-foreground'
                : 'text-muted-foreground hover:bg-accent/50 hover:text-foreground',
            )}
          >
            <Icon className="h-3.5 w-3.5 shrink-0" />
            {label}
          </Link>
        )
      })}
    </nav>
  )
}
