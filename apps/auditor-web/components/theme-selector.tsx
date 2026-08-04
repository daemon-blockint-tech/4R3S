'use client'

import * as React from 'react'
import { useTheme } from 'next-themes'
import { Monitor, Moon, Sun } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

const THEMES = [
  { value: 'light', label: 'Light', icon: Sun },
  { value: 'dark', label: 'Dark', icon: Moon },
  { value: 'system', label: 'System', icon: Monitor },
] as const

export function ThemeSelector() {
  const { theme = 'system', setTheme } = useTheme()
  const [mounted, setMounted] = React.useState(false)

  React.useEffect(() => {
    setMounted(true)
  }, [])

  if (!mounted) {
    return <div className="h-8 w-48 animate-pulse rounded-md bg-muted" />
  }

  return (
    <div className="flex items-center gap-1">
      {THEMES.map(({ value, label, icon: Icon }) => (
        <Button
          key={value}
          type="button"
          variant={theme === value ? 'secondary' : 'ghost'}
          size="sm"
          className={cn('h-8 px-2.5 text-xs', theme === value && 'ring-1 ring-border')}
          onClick={() => setTheme(value)}
        >
          <Icon className="h-3.5 w-3.5 mr-1.5" />
          {label}
        </Button>
      ))}
    </div>
  )
}
