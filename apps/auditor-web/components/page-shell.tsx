'use client'

import { SharedHeader } from '@/components/shared-header'

interface PageShellProps {
  initialStars?: number
  children: React.ReactNode
}

/**
 * The header + scroll container shared by the settings, usage, and profile pages.
 * These three had byte-identical copies of this markup.
 */
export function PageShell({ initialStars, children }: PageShellProps) {
  return (
    <div className="flex-1 bg-background flex flex-col h-full overflow-hidden">
      <div className="flex-shrink-0 p-3">
        <SharedHeader initialStars={initialStars} />
      </div>

      <div className="flex-1 overflow-auto px-4 pb-6">
        <div className="max-w-3xl mx-auto space-y-6">{children}</div>
      </div>
    </div>
  )
}
