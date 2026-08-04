import Link from 'next/link'
import AresLogo from '@/components/logos/ares'
import { cn } from '@/lib/utils'

interface AresBrandProps {
  height?: number
  className?: string
  priority?: boolean
  href?: string
}

export function AresBrand({ height = 28, className, priority, href = '/' }: AresBrandProps) {
  const logo = <AresLogo height={height} priority={priority} className={className} />

  if (!href) {
    return logo
  }

  return (
    <Link
      href={href}
      className={cn(
        'inline-flex shrink-0 rounded-sm overflow-hidden',
        'ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
      )}
      aria-label="ARES Auditor home"
    >
      {logo}
    </Link>
  )
}
