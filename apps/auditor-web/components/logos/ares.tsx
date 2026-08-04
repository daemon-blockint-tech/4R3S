import Image from 'next/image'
import { cn } from '@/lib/utils'

/** Wordmark aspect ratio from apps/auditor-web/ARES.png (1736×932). */
const ASPECT = 1736 / 932

interface AresLogoProps {
  className?: string
  height?: number
  priority?: boolean
}

const AresLogo = ({ className, height = 32, priority }: AresLogoProps) => {
  const width = Math.round(height * ASPECT)

  return (
    <Image
      src="/logos/ares.png"
      alt="ARES"
      width={width}
      height={height}
      priority={priority}
      className={cn('rounded-sm object-contain object-left', className)}
      style={{ height, width }}
    />
  )
}

export default AresLogo
