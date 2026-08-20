'use client'

// The shared @ares/ui Toaster is deliberately theme-agnostic (UI-2) — it
// takes a plain `theme` prop rather than calling any specific hook
// internally, since this app's own theme provider and War Room's are
// genuinely different systems. This wrapper supplies this app's own
// theme value; @ares/ui's version never sees this app's theme-provider
// at all.
import { useTheme } from '@/components/theme-provider'
import { Toaster as SharedToaster } from '@ares/ui'
import type { ToasterProps } from 'sonner'

const Toaster = ({ ...props }: ToasterProps) => {
  const { theme = 'system' } = useTheme()

  return <SharedToaster theme={theme as ToasterProps['theme']} {...props} />
}

export { Toaster }
