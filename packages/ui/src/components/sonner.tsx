"use client"

import type { CSSProperties } from "react"
import {
  CircleCheckIcon,
  InfoIcon,
  Loader2Icon,
  OctagonXIcon,
  TriangleAlertIcon,
} from "lucide-react"
import { Toaster as Sonner, type ToasterProps } from "sonner"

// Deliberately theme-agnostic — UI-2 found the two real consumers use
// genuinely different theme systems: auditor-web (Next.js) has its own
// custom, SSR-aware theme provider (not next-themes), while War Room
// (Vite, dark-default design) has no dynamic theme switching at all.
// Rather than hardcode either app's specific hook here, this accepts a
// plain `theme` value — each app supplies it however it determines theme
// for itself. Defaults to "dark" to match War Room's own existing usage
// unchanged (it never passed a theme prop before this change either).
const Toaster = ({
  theme = "dark",
  ...props
}: ToasterProps) => {
  return (
    <Sonner
      theme={theme}
      className="toaster group"
      icons={{
        success: <CircleCheckIcon className="size-4" />,
        info: <InfoIcon className="size-4" />,
        warning: <TriangleAlertIcon className="size-4" />,
        error: <OctagonXIcon className="size-4" />,
        loading: <Loader2Icon className="size-4 animate-spin" />,
      }}
      style={
        {
          "--normal-bg": "var(--popover)",
          "--normal-text": "var(--popover-foreground)",
          "--normal-border": "var(--border)",
          "--border-radius": "var(--radius)",
        } as CSSProperties
      }
      {...props}
    />
  )
}

export { Toaster }
