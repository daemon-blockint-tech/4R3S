'use client'

import * as React from 'react'
import { Progress as ProgressPrimitive } from 'radix-ui'

import { cn } from '@/lib/utils'

type ProgressContextValue = {
  value: number | null | undefined
  max: number
  min: number
}

const ProgressContext = React.createContext<ProgressContextValue>({
  value: null,
  max: 100,
  min: 0,
})

function useProgressContext() {
  return React.useContext(ProgressContext)
}

function getProgressPercent(value: number | null | undefined, min: number, max: number): number {
  if (value == null) return 0
  if (max <= min) return 0
  return Math.min(100, Math.max(0, ((value - min) / (max - min)) * 100))
}

function Progress({
  className,
  value,
  max = 100,
  min = 0,
  children,
  ...props
}: React.ComponentProps<typeof ProgressPrimitive.Root> & {
  max?: number
  min?: number
}) {
  const contextValue = React.useMemo(() => ({ value, max, min }), [value, max, min])

  return (
    <ProgressContext.Provider value={contextValue}>
      <div data-slot="progress" className={cn('flex w-full flex-col gap-2', className)}>
        {children ?? (
          <ProgressTrack value={value ?? undefined} {...props}>
            <ProgressIndicator />
          </ProgressTrack>
        )}
      </div>
    </ProgressContext.Provider>
  )
}

function ProgressTrack({
  className,
  children,
  value: valueProp,
  ...props
}: React.ComponentProps<typeof ProgressPrimitive.Root>) {
  const { value: contextValue } = useProgressContext()

  return (
    <ProgressPrimitive.Root
      data-slot="progress-track"
      value={valueProp ?? contextValue ?? undefined}
      className={cn('relative h-2 w-full overflow-hidden rounded-full bg-primary/20', className)}
      {...props}
    >
      {children}
    </ProgressPrimitive.Root>
  )
}

function ProgressIndicator({ className, ...props }: React.ComponentProps<typeof ProgressPrimitive.Indicator>) {
  const { value, max, min } = useProgressContext()
  const percent = getProgressPercent(value, min, max)

  return (
    <ProgressPrimitive.Indicator
      data-slot="progress-indicator"
      className={cn('h-full w-full flex-1 bg-primary transition-all', className)}
      style={{ transform: `translateX(-${100 - percent}%)` }}
      {...props}
    />
  )
}

function ProgressLabel({ className, ...props }: React.ComponentProps<'span'>) {
  return <span data-slot="progress-label" className={cn('text-sm font-medium', className)} {...props} />
}

type ProgressValueProps = React.ComponentProps<'span'> & {
  children?: React.ReactNode | ((formatted: string, value: number | null | undefined) => React.ReactNode)
}

function ProgressValue({ className, children, ...props }: ProgressValueProps) {
  const { value, max, min } = useProgressContext()
  const percent = Math.round(getProgressPercent(value, min, max))
  const formatted = `${percent}%`

  const content =
    typeof children === 'function' ? children(formatted, value ?? null) : (children ?? formatted)

  return (
    <span
      data-slot="progress-value"
      className={cn('text-sm text-muted-foreground tabular-nums', className)}
      {...props}
    >
      {content}
    </span>
  )
}

export { Progress, ProgressTrack, ProgressIndicator, ProgressLabel, ProgressValue }
