import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { ApprovalModal } from '@/components/ApprovalModal'
import { useApprovals, type ApprovalRequest } from '@/hooks/useApprovals'
import type { ApprovalPayload } from '@/lib/api'

interface ApprovalContextValue {
  showApproval: (approval: ApprovalPayload | ApprovalRequest) => void
  pendingCount: number
}

const ApprovalContext = createContext<ApprovalContextValue | null>(null)

export function ApprovalProvider({ children }: { children: ReactNode }) {
  const { approvals, refetch } = useApprovals('pending')
  const [active, setActive] = useState<ApprovalRequest | null>(null)
  const [open, setOpen] = useState(false)
  // Approvals the operator explicitly dismissed without deciding. We don't nag by
  // re-opening these, but a *newly* requested approval still surfaces.
  const dismissed = useRef<Set<string>>(new Set())

  const showApproval = useCallback((approval: ApprovalPayload | ApprovalRequest) => {
    dismissed.current.delete(approval.id)
    setActive(approval as ApprovalRequest)
    setOpen(true)
  }, [])

  useEffect(() => {
    if (open || active) return
    const next = approvals.find((a) => !dismissed.current.has(a.id))
    if (next) {
      setActive(next)
      setOpen(true)
    }
  }, [approvals, open, active])

  const handleOpenChange = useCallback((next: boolean) => {
    setOpen(next)
    // Closed without resolving (resolve clears `active` via onResolved): remember the
    // dismissal so the poll loop doesn't immediately re-open the same request, then
    // release `active` so a different pending approval can take its place.
    if (!next) {
      setActive((current) => {
        if (current) dismissed.current.add(current.id)
        return null
      })
    }
  }, [])

  return (
    <ApprovalContext.Provider value={{ showApproval, pendingCount: approvals.length }}>
      {children}
      <ApprovalModal
        approval={active}
        open={open}
        onOpenChange={handleOpenChange}
        onResolved={() => {
          if (active) dismissed.current.delete(active.id)
          setActive(null)
          refetch()
        }}
      />
    </ApprovalContext.Provider>
  )
}

export function useApprovalGate() {
  const ctx = useContext(ApprovalContext)
  if (!ctx) throw new Error('useApprovalGate must be used within ApprovalProvider')
  return ctx
}
