import { useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import type { ApprovalRequest } from '@/hooks/useApprovals'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'

interface ApprovalModalProps {
  approval: ApprovalRequest | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onResolved?: (id: string) => void
}

export function ApprovalModal({ approval, open, onOpenChange, onResolved }: ApprovalModalProps) {
  const [busy, setBusy] = useState<'approve' | 'reject' | null>(null)

  async function resolve(action: 'approve' | 'reject') {
    if (!approval) return
    const { id } = approval
    setBusy(action)
    try {
      await api.post(`/api/approvals/${id}/${action}`)
      toast.success(action === 'approve' ? 'Approved' : 'Rejected')
      onOpenChange(false)
      onResolved?.(id)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Request failed')
    } finally {
      setBusy(null)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldAlert className="size-5 text-amber-400" />
            Approval required
          </DialogTitle>
          <DialogDescription>
            This action needs your sign-off before ARES can proceed.
          </DialogDescription>
        </DialogHeader>
        {approval && (
          <div className="space-y-3 text-sm">
            <div className="flex flex-wrap gap-2">
              <Badge variant="outline" className="font-mono text-[10px]">
                {approval.action}
              </Badge>
              <Badge variant="secondary" className="font-mono text-[10px]">
                {approval.status}
              </Badge>
            </div>
            <div className="rounded-md border border-border bg-muted/30 p-3 font-mono text-xs">
              <p className="text-muted-foreground">Target</p>
              <p className="mt-1 break-all text-foreground">{approval.target}</p>
            </div>
            <p className="leading-relaxed text-muted-foreground">{approval.reason}</p>
          </div>
        )}
        <DialogFooter>
          <Button
            variant="outline"
            disabled={!!busy}
            onClick={() => resolve('reject')}
          >
            {busy === 'reject' ? 'Rejecting…' : 'Reject'}
          </Button>
          <Button disabled={!!busy} onClick={() => resolve('approve')}>
            {busy === 'approve' ? 'Approving…' : 'Approve'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
