import type { Metadata } from 'next'
import { Card, CardContent, CardHeader, CardTitle } from '@ares/ui'

export const metadata: Metadata = {
  title: 'Overview · Dashboard · ARES Auditor',
}

export default function DashboardOverviewPage() {
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">Overview</h1>
        <p className="mt-1 max-w-[62ch] text-sm text-muted-foreground">
          Findings, risk, and report summaries will appear here once audit jobs are wired through{' '}
          <code className="rounded bg-muted px-1 py-0.5 text-xs">apps/auditor-api</code>. No placeholder numbers below —
          that work is tracked separately.
        </p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">License</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Your commercial license terms are available now — see the License tab.
        </CardContent>
      </Card>
    </div>
  )
}
