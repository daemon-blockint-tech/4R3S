import type { Metadata } from 'next'
import { Card, CardContent } from '@ares/ui'
import { LicenseAgreementArticle } from '@/components/dashboard/license-agreement-article'

export const metadata: Metadata = {
  title: 'License · Dashboard · ARES Auditor',
  description: 'Commercial license agreement inside your signed-in ARES Auditor workspace.',
}

export default function DashboardLicensePage() {
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">License</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Your commercial license agreement, kept here for procurement review while signed in.
        </p>
      </div>
      <Card>
        <CardContent className="pt-6">
          <LicenseAgreementArticle />
        </CardContent>
      </Card>
    </div>
  )
}
