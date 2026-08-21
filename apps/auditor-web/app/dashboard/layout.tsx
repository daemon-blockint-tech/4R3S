import type { Metadata } from 'next'
import { getServerSession } from '@/lib/session/get-server-session'
import { DashboardShell } from '@/components/dashboard/dashboard-shell'

export const metadata: Metadata = {
  title: 'Dashboard · ARES Auditor',
  description: 'Findings, risk, reports, and license for your ARES Auditor account.',
}

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const session = await getServerSession()

  return <DashboardShell user={session?.user ?? null}>{children}</DashboardShell>
}
