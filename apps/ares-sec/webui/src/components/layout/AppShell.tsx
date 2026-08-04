import { Outlet } from 'react-router'
import { ApprovalProvider } from '@/contexts/ApprovalContext'
import { Sidebar } from './Sidebar'
import { Header } from './Header'

export function AppShell() {
  return (
    <ApprovalProvider>
      <div className="flex h-[100dvh] overflow-hidden bg-background">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
          <Header />
          <main className="min-h-0 flex-1 overflow-y-auto p-5 md:p-6">
            <Outlet />
          </main>
        </div>
      </div>
    </ApprovalProvider>
  )
}
