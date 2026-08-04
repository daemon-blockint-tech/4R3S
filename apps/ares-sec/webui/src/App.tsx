import { BrowserRouter, Routes, Route } from 'react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TooltipProvider } from '@/components/ui/tooltip'
import { Toaster } from '@/components/ui/sonner'
import { AppShell } from '@/components/layout/AppShell'
import { WarRoomPage } from '@/pages/WarRoomPage'
import { OperativesPage } from '@/pages/OperativesPage'
import { EvidenceVaultPage } from '@/pages/EvidenceVaultPage'
import { ArsenalPage } from '@/pages/ArsenalPage'
import { TerminalPage } from '@/pages/TerminalPage'
import { ConfigLibraryPage } from '@/pages/ConfigLibraryPage'
import { SettingsPage } from '@/pages/SettingsPage'
import { DocsPage } from '@/pages/DocsPage'
import { AdmiralPage } from '@/pages/AdmiralPage'
import { SelfImprovementPage } from '@/pages/SelfImprovementPage'
import { ObsidivmPage, CtfRangePage } from '@/pages/RangePages'
import { MissionIntelPage } from '@/pages/MissionIntelPage'
import { BountyPage } from '@/pages/BountyPage'
import { AttackGraphPage } from '@/pages/AttackGraphPage'
import { WhiteboxPage } from '@/pages/WhiteboxPage'

const qc = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 5_000, retry: 1 },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <TooltipProvider>
        <BrowserRouter basename={import.meta.env.BASE_URL.replace(/\/$/, '') || '/'}>
          <Routes>
            <Route element={<AppShell />}>
              <Route index element={<WarRoomPage />} />
              <Route path="admiral" element={<AdmiralPage />} />
              <Route path="intel" element={<MissionIntelPage />} />
              <Route path="operatives" element={<OperativesPage />} />
              <Route path="evidence" element={<EvidenceVaultPage />} />
              <Route path="obsidivm" element={<ObsidivmPage />} />
              <Route path="ctf" element={<CtfRangePage />} />
              <Route path="arsenal" element={<ArsenalPage />} />
              <Route path="attack-graph" element={<AttackGraphPage />} />
              <Route path="whitebox" element={<WhiteboxPage />} />
              <Route path="bounty" element={<BountyPage />} />
              <Route path="terminal" element={<TerminalPage />} />
              <Route path="config" element={<ConfigLibraryPage />} />
              <Route path="settings" element={<SettingsPage />} />
              <Route path="self-improve" element={<SelfImprovementPage />} />
              <Route path="docs" element={<DocsPage />} />
            </Route>
          </Routes>
        </BrowserRouter>
        <Toaster richColors position="bottom-right" />
      </TooltipProvider>
    </QueryClientProvider>
  )
}
