import {
  Swords,
  Bot,
  Lock,
  LineChart,
  Flag,
  Radar,
  Terminal,
  Save,
  Settings,
  BookText,
  Crown,
  Brain,
  Gauge,
  Bug,
  Network,
  FolderGit2,
  type LucideIcon,
} from 'lucide-react'

export interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  badge?: number
}

export interface NavGroup {
  label: string
  items: NavItem[]
}

export const NAV: NavGroup[] = [
  {
    label: 'Main',
    items: [
      { to: '/admiral', label: 'Op Admiral', icon: Crown },
      { to: '/', label: 'War Room', icon: Swords },
      { to: '/intel', label: 'Mission Intel', icon: Gauge },
      { to: '/operatives', label: 'Operatives', icon: Bot },
      { to: '/evidence', label: 'Evidence Vault', icon: Lock },
    ],
  },
  {
    label: 'Ranges',
    items: [
      { to: '/obsidivm', label: 'OBSIDIVM', icon: LineChart },
      { to: '/ctf', label: 'CTF Range', icon: Flag },
    ],
  },
  {
    label: 'Toolkit',
    items: [
      { to: '/arsenal', label: 'Arsenal', icon: Radar },
      { to: '/attack-graph', label: 'Attack Graph', icon: Network },
      { to: '/whitebox', label: 'White-box', icon: FolderGit2 },
      { to: '/bounty', label: 'Bounty', icon: Bug },
      { to: '/terminal', label: 'Terminal', icon: Terminal },
      { to: '/config', label: 'Config Library', icon: Save },
    ],
  },
  {
    label: 'System',
    items: [
      { to: '/self-improve', label: 'Self-Improvement', icon: Brain },
      { to: '/settings', label: 'Settings', icon: Settings },
      { to: '/docs', label: 'Docs', icon: BookText },
    ],
  },
]
