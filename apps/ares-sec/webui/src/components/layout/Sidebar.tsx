import { NavLink } from 'react-router'
import { cn } from '@/lib/utils'
import { NAV } from './nav'

export function Sidebar() {
  return (
    <aside className="hidden w-60 shrink-0 flex-col border-r border-border bg-card md:flex">
      <div className="flex h-14 items-center gap-2 border-b border-border px-5">
        <img src={`${import.meta.env.BASE_URL}ARES.png`} alt="ARES" className="h-6 w-auto" />
        <span className="rounded bg-secondary px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
          v1.0
        </span>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-4">
        {NAV.map((group) => (
          <div key={group.label} className="mb-5">
            <p className="px-2 pb-1.5 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              {group.label}
            </p>
            <ul className="space-y-0.5">
              {group.items.map((item) => (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    end={item.to === '/'}
                    className={({ isActive }) =>
                      cn(
                        'flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm text-muted-foreground transition-colors',
                        'hover:bg-accent hover:text-foreground',
                        isActive &&
                          'bg-secondary text-foreground shadow-[inset_2px_0_0_var(--color-accent)]',
                      )
                    }
                  >
                    <item.icon className="size-4 shrink-0" strokeWidth={2} />
                    <span className="truncate">{item.label}</span>
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>

      <div className="border-t border-border px-5 py-3 font-mono text-[10px] text-muted-foreground">
        Authorized operators only
      </div>
    </aside>
  )
}
