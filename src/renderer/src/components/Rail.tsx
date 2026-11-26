import Logo from './Logo'
import { ChevronDown, Network, Bug, ArrowDownToLine, Laptop, FileSearch, FolderGit2, Globe, History, LayoutDashboard, Plug, ScrollText, Settings, ShieldHalf, Cloud, Wrench, Smartphone, Radar, Boxes, Crosshair, Command } from 'lucide-react'
import { useState } from 'react'
import { useApp, type Page } from '../store'

type Item = { id: Page; label: string; icon: React.ReactNode }
const I = 16
const it = (id: Page, label: string, icon: React.ReactNode): Item => ({ id, label, icon })
export const GROUPS: { label: string | null; items: Item[]; fold?: boolean }[] = [
  { label: null, items: [it('overview', 'Overview', <LayoutDashboard size={I} />), it('projects', 'Projects', <FolderGit2 size={I} />)] },
  {
    label: 'Tests',
    items: [it('review', 'Code review', <FileSearch size={I} />), it('web', 'Web scan', <Globe size={I} />), it('api', 'API security', <Plug size={I} />), it('mobile', 'Mobile apps', <Smartphone size={I} />), it('recon', 'Recon', <Radar size={I} />), it('audit', 'Cloud and servers', <Cloud size={I} />)]
  },
  {
    label: 'Advanced',
    fold: true,
    items: [it('impact', 'Controlled proofs', <Crosshair size={I} />), it('ad', 'AD review', <Network size={I} />), it('mobsf', 'MobSF', <Bug size={I} />), it('mac', 'This Mac', <Laptop size={I} />)]
  },
  { label: 'Results', items: [it('sessions', 'Results', <History size={I} />), it('assets', 'Assets', <Boxes size={I} />)] }
]
const FOOT: Item[] = [it('plugins', 'Plugins', <Wrench size={I} />), it('tools', 'Tools', <Wrench size={I} />), it('updates', 'Updates', <ArrowDownToLine size={I} />), it('settings', 'Settings', <Settings size={I} />)]
/** The order of the ⌘1 to ⌘9 shortcuts. Kept as it was, so nobody's habit changes. */
export const PAGE_ORDER: Page[] = ['new', 'overview', 'projects', 'review', 'web', 'api', 'recon', 'mobile', 'mobsf', 'ad', 'audit', 'impact', 'mac', 'sessions', 'assets', 'plugins', 'tools', 'updates', 'settings']

export default function Rail(): React.JSX.Element {
  const { page, setPage, sessions, updates, appUpdate } = useApp()
  const running = sessions.filter((s) => s.status === 'running').length
  const [open, setOpen] = useState<Record<string, boolean>>({})

  const item = (x: Item): React.JSX.Element => (
    <button key={x.id} className="rail-item" aria-current={page === x.id ? 'page' : undefined} onClick={() => setPage(x.id)}>
      <span className="ri">{x.icon}</span>
      {x.label}
      {x.id === 'sessions' && (running ? <span className="live" aria-label={`${running} running`} /> : sessions.length ? <span className="count">{sessions.length}</span> : null)}
      {x.id === 'updates' && (appUpdate || updates.length > 0) && <span className="tag tag-ion" style={{ marginLeft: 'auto' }}>{appUpdate ? appUpdate.version : `${updates.length} new`}</span>}
    </button>
  )
  return (
    <aside className="rail glass">
      <div className="brand drag">
        <Logo size={32} running={running > 0} />
        <div>
          <strong>MacSec</strong>
          <small>{running ? `${running} ${running === 1 ? 'test' : 'tests'} running` : 'Security workbench'}</small>
        </div>
      </div>
      <nav aria-label="Main">
        {GROUPS.map((g, i) => {
          // An advanced group stays folded until it is opened, or while a page inside it is showing.
          const inside = g.items.some((x) => x.id === page)
          const shown = !g.fold || inside || open[g.label ?? ''] === true
          return (
            <div key={i} className="rail-group">
              {g.label &&
                (g.fold ? (
                  <button className="rail-fold" aria-expanded={shown} onClick={() => setOpen((o) => ({ ...o, [g.label!]: !shown }))}>
                    {g.label}
                    <ChevronDown size={12} />
                  </button>
                ) : (
                  <span>{g.label}</span>
                ))}
              {shown && g.items.map(item)}
            </div>
          )
        })}
      </nav>
      <div className="rail-foot">{FOOT.map(item)}</div>
    </aside>
  )
}
