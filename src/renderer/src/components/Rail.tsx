import Logo from './Logo'
import { FileSearch, FolderGit2, Globe, History, LayoutDashboard, Plug, ScrollText, Settings, ShieldHalf, Wrench, Smartphone } from 'lucide-react'
import { useApp, type Page } from '../store'

type Item = { id: Page; label: string; icon: React.ReactNode }
const I = 16
export const GROUPS: { label: string | null; items: Item[] }[] = [
  { label: null, items: [{ id: 'overview', label: 'Overview', icon: <LayoutDashboard size={I} /> }, { id: 'projects', label: 'Projects', icon: <FolderGit2 size={I} /> }] },
  {
    label: 'Run a test',
    items: [
      { id: 'review', label: 'Code review', icon: <FileSearch size={I} /> },
      { id: 'web', label: 'Web scan', icon: <Globe size={I} /> },
      { id: 'api', label: 'API security', icon: <Plug size={I} /> },
      { id: 'mobile', label: 'Mobile apps', icon: <Smartphone size={I} /> },
      { id: 'audit', label: 'Special audits', icon: <ShieldHalf size={I} /> }
    ]
  },
  { label: 'Results', items: [{ id: 'sessions', label: 'Sessions', icon: <History size={I} /> }, { id: 'logs', label: 'Logs', icon: <ScrollText size={I} /> }] }
]
const FOOT: Item[] = [
  { id: 'tools', label: 'Tools', icon: <Wrench size={I} /> },
  { id: 'settings', label: 'Settings', icon: <Settings size={I} /> }
]
export const PAGE_ORDER: Page[] = [...GROUPS.flatMap((g) => g.items), ...FOOT].map((i) => i.id)

export default function Rail(): React.JSX.Element {
  const { page, setPage, sessions, updates } = useApp()
  const running = sessions.filter((s) => s.status === 'running').length

  const item = (it: Item): React.JSX.Element => (
    <button key={it.id} className="rail-item" aria-current={page === it.id ? 'page' : undefined} onClick={() => setPage(it.id)}>
      <span className="ri">{it.icon}</span>
      {it.label}
      {it.id === 'sessions' && (running ? <span className="live" aria-label={`${running} running`} /> : sessions.length ? <span className="count">{sessions.length}</span> : null)}
      {it.id === 'tools' && updates.length > 0 && <span className="tag tag-ion" style={{ marginLeft: 'auto' }}>{updates.length} new</span>}
    </button>
  )
  return (
    <aside className="rail glass">
      <div className="brand drag">
        <Logo size={40} running={running > 0} />
        <div>
          <strong>MacSec</strong>
          <small>{running ? `${running} ${running === 1 ? 'test' : 'tests'} running` : 'Security engine'}</small>
        </div>
      </div>
      <nav aria-label="Main">
        {GROUPS.map((g, i) => (
          <div key={i} className="rail-group">
            {g.label && <span>{g.label}</span>}
            {g.items.map(item)}
          </div>
        ))}
      </nav>
      <div className="rail-foot">{FOOT.map(item)}</div>
    </aside>
  )
}
