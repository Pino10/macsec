import { useEffect, useState } from 'react'
import { ChevronDown, FileSearch, FolderGit2, LayoutDashboard, PanelLeftClose, PanelLeftOpen, ScrollText, Settings as SettingsIcon, ShieldCheck, Wrench, History } from 'lucide-react'
import { useApp, type Page } from '../store'
import icon from '../assets/icon-128.png'

type Item = { id: Page; label: string; icon: React.ReactNode }
type Group = { id: string; label: string | null; items: Item[] }

const I = 17
export const GROUPS: Group[] = [
  { id: 'home', label: null, items: [{ id: 'overview', label: 'Overview', icon: <LayoutDashboard size={I} /> }, { id: 'projects', label: 'Projects', icon: <FolderGit2 size={I} /> }] },
  { id: 'test', label: 'Test', items: [{ id: 'review', label: 'Code review', icon: <FileSearch size={I} /> }] },
  { id: 'results', label: 'Results', items: [{ id: 'sessions', label: 'Sessions', icon: <History size={I} /> }, { id: 'logs', label: 'Logs', icon: <ScrollText size={I} /> }] },
  { id: 'setup', label: 'Setup', items: [{ id: 'tools', label: 'Tools', icon: <Wrench size={I} /> }] }
]
const FOOT: Item[] = [{ id: 'settings', label: 'Settings', icon: <SettingsIcon size={16} /> }]
export const PAGE_ORDER: Page[] = [...GROUPS.flatMap((g) => g.items), ...FOOT].map((i) => i.id)

function stored<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key)
    return v === null ? fallback : (JSON.parse(v) as T)
  } catch {
    return fallback
  }
}

export default function Sidebar(): React.JSX.Element {
  const { page, setPage, sessions, tools } = useApp()
  const [slim, setSlim] = useState<boolean>(() => stored('sidebar-slim', false))
  const [folded, setFolded] = useState<string[]>(() => stored('sidebar-folded', []))
  const running = sessions.filter((s) => s.status === 'running').length
  const ready = tools.filter((t) => t.installed && t.method !== 'app').length
  const total = tools.filter((t) => t.method !== 'app').length

  useEffect(() => {
    try {
      localStorage.setItem('sidebar-slim', JSON.stringify(slim))
      localStorage.setItem('sidebar-folded', JSON.stringify(folded))
    } catch {
      // Not remembered.
    }
  }, [slim, folded])
  useEffect(() => {
    const key = (e: KeyboardEvent): void => {
      if ((e.metaKey || e.ctrlKey) && e.key === '\\') {
        e.preventDefault()
        setSlim((s) => !s)
      }
    }
    window.addEventListener('keydown', key)
    return () => window.removeEventListener('keydown', key)
  }, [])

  const badge = (id: Page): React.ReactNode =>
    id === 'sessions' && sessions.length ? (
      <span className="nav-count">
        {running > 0 && <span className="nav-live" />}
        {sessions.length}
      </span>
    ) : null

  return (
    <aside className="sidebar glass" data-slim={slim}>
      <div className="sidebar-top drag" />
      <div className="brand">
        <img className="brand-icon" src={icon} alt="" draggable={false} />
        <span className="nav-label">MacSec</span>
        <button className="icon-btn slim-toggle" data-tip={slim ? 'Expand (⌘\\)' : 'Make slim (⌘\\)'} aria-label={slim ? 'Expand the sidebar' : 'Make the sidebar slim'} onClick={() => setSlim(!slim)}>
          {slim ? <PanelLeftOpen /> : <PanelLeftClose />}
        </button>
      </div>
      <nav className="nav nav-scroll" aria-label="Main">
        {GROUPS.map((g) => {
          const isFolded = folded.includes(g.id) && !slim && !g.items.some((i) => i.id === page)
          return (
            <div key={g.id} className="nav-group" data-folded={isFolded}>
              {g.label &&
                (slim ? (
                  <div className="nav-sep" />
                ) : (
                  <button className="nav-head" aria-expanded={!isFolded} onClick={() => setFolded((f) => (f.includes(g.id) ? f.filter((x) => x !== g.id) : [...f, g.id]))}>
                    {g.label}
                    <ChevronDown size={13} />
                  </button>
                ))}
              <div className="nav-items">
                {g.items.map((it) => (
                  <button key={it.id} className="nav-item" data-tip={slim ? it.label : undefined} aria-label={slim ? it.label : undefined} aria-current={page === it.id ? 'page' : undefined} onClick={() => setPage(it.id)}>
                    <span className="nav-icon">{it.icon}</span>
                    <span className="nav-label">{it.label}</span>
                    {badge(it.id)}
                  </button>
                ))}
              </div>
            </div>
          )
        })}
      </nav>
      <div className="sidebar-bottom">
        <button className="sidebar-foot" onClick={() => setPage(running ? 'sessions' : 'tools')} aria-label="Status">
          <span className="lamp" data-s={running ? 'running' : ready === total && total > 0 ? 'running' : 'stopped'} />
          <div className="nav-label">
            <strong>{running ? `${running} ${running === 1 ? 'test' : 'tests'} running` : 'Ready'}</strong>
            {ready} of {total} scanners installed
          </div>
        </button>
        <div className="foot-row">
          {FOOT.map((it) => (
            <button key={it.id} className="foot-btn" data-tip={it.label} aria-label={it.label} aria-current={page === it.id ? 'page' : undefined} onClick={() => setPage(it.id)}>
              {it.icon}
            </button>
          ))}
          <button className="foot-btn" data-tip="Open the MacSec folder" aria-label="Open the MacSec folder" onClick={() => void window.macsec.invoke('app:open-folder', 'root')}>
            <ShieldCheck size={16} />
          </button>
        </div>
      </div>
    </aside>
  )
}
