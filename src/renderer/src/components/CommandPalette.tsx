import { useEffect, useRef, useState } from 'react'
import { ArrowRight, FileSearch, Globe, Search, Settings, ShieldHalf, X } from 'lucide-react'
import type { SearchHit } from '@shared/types'
import { useApp, type Page } from '../store'
import { kindName } from '../ui'

const PAGES: { page: Page; label: string; icon: React.ReactNode }[] = [
  { page: 'overview', label: 'Overview', icon: <ShieldHalf size={14} /> },
  { page: 'new', label: 'Start a test', icon: <ArrowRight size={14} /> },
  { page: 'projects', label: 'Projects', icon: <FileSearch size={14} /> },
  { page: 'review', label: 'Code review', icon: <FileSearch size={14} /> },
  { page: 'web', label: 'Web scan', icon: <Globe size={14} /> },
  { page: 'api', label: 'API security', icon: <Globe size={14} /> },
  { page: 'recon', label: 'Recon', icon: <Globe size={14} /> },
  { page: 'audit', label: 'Special audits', icon: <ShieldHalf size={14} /> },
  { page: 'impact', label: 'Controlled proofs', icon: <ShieldHalf size={14} /> },
  { page: 'mac', label: 'This Mac', icon: <ShieldHalf size={14} /> },
  { page: 'sessions', label: 'Results', icon: <FileSearch size={14} /> },
  { page: 'assets', label: 'Assets', icon: <ShieldHalf size={14} /> },
  { page: 'tools', label: 'Tools', icon: <Settings size={14} /> },
  { page: 'updates', label: 'Updates', icon: <Settings size={14} /> },
  { page: 'settings', label: 'Settings', icon: <Settings size={14} /> }
]

type Row = { kind: 'page'; page: Page; label: string } | { kind: 'session'; id: string; label: string; sub: string } | { kind: 'finding'; hit: SearchHit }

/** Cmd+K: go anywhere, open a result, or find a finding, without hunting through the rail. */
export default function CommandPalette(): React.JSX.Element | null {
  const { setPage, showSession, sessions } = useApp()
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const [hits, setHits] = useState<SearchHit[]>([])
  const [at, setAt] = useState(0)
  const input = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setOpen((v) => !v)
      }
      if (e.key === 'Escape') setOpen(false)
    }
    const onAsk = (): void => setOpen(true)
    window.addEventListener('keydown', onKey)
    window.addEventListener('macsec:palette', onAsk)
    return () => {
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('macsec:palette', onAsk)
    }
  }, [])

  useEffect(() => {
    if (!open) return
    setQ('')
    setHits([])
    setAt(0)
    setTimeout(() => input.current?.focus(), 20)
  }, [open])

  useEffect(() => {
    if (q.trim().length < 2) {
      setHits([])
      return
    }
    const t = window.setTimeout(() => void window.macsec.invoke('sessions:search', q).then(setHits).catch(() => setHits([])), 250)
    return () => window.clearTimeout(t)
  }, [q])

  const term = q.trim().toLowerCase()
  const rows: Row[] = [
    ...PAGES.filter((p) => !term || p.label.toLowerCase().includes(term)).map((p) => ({ kind: 'page' as const, page: p.page, label: p.label })),
    ...sessions
      .filter((s) => term && `${s.title} ${s.target}`.toLowerCase().includes(term))
      .slice(0, 5)
      .map((s) => ({ kind: 'session' as const, id: s.id, label: s.title, sub: `${kindName(s.kind)} · ${s.target}` })),
    ...hits.slice(0, 6).map((h) => ({ kind: 'finding' as const, hit: h }))
  ].slice(0, 16)

  const choose = (r: Row): void => {
    setOpen(false)
    if (r.kind === 'page') setPage(r.page)
    else if (r.kind === 'session') showSession(r.id)
    else showSession(r.hit.sessionId)
  }

  if (!open) return null
  return (
    <div className="palette-scrim" onClick={() => setOpen(false)}>
      <div className="palette" role="dialog" aria-modal="true" aria-label="Search MacSec" onClick={(e) => e.stopPropagation()}>
        <div className="palette-head">
          <Search size={16} />
          <input
            ref={input}
            value={q}
            onChange={(e) => {
              setQ(e.target.value)
              setAt(0)
            }}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault()
                setAt((i) => Math.min(rows.length - 1, i + 1))
              } else if (e.key === 'ArrowUp') {
                e.preventDefault()
                setAt((i) => Math.max(0, i - 1))
              } else if (e.key === 'Enter' && rows[at]) choose(rows[at])
            }}
            placeholder="Go to a page, a result or a finding…"
            aria-label="Search MacSec"
          />
          <button className="icon-btn" aria-label="Close search" onClick={() => setOpen(false)}>
            <X size={15} />
          </button>
        </div>
        <div className="palette-list" role="listbox" aria-label="Results">
          {rows.length === 0 && <div className="hint" style={{ padding: 16 }}>Nothing matches. Try a page name, a project or a finding.</div>}
          {rows.map((r, i) => (
            <button
              key={r.kind === 'page' ? `p-${r.page}` : r.kind === 'session' ? `s-${r.id}` : `f-${r.hit.findingId}-${i}`}
              className="palette-row"
              data-at={i === at}
              role="option"
              aria-selected={i === at}
              onMouseEnter={() => setAt(i)}
              onClick={() => choose(r)}
            >
              <span className="palette-ic">{r.kind === 'finding' ? <ShieldHalf size={14} /> : r.kind === 'session' ? <FileSearch size={14} /> : <ArrowRight size={14} />}</span>
              <span className="grow">
                <span className="palette-title">{r.kind === 'finding' ? r.hit.title : r.label}</span>
                <span className="palette-sub">{r.kind === 'finding' ? `${kindName(r.hit.kind)}: ${r.hit.sessionTitle}${r.hit.where ? ` · ${r.hit.where}` : ''}` : r.kind === 'session' ? r.sub : 'Go to page'}</span>
              </span>
              <span className="hint">{r.kind === 'page' ? 'page' : r.kind === 'session' ? 'result' : 'finding'}</span>
            </button>
          ))}
        </div>
        <div className="palette-foot">
          <span className="hint">↑ ↓ to move · Enter to open · Esc to close</span>
          <span className="hint">⌘K</span>
        </div>
      </div>
    </div>
  )
}
