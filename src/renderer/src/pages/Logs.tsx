import { useEffect, useRef, useState } from 'react'
import { Copy, Search, Trash2 } from 'lucide-react'
import type { LogLine } from '@shared/types'
import { useApp } from '../store'
import { PageHead, Seg } from '../ui'

export default function Logs(): React.JSX.Element {
  const { showSession, setPage } = useApp()
  const api = window.macsec
  const [lines, setLines] = useState<LogLine[]>([])
  const [level, setLevel] = useState<'all' | 'problems'>('all')
  const [q, setQ] = useState('')
  const end = useRef<HTMLDivElement>(null)

  useEffect(() => {
    void api.invoke('logs:list').then(setLines)
    return api.on('logs:line', (l) => setLines((x) => [...x.slice(-1999), l]))
  }, [api])
  useEffect(() => {
    end.current?.scrollIntoView({ block: 'end' })
  }, [lines.length])

  const needle = q.trim().toLowerCase()
  const shown = lines.filter((l) => (level === 'all' || l.level !== 'info') && (!needle || l.text.toLowerCase().includes(needle)))
  return (
    <>
      <button className="link" onClick={() => setPage('settings')} style={{ marginBottom: 10 }}>
        ← Settings
      </button>
      <PageHead title="Logs" desc="What MacSec and its scanners did. Tokens are hidden before anything is written.">
        <Seg<'all' | 'problems'> label="Show" value={level} onChange={setLevel} options={[['all', 'Everything'], ['problems', 'Problems']]} />
        <button
          className="btn"
          onClick={async () => {
            await api.invoke('logs:clear')
            setLines([])
          }}
        >
          <Trash2 size={14} /> Clear
        </button>
      </PageHead>
      <div className="log-bar">
        <label className="tool-search">
          <Search size={14} aria-hidden />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search the log" aria-label="Search the log" />
        </label>
        <button
          className="btn btn-sm"
          disabled={!shown.length}
          title="Copy the lines shown (tokens are already hidden)"
          onClick={() => void navigator.clipboard.writeText(shown.map((l) => `${new Date(l.at).toISOString()} ${l.level} ${l.text}`).join('\n'))}
        >
          <Copy size={13} /> Copy
        </button>
        <span className="log-count">
          {shown.length} of {lines.length} lines
        </span>
      </div>
      <div className="panel terminal">
        {shown.length === 0 && <span className="hint">{lines.length ? 'No lines match.' : 'Nothing yet.'}</span>}
        {shown.map((l, i) => (
          <div key={i} className={`l-${l.level}`}>
            <time>{new Date(l.at).toLocaleTimeString('en-GB')}</time>
            {l.session && (
              <button className="link" onClick={() => showSession(l.session!)} style={{ marginRight: 8 }}>
                [{l.session.split('-').slice(2, -1).join('-') || 'session'}]
              </button>
            )}
            {l.text}
          </div>
        ))}
        <div ref={end} />
      </div>
    </>
  )
}
