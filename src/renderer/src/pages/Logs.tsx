import { useEffect, useRef, useState } from 'react'
import { Trash2 } from 'lucide-react'
import type { LogLine } from '@shared/types'
import { useApp } from '../store'
import { PageHead, Seg } from '../ui'

export default function Logs(): React.JSX.Element {
  const { showSession } = useApp()
  const api = window.macsec
  const [lines, setLines] = useState<LogLine[]>([])
  const [level, setLevel] = useState<'all' | 'problems'>('all')
  const end = useRef<HTMLDivElement>(null)

  useEffect(() => {
    void api.invoke('logs:list').then(setLines)
    return api.on('logs:line', (l) => setLines((x) => [...x.slice(-1999), l]))
  }, [api])
  useEffect(() => {
    end.current?.scrollIntoView({ block: 'end' })
  }, [lines.length])

  const shown = lines.filter((l) => level === 'all' || l.level !== 'info')
  return (
    <>
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
      <div className="panel terminal">
        {shown.length === 0 && <span className="hint">Nothing yet.</span>}
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
