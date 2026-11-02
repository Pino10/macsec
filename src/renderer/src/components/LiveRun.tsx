import { useEffect, useRef, useState } from 'react'
import type { LogLine, SessionInfo } from '../../../shared/types'

function clock(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000))
  const m = Math.floor(s / 60)
  return m >= 60 ? `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, '0')}m` : `${m}:${String(s % 60).padStart(2, '0')}`
}

/** Ticks once a second while something is running. */
export function useNow(on: boolean): number {
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    if (!on) return
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [on])
  return now
}

/** Overall share of the work done, counting the running step's own progress. */
export function overall(s: SessionInfo): number {
  if (!s.steps.length) return 0
  const done = s.steps.filter((x) => x.status !== 'waiting' && x.status !== 'running').length
  const cur = s.steps.find((x) => x.status === 'running')
  return Math.min(100, Math.round(((done + (cur?.progress ?? 0) / 100) / s.steps.length) * 100))
}

/** What is happening right now: the step, its clock and progress, and the tools' own output as it arrives. */
export function LiveRun({ s }: { s: SessionInfo }): JSX.Element {
  const api = window.macsec
  const now = useNow(true)
  const [lines, setLines] = useState<LogLine[]>([])
  const [open, setOpen] = useState(true)
  const box = useRef<HTMLDivElement>(null)
  useEffect(() => {
    return api.on('logs:line', (l) => {
      if (l.session === s.id) setLines((x) => [...x.slice(-299), l])
    })
  }, [api, s.id])
  useEffect(() => {
    const el = box.current
    if (el && el.scrollHeight - el.scrollTop - el.clientHeight < 80) el.scrollTop = el.scrollHeight
  }, [lines])
  const cur = s.steps.find((x) => x.status === 'running')
  const pct = overall(s)
  const started = new Date(s.createdAt).getTime()
  const idx = cur ? s.steps.indexOf(cur) + 1 : s.steps.filter((x) => x.status !== 'waiting').length

  return (
    <div className="liverun glass" aria-live="polite">
      <div className="live-top">
        <span className="live-dot" />
        <b>Running</b>
        <span className="hint">
          Step {idx} of {s.steps.length}, {clock(now - started)} so far
        </span>
        <span className="live-pct">{pct}%</span>
      </div>
      <div className="bar">
        <i style={{ width: `${pct}%` }} />
      </div>
      {cur && (
        <div className="live-step">
          <div className="live-row">
            <span className="live-name">{cur.label}</span>
            <span className="mono hint">{cur.startedAt ? clock(now - new Date(cur.startedAt).getTime()) : ''}</span>
          </div>
          {typeof cur.progress === 'number' ? (
            <div className="bar thin">
              <i style={{ width: `${cur.progress}%` }} />
            </div>
          ) : (
            <div className="bar thin busy">
              <i />
            </div>
          )}
          <div className="live-line mono" title={cur.lastLine ?? cur.detail}>
            {cur.lastLine ?? cur.detail ?? 'Working…'}
          </div>
        </div>
      )}
      <button className="link" style={{ marginTop: 8 }} onClick={() => setOpen((o) => !o)}>
        {open ? 'Hide live output' : 'Show live output'}
      </button>
      {open && (
        <div className="console mono" ref={box}>
          {lines.length === 0 ? <span className="hint">Tool output appears here as it happens.</span> : lines.map((l, i) => <div key={i} data-level={l.level}>{l.text}</div>)}
        </div>
      )}
    </div>
  )
}

export { clock }
