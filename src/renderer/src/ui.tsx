import { CheckCircle2, CircleDashed, Loader2, MinusCircle, XCircle } from 'lucide-react'
import { SEVERITIES, type Severity, type SessionStep } from '@shared/types'

export function PageHead({ title, desc, children }: { title: string; desc?: string; children?: React.ReactNode }): React.JSX.Element {
  return (
    <div className="page-head">
      <div>
        <h1 className="page-title">{title}</h1>
        {desc && <p className="page-desc">{desc}</p>}
      </div>
      {children && <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>{children}</div>}
    </div>
  )
}

export function Switch({ on, onChange, disabled, label }: { on: boolean; onChange: () => void; disabled?: boolean; label: string }): React.JSX.Element {
  return <button type="button" role="switch" aria-checked={on} aria-label={label} className="switch no-drag" disabled={disabled} onClick={onChange} />
}

export function Seg<T extends string>({ value, options, onChange, label }: { value: T; options: [T, React.ReactNode][]; onChange: (v: T) => void; label: string }): React.JSX.Element {
  return (
    <div className="seg" role="radiogroup" aria-label={label}>
      {options.map(([v, l]) => (
        <button key={v} role="radio" aria-checked={value === v} onClick={() => onChange(v)}>
          {l}
        </button>
      ))}
    </div>
  )
}

export function Sev({ s }: { s: Severity }): React.JSX.Element {
  return (
    <span className="sev" data-sev={s}>
      {s}
    </span>
  )
}

export function Counts({ counts, empty = 'Nothing found' }: { counts: Record<Severity, number>; empty?: string }): React.JSX.Element {
  const shown = SEVERITIES.filter((k) => counts[k] > 0 && k !== 'info')
  if (shown.length === 0)
    return (
      <span className="sev" data-sev="ok">
        {empty}
      </span>
    )
  return (
    <span className="sev-counts">
      {shown.map((k) => (
        <span key={k} className="sev" data-sev={k}>
          {counts[k]} {k}
        </span>
      ))}
    </span>
  )
}

export function SevTiles({ counts }: { counts: Record<Severity, number> }): React.JSX.Element {
  return (
    <div className="sev-tiles">
      {SEVERITIES.map((k) => (
        <div key={k} className="sev-tile glass" data-sev={k} data-zero={counts[k] === 0}>
          <b>{counts[k]}</b>
          <span>{k}</span>
        </div>
      ))}
    </div>
  )
}

export function StepIcon({ status }: { status: SessionStep['status'] }): React.JSX.Element {
  if (status === 'running') return <Loader2 size={16} className="spin" style={{ color: 'var(--accent-text)' }} />
  if (status === 'done') return <CheckCircle2 size={16} style={{ color: 'var(--ok)' }} />
  if (status === 'failed') return <XCircle size={16} style={{ color: 'var(--bad)' }} />
  if (status === 'skipped') return <MinusCircle size={16} style={{ color: 'var(--ink-3)' }} />
  return <CircleDashed size={16} style={{ color: 'var(--ink-3)' }} />
}

export function Empty({ title, children }: { title: string; children?: React.ReactNode }): React.JSX.Element {
  return (
    <div className="empty-state">
      <strong>{title}</strong>
      {children && <span>{children}</span>}
    </div>
  )
}

export function ago(iso: string): string {
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.round(s / 60)} min ago`
  if (s < 86400) return `${Math.round(s / 3600)} h ago`
  const d = Math.round(s / 86400)
  return d < 30 ? `${d} ${d === 1 ? 'day' : 'days'} ago` : new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })
}

export const duration = (ms?: number): string => (!ms ? '' : ms < 60000 ? `${Math.round(ms / 1000)} s` : `${Math.floor(ms / 60000)} min ${Math.round((ms % 60000) / 1000)} s`)
