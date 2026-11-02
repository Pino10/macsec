import { CheckCircle2, CircleDashed, FileSearch, Globe, Loader2, MinusCircle, Plug, ShieldHalf, XCircle, Smartphone } from 'lucide-react'
import { SEVERITIES, type SessionInfo, type Severity, type SessionStep } from '@shared/types'

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

/** Severity as one proportional bar, with the counts underneath. */
export function Spectrum({ counts, legend = true }: { counts: Record<Severity, number>; legend?: boolean }): React.JSX.Element {
  const total = SEVERITIES.reduce((n, k) => n + counts[k], 0)
  return (
    <div>
      <div className="spectrum" aria-hidden>
        {SEVERITIES.filter((k) => counts[k] > 0).map((k) => (
          <span key={k} data-sev={k} style={{ width: `${(counts[k] / total) * 100}%` }} />
        ))}
      </div>
      {legend && (
        <div className="spectrum-legend">
          {SEVERITIES.map((k) => (
            <div key={k} data-sev={k} data-zero={counts[k] === 0}>
              <b>{counts[k]}</b>
              <span>{k}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export function KindIcon({ kind, size = 18 }: { kind: SessionInfo['kind']; size?: number }): React.JSX.Element {
  const g = kind === 'web-scan' ? '#8b6cff' : kind === 'api-scan' ? '#ff3d7f' : kind === 'audit' ? '#3ef0a8' : kind === 'mobile-scan' ? '#ffc94a' : '#38e1ff'
  return (
    <span className="glyph" style={{ ['--g' as string]: g, width: size + 20, height: size + 20, borderRadius: 11 }}>
      {kind === 'web-scan' ? <Globe size={size} /> : kind === 'api-scan' ? <Plug size={size} /> : kind === 'mobile-scan' ? <Smartphone size={size} /> : kind === 'audit' ? <ShieldHalf size={size} /> : <FileSearch size={size} />}
    </span>
  )
}

export const kindName = (k: SessionInfo['kind']): string => (k === 'web-scan' ? 'Web scan' : k === 'api-scan' ? 'API security' : k === 'mobile-scan' ? 'Mobile app check' : k === 'audit' ? 'Special audit' : 'Code review')

export function StepIcon({ status }: { status: SessionStep['status'] }): React.JSX.Element {
  if (status === 'running') return <Loader2 size={16} className="spin" style={{ color: 'var(--pulse)' }} />
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

/** One step of a setup flow: a number, a title, a line of help, and its controls. */
export function FlowStep({ n, title, help, state, children }: { n: number; title: string; help?: string; state: 'done' | 'current' | 'todo'; children: React.ReactNode }): React.JSX.Element {
  return (
    <section className="flow-step glass" data-state={state}>
      <span className="flow-num" aria-hidden>
        {state === 'done' ? '✓' : n}
      </span>
      <div className="flow-body">
        <h2 className="flow-title">{title}</h2>
        {help && <p className="flow-help">{help}</p>}
        {children}
      </div>
    </section>
  )
}

/** The lines behind a finding, numbered, with the line that matters lit up. */
export function CodeView({ context, sev }: { context: { start: number; lines: string[]; at: number }; sev?: Severity }): React.JSX.Element {
  return (
    <div className="codeview" style={sev ? { ['--c' as string]: `var(--sev-${sev})` } : undefined}>
      {context.lines.map((l, i) => (
        <div key={i} data-hit={context.start + i === context.at}>
          <i>{context.start + i}</i>
          <span>{l || ' '}</span>
        </div>
      ))}
    </div>
  )
}
