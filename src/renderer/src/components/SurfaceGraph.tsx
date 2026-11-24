import { useMemo } from 'react'
import type { Finding } from '@shared/types'

/**
 * The attack surface as one picture: the target in the middle, the pages or files it exposes, and
 * the findings on each. Built from what the session already holds, offline, and every leaf opens
 * the finding it came from.
 */
export default function SurfaceGraph({ findings, target, onPick }: { findings: Finding[]; target: string; onPick: (id: string) => void }): React.JSX.Element | null {
  const groups = useMemo(() => {
    const map = new Map<string, Finding[]>()
    for (const f of findings) {
      if (f.verdict === 'false-positive') continue
      const key = f.url ? (() => { try { return new URL(f.url).pathname || '/' } catch { return f.url! } })() : f.file ?? 'elsewhere'
      const list = map.get(key) ?? []
      if (list.length < 6) list.push(f)
      map.set(key, list)
    }
    return [...map.entries()].sort((a, b) => b[1].length - a[1].length).slice(0, 10)
  }, [findings])

  if (!groups.length) return null
  const W = 820
  const H = 560
  const cx = W / 2
  const cy = H / 2
  const ring = 175
  const host = (() => {
    try {
      return new URL(target.includes('://') ? target : `https://${target}`).host
    } catch {
      return target.split('/').filter(Boolean).pop() ?? target
    }
  })()

  return (
    <div className="graph glass" role="img" aria-label={`Attack surface for ${host}: ${groups.length} places, ${findings.length} findings`}>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height="100%">
        <circle cx={cx} cy={cy} r={44} className="graph-hub" />
        <text x={cx} y={cy + 4} textAnchor="middle" className="graph-hub-label">
          {host.length > 18 ? `${host.slice(0, 16)}…` : host}
        </text>
        {groups.map(([key, list], i) => {
          const a = (i / groups.length) * Math.PI * 2 - Math.PI / 2
          const gx = cx + Math.cos(a) * ring
          const gy = cy + Math.sin(a) * ring
          return (
            <g key={key}>
              <line x1={cx} y1={cy} x2={gx} y2={gy} className="graph-edge" />
              <circle cx={gx} cy={gy} r={20} className="graph-page" />
              <text x={gx} y={gy + 4} textAnchor="middle" className="graph-page-label">
                {key.split('/').filter(Boolean).pop()?.slice(0, 9) ?? key.slice(0, 9)}
              </text>
              {list.map((f, k) => {
                const fa = a + (k - (list.length - 1) / 2) * 0.22
                const fx = gx + Math.cos(fa) * 62
                const fy = gy + Math.sin(fa) * 62
                return (
                  <g key={f.id} className="graph-leaf" onClick={() => onPick(f.id)} tabIndex={0} role="button" onKeyDown={(e) => e.key === 'Enter' && onPick(f.id)} aria-label={`${f.severity}: ${f.title}`}>
                    <line x1={gx} y1={gy} x2={fx} y2={fy} className="graph-edge" />
                    <circle cx={fx} cy={fy} r={7} data-sev={f.severity} className="graph-finding" />
                    <title>{`${f.severity.toUpperCase()}: ${f.title}`}</title>
                  </g>
                )
              })}
            </g>
          )
        })}
      </svg>
      <div className="graph-legend">
        <span><i data-sev="critical" /> critical</span>
        <span><i data-sev="high" /> high</span>
        <span><i data-sev="medium" /> medium</span>
        <span><i data-sev="low" /> low</span>
        <span className="hint">Click a dot to open the finding. {groups.length} places shown, up to 6 findings each.</span>
      </div>
    </div>
  )
}
