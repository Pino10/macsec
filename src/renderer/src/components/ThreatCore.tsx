import { SEVERITIES, type Severity } from '@shared/types'

const COLORS: Record<Severity, string> = { critical: '#ff3d7f', high: '#ff8a3d', medium: '#ffc94a', low: '#38a8ff', info: '#8c95b8' }
const WEIGHT: Record<Severity, number> = { critical: 25, high: 10, medium: 4, low: 1, info: 0 }

/** 100 means nothing open; each finding costs points by severity, and criticals cost the most. */
export function postureScore(c: Record<Severity, number>): number {
  const cost = SEVERITIES.reduce((n, k) => n + c[k] * WEIGHT[k], 0)
  return Math.max(0, Math.round(100 - 100 * (1 - Math.exp(-cost / 60))))
}

export function postureWord(score: number, hasData: boolean): string {
  if (!hasData) return 'No results yet'
  return score >= 90 ? 'Strong' : score >= 70 ? 'Guarded' : score >= 45 ? 'Exposed' : 'Critical'
}

/**
 * The threat core: severity as rings of light around a glass sphere, with the posture score in
 * the middle. A sweep turns while tests are running.
 */
export default function ThreatCore({ counts, size = 300, running = false, label = true, hasData = true }: { counts: Record<Severity, number>; size?: number; running?: boolean; label?: boolean; hasData?: boolean }): React.JSX.Element {
  const score = postureScore(counts)
  const total = SEVERITIES.filter((k) => k !== 'info').reduce((n, k) => n + counts[k], 0)
  const c = size / 2
  const r = size * 0.42
  const circ = 2 * Math.PI * r
  const gap = total > 1 ? 6 : 0
  let offset = 0
  const arcs = SEVERITIES.filter((k) => k !== 'info' && counts[k] > 0).map((k) => {
    const len = Math.max(4, (counts[k] / total) * circ - gap)
    const a = { k, len, offset }
    offset += len + gap
    return a
  })
  const glow = score >= 90 ? '#38e1ff' : score >= 70 ? '#7aa2ff' : score >= 45 ? '#ffc94a' : '#ff3d7f'
  const id = `core${size}`
  return (
    <div className="core" style={{ width: size, height: size }} role="img" aria-label={`Security posture ${hasData ? score : 'unknown'} out of 100`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <defs>
          <radialGradient id={`${id}-sphere`} cx="38%" cy="30%" r="75%">
            <stop offset="0" stopColor="#ffffff" stopOpacity="0.22" />
            <stop offset="0.35" stopColor={glow} stopOpacity="0.16" />
            <stop offset="1" stopColor="#05060d" stopOpacity="0.2" />
          </radialGradient>
          <radialGradient id={`${id}-halo`} cx="50%" cy="50%" r="50%">
            <stop offset="0.55" stopColor={glow} stopOpacity="0.22" />
            <stop offset="1" stopColor={glow} stopOpacity="0" />
          </radialGradient>
          <linearGradient id={`${id}-sweep`} x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stopColor="#8b6cff" stopOpacity="0" />
            <stop offset="1" stopColor="#38e1ff" stopOpacity="0.28" />
          </linearGradient>
          <filter id={`${id}-blur`}>
            <feGaussianBlur stdDeviation={size * 0.012} />
          </filter>
        </defs>
        <circle cx={c} cy={c} r={size * 0.5} fill={`url(#${id}-halo)`} />
        {/* Tick ring */}
        {Array.from({ length: 60 }, (_, i) => {
          const a = (i / 60) * Math.PI * 2
          const r1 = size * 0.475
          const r2 = r1 - (i % 5 === 0 ? size * 0.022 : size * 0.01)
          return <line key={i} x1={c + Math.cos(a) * r1} y1={c + Math.sin(a) * r1} x2={c + Math.cos(a) * r2} y2={c + Math.sin(a) * r2} stroke="#a8b6ff" strokeOpacity={i % 5 === 0 ? 0.35 : 0.14} strokeWidth="1" />
        })}
        {/* Track and severity arcs */}
        <circle cx={c} cy={c} r={r} fill="none" stroke="#a8b6ff" strokeOpacity="0.1" strokeWidth={size * 0.035} />
        <g transform={`rotate(-90 ${c} ${c})`}>
          {arcs.map((a) => (
            <g key={a.k}>
              <circle cx={c} cy={c} r={r} fill="none" stroke={COLORS[a.k]} strokeWidth={size * 0.035} strokeDasharray={`${a.len} ${circ}`} strokeDashoffset={-a.offset} strokeLinecap="round" filter={`url(#${id}-blur)`} opacity="0.7" />
              <circle cx={c} cy={c} r={r} fill="none" stroke={COLORS[a.k]} strokeWidth={size * 0.028} strokeDasharray={`${a.len} ${circ}`} strokeDashoffset={-a.offset} strokeLinecap="round" />
            </g>
          ))}
          {total === 0 && hasData && <circle cx={c} cy={c} r={r} fill="none" stroke="#3ef0a8" strokeWidth={size * 0.028} strokeOpacity="0.8" />}
        </g>
        {/* Glass sphere */}
        <circle cx={c} cy={c} r={size * 0.33} fill={`url(#${id}-sphere)`} stroke="#ffffff" strokeOpacity="0.12" />
        <ellipse cx={c - size * 0.08} cy={c - size * 0.2} rx={size * 0.1} ry={size * 0.035} fill="#fff" opacity="0.06" />
        {running && (
          <g className="sweep">
            <path d={`M ${c} ${c} L ${c + size * 0.33} ${c} A ${size * 0.33} ${size * 0.33} 0 0 0 ${c + size * 0.33 * Math.cos(-0.5)} ${c + size * 0.33 * Math.sin(-0.5)} Z`} fill={`url(#${id}-sweep)`} />
            <line x1={c} y1={c} x2={c + size * 0.33} y2={c} stroke="#38e1ff" strokeOpacity="0.5" strokeWidth="1" />
          </g>
        )}
      </svg>
      {label && (
        <div className="core-label">
          <b style={{ textShadow: `0 0 30px ${glow}` }}>{hasData ? score : '·'}</b>
          <span>{postureWord(score, hasData)}</span>
        </div>
      )}
    </div>
  )
}
