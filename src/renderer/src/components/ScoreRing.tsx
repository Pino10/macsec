/** A plain score ring: the number in the middle, the arc coloured by how safe it is. */
export default function ScoreRing({ score, size = 76, empty = false }: { score: number; size?: number; empty?: boolean }): React.JSX.Element {
  const stroke = 7
  const r = (size - stroke) / 2
  const c = 2 * Math.PI * r
  const pct = empty ? 0 : Math.max(0, Math.min(100, score)) / 100
  const color = score >= 90 ? 'var(--ok)' : score >= 70 ? 'var(--sev-medium)' : score >= 45 ? 'var(--sev-high)' : 'var(--sev-critical)'
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={empty ? 'No score yet' : `Score ${score} out of 100`}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--surface-3)" strokeWidth={stroke} />
      {!empty && <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke} strokeLinecap="round" strokeDasharray={`${c * pct} ${c}`} transform={`rotate(-90 ${size / 2} ${size / 2})`} />}
      <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central" fill="var(--ink)" style={{ font: `600 ${size * 0.3}px var(--display)`, fontVariantNumeric: 'tabular-nums' }}>
        {empty ? '–' : score}
      </text>
    </svg>
  )
}
