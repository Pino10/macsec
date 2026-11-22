import { Check, Copy, HelpCircle } from 'lucide-react'
import { useState } from 'react'
import type { Finding } from '../../../shared/types'

/** "Confirmed" or "Possible", with what proves it. Nothing here is a guess: if there is no proof, it says so. */
export function ConfidenceTag({ f }: { f: Finding }): React.JSX.Element | null {
  if (!f.confidence) return null
  return f.confidence === 'confirmed' ? (
    <span className="tag tag-ok" title="The problem itself was seen. The proof is below.">
      <Check size={11} /> Confirmed
    </span>
  ) : (
    <span className="tag tag-warn" title="The evidence points at it but does not prove it.">
      <HelpCircle size={11} /> Possible
    </span>
  )
}

/** How far it is proven: Proven, Known exploited, Likely or Not proven, with the reason on hover. */
export function ExploitTag({ f, compact }: { f: Finding; compact?: boolean }): React.JSX.Element | null {
  const e = f.exploit
  if (!e) return null
  const cls = e.state === 'proven' ? 'tag tag-ok' : e.state === 'known-exploited' ? 'tag tag-bad' : 'tag tag-warn'
  return (
    <span className={cls} title={`${e.why} Risk ${e.risk} of 100.`} style={compact ? { flex: 'none' } : undefined}>
      {e.state === 'proven' ? <Check size={11} /> : <HelpCircle size={11} />} {e.label}
    </span>
  )
}

export default function ProofBlock({ f }: { f: Finding }): React.JSX.Element | null {
  const [copied, setCopied] = useState(false)
  const p = f.proof
  if (!p) return null
  const copy = (): void => {
    void navigator.clipboard.writeText(p.reproduce).then(() => {
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1800)
    })
  }
  return (
    <div className="proof">
      <h5>{f.confidence === 'possible' ? 'The evidence (not proof)' : 'The proof'}</h5>
      <ul className="proof-shows">
        {p.shows.map((s) => (
          <li key={s}>{s}</li>
        ))}
      </ul>
      <dl className="proof-meta">
        <dt>Request</dt>
        <dd>{p.request}</dd>
        <dt>Answer</dt>
        <dd>
          HTTP {p.status}
          {p.contentType ? `, ${p.contentType}` : ''}, {p.bytes.toLocaleString()} bytes read
        </dd>
        <dt>Fingerprint</dt>
        <dd className="mono" title="SHA-256 of the answer that was read. Compare it later to see if it changed.">
          {p.sha256.slice(0, 16)}…
        </dd>
        <dt>Seen</dt>
        <dd>{new Date(p.at).toLocaleString()}</dd>
      </dl>
      <button className="btn btn-sm" onClick={copy} aria-label="Copy the command that repeats this request">
        {copied ? <Check size={13} /> : <Copy size={13} />} {copied ? 'Copied' : 'Copy the command to repeat it'}
      </button>
    </div>
  )
}
