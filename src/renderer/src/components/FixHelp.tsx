import { useState } from 'react'
import { Check, Copy, ExternalLink, KeyRound } from 'lucide-react'
import type { Finding } from '@shared/types'
import { fixDiff, unifiedDiff } from '@shared/fixdiff'
import { afterRevoking, leakGuide } from '@shared/leaked'

function CopyButton({ text, label }: { text: string; label: string }): React.JSX.Element {
  const [done, setDone] = useState(false)
  return (
    <button
      className="btn btn-sm"
      onClick={() => {
        void navigator.clipboard.writeText(text).then(() => {
          setDone(true)
          setTimeout(() => setDone(false), 1600)
        })
      }}
    >
      {done ? <Check size={13} /> : <Copy size={13} />} {done ? 'Copied' : label}
    </button>
  )
}

/** The AI's fix as a diff against the code around the finding. You copy it and apply it. */
export function FixDiff({ f }: { f: Finding }): React.JSX.Element | null {
  if (!f.fixCode) return null
  const lines = f.context ? fixDiff(f.context, f.fixCode) : []
  const changed = lines.some((l) => l.kind !== 'same')
  if (!lines.length || !changed) return <pre style={{ marginTop: 10 }}>{f.fixCode}</pre>
  return (
    <div className="fixdiff">
      <div className="fixdiff-code" role="table" aria-label="Suggested change">
        {lines.map((l, i) => (
          <div key={i} className={`fd-line fd-${l.kind}`} role="row">
            <span className="fd-n">{l.kind === 'add' ? '' : l.n}</span>
            <span className="fd-sign">{l.kind === 'add' ? '+' : l.kind === 'del' ? '−' : ''}</span>
            <code>{l.text || ' '}</code>
          </div>
        ))}
      </div>
      <div className="fixdiff-foot">
        <span className="hint">A suggestion: read it, then apply it yourself. MacSec never changes your code.</span>
        <CopyButton text={f.fixCode} label="Copy the fix" />
        {f.file && <CopyButton text={unifiedDiff(f.file, lines)} label="Copy as a patch" />}
      </div>
    </div>
  )
}

/** "I leaked a key": the steps for this kind of key, in order. */
export function LeakHelp({ f }: { f: Finding }): React.JSX.Element | null {
  const [open, setOpen] = useState(f.severity === 'critical')
  if (f.category !== 'secret') return null
  const g = leakGuide(f)
  const inHistory = /history|commit/i.test(f.description ?? '')
  return (
    <div className="leak">
      <button className="leak-head" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span className="leak-icon">
          <KeyRound size={15} />
        </span>
        <span>
          <strong>I leaked a key: what now?</strong>
          <span className="hint"> Steps for {g.name}, in order.</span>
        </span>
      </button>
      {open && (
        <ol className="leak-steps">
          <li>
            <b>Revoke it first.</b> Removing it from the code does not stop someone who already copied it.
            {g.revokeUrl && ' '}
            {g.revokeUrl && (
              <button className="link" onClick={() => void window.macsec.invoke('app:open-external', g.revokeUrl)}>
                Open {g.name} <ExternalLink size={11} />
              </button>
            )}
          </li>
          {g.steps.map((s) => (
            <li key={s}>{s}</li>
          ))}
          {g.logs && (
            <li>
              <b>Check whether it was used.</b> {g.logs}
            </li>
          )}
          {afterRevoking(inHistory).map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ol>
      )}
    </div>
  )
}
