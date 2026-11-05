import { useEffect, useState } from 'react'
import { Copy, FolderDown, KeyRound } from 'lucide-react'
import type { LeakKitInfo } from '@shared/types'
import { useApp } from '../store'

type Part = 'hook' | 'preCommit' | 'action'
const PARTS: [Part, string, string][] = [
  ['hook', 'Before each commit', '.git/hooks/pre-commit'],
  ['preCommit', 'pre-commit tool', '.pre-commit-config.yaml'],
  ['action', 'GitHub Action', '.github/workflows/gitleaks.yml']
]

/** "Stop leaking keys": Gitleaks before every commit and on GitHub. Copy only: MacSec writes nothing in your projects. */
export function LeakKit(): React.JSX.Element | null {
  const { act, busy, notify } = useApp()
  const api = window.macsec
  const [kit, setKit] = useState<LeakKitInfo | null>(null)
  const [part, setPart] = useState<Part>('hook')
  useEffect(() => {
    void api.invoke('kit:leaks').then(setKit)
  }, [api])
  if (!kit) return null
  const text = kit[part]
  return (
    <div className="panel leakkit">
      <div className="leakkit-head">
        <span className="glyph" style={{ ['--g' as string]: '#ff3d7f' }}>
          <KeyRound size={18} />
        </span>
        <div>
          <div className="row-title">Stop leaking keys</div>
          <div className="row-sub" style={{ whiteSpace: 'normal' }}>
            Gitleaks {kit.version} catches keys and passwords before they are committed, and again on GitHub before they are merged. Free, no account. Copy these into your project: MacSec does not change your projects.
          </div>
        </div>
        <button className="btn btn-sm" disabled={busy.has('kit')} onClick={async () => { const d = await act('kit', () => api.invoke('kit:save')); if (d) notify({ kind: 'info', text: 'Saved all three in ~/MacSec/kits.' }) }}>
          <FolderDown size={13} /> Save all three
        </button>
      </div>
      <div className="tabs" role="tablist">
        {PARTS.map(([id, label]) => (
          <button key={id} role="tab" aria-selected={part === id} onClick={() => setPart(id)}>
            {label}
          </button>
        ))}
      </div>
      <ol className="leakkit-steps">
        {kit.steps[part].map((s) => (
          <li key={s}>{s}</li>
        ))}
      </ol>
      <div className="leakkit-code">
        <div className="leakkit-file">
          <span className="mono">{PARTS.find((p) => p[0] === part)![2]}</span>
          <button
            className="btn btn-sm btn-primary"
            onClick={() => {
              void navigator.clipboard.writeText(text)
              notify({ kind: 'info', text: 'Copied.' })
            }}
          >
            <Copy size={12} /> Copy
          </button>
        </div>
        <pre className="mono">{text}</pre>
      </div>
    </div>
  )
}
