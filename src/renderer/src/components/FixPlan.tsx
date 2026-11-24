import { useEffect, useState } from 'react'
import type { FixPlan as Plan, SessionDetail } from '@shared/types'
import { Sev } from '../ui'

/** "Fix these first" and "How these connect" for one result. */
export default function FixPlan({ detail }: { detail: SessionDetail }): React.JSX.Element | null {
  const api = window.macsec
  const [p, setP] = useState<Plan | null>(null)
  useEffect(() => {
    if (detail.status === 'running') return
    void api.invoke('sessions:fixplan', detail.id).then(setP)
  }, [api, detail.id, detail.status, detail.findings])
  if (!p || (!p.actions.length && !p.chains.length)) return null
  return (
    <div className="panel" style={{ marginBottom: 18 }}>
      {p.actions.length > 0 && (
        <>
          <h3 style={{ margin: '0 0 6px', fontSize: 15 }}>Fix these first</h3>
          <p className="hint" style={{ margin: '0 0 8px' }}>
            Doing these {p.actions.length} {p.actions.length === 1 ? 'thing' : 'things'} takes the risk score from {p.before} to {p.after}.
          </p>
          <ol style={{ margin: 0, paddingLeft: 20, display: 'grid', gap: 6 }}>
            {p.actions.map((a) => (
              <li key={a.ids.join()}>
                <Sev s={a.worst} /> <strong>{a.title}</strong>
                {a.fix && <div className="hint">{a.fix}</div>}
              </li>
            ))}
          </ol>
        </>
      )}
      {p.chains.length > 0 && (
        <>
          <h3 style={{ margin: '16px 0 6px', fontSize: 15 }}>How these connect</h3>
          <div style={{ display: 'grid', gap: 8 }}>
            {p.chains.map((c) => (
              <div key={c.id}>
                <Sev s={c.severity} /> <strong>{c.name}</strong> <span className="tag">{c.confidence}</span>
                <div className="hint">{c.story}</div>
                {c.impact ? <div className="hint">If it is used: {c.impact}</div> : null}
                {c.breakAt ? (
                  <div className="hint" style={{ color: 'var(--ink-2)' }}>
                    <b>Break it here:</b> {c.breakAt.title}. {c.breakAt.fix}
                  </div>
                ) : null}
                <div className="hint">Parts: {c.members.map((m) => m.title).join('; ')}</div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
