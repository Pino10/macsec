import { useState } from 'react'
import { FileSearch, Play, ShieldHalf } from 'lucide-react'
import { useApp } from '../store'
import { PageHead } from '../ui'

/** BloodHound export review: Kerberos, delegation and privileged accounts. No domain traffic. */
export default function Ad(): React.JSX.Element {
  const { act, showSession, notify } = useApp()
  const api = window.macsec
  const [path, setPath] = useState('')
  return (
    <>
      <PageHead title="AD review" desc="Read a BloodHound JSON or ZIP export and report the Kerberos, delegation and privileged-account problems it shows. This reads a file: it does not touch a domain, guess a password or run a credential attack." />
      <div className="panel" style={{ padding: 20, display: 'grid', gap: 14, maxWidth: 760 }}>
        <div className="row" style={{ cursor: 'default', gap: 14 }}>
          <ShieldHalf size={26} />
          <div className="grow">
            <strong>BloodHound export</strong>
            <p className="hint">The import finds Kerberoastable SPNs, AS-REP roastable accounts, unconstrained and constrained delegation, AdminCount=1, passwords that never expire or are not required, and missing LAPS. The findings are <strong>possible</strong>: an export can be stale.</p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn" onClick={async () => { const p = await api.invoke('ad:pick'); if (p) setPath(p) }}>
            <FileSearch size={15} /> Choose export
          </button>
          <button className="btn btn-primary" disabled={!path} onClick={async () => {
            const s = await act('ad-review', () => api.invoke('ad:start', path))
            if (s) {
              notify({ kind: 'info', title: 'AD review started', text: 'The findings appear in the result when it finishes.' })
              showSession(s.id)
            }
          }}>
            <Play size={15} /> Review
          </button>
        </div>
        {path && <p className="row-sub mono">{path}</p>}
        <p className="hint">A ZIP may contain users.json, computers.json, groups.json and domains.json. A single JSON array or a JSON object with those keys also works. Nothing is uploaded.</p>
      </div>
    </>
  )
}
