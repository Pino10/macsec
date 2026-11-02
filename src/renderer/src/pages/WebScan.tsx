import { useEffect, useState } from 'react'
import { ExternalLink, Gauge, Globe, Laptop, Radar, Telescope, Zap } from 'lucide-react'
import type { LocalSite, Reviewer, ScanMode } from '@shared/types'
import { useApp } from '../store'
import { PageHead, Seg } from '../ui'
import ReviewerChoice from '../components/ReviewerChoice'

export const MODES: { id: ScanMode; icon: React.ReactNode; title: string; text: string }[] = [
  { id: 'quick', icon: <Zap size={16} />, title: 'Quick', text: 'The main address: headers, the most dangerous exposed files, serious known problems. A minute or two.' },
  { id: 'standard', icon: <Gauge size={16} />, title: 'Standard', text: 'Maps the site, checks every exposed-file path and runs every read-only Nuclei check.' },
  { id: 'thorough', icon: <Telescope size={16} />, title: 'Thorough', text: 'A deeper map with JavaScript, and the checks on every page found. Can take an hour.' }
]

const isLocal = (u: string): boolean => {
  try {
    const h = new URL(u).hostname
    return /^(localhost|127\.\d+\.\d+\.\d+)$/.test(h) || /\.(test|localhost)$/.test(h)
  } catch {
    return false
  }
}

export default function WebScan(): React.JSX.Element {
  const { settings, act, busy, showSession, notify } = useApp()
  const api = window.macsec
  const [where, setWhere] = useState<'local' | 'url'>('local')
  const [sites, setSites] = useState<LocalSite[]>([])
  const [site, setSite] = useState('')
  const [url, setUrl] = useState('')
  const [mode, setMode] = useState<ScanMode>('standard')
  const [reviewer, setReviewer] = useState<Reviewer>(settings?.reviewer ?? 'none')
  const [ok, setOk] = useState(false)
  const [headers, setHeaders] = useState('')
  const [login, setLogin] = useState(false)

  useEffect(() => {
    void api.invoke('web:sites').then((s) => {
      setSites(s)
      if (s[0]) setSite(s[0].name)
    })
  }, [api])

  const target = where === 'local' ? sites.find((s) => s.name === site)?.url ?? '' : url.trim()
  const valid = /^https?:\/\/[^\s]+$/.test(target)
  const needsOk = valid && !isLocal(target)

  return (
    <>
      <PageHead title="Web scan" desc="Looks at a site the way a careful visitor would: what it reveals, what it leaves open, and which known problems it has. Every check only reads; nothing is attacked or changed." />
      <div className="setup glass">
        <div className="field">
          <span className="field-label">Which site</span>
          <Seg<'local' | 'url'>
            label="Where"
            value={where}
            onChange={setWhere}
            options={[
              ['local', <><Laptop size={13} /> A Laramac site</>],
              ['url', <><Globe size={13} /> Any address</>]
            ]}
          />
          {where === 'local' ? (
            <select className="input" value={site} onChange={(e) => setSite(e.target.value)} aria-label="Site">
              {sites.length === 0 && <option value="">No sites in your www folder</option>}
              {sites.map((s) => (
                <option key={s.name} value={s.name}>
                  {s.url.replace(/^https?:\/\//, '')}
                </option>
              ))}
            </select>
          ) : (
            <input className="input mono" placeholder="https://staging.yoursite.com" value={url} onChange={(e) => setUrl(e.target.value)} aria-label="Address" />
          )}
          <label className="check">
            <input type="checkbox" checked={login} onChange={(e) => setLogin(e.target.checked)} /> Scan behind a login
          </label>
          {login && (
            <>
              <textarea className="input mono" rows={3} placeholder={'Cookie: laravel_session=…\nAuthorization: Bearer …'} value={headers} onChange={(e) => setHeaders(e.target.value)} aria-label="Request headers" />
              <span className="field-help">Copy the Cookie or Authorization header from your browser’s developer tools while signed in. It is used for this scan only and not saved.</span>
            </>
          )}
        </div>

        <div className="field">
          <span className="field-label">How much to cover</span>
          <div className="choices" role="radiogroup" aria-label="Mode">
            {MODES.map((m) => (
              <button key={m.id} className="choice" role="radio" aria-checked={mode === m.id} onClick={() => setMode(m.id)}>
                <strong>
                  {m.icon} {m.title}
                </strong>
                <span>{m.text}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="field">
          <span className="field-label">AI summary</span>
          <ReviewerChoice value={reviewer} onChange={setReviewer} what="findings" />
        </div>

        {needsOk && (
          <label className="consent">
            <input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} />
            <span>
              <strong style={{ color: 'var(--ink)' }}>I own {new URL(target).host}, or have written permission to test it.</strong> Scanning sites you are not allowed to test can be against the law, even when the checks only read.
            </span>
          </label>
        )}

        <div className="go-bar">
          <span className="hint grow">{valid ? `Scans ${target}` : 'Choose a site or enter an address.'}</span>
          <button className="btn" onClick={() => void act('burp', () => api.invoke('burp:open')).then(() => notify({ kind: 'info', text: 'Burp Suite is opening. Point it at the same address for hands-on testing.' }))}>
            <ExternalLink size={14} /> Open Burp Suite
          </button>
          <button
            className="btn btn-primary btn-lg"
            disabled={!valid || (needsOk && !ok) || busy.has('web')}
            onClick={async () => {
              const s = await act('web', () => api.invoke('web:start', { target: where === 'local' ? { kind: 'local', name: site } : { kind: 'url', url: target }, mode, authorized: ok, headers: login ? headers : undefined, reviewer }))
              if (s) showSession(s.id)
            }}
          >
            <Radar size={16} /> Start scan
          </button>
        </div>
      </div>
    </>
  )
}
