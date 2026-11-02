import { useEffect, useState } from 'react'
import { ExternalLink, Gauge, Globe, KeyRound, Laptop, LogIn, Radar, Telescope, UserX, Zap } from 'lucide-react'
import type { LocalSite, Reviewer, ScanMode } from '@shared/types'
import { useApp } from '../store'
import { FlowStep, PageHead, Seg } from '../ui'
import ReviewerChoice from '../components/ReviewerChoice'

export const MODES: { id: ScanMode; icon: React.ReactNode; title: string; text: string }[] = [
  { id: 'quick', icon: <Zap size={18} />, title: 'Quick', text: 'The main address: headers, TLS, the most dangerous exposed files and serious known problems. A minute or two.' },
  { id: 'standard', icon: <Gauge size={18} />, title: 'Standard', text: 'Maps the site, checks every exposed-file path, keys in its JavaScript, and every read-only Nuclei check.' },
  { id: 'thorough', icon: <Telescope size={18} />, title: 'Thorough', text: 'A deeper map with JavaScript and the checks on every page found. Can take an hour.' }
]

export const isLocal = (u: string): boolean => {
  try {
    const h = new URL(u).hostname
    return /^(localhost|127\.\d+\.\d+\.\d+)$/.test(h) || /\.(test|localhost)$/.test(h)
  } catch {
    return false
  }
}

type Login = 'none' | 'browser' | 'paste'

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
  const [login, setLogin] = useState<Login>('none')
  const [headers, setHeaders] = useState('')
  const [captured, setCaptured] = useState<number | null>(null)

  useEffect(() => {
    void api.invoke('web:sites').then((s) => {
      setSites(s)
      if (s[0]) setSite(s[0].name)
    })
  }, [api])

  const target = where === 'local' ? (sites.find((s) => s.name === site)?.url ?? '') : url.trim()
  const valid = /^https?:\/\/[^\s]+$/.test(target)
  const needsOk = valid && !isLocal(target)
  const signedIn = login !== 'none' && headers.trim().length > 0

  return (
    <>
      <PageHead title="Web scan" desc="Looks at a site the way a careful visitor would: what it reveals, what it leaves open, and which known problems it has. Every check only reads; nothing is attacked or changed." />
      <div className="flow">
        <FlowStep n={1} title="Which site" state={valid ? 'done' : 'current'}>
          <Seg<'local' | 'url'>
            label="Where"
            value={where}
            onChange={setWhere}
            options={[
              ['local', <><Laptop size={14} /> A Laramac site</>],
              ['url', <><Globe size={14} /> Any address</>]
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
        </FlowStep>

        <FlowStep n={2} title="Signed out, or signed in too" help="Signed in, the scan reaches the pages only members see, and checks that private pages really need the login." state={valid ? (login === 'none' || signedIn ? 'done' : 'current') : 'todo'}>
          <div className="choices" role="radiogroup" aria-label="Sign-in">
            <button className="choice" role="radio" aria-checked={login === 'none'} onClick={() => setLogin('none')}>
              <span className="ci" style={{ ['--g' as string]: '#8c95b8' }}>
                <UserX size={18} />
              </span>
              <strong>Signed out</strong>
              <span>What any visitor sees.</span>
            </button>
            <button className="choice" role="radio" aria-checked={login === 'browser'} onClick={() => setLogin('browser')}>
              <span className="ci" style={{ ['--g' as string]: '#38e1ff' }}>
                <LogIn size={18} />
              </span>
              <strong>Sign in through MacSec</strong>
              <span>A private window opens your site. Sign in as usual and close it; MacSec keeps that login for this scan only.</span>
            </button>
            <button className="choice" role="radio" aria-checked={login === 'paste'} onClick={() => setLogin('paste')}>
              <span className="ci" style={{ ['--g' as string]: '#8b6cff' }}>
                <KeyRound size={18} />
              </span>
              <strong>Paste a cookie or token</strong>
              <span>Copied from your browser’s developer tools while signed in.</span>
            </button>
          </div>
          {login === 'browser' && (
            <div style={{ display: 'flex', gap: 14, alignItems: 'center' }}>
              <button
                className="btn"
                disabled={!valid || busy.has('login')}
                onClick={async () => {
                  const r = await act('login', () => api.invoke('web:login', target))
                  if (r) {
                    setHeaders(r.cookie)
                    setCaptured(r.count)
                    notify({ kind: 'info', text: `Signed in: ${r.count} cookies kept for this scan.` })
                  } else notify({ kind: 'error', text: 'No login was saved. Sign in, then close the window.' })
                }}
              >
                <LogIn size={15} /> {busy.has('login') ? 'Waiting for you to sign in…' : captured ? 'Sign in again' : 'Open the sign-in window'}
              </button>
              <span className="hint">{captured ? `Signed in, ${captured} cookies captured. They are never saved.` : 'Close the window when you are signed in.'}</span>
            </div>
          )}
          {login === 'paste' && <textarea className="input mono" rows={3} placeholder={'Cookie: laravel_session=…\nAuthorization: Bearer …'} value={headers} onChange={(e) => setHeaders(e.target.value)} aria-label="Request headers" />}
        </FlowStep>

        <FlowStep n={3} title="How much to cover" state={valid ? 'current' : 'todo'}>
          <div className="choices" role="radiogroup" aria-label="Mode">
            {MODES.map((m) => (
              <button key={m.id} className="choice" role="radio" aria-checked={mode === m.id} onClick={() => setMode(m.id)}>
                <span className="ci">{m.icon}</span>
                <strong>{m.title}</strong>
                <span>{m.text}</span>
              </button>
            ))}
          </div>
        </FlowStep>

        <FlowStep n={4} title="Who writes the report" help="The AI reads every finding and explains what matters for your stack, with the exact configuration to fix it." state={valid ? 'current' : 'todo'}>
          <ReviewerChoice value={reviewer} onChange={setReviewer} what="findings" />
        </FlowStep>

        {needsOk && (
          <label className="consent">
            <input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} />
            <span>
              <strong style={{ color: 'var(--ink)' }}>I own {new URL(target).host}, or have written permission to test it.</strong> Scanning sites you are not allowed to test can be against the law, even when the checks only read.
            </span>
          </label>
        )}

        <div className="flow-go glass">
          <span className="hint grow">{valid ? `Scans ${target}${signedIn ? ', signed in' : ''}` : 'Choose a site or enter an address.'}</span>
          <button className="btn" onClick={() => void act('burp', () => api.invoke('burp:open')).then(() => notify({ kind: 'info', text: 'Burp Suite is opening for hands-on testing.' }))}>
            <ExternalLink size={15} /> Burp Suite
          </button>
          <button
            className="btn btn-primary btn-lg"
            disabled={!valid || (needsOk && !ok) || (login !== 'none' && !signedIn) || busy.has('web')}
            onClick={async () => {
              const s = await act('web', () => api.invoke('web:start', { target: where === 'local' ? { kind: 'local', name: site } : { kind: 'url', url: target }, mode, authorized: ok, headers: signedIn ? headers : undefined, reviewer }))
              if (s) showSession(s.id)
            }}
          >
            <Radar size={17} /> Start scan
          </button>
        </div>
      </div>
    </>
  )
}
