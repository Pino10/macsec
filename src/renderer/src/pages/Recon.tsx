import { useEffect, useState } from 'react'
import { Download, Radar } from 'lucide-react'
import type { Reviewer, ToolInfo } from '@shared/types'
import { useApp } from '../store'
import { FlowStep, PageHead } from '../ui'
import ReviewerChoice from '../components/ReviewerChoice'

const local = (t: string): boolean => /\.(test|localhost)$/.test(t.trim().replace(/^https?:\/\//, '').replace(/[/:].*$/, ''))

export default function Recon(): React.JSX.Element {
  const { act, busy, showSession, tools, setTools } = useApp()
  const api = window.macsec
  const [target, setTarget] = useState('')
  const [depth, setDepth] = useState<'passive' | 'standard' | 'deep'>('standard')
  const [reviewer, setReviewer] = useState<Reviewer>('none')
  const [ok, setOk] = useState(false)
  const sub: ToolInfo | undefined = tools.find((t) => t.id === 'subfinder')
  useEffect(() => undefined, [])
  const host = target.trim().replace(/^https?:\/\//, '').replace(/[/:].*$/, '')
  const valid = /^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(host)
  const needsOk = valid && !local(target)
  return (
    <>
      <PageHead title="Recon" desc="Map what a domain exposes before you test it: subdomains, live hosts and what they run, old URLs and parameters, JavaScript source maps, endpoints and keys, and files that should not be public. Read-only: nothing is attacked." />
      <div className="flow">
        <FlowStep n={1} title="Which domain" help="Its subdomains are included. Nothing outside it is touched." state={valid ? 'done' : 'current'}>
          <input className="input mono" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="example.com" aria-label="Domain" />
        </FlowStep>
        <FlowStep n={2} title="How far" state="current">
          <div className="choices" role="radiogroup" aria-label="Depth">
            {(
              [
                ['passive', 'Passive', 'Certificate logs, the Wayback Machine and subfinder’s public sources, plus DNS. Nothing is sent to the site itself.'],
                ['standard', 'Standard', 'Plus which hosts answer and what they run, a light crawl, every script checked for source maps, endpoints and keys, and a few exposed files.'],
                ['deep', 'Deep', 'More hosts, pages and scripts, archived JavaScript too. Takes longer.']
              ] as const
            ).map(([id, t, d]) => (
              <button key={id} className="choice" role="radio" aria-checked={depth === id} onClick={() => setDepth(id)}>
                <strong>{t}</strong>
                <span>{d}</span>
              </button>
            ))}
          </div>
          {sub && !sub.installed && (
            <p className="hint" style={{ marginTop: 10 }}>
              subfinder adds many more subdomains; it installs on the first recon, or now:{' '}
              <button
                className="link"
                onClick={async () => {
                  const r = await act('sf', () => api.invoke('tools:install', ['subfinder']))
                  if (r) setTools(r)
                }}
              >
                <Download size={11} /> {busy.has('sf') ? 'Installing…' : 'Install subfinder'}
              </button>
            </p>
          )}
        </FlowStep>
        <FlowStep n={3} title="Who writes the report" help="The AI reads the recon results (never the site) with MacSec’s recon skills, and writes the attack surface map and where to look first." state="current">
          <ReviewerChoice value={reviewer} onChange={setReviewer} what="findings" />
        </FlowStep>
        {needsOk && (
          <label className="consent">
            <input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} />
            <span>
              <strong style={{ color: 'var(--ink)' }}>I own this domain, or have written permission to assess it</strong> (a bug bounty programme that includes it, for example).
            </span>
          </label>
        )}
        <div className="flow-go glass">
          <span className="hint grow">Ordinary reads at a gentle rate. You can watch every step, and the session keeps the hosts, scripts and findings.</span>
          <button
            className="btn btn-primary btn-lg"
            disabled={!valid || (needsOk && !ok) || busy.has('recon')}
            onClick={async () => {
              const s = await act('recon', () => api.invoke('recon:start', { target: host, depth, reviewer, authorized: ok }))
              if (s) showSession(s.id)
            }}
          >
            <Radar size={17} /> Start recon
          </button>
        </div>
      </div>
    </>
  )
}
