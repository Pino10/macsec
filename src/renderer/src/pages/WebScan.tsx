import { useEffect, useState } from 'react'
import { Box, ExternalLink, FolderOpen, Gauge, Globe, KeyRound, Laptop, LogIn, Radar, Telescope, UserX, Zap } from 'lucide-react'
import type { ConfirmOptions, LocalSite, Reviewer, ScanMode } from '@shared/types'
import { useApp } from '../store'
import { FlowStep, PageHead, Seg, Switch } from '../ui'
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
  const [box, setBox] = useState<'black' | 'white'>('black')
  const [code, setCode] = useState<string | null>(null)
  const [checklist, setChecklist] = useState(false)
  const [autopilot, setAutopilot] = useState(false)
  const [headers, setHeaders] = useState('')
  const [captured, setCaptured] = useState<number | null>(null)
  const [cc, setCc] = useState<ConfirmOptions>({ fuzz: false, auth: false, authz: false, waf: false, logic: false, inject: false, proto: false })
  const [ccOk, setCcOk] = useState(false)
  const setC = (p: Partial<ConfirmOptions>): void => setCc((x) => ({ ...x, ...p }))
  const ccOn = cc.fuzz || cc.auth || cc.authz || cc.waf || cc.logic || cc.inject || cc.proto

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
  const ccReady = !ccOn || (ccOk && (!cc.authz || (signedIn && !!cc.headersB?.trim())))

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

        <FlowStep n={3} title="Black box or white box" help="Black box tests the site from outside, like an attacker with no inside knowledge. White box also reads the site's own code, so it knows every route and parameter, finds pages nothing links to, and checks them on the live site." state={valid ? 'current' : 'todo'}>
          <div className="choices" role="radiogroup" aria-label="Approach">
            <button className="choice" role="radio" aria-checked={box === 'black'} onClick={() => setBox('black')}>
              <span className="ci"><Box size={18} /></span>
              <strong>Black box</strong>
              <span>From outside only. No code needed.</span>
            </button>
            <button className="choice" role="radio" aria-checked={box === 'white'} onClick={() => setBox('white')}>
              <span className="ci"><FolderOpen size={18} /></span>
              <strong>White box</strong>
              <span>Reads the code (it never changes it) and tests what it finds, live.</span>
            </button>
          </div>
          {box === 'white' && (
            <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginTop: 10, flexWrap: 'wrap' }}>
              {where === 'local' ? (
                <span className="hint">The code is the {site || 'site'} folder in your www folder.</span>
              ) : (
                <>
                  <button className="btn" onClick={async () => setCode((await act('pick', () => api.invoke('web:pick-code'))) ?? code)}>
                    <FolderOpen size={14} /> {code ? 'Choose another folder' : 'Choose the code folder'}
                  </button>
                  <span className="hint mono">{code ?? 'No folder chosen yet.'}</span>
                </>
              )}
            </div>
          )}
          <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start', marginTop: 12 }}>
            <Switch on={autopilot} onChange={() => setAutopilot(!autopilot)} label="Autopilot" />
            <div>
              <strong>Autopilot: the AI chooses what to test next</strong>
              <div className="hint">After the normal steps, the AI reads what was found and picks up to 14 more checks from a fixed safe menu (read a page, injection markers, hidden parameters, CORS, GraphQL, OAuth, tokens, business logic), in up to three rounds. MacSec runs each one with its own safety rules and proof. The AI never sends requests or writes findings itself. Tick it only for a site you may test. It needs an AI choice in the last step.</div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start', marginTop: 12 }}>
            <Switch on={checklist} onChange={() => setChecklist(!checklist)} label="Walk my checklist" />
            <div>
              <strong>Walk my checklist</strong>
              <div className="hint">Goes through your 638-item web checklist for this site. Items MacSec can test are marked found or clear. The AI you pick below judges the rest from the evidence only, and says "try by hand" where it cannot know. It needs an AI choice in the last step.</div>
            </div>
          </div>
        </FlowStep>

        <FlowStep n={4} title="How much to cover" state={valid ? 'current' : 'todo'}>
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

        <FlowStep n={5} title="Control confirmations (optional)" help="Active checks that try a harmless version of a problem, so every finding comes with proof and nothing is a guess. They only use harmless test strings, never change data, and stop if the server struggles." state={valid ? 'current' : 'todo'}>
          <div className="stack" style={{ display: 'grid', gap: 10 }}>
            <div role="group" aria-label="Quick choices" style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
              <span className="hint">Quick choices:</span>
              {(
                [
                  ['None', { fuzz: false, waf: false, auth: false, authz: false, logic: false, inject: false, proto: false }],
                  ['Public site', { fuzz: true, waf: true, auth: false, authz: false, logic: true, inject: true, proto: true }],
                  ['Login and accounts', { fuzz: false, waf: false, auth: true, authz: false, logic: true, inject: true, proto: true }],
                  ['Shop or booking flow', { fuzz: true, waf: false, auth: true, authz: false, logic: true, inject: true, proto: true }]
                ] as const
              ).map(([name, set]) => (
                <button key={name} className="btn btn-sm" onClick={() => setC(set)}>
                  {name}
                </button>
              ))}
            </div>
            {(
              [
                ['fuzz', 'Hidden pages and parameters', 'Looks for pages and settings that are not linked, and tells you which are real. Sites that answer yes to everything are detected and ignored.'],
                ['waf', 'Web firewall tests', 'Finds which firewall answers, what it blocks, and whether a harmless marker gets past it. A way through is reported at once so the owner can tighten the rule.'],
                ['inject', 'Injection tests on every page and form', 'Sends harmless markers into every parameter and every search-style form it finds (signed in too, if you signed in above) and reads what comes back: unescaped output, database errors, a calculated expression, a line break in a header. It only reads: forms that send data are listed, never submitted.'],
                ['proto', 'Sign-in protocols, tokens, GraphQL and cross-site checks', 'Checks how the site signs people in and talks to other sites. OAuth and OpenID: a missing or fixed state value, the implicit flow, a callback address the server accepts without checking. Tokens (JWT): no signature, a weak secret, no expiry, and whether the server really checks the signature of your own token. GraphQL: open schema, open IDE, mutations over GET. Other sites: CORS that repeats any origin, forms without an anti-forgery token, session ids in links. All of it only reads, with made-up addresses that cannot exist.'],
                ['logic', 'Business logic checks', 'Tests for open redirects, a poisoned host header, forms that accept endless wrong codes, price or role fields the browser sends, and steps of a flow that can be skipped. Anything that would change data is listed as a lead for you to test by hand.'],
                ['auth', 'Login checks', 'Eight wrong guesses for a user that does not exist (to see if anything slows them), and whether the login reveals which usernames exist.'],
                ['authz', 'Two-account access check', 'Compares what a second account can open with what the first can. Needs you to be signed in above, and a second account below.']
              ] as const
            ).map(([k, t, d]) => (
              <div key={k} style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                <Switch on={!!cc[k]} onChange={() => setC({ [k]: !cc[k] })} label={t} />
                <div>
                  <strong>{t}</strong>
                  <div className="hint">{d}</div>
                </div>
              </div>
            ))}
            {cc.auth && (
              <>
                <input className="input mono" placeholder="Sign-in page address, if it is not /login (optional)" value={cc.loginUrl ?? ''} onChange={(e) => setC({ loginUrl: e.target.value })} aria-label="Sign-in page address" />
                <input className="input mono" placeholder="Your own username or email on this site (optional, tried with 2 wrong passwords)" value={cc.knownUser ?? ''} onChange={(e) => setC({ knownUser: e.target.value })} aria-label="Your username" />
                {cc.knownUser?.includes('@') && (
                  <label className="consent">
                    <input type="checkbox" checked={!!cc.allowReset} onChange={(e) => setC({ allowReset: e.target.checked })} />
                    <span>Also test “forgot password”. This sends one reset email to {cc.knownUser}.</span>
                  </label>
                )}
              </>
            )}
            {cc.authz && (
              <>
                {!signedIn && <span className="hint">Sign in above first: that is the first account.</span>}
                <textarea className="input mono" rows={2} placeholder={'Second account, copied the same way:\nCookie: session=…'} value={cc.headersB ?? ''} onChange={(e) => setC({ headersB: e.target.value })} aria-label="Second account cookie or token" />
                <input className="input mono" placeholder="First account's email or username (so a leak can be proven)" value={cc.identityA ?? ''} onChange={(e) => setC({ identityA: e.target.value })} aria-label="First account's identifier" />
              </>
            )}
            {ccOn && (
              <label className="consent">
                <input type="checkbox" checked={ccOk} onChange={(e) => setCcOk(e.target.checked)} />
                <span>
                  <strong style={{ color: 'var(--ink)' }}>I am allowed to run active tests on {valid ? new URL(target).host : 'this site'}.</strong> Each finding is repeated once before it is reported. Nothing is saved except the proof.
                </span>
              </label>
            )}
          </div>
        </FlowStep>

        <FlowStep n={6} title="Who writes the report" help="The AI reads every finding and explains what matters for your stack, with the exact configuration to fix it." state={valid ? 'current' : 'todo'}>
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
            disabled={!valid || (needsOk && !ok) || (login !== 'none' && !signedIn) || !ccReady || busy.has('web') || (box === 'white' && where === 'url' && !code)}
            onClick={async () => {
              const s = await act('web', () => api.invoke('web:start', { target: where === 'local' ? { kind: 'local', name: site } : { kind: 'url', url: target }, mode, authorized: ok, headers: signedIn ? headers : undefined, confirm: ccOn ? cc : undefined, codePath: box === 'white' ? (where === 'local' ? `${settings?.wwwPath ?? ''}/${site}` : (code ?? undefined)) : undefined, checklist: checklist && reviewer !== 'none', autopilot: autopilot && reviewer !== 'none', reviewer }))
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
