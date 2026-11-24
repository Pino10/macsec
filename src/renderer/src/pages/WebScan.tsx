import { useEffect, useState } from 'react'
import { Box, ExternalLink, FolderOpen, Gauge, Globe, KeyRound, Laptop, LogIn, Radar, Telescope, UserX, Zap } from 'lucide-react'
import type { ConfirmOptions, LocalSite, Reviewer, ScanMode } from '@shared/types'
import { estimateWebScan, minutesText } from '@shared/estimate'
import { useApp } from '../store'
import { FlowStep, PageHead, Seg, SwitchLine } from '../ui'
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
type Pacing = 'normal' | 'gentle'
type ConfirmKey = 'discover' | 'fuzz' | 'waf' | 'auth' | 'authz' | 'logic' | 'inject' | 'proto'

const CONFIRM_FIELDS: { key: ConfirmKey; title: string; help: string }[] = [
  { key: 'discover', title: 'Content discovery with ffuf', help: 'Asks for up to 435 common paths at 20 a second, signed out, with ffuf’s own calibration. Every path that answers is asked again and proved. Read-only: no redirects, no parameters fuzzed, no cookie sent.' },
  { key: 'fuzz', title: 'Hidden pages and parameters', help: 'Looks for pages and settings that are not linked, and tells you which are real. Sites that answer yes to everything are detected and ignored.' },
  { key: 'waf', title: 'Web firewall tests', help: 'Finds which firewall answers, what it blocks, and whether a harmless marker gets past it. A way through is reported at once so the owner can tighten the rule.' },
  { key: 'inject', title: 'Injection tests on every page and form', help: 'Sends harmless markers into every parameter and search-style form it finds and reads what comes back: unescaped output, database errors, a calculated expression, a line break in a header. It only reads: forms that send data are listed, never submitted.' },
  { key: 'proto', title: 'Sign-in protocols, tokens and cross-site checks', help: 'OAuth and OpenID, JWTs, GraphQL, CORS and anti-forgery checks. Only reads, with made-up addresses that cannot exist.' },
  { key: 'logic', title: 'Business logic checks', help: 'Open redirects, a poisoned host header, endless wrong codes, price or role fields the browser sends. Anything that would change data is a lead, never tried.' },
  { key: 'auth', title: 'Login checks', help: 'Eight wrong guesses for a user that does not exist, and whether the login reveals which usernames exist.' },
  { key: 'authz', title: 'Two-account access check', help: 'Compares what a second account can open with what the first can. Needs you signed in above, and a second account below.' }
]

/** The same options as a preset, so the buttons can show which one is active. */
const PRESETS: [string, Partial<Record<ConfirmKey, boolean>>][] = [
  ['None (read-only)', {}],
  ['Public site', { fuzz: true, waf: true, logic: true, inject: true, proto: true }],
  ['Login and accounts', { auth: true, logic: true, inject: true, proto: true }],
  ['Shop or booking flow', { fuzz: true, auth: true, logic: true, inject: true, proto: true }]
]

const emptyConfirm = (): ConfirmOptions => ({ fuzz: false, auth: false, authz: false, waf: false, logic: false, inject: false, proto: false, discover: false })

export default function WebScan(): React.JSX.Element {
  const { settings, act, busy, showSession, notify } = useApp()
  const api = window.macsec
  const [where, setWhere] = useState<'local' | 'url'>('local')
  const [sites, setSites] = useState<LocalSite[]>([])
  const [site, setSite] = useState('')
  const [url, setUrl] = useState('')
  const [mode, setMode] = useState<ScanMode>('standard')
  const [pacing, setPacing] = useState<Pacing>('normal')
  const [reviewer, setReviewer] = useState<Reviewer>(settings?.reviewer ?? 'none')
  const [ok, setOk] = useState(false)
  const [login, setLogin] = useState<Login>('none')
  const [box, setBox] = useState<'black' | 'white'>('black')
  const [code, setCode] = useState<string | null>(null)
  const [checklist, setChecklist] = useState(false)
  const [autopilot, setAutopilot] = useState(false)
  const [headers, setHeaders] = useState('')
  const [captured, setCaptured] = useState<number | null>(null)
  const [cc, setCc] = useState<ConfirmOptions>(emptyConfirm())
  const [ccOk, setCcOk] = useState(false)
  const setC = (p: Partial<ConfirmOptions>): void => setCc((x) => ({ ...x, ...p }))
  const ccOn = CONFIRM_FIELDS.some((f) => !!cc[f.key])
  const ccCount = CONFIRM_FIELDS.filter((f) => !!cc[f.key]).length

  useEffect(() => {
    void api.invoke('web:sites').then((s) => {
      setSites(s)
      if (s[0]) setSite(s[0].name)
    })
  }, [api])

  const target = where === 'local' ? (sites.find((s) => s.name === site)?.url ?? '') : url.trim()
  const valid = /^https?:\/\/[^\s]+$/.test(target)
  const host = valid ? new URL(target).host : ''
  const needsOk = valid && !isLocal(target)
  const signedIn = login !== 'none' && headers.trim().length > 0
  const aiOn = reviewer !== 'none'
  const ccReady = !ccOn || (ccOk && (!cc.authz || (signedIn && !!cc.headersB?.trim())))

  // A consent, a session and an active test set belong to one host. Moving to another host starts
  // again: no tick and no cookie carries over to a different site.
  useEffect(() => {
    setOk(false)
    setCcOk(false)
    setHeaders('')
    setCaptured(null)
    setLogin('none')
  }, [host])

  const est = estimateWebScan({ mode, pacing, confirm: ccOn, discover: !!cc.discover, autopilot: autopilot && aiOn, checklist: checklist && aiOn, signedIn, white: box === 'white' })
  const why = !valid
    ? 'Choose a site or enter an address.'
    : needsOk && !ok
      ? `Confirm that you are allowed to test ${host}.`
      : login !== 'none' && !signedIn
        ? 'Sign in, or choose signed out.'
        : !ccReady
          ? 'The two-account check needs you signed in and a second account below.'
          : box === 'white' && where === 'url' && !code
            ? 'Choose the code folder for the white box check.'
            : ''

  const active = (set: Partial<Record<ConfirmKey, boolean>>): boolean => CONFIRM_FIELDS.every((f) => !!cc[f.key] === !!set[f.key])

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
              ['local', <><Laptop size={14} /> A site on this Mac</>],
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

        <FlowStep n={2} title="Signed out, or signed in too" help="Signed in, the scan reaches the pages only members see, and checks that private pages really need the login. The session is used by MacSec's own requests only: the scanner tools run signed out." state={valid ? (login === 'none' || signedIn ? 'done' : 'current') : 'todo'}>
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
              <span>A private window opens your site. Sign in as usual and close it; the login is kept for this scan only.</span>
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
          {signedIn && <p className="hint">If the sign-in expires during the scan, MacSec notices and says so instead of reporting missing pages.</p>}
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
          <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
            <Seg<Pacing>
              label="Pace"
              value={pacing}
              onChange={setPacing}
              options={[
                ['normal', 'Normal pace'],
                ['gentle', 'Gentle: a quarter of the rate']
              ]}
            />
            <span className="hint">Gentle sends far fewer requests a minute and pauses longer. Use it on a live site that must stay responsive.</span>
          </div>
        </FlowStep>

        <FlowStep n={4} title="From outside, or with the code" help="Black box tests the site as a visitor could. White box also reads the site's own code, so it knows every route and parameter, finds pages nothing links to, and checks them live. The code is only read." state={valid ? 'current' : 'todo'}>
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
                  <span className="hint mono">{code ?? 'No folder chosen yet. The scan cannot start without it.'}</span>
                </>
              )}
            </div>
          )}
        </FlowStep>

        <FlowStep n={5} title="Control confirmations (optional)" help="Active checks that try a harmless version of a problem, so every finding comes with proof. They use harmless test strings, never change data, and stop if the server struggles." state={valid ? 'current' : 'todo'}>
          <div className="stack" style={{ display: 'grid', gap: 12 }}>
            <div role="group" aria-label="Quick choices" style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
              <span className="hint">Presets:</span>
              {PRESETS.map(([name, set]) => (
                <button
                  key={name}
                  className={active(set) ? 'btn btn-sm btn-primary' : 'btn btn-sm'}
                  aria-pressed={active(set)}
                  onClick={() => {
                    setCc({ ...emptyConfirm(), ...set })
                    setCcOk(false)
                  }}
                >
                  {name}
                </button>
              ))}
              <span className="hint">Content discovery is never part of a preset; turn it on below when you want it.</span>
            </div>
            {CONFIRM_FIELDS.map((f) => (
              <SwitchLine key={f.key} on={!!cc[f.key]} onChange={() => setC({ [f.key]: !cc[f.key] })} label={f.title} help={f.help} />
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
                  <strong style={{ color: 'var(--ink)' }}>I am allowed to run active tests on {valid ? host : 'this site'}.</strong> Each finding is repeated once before it is reported. Nothing is saved except the proof.
                </span>
              </label>
            )}
            {needsOk && (
              <label className="consent">
                <input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} />
                <span>
                  <strong style={{ color: 'var(--ink)' }}>I own {host}, or have written permission to test it.</strong> Scanning sites you are not allowed to test can be against the law, even when the checks only read.
                </span>
              </label>
            )}
          </div>
        </FlowStep>

        <FlowStep n={6} title="The AI: who reads the results, and what it may do" help="The AI reads every finding and explains what matters for your stack. It can also run the two optional extras below, both on a fixed safe menu." state={valid ? (aiOn ? 'done' : 'current') : 'todo'}>
          <ReviewerChoice value={reviewer} onChange={setReviewer} what="findings" />
          <div style={{ display: 'grid', gap: 12, marginTop: 12 }}>
            <SwitchLine
              on={autopilot}
              disabled={!aiOn}
              onChange={() => setAutopilot(!autopilot)}
              label="Autopilot: the AI chooses what to test next"
              help={aiOn ? 'After the normal steps, the AI reads what was found and picks up to 14 more checks from a fixed safe menu, in up to three rounds. MacSec runs each one with its own safety rules and proof. Tick it only for a site you may test.' : 'Choose an AI first. Without one, Autopilot cannot run.'}
            />
            <SwitchLine
              on={checklist}
              disabled={!aiOn}
              onChange={() => setChecklist(!checklist)}
              label="Walk my 638-item checklist"
              help={aiOn ? 'Goes through your web checklist for this site. Items MacSec can test are marked found or clear; the AI judges the rest from the evidence only and says “try by hand” where it cannot know.' : 'Choose an AI first. Without one, the checklist cannot be judged.'}
            />
          </div>
        </FlowStep>
      </div>

      {/* One bar that stays in view: what will run, how much of it, and why it cannot start. */}
      <div className="flow-go glass">
        <div className="grow">
          <div className="summary-line">
            <strong>{valid ? host : 'No site chosen'}</strong>
            <span className="hint">{mode} · {pacing === 'gentle' ? 'gentle pace' : 'normal pace'} · {signedIn ? 'signed in' : 'signed out'} · {ccOn ? `${ccCount} confirmation${ccCount === 1 ? '' : 's'}` : 'read-only'}{aiOn ? ' · AI report' : ''}</span>
          </div>
          <div className="hint">
            About {est.requests.toLocaleString()} requests, roughly {minutesText(est.minutes)}. Most of it: {est.heaviest}.
          </div>
          {why && <div className="hint" style={{ color: 'var(--warn)' }}>{why}</div>}
        </div>
        <button className="btn" onClick={() => void act('burp', () => api.invoke('burp:open')).then(() => notify({ kind: 'info', text: 'Burp Suite is opening for hands-on testing.' }))}>
          <ExternalLink size={15} /> Burp
        </button>
        <button
          className="btn btn-primary btn-lg"
          disabled={!!why || busy.has('web')}
          onClick={async () => {
            const s = await act('web', () => api.invoke('web:start', { target: where === 'local' ? { kind: 'local', name: site } : { kind: 'url', url: target }, mode, pacing, authorized: ok, headers: signedIn ? headers : undefined, confirm: ccOn ? cc : undefined, codePath: box === 'white' ? (where === 'local' ? `${settings?.wwwPath?.replace(/\/$/, '')}/${site}` : (code ?? undefined)) : undefined, checklist: checklist && aiOn, autopilot: autopilot && aiOn, reviewer }))
            if (s) showSession(s.id)
          }}
        >
          <Radar size={17} /> {busy.has('web') ? 'Starting…' : 'Start scan'}
        </button>
      </div>
    </>
  )
}
