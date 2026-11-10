import { useEffect, useState } from 'react'
import { Cloud, GitCompareArrows, Layers3, LogIn, Radar, Server, ShieldHalf } from 'lucide-react'
import type { LocalProject, LocalSite, ReviewDepth, Reviewer } from '@shared/types'
import { useApp } from '../store'
import { FlowStep, PageHead } from '../ui'
import ReviewerChoice from '../components/ReviewerChoice'
import { isLocal } from './WebScan'

export type AuditKind = 'full' | 'portfolio' | 'changes' | 'cloud' | 'server'
type Kind = AuditKind

const AUDITS: { id: Kind; g: string; icon: React.ReactNode; title: string; text: string }[] = [
  { id: 'full', g: '#3ef0a8', icon: <ShieldHalf size={24} />, title: 'Full audit', text: 'A code review and a web scan of the same project, then one AI report that connects them: the route the code leaves open and the page that shows it.' },
  { id: 'portfolio', g: '#38e1ff', icon: <Layers3 size={24} />, title: 'Portfolio sweep', text: 'Every project in your www folder at once: keys and passwords in files and Git history, and packages with known flaws.' },
  { id: 'changes', g: '#8b6cff', icon: <GitCompareArrows size={24} />, title: 'Change review', text: 'Claude Code’s own /security-review of the changes on a project’s current branch, before you merge or deploy.' },
  { id: 'cloud', g: '#ff8a3d', icon: <Cloud size={24} />, title: 'Cloud account', text: 'Your Azure or AWS account against best practice (ScoutSuite), what it exposes (CloudFox) and, on AWS, who could raise their own access (PMapper). Only reads.' },
  { id: 'server', g: '#ff3d7f', icon: <Server size={24} />, title: 'Servers and ports', text: 'The open ports on a server, a list of servers or a network you own, and the service behind each one, with the ones that should not be reachable.' }
]

/**
 * The bigger jobs, each shown where it belongs: Cloud and servers is its own page, and Code review
 * offers "Just my changes" and "Code and its live site". `kinds` limits what this shows; with one
 * kind there is no picker.
 */
export function AuditFlow({ kinds, start = 'Start' }: { kinds: Kind[]; start?: string }): React.JSX.Element {
  const { settings, act, busy, showSession } = useApp()
  const api = window.macsec
  const [kind, setKind] = useState<Kind>(kinds[0])
  useEffect(() => setKind(kinds[0]), [kinds])
  const [projects, setProjects] = useState<LocalProject[]>([])
  const [sites, setSites] = useState<LocalSite[]>([])
  const [path, setPath] = useState('')
  const [site, setSite] = useState('')
  const [reviewer, setReviewer] = useState<Reviewer>(settings?.reviewer ?? 'claude')
  const [depth, setDepth] = useState<ReviewDepth>('standard')
  const [ok, setOk] = useState(false)
  const [provider, setProvider] = useState<'azure' | 'aws'>('azure')
  const [cloud, setCloud] = useState<{ azure: string | null; aws: string | null } | null>(null)
  const [host, setHost] = useState('')
  const [ports, setPorts] = useState<'top100' | 'top1000'>('top100')
  useEffect(() => {
    if (kind === 'cloud' && !cloud) void api.invoke('cloud:status').then(setCloud)
  }, [api, kind, cloud])

  useEffect(() => {
    void api.invoke('projects:local').then((p) => {
      setProjects(p)
      if (p[0]) setPath(p[0].path)
    })
    void api.invoke('web:sites').then(setSites)
  }, [api])
  // The Laramac address of the chosen project, filled in for you.
  useEffect(() => {
    const name = path.split('/').pop()
    const s = sites.find((x) => x.name === name)
    if (s) setSite(s.url)
  }, [path, sites])

  const project = projects.find((p) => p.path === path)
  const validSite = /^https?:\/\/[^\s]+$/.test(site.trim())
  // One server, a list (one per line or separated by commas) or a small network such as 192.168.1.0/28.
  const typedHosts = host.split(/[\s,;]+/).map((t) => t.trim()).filter(Boolean)
  const multi = typedHosts.length > 1 || /^[\d.]+\/\d+$/.test(host.trim()) || /^[\d.]+-\d+$/.test(host.trim())
  const cleanHost = multi ? typedHosts.join('\n') : host.trim().replace(/^[a-z]+:\/\//i, '').replace(/[/:].*$/, '')
  const validHost = multi ? typedHosts.every((t) => /^[a-z0-9]([a-z0-9./-]*[a-z0-9])?$/i.test(t)) : /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(cleanHost)
  const localHost = !multi && (/^(localhost|127\.\d+\.\d+\.\d+)$/.test(cleanHost) || /\.(test|localhost)$/.test(cleanHost))
  const needsOk = (kind === 'full' && validSite && !isLocal(site.trim())) || (kind === 'server' && validHost && !localHost)
  const signedIn = cloud?.[provider]
  const ready =
    kind === 'portfolio' ||
    (kind === 'changes' && !!project) ||
    (kind === 'full' && !!project && validSite && (!needsOk || ok)) ||
    (kind === 'cloud' && !!signedIn) ||
    (kind === 'server' && validHost && (!needsOk || ok))

  return (
    <>
      {kinds.length > 1 && (
      <div className="audit-grid" role="radiogroup" aria-label="What to check" style={{ marginBottom: 18 }}>
        {AUDITS.filter((a) => kinds.includes(a.id)).map((a) => (
          <button key={a.id} className="audit-card glass" role="radio" aria-checked={kind === a.id} onClick={() => setKind(a.id)}>
            <span className="glyph" style={{ ['--g' as string]: a.g }}>
              {a.icon}
            </span>
            <h3>{a.title}</h3>
            <p>{a.text}</p>
          </button>
        ))}
      </div>
      )}

      <div className="flow">
        {kind === 'cloud' && (
          <>
            <FlowStep n={1} title="Which cloud" help="Azure signs in through Microsoft’s page and the sign-in stays inside MacSec. AWS uses the profile you already set up with the AWS CLI (aws configure or aws sso login), and only reads it." state={signedIn ? 'done' : 'current'}>
              <div className="choices" role="radiogroup" aria-label="Cloud">
                {(['azure', 'aws'] as const).map((p) => (
                  <button key={p} className="choice" role="radio" aria-checked={provider === p} onClick={() => setProvider(p)}>
                    <strong>{p === 'azure' ? 'Azure' : 'AWS'}</strong>
                    <span>{cloud === null ? 'Checking…' : cloud[p] ? `Signed in: ${cloud[p]}` : 'Not signed in'}</span>
                  </button>
                ))}
              </div>
              {cloud && !signedIn && (
                <div style={{ marginTop: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                  {provider === 'azure' ? (
                    <button className="btn" disabled={busy.has('azlogin')} onClick={async () => {
                      const r = await act('azlogin', () => api.invoke('cloud:azure-login'))
                      if (r) setCloud(r)
                    }}>
                      <LogIn size={15} /> {busy.has('azlogin') ? 'Waiting for the browser…' : 'Sign in to Azure'}
                    </button>
                  ) : (
                    <span className="hint">In Terminal, run <span className="mono">aws configure</span> or <span className="mono">aws sso login</span>, then check again.</span>
                  )}
                  <button className="link" onClick={() => setCloud(null)}>Check again</button>
                </div>
              )}
            </FlowStep>
            <FlowStep n={2} title="Who writes the report" state="current">
              <ReviewerChoice value={reviewer} onChange={setReviewer} what="findings" />
            </FlowStep>
          </>
        )}

        {kind === 'server' && (
          <>
            <FlowStep n={1} title="Which servers" help="One server, a list, or a small network: a name or IP address per line, a range such as 192.168.1.10-20, or a network such as 192.168.1.0/28 (up to 64 servers at a time). Only connections are opened: nothing is logged into, guessed or changed. Install Nmap (brew install nmap) to also name the service on each port." state={validHost ? 'done' : 'current'}>
              <textarea className="input mono" rows={3} value={host} onChange={(e) => setHost(e.target.value)} placeholder={'example.com\n203.0.113.10\n192.168.1.0/28'} aria-label="Servers" />
              {multi && validHost && <span className="hint">{typedHosts.length} {typedHosts.length === 1 ? 'entry' : 'entries'}. Ranges and networks are expanded when the check starts.</span>}
            </FlowStep>
            <FlowStep n={2} title="How many ports" state="current">
              <div className="choices" role="radiogroup" aria-label="Ports">
                {(['top100', 'top1000'] as const).map((p) => (
                  <button key={p} className="choice" role="radio" aria-checked={ports === p} onClick={() => setPorts(p)}>
                    <strong>{p === 'top100' ? 'The 100 most common' : 'The 1,000 most common'}</strong>
                    <span>{p === 'top100' ? 'About a minute.' : 'A few minutes. Finds less common services too.'}</span>
                  </button>
                ))}
              </div>
            </FlowStep>
            <FlowStep n={3} title="Who writes the report" state="current">
              <ReviewerChoice value={reviewer} onChange={setReviewer} what="findings" />
            </FlowStep>
            {needsOk && (
              <label className="consent">
                <input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} />
                <span>
                  <strong style={{ color: 'var(--ink)' }}>I own these servers, or have written permission to test them.</strong> Port checks of servers you do not own may break the provider’s rules or the law.
                </span>
              </label>
            )}
          </>
        )}

        {(kind === 'full' || kind === 'changes') && (
          <FlowStep n={1} title="Which project" help={kind === 'changes' ? 'It needs to be a Git project: the review reads the changes on its current branch.' : 'Projects from your www folder.'} state={project ? 'done' : 'current'}>
            <select className="input" value={path} onChange={(e) => setPath(e.target.value)} aria-label="Project">
              {projects.length === 0 && <option value="">No projects in your www folder</option>}
              {projects.map((p) => (
                <option key={p.path} value={p.path}>
                  {p.name}
                  {p.git ? '' : ' (no Git)'}
                </option>
              ))}
            </select>
          </FlowStep>
        )}

        {kind === 'full' && (
          <>
            <FlowStep n={2} title="Where it runs" help="Its Laramac address is filled in when there is one. Use staging rather than production when you can." state={validSite ? 'done' : 'current'}>
              <input className="input mono" value={site} onChange={(e) => setSite(e.target.value)} placeholder="http://myproject.test" aria-label="Site address" />
            </FlowStep>
            <FlowStep n={3} title="Who writes the report" state="current">
              <ReviewerChoice value={reviewer} onChange={setReviewer} what="code" />
            </FlowStep>
            <FlowStep n={4} title="How deep" state="current">
              <div className="choices" role="radiogroup" aria-label="Depth">
                {(['quick', 'standard', 'deep'] as const).map((d) => (
                  <button key={d} className="choice" role="radio" aria-checked={depth === d} onClick={() => setDepth(d)}>
                    <strong style={{ textTransform: 'capitalize' }}>{d}</strong>
                    <span>{d === 'quick' ? 'A fast look at both.' : d === 'standard' ? 'The full code review and a standard web scan.' : 'Git history, every audit rule and a thorough web scan.'}</span>
                  </button>
                ))}
              </div>
            </FlowStep>
            {needsOk && (
              <label className="consent">
                <input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} />
                <span>
                  <strong style={{ color: 'var(--ink)' }}>I own this site, or have written permission to test it.</strong>
                </span>
              </label>
            )}
          </>
        )}

        <div className="flow-go glass">
          <span className="hint grow">
            {kind === 'portfolio'
              ? `Sweeps every project in ${settings?.wwwPath ?? 'your www folder'}.`
              : kind === 'changes'
                ? 'Runs as a normal Claude Code session, read-only, that you can continue in Terminal.'
                : kind === 'cloud'
                  ? 'Read-only. A large account can take 20 minutes or more; you can watch every step.'
                  : kind === 'server'
                    ? 'Plain connections only, at a gentle rate.'
                    : 'The code review and the web scan each get their own session too.'}
          </span>
          <button
            className="btn btn-primary btn-lg"
            disabled={!ready || busy.has('audit')}
            onClick={async () => {
              const req =
                kind === 'portfolio' ? { kind } : kind === 'changes' ? { kind, path } : kind === 'cloud' ? { kind, provider, reviewer } : kind === 'server' ? { kind, host: cleanHost, ports, reviewer, authorized: ok } : { kind, path, site: site.trim(), reviewer, depth, authorized: ok }
              const s = await act('audit', () => api.invoke('audit:start', req as never))
              if (s) showSession(s.id)
            }}
          >
            <Radar size={17} /> {start}
          </button>
        </div>
      </div>
    </>
  )
}

/** Cloud and servers: a cloud account or a server you own, read-only. */
export default function Audits(): React.JSX.Element {
  return (
    <>
      <PageHead title="Cloud and servers" desc="Check a cloud account against best practice, or the open ports of a server you own. Both only read: nothing is signed into, guessed or changed." />
      <AuditFlow kinds={CLOUD_KINDS} start="Start check" />
    </>
  )
}
const CLOUD_KINDS: Kind[] = ['cloud', 'server']
