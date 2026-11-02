import { useEffect, useState } from 'react'
import { GitCompareArrows, Layers3, Radar, ShieldHalf } from 'lucide-react'
import type { LocalProject, LocalSite, ReviewDepth, Reviewer } from '@shared/types'
import { useApp } from '../store'
import { FlowStep, PageHead } from '../ui'
import ReviewerChoice from '../components/ReviewerChoice'
import { isLocal } from './WebScan'

type Kind = 'full' | 'portfolio' | 'changes'

const AUDITS: { id: Kind; g: string; icon: React.ReactNode; title: string; text: string }[] = [
  { id: 'full', g: '#3ef0a8', icon: <ShieldHalf size={24} />, title: 'Full audit', text: 'A code review and a web scan of the same project, then one AI report that connects them: the route the code leaves open and the page that shows it.' },
  { id: 'portfolio', g: '#38e1ff', icon: <Layers3 size={24} />, title: 'Portfolio sweep', text: 'Every project in your www folder at once: keys and passwords in files and Git history, and packages with known flaws.' },
  { id: 'changes', g: '#8b6cff', icon: <GitCompareArrows size={24} />, title: 'Change review', text: 'Claude Code’s own /security-review of the changes on a project’s current branch, before you merge or deploy.' }
]

export default function Audits(): React.JSX.Element {
  const { settings, act, busy, showSession } = useApp()
  const api = window.macsec
  const [kind, setKind] = useState<Kind>('full')
  const [projects, setProjects] = useState<LocalProject[]>([])
  const [sites, setSites] = useState<LocalSite[]>([])
  const [path, setPath] = useState('')
  const [site, setSite] = useState('')
  const [reviewer, setReviewer] = useState<Reviewer>(settings?.reviewer ?? 'claude')
  const [depth, setDepth] = useState<ReviewDepth>('standard')
  const [ok, setOk] = useState(false)

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
  const needsOk = kind === 'full' && validSite && !isLocal(site.trim())
  const ready = kind === 'portfolio' || (kind === 'changes' && !!project) || (kind === 'full' && !!project && validSite && (!needsOk || ok))

  return (
    <>
      <PageHead title="Special audits" desc="Bigger jobs built from MacSec’s tests. Each one is kept as a session with its own report." />
      <div className="audit-grid" role="radiogroup" aria-label="Audit" style={{ marginBottom: 18 }}>
        {AUDITS.map((a) => (
          <button key={a.id} className="audit-card glass" role="radio" aria-checked={kind === a.id} onClick={() => setKind(a.id)}>
            <span className="glyph" style={{ ['--g' as string]: a.g }}>
              {a.icon}
            </span>
            <h3>{a.title}</h3>
            <p>{a.text}</p>
          </button>
        ))}
      </div>

      <div className="flow">
        {kind !== 'portfolio' && (
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
                : 'The code review and the web scan each get their own session too.'}
          </span>
          <button
            className="btn btn-primary btn-lg"
            disabled={!ready || busy.has('audit')}
            onClick={async () => {
              const req = kind === 'portfolio' ? { kind } : kind === 'changes' ? { kind, path } : { kind, path, site: site.trim(), reviewer, depth, authorized: ok }
              const s = await act('audit', () => api.invoke('audit:start', req as never))
              if (s) showSession(s.id)
            }}
          >
            <Radar size={17} /> Start audit
          </button>
        </div>
      </div>
    </>
  )
}
