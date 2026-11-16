import { useEffect, useState } from 'react'
import { ChevronRight, Download, FileSearch, Globe, Plug, ShieldAlert, ShieldCheck, RefreshCw, TrendingDown, TrendingUp } from 'lucide-react'
import { coverage, coverageText, sparkPath, trends, type TopFinding } from '@shared/insights'
import { latestPerTarget } from '@shared/latest'
import { SEVERITIES, type Severity } from '@shared/types'
import { useApp, type Page } from '../store'
import { Counts, KindIcon, Spectrum, ago, kindName } from '../ui'
import ThreatCore, { postureOf, postureScore, postureWord } from '../components/ThreatCore'
import Watch from '../components/Watch'

const LAUNCH: { page: Page; icon: React.ReactNode; g: string; title: string; text: string }[] = [
  { page: 'review', icon: <FileSearch size={20} />, g: '#38e1ff', title: 'Review code', text: 'Every scanner that fits, then an AI reviewer that checks their work.' },
  { page: 'web', icon: <Globe size={20} />, g: '#8b6cff', title: 'Scan a website', text: 'Headers, exposed files and thousands of known problems, read-only.' },
  { page: 'api', icon: <Plug size={20} />, g: '#ff3d7f', title: 'Check an API', text: 'Load a Postman or OpenAPI file and see what it gives away.' }
]
/** One go: a project's code and its live site, joined in one report. */
const testFully = (setPage: (p: Page) => void): void => {
  try {
    sessionStorage.setItem('macsec.reviewMode', 'full')
  } catch {
    // Not available: the page opens on the whole-project review.
  }
  setPage('review')
}

export default function Overview(): React.JSX.Element {
  const { sessions, tools, setPage, showSession, act, setTools, busy, notify, settings, updateSettings } = useApp()
  const [withPacks, setWithPacks] = useState(true)
  // One entry per target; an audit's own code review and web scan are counted inside the audit, not twice.
  const latest = new Map(latestPerTarget(sessions).map((s) => [`${s.kind}|${s.target}`, s] as const))
  const totals = SEVERITIES.reduce((acc, k) => ({ ...acc, [k]: [...latest.values()].reduce((n, s) => n + s.counts[k], 0) }), {} as Record<Severity, number>)
  const running = sessions.filter((s) => s.status === 'running')
  const worst = [...latest.values()].filter((s) => s.counts.critical + s.counts.high > 0).sort((a, b) => b.counts.critical - a.counts.critical || b.counts.high - a.counts.high).slice(0, 5)
  const missing = tools.filter((t) => !t.installed && t.method !== 'app')
  const score = postureOf([...latest.values()].map((s) => s.counts))
  const has = latest.size > 0
  // First run only: nothing installed, nothing tested, and the question not answered yet.
  const welcome = !!settings && !settings.welcomed && sessions.length === 0 && tools.length > 0 && tools.every((t) => !t.installed || t.method === 'app')
  const [top, setTop] = useState<TopFinding[]>([])
  const [macChecked, setMacChecked] = useState(false)
  const stamp = sessions.map((s) => `${s.id}:${s.status}:${s.counts.critical}:${s.counts.high}:${s.counts.medium}`).join('|')
  useEffect(() => {
    void window.macsec.invoke('overview:top').then(setTop).catch(() => setTop([]))
    void window.macsec.invoke('checkup:last').then((r) => setMacChecked(!!r)).catch(() => undefined)
  }, [stamp])
  const cover = coverageText(coverage(sessions, macChecked))
  const trend = trends(sessions, postureScore).slice(0, 4)

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Overview</h1>
          <p className="page-desc">Your security posture, from the latest test of each project, site and API. It changes when you test again or mark findings fixed, accepted or not a problem.</p>
        </div>
      </div>

      {welcome && (
        <section className="welcome glass">
          <h2>Welcome to MacSec</h2>
          <p className="page-desc" style={{ marginTop: 0 }}>
            MacSec tests your code, sites and APIs with free scanners, then an AI reviewer explains what matters. Everything only reads: nothing is attacked or changed.
          </p>
          <ol className="welcome-steps">
            <li>
              <b>Scanners</b> {missing.length} free scanners are downloaded into the MacSec folder only, each checked against its publisher’s checksum.
            </li>
            <li>
              <label className="check" style={{ display: 'inline-flex', gap: 8, alignItems: 'center' }}>
                <input type="checkbox" checked={withPacks} onChange={(e) => setWithPacks(e.target.checked)} />
                <span>
                  <b>Skill sets from security teams</b> Trail of Bits, Sentry, Cloudflare and Anthropic. Downloaded from GitHub. Untick to skip.
                </span>
              </label>
            </li>
          </ol>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <button
              className="btn btn-primary"
              disabled={busy.has('install-all')}
              onClick={async () => {
                await updateSettings({ welcomed: true })
                void window.macsec.invoke('packs:answer', withPacks)
                const r = await act('install-all', () => window.macsec.invoke('tools:install', ['uv', ...missing.map((t) => t.id)]))
                if (r) setTools(r)
              }}
            >
              <Download size={15} /> {busy.has('install-all') ? 'Installing…' : 'Install and get started'}
            </button>
            <button
              className="btn"
              onClick={async () => {
                await updateSettings({ welcomed: true })
                void window.macsec.invoke('packs:answer', false)
              }}
            >
              Not now
            </button>
            <span className="hint">You can add or remove any of these later on Tools.</span>
          </div>
        </section>
      )}

      {!welcome && missing.length > 0 && (
        <div className="notice info">
          <Download size={17} style={{ color: 'var(--ion)', flexShrink: 0 }} />
          <span className="grow">
            {missing.length} scanner{missing.length === 1 ? ' is' : 's are'} not installed yet. They go into the MacSec folder only, checked against their published checksums.
          </span>
          <button
            className="btn btn-sm btn-primary"
            disabled={busy.has('install-all')}
            onClick={async () => {
              const r = await act('install-all', () => window.macsec.invoke('tools:install', ['uv', ...missing.map((t) => t.id)]))
              if (r) setTools(r)
            }}
          >
            {busy.has('install-all') ? 'Installing…' : 'Install all'}
          </button>
        </div>
      )}

      <section className="hero glass">
        <div style={{ display: 'grid', gap: 12, justifyItems: 'center' }}>
          <ThreatCore counts={totals} size={300} running={running.length > 0} hasData={has} score={score} />
          {has && (
            <button
              className="btn btn-sm"
              disabled={busy.has('retest') || running.length > 0}
              title="Runs the newest test of each project, site and API again, so the core shows how things stand now"
              onClick={async () => {
                const r = await act('retest', () => window.macsec.invoke('sessions:rerun-latest'))
                if (r) notify({ kind: 'info', text: `${r.length} ${r.length === 1 ? 'test' : 'tests'} started again. The core updates as they finish.` })
              }}
            >
              <RefreshCw size={13} /> {running.length ? 'Testing…' : busy.has('retest') ? 'Starting…' : 'Test everything again'}
            </button>
          )}
        </div>
        <div style={{ display: 'grid', gap: 20 }}>
          <div>
            <h2>{has ? `Posture: ${postureWord(score, true).toLowerCase()}, ${score} out of 100` : 'Run your first test'}</h2>
            <p className="page-desc" style={{ marginTop: 0 }}>
              {!has
                ? 'Pick a project, a site or an API below. Results gather here, and the core in the middle shows how exposed you are.'
                : totals.critical
                  ? `${totals.critical} critical ${totals.critical === 1 ? 'problem needs' : 'problems need'} fixing first, across ${latest.size} ${latest.size === 1 ? 'target' : 'targets'}.`
                  : totals.high
                    ? `No critical problems. ${totals.high} high ${totals.high === 1 ? 'one is' : 'ones are'} worth fixing next.`
                    : `Nothing critical or high across ${latest.size} ${latest.size === 1 ? 'target' : 'targets'}.`}
            </p>
          </div>
          {has && <Spectrum counts={totals} />}
          {has && (
            <p className="coverage">
              {cover.basedOn}{' '}
              {cover.missing.length > 0 && (
                <>
                  Not tested yet:{' '}
                  {cover.missing.map((m, i) => (
                    <span key={m.area}>
                      {i > 0 && ', '}
                      <button className="link" onClick={() => setPage(m.page)}>
                        {m.name}
                      </button>
                    </span>
                  ))}
                  . A good score only covers what was tested.
                </>
              )}
            </p>
          )}
          {has && top.length > 0 && (
            <div>
              <h3 className="fix-first-title">Fix these first</h3>
              <div className="panel inner-well">
                {top.map((f) => (
                  <button key={`${f.session}-${f.id}`} className="row fix-row" onClick={() => showSession(f.session)}>
                    <span className="sev" data-sev={f.severity}>
                      {f.severity}
                    </span>
                    <span style={{ minWidth: 0 }}>
                      <span className="row-title" style={{ display: 'block' }}>
                        {f.title}
                      </span>
                      <span className="row-sub">
                        {f.sessionTitle}
                        {f.where ? ` · ${f.where}` : ''}
                      </span>
                    </span>
                    <ChevronRight size={16} style={{ color: 'var(--ink-3)' }} />
                  </button>
                ))}
              </div>
            </div>
          )}
          {!(has && top.length > 0) && (
          <div className="panel inner-well">
            <button className="row launch" onClick={() => testFully(setPage)}>
              <span className="glyph" style={{ ['--g' as string]: '#3ef0a8' }}>
                <ShieldCheck size={20} />
              </span>
              <span>
                <span className="row-title" style={{ display: 'block' }}>
                  Test a project fully
                </span>
                <span className="row-sub">Its code and its live site in one go, joined in one report.</span>
              </span>
              <ChevronRight size={16} style={{ color: 'var(--ink-3)' }} />
            </button>
            {LAUNCH.map((l) => (
              <button key={l.page} className="row launch" onClick={() => setPage(l.page)}>
                <span className="glyph" style={{ ['--g' as string]: l.g }}>
                  {l.icon}
                </span>
                <span>
                  <span className="row-title" style={{ display: 'block' }}>
                    {l.title}
                  </span>
                  <span className="row-sub">{l.text}</span>
                </span>
                <ChevronRight size={16} style={{ color: 'var(--ink-3)' }} />
              </button>
            ))}
          </div>
          )}
        </div>
      </section>

      {has && top.length > 0 && (
        <div className="launch-strip">
          <button className="launch-chip glass" onClick={() => testFully(setPage)}>
            <span className="glyph" style={{ ['--g' as string]: '#3ef0a8' }}>
              <ShieldCheck size={20} />
            </span>
            <span>
              <span className="row-title" style={{ display: 'block' }}>
                Test a project fully
              </span>
              <span className="row-sub">Its code and its live site in one go.</span>
            </span>
          </button>
          {LAUNCH.map((l) => (
            <button key={l.page} className="launch-chip glass" onClick={() => setPage(l.page)}>
              <span className="glyph" style={{ ['--g' as string]: l.g }}>
                {l.icon}
              </span>
              <span>
                <span className="row-title" style={{ display: 'block' }}>
                  {l.title}
                </span>
                <span className="row-sub">{l.text}</span>
              </span>
            </button>
          ))}
        </div>
      )}

      {trend.length > 0 && (
        <>
          <h2 className="section-title">Getting safer?</h2>
          <div className="trend-grid">
            {trend.map((t) => {
              const now = t.points[t.points.length - 1].score
              return (
                <div key={t.key} className="panel trend">
                  <div>
                    <span className="row-title" style={{ display: 'block' }}>
                      {t.title}
                    </span>
                    <span className="row-sub">
                      {now} out of 100, {t.points.length} tests
                    </span>
                  </div>
                  <svg viewBox="0 0 120 36" width="120" height="36" aria-hidden>
                    <path d={sparkPath(t.points.map((p) => p.score), 120, 34)} fill="none" stroke={t.change < 0 ? 'var(--sev-high)' : 'var(--ok)'} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" transform="translate(0 1)" />
                  </svg>
                  <span className="trend-change" data-dir={t.change > 0 ? 'up' : t.change < 0 ? 'down' : 'same'}>
                    {t.change > 0 ? <TrendingUp size={14} /> : t.change < 0 ? <TrendingDown size={14} /> : null}
                    {t.change > 0 ? `Up ${t.change}` : t.change < 0 ? `Down ${-t.change}` : 'No change'}
                  </span>
                </div>
              )
            })}
          </div>
        </>
      )}

      <div className="two" style={{ marginTop: 6 }}>
        <div>
          <h2 className="section-title">Needs attention</h2>
          <div className="panel">
            {worst.length === 0 ? (
              <div className="row">
                <ShieldCheck size={17} style={{ color: 'var(--ok)' }} />
                <span className="hint">{has ? 'No critical or high findings in your latest tests.' : 'Problems that need fixing show up here.'}</span>
              </div>
            ) : (
              worst.map((s) => (
                <button key={s.id} className="row" onClick={() => showSession(s.id)}>
                  <ShieldAlert size={17} style={{ color: s.counts.critical ? 'var(--sev-critical)' : 'var(--sev-high)' }} />
                  <span className="grow">
                    <span className="row-title" style={{ display: 'block' }}>
                      {s.title}
                    </span>
                    <span className="row-sub">
                      {kindName(s.kind)}, {ago(s.createdAt)}
                    </span>
                  </span>
                  <Counts counts={s.counts} />
                </button>
              ))
            )}
          </div>
        </div>
        <div>
          <h2 className="section-title">Recent tests</h2>
          <div className="panel">
            {sessions.length === 0 ? (
              <div className="row">
                <span className="hint">Every test is kept as a session you can reopen, export as a PDF or continue in Claude Code.</span>
              </div>
            ) : (
              sessions.slice(0, 6).map((s) => (
                <button key={s.id} className="row" onClick={() => showSession(s.id)}>
                  <KindIcon kind={s.kind} size={15} />
                  <span className="grow">
                    <span className="row-title" style={{ display: 'block' }}>
                      {s.title}
                    </span>
                    <span className="row-sub">{s.status === 'running' ? s.steps.find((x) => x.status === 'running')?.label ?? 'Starting' : `${kindName(s.kind)}, ${ago(s.createdAt)}`}</span>
                  </span>
                  {s.status === 'running' ? <span className="dot" data-s="busy" /> : s.status === 'done' ? <Counts counts={s.counts} /> : <span className="hint">{s.status}</span>}
                </button>
              ))
            )}
          </div>
        </div>
      </div>
      <Watch />
    </>
  )
}
