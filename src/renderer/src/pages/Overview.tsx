import { ArrowRight, Download, FileSearch, FolderGit2, ShieldAlert, ShieldCheck } from 'lucide-react'
import { SEVERITIES, type Severity } from '@shared/types'
import { useApp } from '../store'
import { Counts, PageHead, SevTiles, ago } from '../ui'

export default function Overview(): React.JSX.Element {
  const { sessions, tools, setPage, showSession, act, setTools, busy } = useApp()
  // The latest finished session per target is the current state of that target.
  const latest = new Map<string, (typeof sessions)[number]>()
  for (const s of sessions) if (s.status === 'done' && !latest.has(s.target)) latest.set(s.target, s)
  const totals = SEVERITIES.reduce((acc, k) => ({ ...acc, [k]: [...latest.values()].reduce((n, s) => n + s.counts[k], 0) }), {} as Record<Severity, number>)
  const worst = [...latest.values()].filter((s) => s.counts.critical + s.counts.high > 0).sort((a, b) => b.counts.critical - a.counts.critical || b.counts.high - a.counts.high).slice(0, 5)
  const missing = tools.filter((t) => !t.installed && ['code', 'secrets', 'deps'].includes(t.category))
  const running = sessions.filter((s) => s.status === 'running')

  return (
    <>
      <PageHead title="Overview" desc="The security state of your projects, from the latest review of each.">
        <button className="btn btn-primary" onClick={() => setPage('review')}>
          <FileSearch size={14} /> New code review
        </button>
      </PageHead>

      {missing.length > 0 && (
        <div className="notice info" style={{ marginBottom: 16 }}>
          <Download size={16} style={{ flexShrink: 0, marginTop: 2 }} />
          <div style={{ flex: 1 }}>
            <strong>Install the code review scanners</strong> ({missing.map((t) => t.name).join(', ')}). They go into the MacSec folder only, and are checked against their published checksums.
          </div>
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

      <SevTiles counts={totals} />
      <p className="hint" style={{ margin: '8px 2px 0' }}>
        Across {latest.size} {latest.size === 1 ? 'project' : 'projects'}. Findings the AI reviewer ruled out are not counted.
      </p>

      {running.length > 0 && (
        <>
          <h2 className="section-title">Running now</h2>
          <div className="panel">
            {running.map((s) => (
              <button key={s.id} className="ms-row link-row" style={{ width: '100%', background: 'none', border: 0, color: 'inherit', font: 'inherit', textAlign: 'left', cursor: 'pointer' }} onClick={() => showSession(s.id)}>
                <ShieldCheck size={16} className="spin" style={{ color: 'var(--accent-text)', animationDuration: '3s' }} />
                <div className="grow">
                  <div className="row-title">{s.title}</div>
                  <div className="row-sub">{s.steps.find((x) => x.status === 'running')?.label ?? 'Starting'}</div>
                </div>
                <ArrowRight size={14} />
              </button>
            ))}
          </div>
        </>
      )}

      <div className="two" style={{ marginTop: 6 }}>
        <div>
          <h2 className="section-title">Needs attention</h2>
          <div className="panel">
            {worst.length === 0 ? (
              <div className="ms-row">
                <ShieldCheck size={16} style={{ color: 'var(--ok)' }} />
                <span className="hint">{latest.size ? 'No critical or high findings in your latest reviews.' : 'Run your first review to see results here.'}</span>
              </div>
            ) : (
              worst.map((s) => (
                <button key={s.id} className="ms-row" style={{ width: '100%', background: 'none', border: 0, color: 'inherit', font: 'inherit', textAlign: 'left', cursor: 'pointer' }} onClick={() => showSession(s.id)}>
                  <ShieldAlert size={16} style={{ color: 'var(--sev-high)' }} />
                  <div className="grow">
                    <div className="row-title">{s.title}</div>
                    <div className="row-sub">{ago(s.createdAt)}</div>
                  </div>
                  <Counts counts={s.counts} />
                </button>
              ))
            )}
          </div>
        </div>
        <div>
          <h2 className="section-title">Recent sessions</h2>
          <div className="panel">
            {sessions.length === 0 ? (
              <div className="ms-row">
                <FolderGit2 size={16} style={{ color: 'var(--ink-3)' }} />
                <span className="hint">
                  Pick a project on{' '}
                  <button className="link" onClick={() => setPage('projects')}>
                    Projects
                  </button>{' '}
                  to begin.
                </span>
              </div>
            ) : (
              sessions.slice(0, 6).map((s) => (
                <button key={s.id} className="ms-row" style={{ width: '100%', background: 'none', border: 0, color: 'inherit', font: 'inherit', textAlign: 'left', cursor: 'pointer' }} onClick={() => showSession(s.id)}>
                  <FileSearch size={16} style={{ color: 'var(--ink-3)' }} />
                  <div className="grow">
                    <div className="row-title">{s.title}</div>
                    <div className="row-sub">
                      {ago(s.createdAt)} · {s.status === 'running' ? 'running' : s.status}
                    </div>
                  </div>
                  {s.status === 'done' && <Counts counts={s.counts} />}
                </button>
              ))
            )}
          </div>
        </div>
      </div>
    </>
  )
}
