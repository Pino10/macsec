import { LiveRun, useNow, clock, overall } from '../components/LiveRun'
import { useEffect, useMemo, useState } from 'react'
import { ArrowLeft, Bot, ChevronRight, CircleStop, ExternalLink, FileDown, FileSearch, FolderOpen, Search, Sparkles, Trash2, XCircle } from 'lucide-react'
import { SEVERITIES, type Finding, type FindingCategory, type SessionDetail, type SessionInfo, type Severity } from '@shared/types'
import { useApp } from '../store'
import Markdown from '../components/Markdown'
import ThreatCore, { postureScore, postureWord } from '../components/ThreatCore'
import { CodeView, Counts, Empty, KindIcon, PageHead, Sev, Spectrum, StepIcon, ago, duration, kindName } from '../ui'

const reviewerName = (s: SessionInfo): string => ({ claude: 'Claude Code', 'claude-local': 'Claude Code on your model', codex: 'Codex', gemini: 'Gemini CLI', model: 'Your model', none: 'No AI' } as const)[s.reviewer ?? 'none'] ?? 'No AI'

export default function Sessions(): React.JSX.Element {
  const { sessions, openSession, showSession } = useApp()
  const [q, setQ] = useState('')
  const [kind, setKind] = useState<SessionInfo['kind'] | 'all'>('all')
  if (openSession) return <SessionView id={openSession} onBack={() => showSession(null)} />
  const list = sessions.filter((s) => (kind === 'all' || s.kind === kind) && (!q.trim() || `${s.title} ${s.target}`.toLowerCase().includes(q.toLowerCase())))
  return (
    <>
      <PageHead title="Sessions" desc="Every test you ran, kept with its findings, the AI’s report and each tool’s raw output.">
        <button className="btn" onClick={() => void window.macsec.invoke('app:open-folder', 'sessions')}>
          <FolderOpen size={14} /> Open folder
        </button>
      </PageHead>
      {sessions.length === 0 ? (
        <Empty title="No tests yet">Run a code review, web scan or API review and it appears here.</Empty>
      ) : (
        <>
          <div style={{ display: 'flex', gap: 10, marginBottom: 14 }}>
            <div className="chips">
              {(['all', 'code-review', 'web-scan', 'api-scan', 'mobile-scan', 'recon', 'audit'] as const).map((k) => (
                <button key={k} className="chip" aria-pressed={kind === k} onClick={() => setKind(k)} style={{ textTransform: 'none' }}>
                  {k === 'all' ? 'All' : kindName(k)} <i>{k === 'all' ? sessions.length : sessions.filter((s) => s.kind === k).length}</i>
                </button>
              ))}
            </div>
            <div style={{ flex: 1, position: 'relative' }}>
              <Search size={14} style={{ position: 'absolute', left: 12, top: 13, color: 'var(--ink-3)' }} />
              <input className="input" style={{ paddingLeft: 34 }} placeholder="Find a project, site or API" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter" />
            </div>
          </div>
          <div className="panel">
            {list.map((s) => (
              <button key={s.id} className="row" onClick={() => showSession(s.id)}>
                <KindIcon kind={s.kind} size={16} />
                <span className="grow">
                  <span className="row-title" style={{ display: 'block' }}>
                    {s.title}
                  </span>
                  <span className="row-sub">
                    {kindName(s.kind)} of {s.target.replace(/^https?:\/\//, '')}, {ago(s.createdAt)}, {reviewerName(s)}
                  </span>
                </span>
                {s.status === 'running' ? (
                  <span className="tag tag-ion">
                    <span className="dot" data-s="busy" style={{ width: 6, height: 6 }} /> Running {overall(s)}%
                  </span>
                ) : s.status === 'done' ? (
                  <Counts counts={s.counts} />
                ) : (
                  <span className="tag">{s.status === 'failed' ? 'Failed' : 'Stopped'}</span>
                )}
                <ChevronRight size={15} style={{ color: 'var(--ink-3)' }} />
              </button>
            ))}
          </div>
        </>
      )}
    </>
  )
}

const CATS: [FindingCategory | 'all', string][] = [
  ['all', 'All'],
  ['ai', 'AI'],
  ['code', 'Code'],
  ['secret', 'Keys'],
  ['dependency', 'Packages'],
  ['config', 'Config'],
  ['web', 'Web'],
  ['api', 'API'],
  ['mobile', 'Mobile'],
  ['binary', 'Binary'],
  ['cloud', 'Cloud'],
  ['network', 'Ports'],
  ['recon', 'Recon']
]

function SessionView({ id, onBack }: { id: string; onBack: () => void }): React.JSX.Element {
  const { sessions, act, busy, setSessions, notify, showSession: showSessionById } = useApp()
  const api = window.macsec
  const [detail, setDetail] = useState<SessionDetail | null>(null)
  const [sevs, setSevs] = useState<Set<Severity>>(new Set(['critical', 'high', 'medium', 'low']))
  const [cat, setCat] = useState<FindingCategory | 'all'>('all')
  const [showFp, setShowFp] = useState(false)
  const [tab, setTab] = useState<'findings' | 'report' | 'run' | 'surface'>('findings')
  const [sel, setSel] = useState<string | null>(null)
  const live = sessions.find((s) => s.id === id)
  const now = useNow(live?.status === 'running')

  const stamp = `${live?.status}|${live?.steps.map((s) => `${s.status}${s.findings ?? ''}`).join(',')}`
  useEffect(() => {
    void api
      .invoke('sessions:get', id)
      .then(setDetail)
      .catch(() => setDetail(null))
  }, [api, id, stamp])

  const findings = useMemo(() => (detail?.findings ?? []).filter((f) => sevs.has(f.severity) && (cat === 'all' || f.category === cat) && (showFp || f.verdict !== 'false-positive')), [detail, sevs, cat, showFp])
  useEffect(() => {
    if (!findings.some((f) => f.id === sel)) setSel(findings[0]?.id ?? null)
  }, [findings, sel])

  if (!detail) return <Empty title="Opening…" />
  const s = { ...detail, ...(live ?? {}) }
  const fp = detail.findings.filter((f) => f.verdict === 'false-positive').length
  const running = s.status === 'running'
  const hasCode = (s.kind === 'code-review' || s.kind === 'audit') && !!s.codePath
  const current = findings.find((f) => f.id === sel) ?? null
  const cats = CATS.filter(([k]) => k === 'all' || detail.findings.some((f) => f.category === k))
  const total = SEVERITIES.reduce((n, k) => n + s.counts[k], 0)

  return (
    <>
      <button className="link" onClick={onBack} style={{ marginTop: 10 }}>
        <ArrowLeft size={14} /> All sessions
      </button>
      <div className="session-head">
        <div style={{ display: 'flex', gap: 14, alignItems: 'center', minWidth: 0 }}>
          <KindIcon kind={s.kind} size={20} />
          <div style={{ minWidth: 0 }}>
            <h1 className="page-title" style={{ fontSize: 28 }}>
              {s.title}
            </h1>
            <div className="hint" style={{ marginTop: 4 }}>
              {kindName(s.kind)} of <span className="mono">{s.target}</span>
              {', '}
              {new Date(s.createdAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })}
              {s.mode || s.depth ? `, ${s.mode ?? s.depth}` : ''}, {reviewerName(s)}
            </div>
          </div>
        </div>
        <div className="end">
          {running ? (
            <button className="btn btn-danger" onClick={() => void act('cancel', () => api.invoke('sessions:cancel', id))}>
              <CircleStop size={14} /> Stop
            </button>
          ) : (
            <>
              {hasCode && (
                <>
                  <button className="btn btn-primary" onClick={() => void act('claude', () => api.invoke('sessions:open', id, 'claude'))} data-tip="Opens Claude Code in Terminal, ready to fix these findings with you. With Remote Control on, you can also carry on at claude.ai/code or on your phone.">
                    <Sparkles size={14} /> Fix with Claude Code
                  </button>
                  <button className="btn" onClick={() => void act('codex', () => api.invoke('sessions:open', id, 'codex'))}>
                    <Bot size={14} /> Codex
                  </button>
                </>
              )}
              <button className="btn" disabled={busy.has('pdf')} onClick={() => void act('pdf', () => api.invoke('sessions:pdf', id)).then((p) => p && notify({ kind: 'info', text: 'Saved the PDF in the session folder.' }))}>
                <FileDown size={14} /> {busy.has('pdf') ? 'Making PDF…' : 'PDF'}
              </button>
            </>
          )}
          <button className="icon-btn" data-tip="Open the session folder" aria-label="Open the session folder" onClick={() => void api.invoke('sessions:open', id, 'folder')}>
            <FolderOpen />
          </button>
          {!running && (
            <button
              className="icon-btn danger-text"
              data-tip="Delete this session"
              aria-label="Delete this session"
              onClick={async () => {
                const r = await act('del', () => api.invoke('sessions:delete', id))
                if (r) {
                  setSessions(r)
                  onBack()
                }
              }}
            >
              <Trash2 />
            </button>
          )}
        </div>
      </div>

      {s.error && (
        <div className="notice bad">
          <XCircle size={17} style={{ color: 'var(--bad)', flexShrink: 0 }} /> {s.error}
        </div>
      )}

      <div className="kpis glass">
        <div className="kpi">
          <b>{running ? s.steps.filter((x) => x.status === 'done' || x.status === 'failed').length + '/' + s.steps.length : total}</b>
          <span>{running ? 'steps done' : 'open findings'}</span>
        </div>
        {SEVERITIES.map((k) => (
          <div key={k} className="kpi" data-zero={s.counts[k] === 0} style={{ ['--c' as string]: `var(--sev-${k})` }}>
            <b>{s.counts[k]}</b>
            <span>{k}</span>
          </div>
        ))}
      </div>
      {s.codeKept && (
        <p className="hint" style={{ margin: '-6px 2px 14px' }}>
          The downloaded code is kept in this session so you can fix it.{' '}
          <button className="link" onClick={() => void act('discard', () => api.invoke('sessions:discard-code', id))}>
            Delete it now
          </button>
        </p>
      )}

      {running && <LiveRun s={s} />}

      <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 14, flexWrap: 'wrap' }}>
        <div className="tabs" role="tablist">
          <button role="tab" aria-selected={tab === 'findings'} onClick={() => setTab('findings')}>
            Findings
          </button>
          <button role="tab" aria-selected={tab === 'report'} onClick={() => setTab('report')}>
            Report
          </button>
          <button role="tab" aria-selected={tab === 'run'} onClick={() => setTab('run')}>
            What ran
          </button>
          {s.kind === 'recon' && (
            <button role="tab" aria-selected={tab === 'surface'} onClick={() => setTab('surface')}>
              Hosts and scripts
            </button>
          )}
        </div>
        {tab === 'findings' && (
          <>
            <div className="chips">
              {SEVERITIES.map((k) => (
                <button key={k} className="chip" aria-pressed={sevs.has(k)} onClick={() => setSevs((x) => (x.has(k) ? new Set([...x].filter((y) => y !== k)) : new Set([...x, k])))}>
                  {k} <i>{detail.findings.filter((f) => f.severity === k && f.verdict !== 'false-positive').length}</i>
                </button>
              ))}
            </div>
            {cats.length > 2 && (
              <select className="input" style={{ width: 130, height: 30, fontSize: 12.5 }} value={cat} onChange={(e) => setCat(e.target.value as FindingCategory | 'all')} aria-label="Kind">
                {cats.map(([k, l]) => (
                  <option key={k} value={k}>
                    {l}
                  </option>
                ))}
              </select>
            )}
            {fp > 0 && (
              <label className="check" style={{ fontSize: 12.5 }}>
                <input type="checkbox" checked={showFp} onChange={(e) => setShowFp(e.target.checked)} /> {fp} ruled out by AI
              </label>
            )}
          </>
        )}
      </div>

      {(tab === 'run' || (running && detail.findings.length === 0 && tab === 'findings')) && (
        <div className="panel timeline" style={{ marginBottom: 14 }}>
          {s.steps.map((st) => (
            <div key={st.id} className="tl" data-status={st.status}>
              <StepIcon status={st.status} />
              <span>{st.label}</span>
              <span className="detail" title={st.lastLine ?? st.detail}>
                {st.status === 'running' ? (st.lastLine ?? st.detail ?? 'Working…') : (st.detail ?? (st.status === 'waiting' ? 'Waiting' : ''))}
                {st.ms ? `, ${duration(st.ms)}` : st.status === 'running' && st.startedAt ? `, ${clock(now - new Date(st.startedAt).getTime())}` : ''}
              </span>
              {st.status === 'running' && (
                <div className={`bar thin tl-bar${typeof st.progress === 'number' ? '' : ' busy'}`}>
                  <i style={typeof st.progress === 'number' ? { width: `${st.progress}%` } : undefined} />
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {tab === 'surface' && <Surface id={id} />}

      {tab === 'report' && (
        <>
          <div className="report-cover glass">
            <ThreatCore counts={s.counts} size={190} hasData={s.status === 'done'} running={running} />
            <div style={{ display: 'grid', gap: 16 }}>
              <div>
                <h2>{s.status === 'done' ? `${postureWord(postureScore(s.counts), true)} posture, ${total} open ${total === 1 ? 'finding' : 'findings'}` : running ? 'The report is being written' : 'This test did not finish'}</h2>
                <p className="page-desc" style={{ margin: 0 }}>
                  {kindName(s.kind)} of {s.target}. {detail.aiReport ? `Written by ${reviewerName(s)} after reading ${s.kind === 'code-review' ? 'the code and every scanner result' : 'every finding'}.` : 'No AI report for this test: the findings come straight from the scanners.'}
                </p>
              </div>
              <Spectrum counts={s.counts} />
            </div>
          </div>
          {s.children && s.children.length > 0 && (
            <div className="panel" style={{ marginBottom: 18 }}>
              {s.children.map((c) => {
                const child = sessions.find((x) => x.id === c)
                return child ? (
                  <button key={c} className="row" onClick={() => showSessionById(c)}>
                    <KindIcon kind={child.kind} size={15} />
                    <span className="grow">
                      <span className="row-title" style={{ display: 'block' }}>
                        {kindName(child.kind)}: {child.title}
                      </span>
                      <span className="row-sub">Its own session, with every detail</span>
                    </span>
                    <Counts counts={child.counts} />
                    <ChevronRight size={15} />
                  </button>
                ) : null
              })}
            </div>
          )}
          {detail.aiReport ? (
            <div className="md glass">
              <Markdown text={detail.aiReport} />
            </div>
          ) : (
            <Empty title="No AI report">Choose Claude Code, Codex or your model next time for a written report that explains every finding.</Empty>
          )}
        </>
      )}

      {tab === 'findings' &&
        (findings.length === 0 ? (
          !running && <Empty title={detail.findings.length ? 'Nothing matches these filters' : 'Nothing found'}>{detail.findings.length ? 'Try turning more severities on.' : 'None of the checks found a problem.'}</Empty>
        ) : (
          <div className="split">
            <div className="panel f-list" role="listbox" aria-label="Findings">
              {findings.map((f) => (
                <button key={f.id} className="f-row" role="option" data-sev={f.severity} data-fp={f.verdict === 'false-positive'} aria-selected={f.id === sel} onClick={() => setSel(f.id)}>
                  <Sev s={f.severity} />
                  <span className="t">{f.title}</span>
                  <span className="w">{f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : (f.advisory ?? f.tool)}</span>
                </button>
              ))}
            </div>
            {current && <Detail f={current} id={id} canOpen={hasCode} />}
          </div>
        ))}
    </>
  )
}

function Detail({ f, id, canOpen }: { f: Finding; id: string; canOpen: boolean }): React.JSX.Element {
  const api = window.macsec
  return (
    <div className="panel f-detail" key={f.id}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <Sev s={f.severity} />
        {f.verdict === 'confirmed' && <span className="tag tag-ok">Confirmed by AI</span>}
        {f.verdict === 'false-positive' && <span className="tag tag-warn">Ruled out by AI</span>}
        <span className="tag">{f.tool}</span>
        {f.cwe && (
          <button className="tag" style={{ border: 0, cursor: 'pointer' }} onClick={() => void api.invoke('app:open-external', `https://cwe.mitre.org/data/definitions/${f.cwe!.replace('CWE-', '')}.html`)}>
            {f.cwe} <ExternalLink size={10} />
          </button>
        )}
        {f.advisory && <span className="tag">{f.advisory}</span>}
      </div>
      <h3>{f.title}</h3>
      {(f.file || f.url) && <div className="where">{f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : f.url}</div>}
      {f.description && <p>{f.description}</p>}
      {f.context ? (
        <>
          <h5>The code</h5>
          <CodeView context={f.context} sev={f.severity} />
        </>
      ) : f.snippet ? (
        <>
          <h5>The code</h5>
          <pre>{f.snippet}</pre>
        </>
      ) : null}
      {(f.why || f.aiNote) && (
        <div className="ai-note">
          <b style={{ display: 'block', marginBottom: 4, fontWeight: 600 }}>{f.verdict === 'false-positive' ? 'Why the AI ruled it out' : `Why it is ${f.severity}`}</b>
          {f.why ?? f.aiNote}
        </div>
      )}
      {f.impact && (
        <>
          <h5>What could happen</h5>
          <p>{f.impact}</p>
        </>
      )}
      {(f.fix || f.fixCode) && (
        <div className="fix">
          <b>How to fix</b>
          {f.fix}
          {f.fixCode && <pre style={{ marginTop: 10 }}>{f.fixCode}</pre>}
        </div>
      )}
      {f.verify && (
        <>
          <h5>How to check the fix</h5>
          <p>{f.verify}</p>
        </>
      )}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {canOpen && f.file && !/^https?:/.test(f.file) && (
          <button className="btn btn-sm" onClick={() => void api.invoke('sessions:open', id, 'file', f.file, f.line)}>
            <FileSearch size={13} /> Open in editor
          </button>
        )}
        {f.url && /^https:\/\//.test(f.url) && (
          <button className="btn btn-sm" onClick={() => void api.invoke('app:open-external', f.url!)}>
            <ExternalLink size={13} /> {f.category === 'web' || f.category === 'api' ? 'Open page' : 'Details'}
          </button>
        )}
      </div>
    </div>
  )
}

type SurfaceData = NonNullable<Awaited<ReturnType<typeof window.macsec.invoke<'recon:data'>>>>

/** A recon's hosts, scripts, endpoints and parameters. */
function Surface({ id }: { id: string }): React.JSX.Element {
  const [d, setD] = useState<SurfaceData | null>(null)
  useEffect(() => {
    void window.macsec.invoke('recon:data', id).then(setD)
  }, [id])
  if (!d) return <div className="panel" style={{ padding: 20 }}><span className="hint">The map appears when the recon has collected it.</span></div>
  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div className="panel">
        <div style={{ padding: '14px 18px 4px' }} className="section-title">
          {d.hosts.length} hosts, {d.hosts.filter((h) => h.live).length} answer
        </div>
        {d.hosts.map((h) => (
          <div key={h.host} className="row" style={{ cursor: 'default' }}>
            <span className="grow">
              <span className="row-title mono" style={{ display: 'block' }}>
                {h.host}
              </span>
              <span className="row-sub">
                {h.ips.join(', ') || (h.cname ? `CNAME ${h.cname}` : 'does not resolve')} · {h.sources.join(', ')}
              </span>
            </span>
            {h.live && (
              <span className="hint" style={{ textAlign: 'right' }}>
                {h.live.status} {h.live.title?.slice(0, 40)}
                <br />
                {h.live.tech.slice(0, 4).join(', ')}
              </span>
            )}
          </div>
        ))}
      </div>
      <div className="panel">
        <div style={{ padding: '14px 18px 4px' }} className="section-title">
          {d.js.length} scripts, {d.js.filter((j) => j.sourceMap).length} with a public source map
        </div>
        {d.js
          .slice()
          .sort((a, b) => Number(!!b.sourceMap) - Number(!!a.sourceMap))
          .map((j) => (
            <div key={j.url} className="row" style={{ cursor: 'default' }}>
              <span className="grow">
                <span className="row-title mono" style={{ display: 'block', wordBreak: 'break-all' }}>
                  {j.url.replace(/^https?:\/\//, '')}
                </span>
                <span className="row-sub">
                  {Math.round(j.bytes / 1024)} KB · {j.endpoints.length} endpoints
                  {j.sourceMap ? ` · source map, ${j.sourceMap.files} files: ${j.sourceMap.sample.slice(0, 4).join(', ')}` : ''}
                  {j.secrets.length ? ` · keys: ${j.secrets.map((k) => `${k.kind} ${k.masked}`).join(', ')}` : ''}
                </span>
              </span>
            </div>
          ))}
      </div>
      <div className="panel" style={{ padding: 18 }}>
        <div className="section-title">Endpoints in the JavaScript, and parameters from {d.urls} archived URLs</div>
        <pre className="codeview" style={{ maxHeight: 360, overflow: 'auto', padding: 14 }}>{d.endpoints.join('\n') || 'None found.'}</pre>
        <p className="hint mono" style={{ wordBreak: 'break-word' }}>{d.params.slice(0, 200).join(', ')}</p>
      </div>
    </div>
  )
}
