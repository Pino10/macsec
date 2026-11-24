import ProofBlock, { ConfidenceTag, ExploitTag } from '../components/ProofBlock'
import ChecklistView from '../components/ChecklistView'
import FixPlan from '../components/FixPlan'
import { LiveRun, useNow, clock, overall } from '../components/LiveRun'
import { useEffect, useMemo, useRef, useState } from 'react'
import { issueText } from '@shared/insights'
import { tokensText } from '@shared/estimate'
import { verificationOf, VERIFICATION_TEXT, asvsOf } from '@shared/verification'
import { ArrowLeft, Bot, Check, ChevronRight, Copy, CircleStop, ExternalLink, FileDown, FileSearch, FolderOpen, Search, Sparkles, Trash2, XCircle, RefreshCw, Pause, Play, Ticket, Bug, RotateCcw, FileText, Globe } from 'lucide-react'
import { SEVERITIES, type Finding, type FindingCategory, type SearchHit, type SessionDetail, type SessionInfo, type Severity, type SessionCompare, type VhostHit, type PatchRecord } from '@shared/types'
import { useApp } from '../store'
import Markdown from '../components/Markdown'
import { SessionMasvs, SessionOwasp } from '../components/OwaspList'
import { ReconPages } from '../components/ReconPages'
import ThreatCore, { postureScore, postureWord } from '../components/ThreatCore'
import SurfaceGraph from '../components/SurfaceGraph'
import { FixDiff, LeakHelp } from '../components/FixHelp'
import { CodeView, Counts, Empty, KindIcon, PageHead, Sev, Spectrum, StepIcon, ago, duration, kindName } from '../ui'

const reviewerName = (s: SessionInfo): string => ({ claude: 'Claude Code', 'claude-local': 'Claude Code on your model', 'claude-free': 'Claude Code on Free LLM API', codex: 'Codex', gemini: 'Gemini CLI', model: 'Your model', none: 'No AI' } as const)[s.reviewer ?? 'none'] ?? 'No AI'

export default function Sessions(): React.JSX.Element {
  const { sessions, openSession, showSession } = useApp()
  const [q, setQ] = useState('')
  const [hits, setHits] = useState<SearchHit[]>([])
  const [kind, setKind] = useState<SessionInfo['kind'] | 'all'>('all')
  const list = sessions.filter((s) => (kind === 'all' || s.kind === kind) && (!q.trim() || `${s.title} ${s.target}`.toLowerCase().includes(q.toLowerCase())))
  // The same box searches inside every finding, not only the session titles.
  useEffect(() => {
    if (q.trim().length < 2) {
      setHits([])
      return
    }
    const t = window.setTimeout(() => void window.macsec.invoke('sessions:search', q).then(setHits).catch(() => setHits([])), 300)
    return () => window.clearTimeout(t)
  }, [q])
  if (openSession) return <SessionView id={openSession} onBack={() => showSession(null)} />
  return (
    <>
      <PageHead title="Results" desc="Every test you ran, kept with its findings, the AI’s report and each tool’s raw output.">
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
          {q.trim().length >= 2 && (
            <div className="panel" style={{ marginTop: 14 }}>
              <div className="row" style={{ cursor: 'default' }}>
                <span className="grow">
                  <span className="row-title">{hits.length ? `${hits.length} finding${hits.length === 1 ? '' : 's'} match "${q}" in every session` : `No finding matches "${q}"`}</span>
                  <span className="row-sub">Searching titles, tools, files and addresses in every finished session.</span>
                </span>
              </div>
              {hits.slice(0, 30).map((h) => (
                <button key={`${h.sessionId}-${h.findingId}`} className="row" onClick={() => showSession(h.sessionId)}>
                  <Sev s={h.severity as never} />
                  <span className="grow">
                    <span className="row-title" style={{ display: 'block' }}>{h.title}</span>
                    <span className="row-sub">{kindName(h.kind)}: {h.sessionTitle}{h.where ? ` · ${h.where}` : ''}</span>
                  </span>
                </button>
              ))}
            </div>
          )}
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
  const [paused, setPaused] = useState(false)
  const [onlyProven, setOnlyProven] = useState(false)
  const [tab, setTab] = useState<'findings' | 'paths' | 'owasp' | 'report' | 'run' | 'surface' | 'checklist'>('findings')
  const [sel, setSel] = useState<string | null>(null)
  const [sureDelete, setSureDelete] = useState(false)
  const [selecting, setSelecting] = useState(false)
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const [owner, setOwner] = useState('')
  const [due, setDue] = useState('')
  const togglePick = (fid: string): void => setPicked((p) => { const n = new Set(p); if (n.has(fid)) n.delete(fid); else n.add(fid); return n })
  const applyBulk = async (t: 'fixed' | 'accepted' | 'not-a-problem' | null): Promise<void> => {
    const d = await act('bulk', () => api.invoke('findings:triage-bulk', id, [...picked], t, { ...(owner.trim() ? { owner: owner.trim() } : {}), ...(due ? { due } : {}) }))
    if (d) {
      setDetail(d)
      setPicked(new Set())
      setSelecting(false)
      setOwner('')
      setDue('')
    }
  }
  const listRef = useRef<HTMLDivElement | null>(null)
  const onListKeys = (e: React.KeyboardEvent<HTMLDivElement>): void => {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(e.key)) return
    const items = [...(listRef.current?.querySelectorAll<HTMLButtonElement>('button.f-row') ?? [])]
    if (!items.length) return
    e.preventDefault()
    const at = items.indexOf(document.activeElement as HTMLButtonElement)
    const next = e.key === 'Home' ? 0 : e.key === 'End' ? items.length - 1 : e.key === 'ArrowDown' ? Math.min(items.length - 1, at + 1) : Math.max(0, at - 1)
    items[next]?.focus()
  }
  const onTabKeys = (e: React.KeyboardEvent<HTMLDivElement>): void => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return
    const tabs = [...e.currentTarget.querySelectorAll<HTMLButtonElement>('[role=tab]')]
    const at = tabs.indexOf(document.activeElement as HTMLButtonElement)
    if (at < 0) return
    e.preventDefault()
    const n = e.key === 'ArrowRight' ? (at + 1) % tabs.length : (at - 1 + tabs.length) % tabs.length
    tabs[n].focus()
    tabs[n].click()
  }
  const live = sessions.find((s) => s.id === id)
  const now = useNow(live?.status === 'running')

  const stamp = `${live?.status}|${live?.steps.map((s) => `${s.status}${s.findings ?? ''}`).join(',')}`
  useEffect(() => {
    void api
      .invoke('sessions:get', id)
      .then(setDetail)
      .catch(() => setDetail(null))
  }, [api, id, stamp])

  const findings = useMemo(() => (detail?.findings ?? []).filter((f) => sevs.has(f.severity) && (cat === 'all' || f.category === cat) && (showFp || f.verdict !== 'false-positive') && (!onlyProven || f.confidence === 'confirmed')), [detail, sevs, cat, showFp, onlyProven])
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
  // Open means: not dealt with by you, and not ruled out by the AI. The same rule as the list below, so the numbers agree.
  const openList = detail.findings.filter((f) => !f.triage && f.verdict !== 'false-positive')
  const openBy = (k: Severity): number => openList.filter((f) => f.severity === k).length
  const total = openList.length
  const hiddenInfo = !sevs.has('info') ? openList.filter((f) => f.severity === 'info' && (cat === 'all' || f.category === cat)).length : 0

  return (
    <>
      <button className="link" onClick={onBack} style={{ marginTop: 10 }}>
        <ArrowLeft size={14} /> All results
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
              {s.estimate && s.estimate.tokens > 0 ? `, AI estimate ${tokensText(s.estimate.tokens)} tokens${s.estimate.costUsd === null ? ' (included in your plan)' : s.estimate.costUsd === 0 ? ' (no cost)' : ` (about $${s.estimate.costUsd})`}` : ''}
            </div>
          </div>
        </div>
        <div className="end">
          {running ? (
            <>
              <button className="btn" aria-pressed={paused} onClick={() => void act('pause', () => api.invoke('sessions:pause', id, !paused)).then((v) => setPaused(v === true))} data-tip="Pauses the tools and MacSec's own requests where they are. Resume carries on.">
                {paused ? <Play size={14} /> : <Pause size={14} />} {paused ? 'Resume' : 'Pause'}
              </button>
              <button className="btn btn-danger" onClick={() => void act('cancel', () => api.invoke('sessions:cancel', id))}>
                <CircleStop size={14} /> Stop
              </button>
            </>
          ) : (
            <>
              {s.kind === 'recon' && (
                <button className="btn btn-primary" onClick={async () => { const r = await act('handoff', () => api.invoke('recon:handoff', id)); if (r) showSessionById(r.id) }} data-tip="Starts a web scan of the first live host, with the pages and endpoints this recon found already in the list.">
                  <Globe size={14} /> Scan this site
                </button>
              )}
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
              <button className="btn" disabled={busy.has('pdfx')} onClick={() => void act('pdfx', () => api.invoke('sessions:pdf-executive', id)).then((p) => p && notify({ kind: 'info', text: 'Saved the one-page summary in the session folder.' }))} data-tip="A short summary for people who decide: the score, what to fix first and how problems connect.">
                <FileText size={14} /> {busy.has('pdfx') ? 'Making summary…' : 'Summary'}
              </button>
            </>
          )}
          {!running && (
            <button
              className="btn"
              disabled={busy.has('rerun')}
              title="Runs the same test again, as a new session"
              onClick={async () => {
                const r = await act('rerun', () => api.invoke('sessions:rerun', id))
                if (r) showSessionById(r.id)
              }}
            >
              <RefreshCw size={14} /> Test again
            </button>
          )}
          {!running && (
            <select
              className="input"
              style={{ width: 150 }}
              value=""
              aria-label="Export findings"
              onChange={(e) => {
                const f = e.target.value as 'sarif' | 'defectdojo' | 'cyclonedx' | 'csv' | 'json' | 'masvs-report'
                if (f) void act('export', () => api.invoke('sessions:export', id, f)).then((p) => p && notify({ kind: 'info', text: 'Exported.' }))
              }}
            >
              <option value="">Export…</option>
              {live?.kind === 'mobile-scan' && <option value="masvs-report">MASVS report (open, then Print to PDF)</option>}
              <option value="sarif">SARIF (GitHub, editors)</option>
              <option value="defectdojo">DefectDojo</option>
              <option value="cyclonedx">SBOM (CycloneDX)</option>
              <option value="csv">CSV (a spreadsheet)</option>
              <option value="json">JSON</option>
            </select>
          )}
          <button className="icon-btn" data-tip="Open the session folder" aria-label="Open the session folder" onClick={() => void api.invoke('sessions:open', id, 'folder')}>
            <FolderOpen />
          </button>
          {!running && (
            <button
              className={sureDelete ? 'btn btn-danger btn-sm' : 'icon-btn danger-text'}
              data-tip={sureDelete ? 'This deletes the session folder and its raw output for good' : 'Delete this session'}
              title={sureDelete ? 'This deletes the session folder and its raw output for good' : 'Delete this session'}
              aria-label={sureDelete ? 'Confirm deleting this session' : 'Delete this session'}
              onClick={async () => {
                if (!sureDelete) {
                  setSureDelete(true)
                  window.setTimeout(() => setSureDelete(false), 6000)
                  return
                }
                const r = await act('del', () => api.invoke('sessions:delete', id))
                if (r) {
                  setSessions(r)
                  onBack()
                }
              }}
            >
              {sureDelete ? 'Delete for good' : <Trash2 />}
            </button>
          )}
        </div>
      </div>

      {!running && <SinceLastTime id={id} />}

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
          <div key={k} className="kpi" data-zero={(running ? s.counts[k] : openBy(k)) === 0} style={{ ['--c' as string]: `var(--sev-${k})` }}>
            <b>{running ? s.counts[k] : openBy(k)}</b>
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
        <div className="tabs" role="tablist" onKeyDown={onTabKeys}>
          <button role="tab" aria-selected={tab === 'findings'} onClick={() => setTab('findings')}>
            Findings
          </button>
          <button role="tab" aria-selected={tab === 'paths'} onClick={() => setTab('paths')}>
            Attack paths
          </button>
          {(live?.kind === 'web-scan' || live?.kind === 'api-scan' || live?.kind === 'mobile-scan') && (
            <button role="tab" aria-selected={tab === 'owasp'} onClick={() => setTab('owasp')}>
              {live?.kind === 'mobile-scan' ? 'OWASP' : 'OWASP Top 10'}
            </button>
          )}
          <button role="tab" aria-selected={tab === 'report'} onClick={() => setTab('report')}>
            Report
          </button>
          <button role="tab" aria-selected={tab === 'run'} onClick={() => setTab('run')}>
            What ran
          </button>
          {s.kind === 'web-scan' && (
            <button role="tab" aria-selected={tab === 'checklist'} onClick={() => setTab('checklist')}>
              Checklist
            </button>
          )}
          {(s.kind === 'recon' || s.kind === 'web-scan') && (
            <button role="tab" aria-selected={tab === 'surface'} onClick={() => setTab('surface')}>
              {s.kind === 'recon' ? 'Pages and hosts' : 'JavaScript map'}
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
            {detail.findings.some((f) => f.confidence) && (
              <label className="check" style={{ fontSize: 12.5 }}>
                <input type="checkbox" checked={onlyProven} onChange={(e) => setOnlyProven(e.target.checked)} /> Confirmed only ({detail.findings.filter((f) => f.confidence === 'confirmed').length})
              </label>
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

      {tab === 'paths' && <AttackPaths detail={detail} onPick={(fid) => { setTab('findings'); setSel(fid) }} />}
      {tab === 'surface' && <Surface id={id} detail={detail} onPick={setSel} />}
      {tab === 'checklist' && <ChecklistView id={id} />}
      {tab === 'owasp' && (
        <>
          {live?.kind === 'mobile-scan' && <SessionMasvs id={id} stamp={stamp} />}
          <SessionOwasp id={id} stamp={stamp} />
        </>
      )}

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
              <ExploitStrip findings={detail.findings} />
            </div>
          </div>
          <FixPlan detail={detail} />
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
          {detail.plan && (
            <div className="md glass" style={{ marginTop: 18 }}>
              <Markdown text={detail.plan} />
            </div>
          )}
        </>
      )}

          {tab === 'findings' && (
            <div className="bulk-bar">
              {!selecting ? (
                <button className="btn btn-sm" onClick={() => { setSelecting(true); setPicked(new Set()) }}>Select findings</button>
              ) : (
                <>
                  <span className="hint">{picked.size} selected</span>
                  <input className="input" style={{ width: 170, height: 30 }} placeholder="Owner (optional)" value={owner} onChange={(e) => setOwner(e.target.value)} aria-label="Owner" />
                  <input className="input" style={{ width: 150, height: 30 }} type="date" value={due} onChange={(e) => setDue(e.target.value)} aria-label="Due date" />
                  <button className="btn btn-sm" disabled={!picked.size} onClick={() => void applyBulk('fixed')}>Fixed</button>
                  <button className="btn btn-sm" disabled={!picked.size} onClick={() => void applyBulk('accepted')}>Accepted</button>
                  <button className="btn btn-sm" disabled={!picked.size} onClick={() => void applyBulk('not-a-problem')}>Not a problem</button>
                  <button className="btn btn-sm" disabled={!picked.size} onClick={() => void applyBulk(null)}>Clear</button>
                  <button className="link" onClick={() => { setSelecting(false); setPicked(new Set()) }}>Done</button>
                </>
              )}
            </div>
          )}
      {tab === 'findings' &&
        (findings.length === 0 ? (
          !running && <Empty title={detail.findings.length ? 'Nothing matches these filters' : 'Nothing found'}>{detail.findings.length ? 'Try turning more severities on.' : 'None of the checks found a problem.'}</Empty>
        ) : (
          <div className="split">
            <div className="panel f-list" role="listbox" aria-label="Findings" ref={listRef} onKeyDown={onListKeys}>
              {hiddenInfo > 0 && (
                <div className="f-note">
                  {hiddenInfo} info {hiddenInfo === 1 ? 'note is' : 'notes are'} hidden.{' '}
                  <button className="link" onClick={() => setSevs((x) => new Set([...x, 'info']))}>
                    Show {hiddenInfo === 1 ? 'it' : 'them'}
                  </button>
                </div>
              )}
              {findings.map((f) => (
                <button
                  key={f.id}
                  className="f-row"
                  role="option"
                  data-sev={f.severity}
                  data-fp={f.verdict === 'false-positive' || !!f.triage}
                  data-picked={selecting ? picked.has(f.id) : undefined}
                  aria-selected={selecting ? picked.has(f.id) : f.id === sel}
                  onClick={() => (selecting ? togglePick(f.id) : setSel(f.id))}
                >
                  {selecting && <span className="pick">{picked.has(f.id) ? <Check size={13} /> : null}</span>}
                  <Sev s={f.severity} />
                  <span className="t">{f.title}</span>
                  {f.exploit ? <ExploitTag f={f} compact /> : f.confidence === 'possible' && <span className="tag tag-warn" style={{ flex: 'none' }}>Possible</span>}
                  <span className="w">{f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : (f.advisory ?? f.tool)}</span>
                </button>
              ))}
            </div>
            {current && <Detail f={current} id={id} canOpen={hasCode} canFix={hasCode} from={s.title} onChange={setDetail} />}
          </div>
        ))}
    </>
  )
}

/** Proven, known exploited, likely and not proven, counted over the findings that are still open. */
function ExploitStrip({ findings }: { findings: Finding[] }): React.JSX.Element | null {
  const open = findings.filter((f) => f.exploit && f.verdict !== 'false-positive' && !f.triage)
  if (!open.length) return null
  const n = (s: string): number => open.filter((f) => f.exploit!.state === s).length
  const chips: [string, string, string][] = [['proven', 'Proven', 'tag tag-ok'], ['known-exploited', 'Known exploited', 'tag tag-bad'], ['likely', 'Likely', 'tag tag-warn'], ['unproven', 'Not proven', 'tag']]
  return (
    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }} title="Proven means a harmless request showed the problem and the proof can be repeated. The rest are leads.">
      {chips.filter(([k]) => n(k)).map(([k, l, c]) => (
        <span key={k} className={c}>
          {n(k)} {l.toLowerCase()}
        </span>
      ))}
    </div>
  )
}

function Detail({ f, id, canOpen, canFix, from, onChange }: { f: Finding; id: string; canOpen: boolean; canFix: boolean; from: string; onChange: (d: SessionDetail) => void }): React.JSX.Element {
  const api = window.macsec
  const { act, settings, notify } = useApp()
  const simple = !!settings?.explainSimply
  const [asking, setAsking] = useState(false)
  const [patch, setPatch] = useState<PatchRecord | null>(null)
  const [phrase, setPhrase] = useState('')
  const [patching, setPatching] = useState(false)
  const triage = async (t: Finding['triage'] | null, remember?: 'site' | 'everywhere'): Promise<void> => {
    const d = await act('triage', () => api.invoke('findings:triage', id, f.id, t ?? null, remember))
    if (d) onChange(d)
  }
  return (
    <div className="panel f-detail" key={f.id} data-simple={simple}>
      {simple && (
        <div className="plain">
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <Sev s={f.severity} />
            {f.verdict === 'false-positive' && <span className="tag tag-warn">Probably not a real problem</span>}
          </div>
          <h3>{f.title}</h3>
          <h5>What could happen</h5>
          <p>{f.impact ?? f.why ?? f.description ?? 'The check did not say. Open the technical details below.'}</p>
          {f.fix && (
            <>
              <h5>What to do</h5>
              <p>{f.fix}</p>
            </>
          )}
        </div>
      )}
      {f.secondOpinion && (
        <p className="hint" style={{ margin: '0 0 8px' }}>
          Second opinion ({f.secondOpinion.by}, {new Date(f.secondOpinion.at).toLocaleDateString()}): <strong>{f.secondOpinion.verdict}</strong>. {f.secondOpinion.reason}
        </p>
      )}
      {!f.secondOpinion && canOpen && f.severity !== 'info' && !f.triage && (
        <button
          className="btn btn-sm"
          style={{ marginBottom: 8 }}
          disabled={asking}
          data-tip="A separate AI session, with no knowledge of the first reviewer, tries to disprove this finding. It never changes the confidence."
          onClick={async () => {
            setAsking(true)
            const d = await act('second', () => api.invoke('findings:second-opinion', id, f.id))
            if (d) onChange(d)
            setAsking(false)
          }}
        >
          <Bot size={13} /> {asking ? 'Asking a second AI…' : 'Ask a second AI to try to disprove this'}
        </button>
      )}
      {canOpen && !f.triage && f.severity !== 'info' && (
        <div className="patch-box">
          {!patch && (
            <button
              className="btn btn-sm"
              disabled={patching}
              onClick={async () => {
                setPatching(true)
                try {
                  const p = await api.invoke('patches:propose', id, f.id)
                  setPatch(p)
                  setPhrase('')
                } catch (e) {
                  notify({ kind: 'error', text: (e as Error).message })
                } finally {
                  setPatching(false)
                }
              }}
            >
              <Sparkles size={13} /> {patching ? 'Preparing a patch in a scratch copy…' : 'Prepare a fix in a scratch copy'}
            </button>
          )}
          {patch && (
            <div style={{ display: 'grid', gap: 10 }}>
              <div className="hint">
                <strong style={{ color: 'var(--ink)' }}>{patch.id}</strong> in a scratch copy, never in your project.
                {patch.tests.ran ? ` Tests: ${patch.tests.passed ? 'passed' : 'failed'} (${patch.tests.command}).` : ' No test command found, so this cannot be applied.'}
              </div>
              {patch.error && <div className="hint" style={{ color: 'var(--warn)' }}>{patch.error}</div>}
              {!!patch.diff && <pre className="patch-diff">{patch.diff.slice(0, 20000)}</pre>}
              {patch.tests.output && <details><summary className="hint">Test output</summary><pre className="patch-diff">{patch.tests.output.slice(-4000)}</pre></details>}
              {!patch.applied ? (
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                  <input className="input mono" style={{ width: 260, height: 32 }} placeholder={`Type APPLY ${patch.id}`} value={phrase} onChange={(e) => setPhrase(e.target.value)} aria-label="Confirmation phrase" />
                  <button
                    className="btn btn-sm btn-primary"
                    disabled={!patch.tests.passed || phrase !== `APPLY ${patch.id}`}
                    onClick={async () => {
                      try {
                        setPatch(await api.invoke('patches:apply', patch.id, phrase))
                        notify({ kind: 'info', text: 'Patch applied. Roll it back here if anything is wrong.' })
                      } catch (e) {
                        notify({ kind: 'error', text: (e as Error).message })
                      }
                    }}
                  >
                    Apply
                  </button>
                  <button className="btn btn-sm" onClick={async () => { await api.invoke('patches:discard', patch.id); setPatch(null) }}>Discard</button>
                </div>
              ) : (
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <span className="tag tag-ok">Applied {patch.appliedAt ? new Date(patch.appliedAt).toLocaleString('en-GB') : ''}</span>
                  <button className="btn btn-sm" onClick={async () => { try { setPatch(await api.invoke('patches:rollback', patch.id)) } catch (e) { notify({ kind: 'error', text: (e as Error).message }) } }}>Roll back</button>
                </div>
              )}
            </div>
          )}
        </div>
      )}
      {(f.owner || f.due) && (
        <p className="hint" style={{ margin: '0 0 8px' }}>
          {f.owner ? `Owner: ${f.owner}` : ''}
          {f.owner && f.due ? ' · ' : ''}
          {f.due ? `due ${f.due}` : ''}
        </p>
      )}
      <details className="tech" open={!simple}>
      {simple && <summary>Technical details</summary>}
      <div className="tech-body">
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <Sev s={f.severity} />
        {f.verdict === 'confirmed' && <span className="tag tag-ok">Confirmed by AI</span>}
        {f.verdict === 'false-positive' && <span className="tag tag-warn">Ruled out by AI</span>}
        <ConfidenceTag f={f} />
        {f.controlled && <span className="tag tag-ok" data-tip={`Run ${f.controlled.runId} under engagement ${f.controlled.engagementRef}`}>Proven by a controlled proof</span>}
        <ExploitTag f={f} />
        <span className="tag" data-tip={VERIFICATION_TEXT[verificationOf(f)]}>{VERIFICATION_TEXT[verificationOf(f)].split(":")[0]}</span>
        {asvsOf(f.cwe) && <span className="tag" data-tip="The OWASP ASVS chapter this kind of problem belongs to.">{asvsOf(f.cwe)}</span>}
        <span className="tag">{f.tool}</span>
        {f.alsoFoundBy?.length ? <span className="tag" data-tip="Other tools reported the same problem in the same place. MacSec shows it once.">Also found by {f.alsoFoundBy.join(', ')}</span> : null}
        {f.checkId && <span className="tag" data-tip="The stable id of the check that found this, so a report and a re-test can name it.">{f.checkId}</span>}
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
      {f.exploit && (
        <p className="hint">
          <strong>{f.exploit.label}.</strong> {f.exploit.why} Risk score {f.exploit.risk} of 100.
        </p>
      )}
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
      {f.controlled ? (
        <div className="fix" style={{ marginTop: 4 }}>
          <b>Proven by a controlled proof.</b> Engagement {f.controlled.engagementRef}, run {f.controlled.runId}, on {new Date(f.controlled.at).toLocaleString('en-GB')}.
          <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>
            {f.controlled.shows.map((x) => (
              <li key={x}>{x}</li>
            ))}
          </ul>
        </div>
      ) : null}
      <ProofBlock f={f} />
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
          <FixDiff f={f} />
        </div>
      )}
      <LeakHelp f={f} />
      {f.verify && (
        <>
          <h5>How to check the fix</h5>
          <p>{f.verify}</p>
        </>
      )}
      </div>
      </details>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {canFix && !f.triage && (
          <button className="btn btn-sm btn-primary" data-tip="Opens Claude Code in Terminal, in this project, to fix just this finding with you" onClick={() => void act('fix-one', () => api.invoke('sessions:open', id, 'claude-one', f.id))}>
            <Sparkles size={13} /> Fix this one with Claude Code
          </button>
        )}
        <button
          className="btn btn-sm"
          onClick={() => {
            void navigator.clipboard.writeText(issueText(f, from)).then(() => notify({ kind: 'info', text: 'Copied. Paste it into GitHub, Jira or wherever you track work. Secrets are left out.' }))
          }}
        >
          <Copy size={13} /> Copy as an issue
        </button>
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
      <TicketBar f={f} id={id} onChange={onChange} />
      <div className="triage">
        {f.triage ? (
          <>
            <span className="tag tag-ok">{f.triage === 'fixed' ? 'Marked fixed' : f.triage === 'accepted' ? 'Risk accepted' : 'Not a problem'}</span>
            <span className="hint">{f.remembered ? 'Left alone because you told MacSec to remember it. Undo in Settings.' : 'It no longer counts towards the posture.'}</span>
            <button className="link" onClick={() => void triage(null)}>
              Open it again
            </button>
          </>
        ) : (
          <>
            <span className="hint">When you have dealt with it:</span>
            <button className="btn btn-sm" onClick={() => void triage('fixed')}>
              Fixed
            </button>
            <button className="btn btn-sm" onClick={() => void triage('accepted')}>
              Accept the risk
            </button>
            <button className="btn btn-sm" onClick={() => void triage('not-a-problem')}>
              Not a problem
            </button>
            <button className="btn btn-sm" title="Later scans of this site leave it alone. You can undo this in Settings." onClick={() => void triage('not-a-problem', 'site')}>
              Not a problem, remember
            </button>
            <button className="link" title="Leave this kind of finding alone on every site. You can undo this in Settings." onClick={() => void triage('not-a-problem', 'everywhere')}>
              on every site
            </button>
          </>
        )}
      </div>
    </div>
  )
}

type SurfaceData = NonNullable<Awaited<ReturnType<typeof window.macsec.invoke<'recon:data'>>>>

type ChainPlan = Awaited<ReturnType<typeof window.macsec.invoke<'sessions:fixplan'>>>

/**
 * How the findings add up to a real attack, and the one fix that breaks each path. A path is shown
 * only when every part of it was found, so this is evidence from the session, not a guess.
 */
function AttackPaths({ detail, onPick }: { detail: SessionDetail; onPick: (findingId: string) => void }): React.JSX.Element {
  const [plan, setPlan] = useState<ChainPlan | null>(null)
  useEffect(() => {
    if (detail.status === 'running') return
    void window.macsec.invoke('sessions:fixplan', detail.id).then(setPlan).catch(() => setPlan(null))
  }, [detail.id, detail.status, detail.findings])
  if (detail.status === 'running') return <Empty title="The run is still going">Paths appear when it finishes.</Empty>
  if (!plan) return <Empty title="Looking for paths…">Reading the findings that are still open.</Empty>
  if (!plan.chains.length) {
    return (
      <Empty title="No attack path in this result">
        A path needs two or more open findings that add up, for example an exposed file with a key in it, or a way to find accounts with no limit on guessing. Fixing the open findings one by one is still the right next step.
      </Empty>
    )
  }
  return (
    <div style={{ display: 'grid', gap: 14 }}>
      {plan.chains.map((c) => (
        <section key={c.id} className="panel" style={{ padding: 16 }} aria-label={c.name}>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <Sev s={c.severity} />
            <strong style={{ fontSize: 15 }}>{c.name}</strong>
            <span className="tag">{c.confidence}</span>
            <span className="hint">made of {c.members.length} findings</span>
          </div>
          <p style={{ margin: '8px 0 0', color: 'var(--ink-2)' }}>{c.story}</p>
          {c.impact ? <p className="hint" style={{ marginTop: 4 }}>If someone used it: {c.impact}</p> : null}
          {c.breakAt ? (
            <div className="fix" style={{ marginTop: 10 }}>
              <b>Break it here:</b> {c.breakAt.title}
              <div className="hint" style={{ marginTop: 2 }}>{c.breakAt.fix}</div>
            </div>
          ) : null}
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 10 }}>
            {c.members.map((m) => (
              <button key={m.id} className="btn btn-sm" onClick={() => onPick(m.id)} data-tip="Open this finding">
                <Sev s={m.severity} /> {m.title.length > 60 ? `${m.title.slice(0, 60)}…` : m.title}
              </button>
            ))}
          </div>
        </section>
      ))}
    </div>
  )
}

/** What is different from the last recon of the same domain. */
function ReconChanges({ delta }: { delta: NonNullable<SurfaceData['delta']> }): React.JSX.Element {
  const none = !delta.newHosts.length && !delta.goneHosts.length && !delta.newEndpoints.length && !delta.newFindings.length && !delta.fixedFindings.length
  const list = (title: string, items: string[]): React.JSX.Element | null =>
    items.length ? (
      <div style={{ padding: '4px 18px' }}>
        <div className="row-title">{title} ({items.length})</div>
        <div className="row-sub mono" style={{ wordBreak: 'break-all' }}>{items.slice(0, 12).join(', ')}{items.length > 12 ? `, and ${items.length - 12} more` : ''}</div>
      </div>
    ) : null
  return (
    <div className="panel" style={{ paddingBottom: 12 }}>
      <div style={{ padding: '14px 18px 4px' }} className="section-title">
        What changed since the recon on {delta.since.at.slice(0, 10)}
      </div>
      {none && <div className="hint" style={{ padding: '4px 18px' }}>Nothing changed: the same hosts, endpoints and findings.</div>}
      {list('New hosts', delta.newHosts)}
      {list('Hosts no longer seen', delta.goneHosts)}
      {list('New endpoints', delta.newEndpoints)}
      {list('New findings', delta.newFindings.map((f) => `${f.severity}: ${f.title}`))}
      {list('Findings no longer seen', delta.fixedFindings.map((f) => `${f.severity}: ${f.title}`))}
    </div>
  )
}

/** A recon's hosts, scripts, endpoints and parameters. */
function Surface({ id, detail, onPick }: { id: string; detail: SessionDetail; onPick: (fid: string) => void }): React.JSX.Element {
  const { notify } = useApp()
  const [d, setD] = useState<SurfaceData | null>(null)
  const [vhosts, setVhosts] = useState<VhostHit[] | null>(null)
  const [probing, setProbing] = useState(false)
  useEffect(() => {
    void window.macsec.invoke('recon:data', id).then(setD)
  }, [id])
  const graph = <SurfaceGraph findings={detail.findings} target={detail.target} onPick={onPick} />
  const vhostCard = (
    <div className="panel" style={{ padding: 16 }}>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
        <div className="grow">
          <strong>Virtual hosts</strong>
          <div className="hint">Ten common names against this address, each compared with a name that cannot exist. Read-only, one at a time, for a host you own.</div>
        </div>
        <button
          className="btn btn-sm"
          disabled={probing}
          onClick={async () => {
            setProbing(true)
            try {
              const r = await window.macsec.invoke('recon:vhosts', id)
              setVhosts(r)
            } catch (e) {
              notify({ kind: 'error', text: (e as Error).message })
            } finally {
              setProbing(false)
            }
          }}
        >
          {probing ? 'Probing…' : 'Probe virtual hosts'}
        </button>
      </div>
      {vhosts && (
        <div style={{ marginTop: 10, display: 'grid', gap: 6 }}>
          {vhosts.length === 0 && <span className="hint">No virtual host answered differently from the made-up name.</span>}
          {vhosts.map((v) => (
            <div key={v.name} className="since-line">
              <span className="tag tag-warn">{v.status}</span> <strong>{v.name}</strong> {v.title ? `"${v.title}"` : ''}
              <span className="hint"> {v.reason}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
  if (!d) {
    return (
      <div style={{ display: 'grid', gap: 14 }}>
        {graph}
        {vhostCard}
        <div className="panel" style={{ padding: 20 }}>
          <span className="hint">The recon map appears when the recon has collected it.</span>
        </div>
      </div>
    )
  }
  return (
    <div style={{ display: 'grid', gap: 14 }}>
      {graph}
      {vhostCard}
      {d.delta && <ReconChanges delta={d.delta} />}
      {d.jsmap && <JsMap id={id} m={d.jsmap} />}
      {d.pages && <ReconPages pages={d.pages} />}
      {d.hosts.length > 0 && (
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
      )}
      {d.js.length > 0 && (
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
      )}
      {d.js.length > 0 && (
      <div className="panel" style={{ padding: 18 }}>
        <div className="section-title">Endpoints in the JavaScript, and parameters from {d.urls} archived URLs</div>
        <pre className="codeview" style={{ maxHeight: 360, overflow: 'auto', padding: 14 }}>{d.endpoints.join('\n') || 'None found.'}</pre>
        <p className="hint mono" style={{ wordBreak: 'break-word' }}>{d.params.slice(0, 200).join(', ')}</p>
      </div>
      )}
    </div>
  )
}

/** What the site's scripts name: endpoints, routes, GraphQL operations, build variables, other sites and cloud storage. */
function JsMap({ id, m }: { id: string; m: NonNullable<SurfaceData['jsmap']> }): React.JSX.Element {
  const block = (title: string, items: string[]): React.JSX.Element | null =>
    items.length ? (
      <div style={{ padding: '4px 18px 12px' }}>
        <div className="section-title" style={{ marginBottom: 6 }}>
          {title} ({items.length})
        </div>
        <pre className="codeview" style={{ maxHeight: 220, overflow: 'auto', padding: 12 }}>{items.join('\n')}</pre>
      </div>
    ) : null
  const maps = m.scripts.filter((x) => x.sourceMap)
  return (
    <div className="panel">
      <div style={{ padding: '14px 18px 4px', display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <span className="section-title grow">
          JavaScript map: {m.scripts.length} scripts, {m.endpoints.length} endpoints, {m.routes.length} routes, {m.graphql.length} GraphQL operations, {maps.length} source maps
        </span>
        {m.sources && (
          <button className="btn" onClick={() => void window.macsec.invoke('sessions:open-sources', id)}>
            Open the rebuilt source
          </button>
        )}
      </div>
      {block('Routes the front end names', m.routes)}
      {block('API endpoints', m.endpoints)}
      {block('GraphQL operations', m.graphql)}
      {block('Build variables (names only)', m.envVars)}
      {block('Other sites the scripts talk to', m.hosts)}
      {block('Cloud storage named', [...m.refs.firebase, ...m.refs.s3, ...m.refs.gcs])}
      {maps.length > 0 && block('Source maps', maps.map((x) => `${x.sourceMap!.url}  (${x.sourceMap!.files} files${x.sourceMap!.recovered ? `, ${x.sourceMap!.recovered} rebuilt` : ''})`))}
    </div>
  )
}


/** What is new, fixed or still there since the previous session on the same target. */
function SinceLastTime({ id }: { id: string }): React.JSX.Element | null {
  const { showSession } = useApp()
  const [c, setC] = useState<SessionCompare | null>(null)
  const [open, setOpen] = useState(false)
  useEffect(() => {
    void window.macsec.invoke('sessions:compare', id).then(setC).catch(() => setC(null))
  }, [id])
  if (!c?.previous) return null
  return (
    <div className="since glass">
      <div className="since-head">
        <strong>Since last time</strong>
        <span className="hint">compared with {new Date(c.previous.at).toLocaleDateString()}</span>
        <span className="tag tag-warn">{c.added.length} new</span>
        <span className="tag tag-ok">{c.fixed.length} fixed</span>
        <span className="tag">{c.still} still there</span>
        <button className="link" style={{ marginLeft: 'auto' }} onClick={() => showSession(c.previous!.id)}>
          Open the earlier session
        </button>
        {(c.added.length > 0 || c.fixed.length > 0) && (
          <button className="link" onClick={() => setOpen(!open)}>
            {open ? 'Hide' : 'Show'}
          </button>
        )}
      </div>
      {open && (
        <div className="since-lists">
          {c.added.length > 0 && (
            <div>
              <div className="row-title">New</div>
              {c.added.slice(0, 50).map((f) => (
                <div key={f.id} className="since-line"><span className="sev" data-sev={f.severity}>{f.severity}</span> {f.title}{f.file ? <span className="hint mono"> {f.file}{f.line ? `:${f.line}` : ''}</span> : null}</div>
              ))}
            </div>
          )}
          {c.fixed.length > 0 && (
            <div>
              <div className="row-title">Fixed</div>
              {c.fixed.slice(0, 50).map((f) => (
                <div key={f.id} className="since-line"><span className="sev" data-sev={f.severity}>{f.severity}</span> <s>{f.title}</s></div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

const RETEST_TEXT = { still: 'Still there', changed: 'The answer changed: look again', gone: 'No longer there', unreachable: 'Could not reach it', unsupported: 'Cannot be repeated automatically' } as const

/** Re-test one finding, copy it as a ticket, or open a GitHub issue. */
function TicketBar({ f, id, onChange }: { f: Finding; id: string; onChange: (d: SessionDetail) => void }): React.JSX.Element {
  const api = window.macsec
  const { act, busy, notify } = useApp()
  const [repo, setRepo] = useState('')
  const [ask, setAsk] = useState(false)
  const copy = async (format: 'markdown' | 'jira'): Promise<void> => {
    const t = await act('ticket', () => api.invoke('findings:ticket', id, f.id, format))
    if (t) {
      await navigator.clipboard.writeText(t)
      notify({ kind: 'info', text: format === 'jira' ? 'Copied for Jira. Paste it into a new ticket.' : 'Copied as Markdown. Paste it into GitHub, Linear or anywhere.' })
    }
  }
  return (
    <div className="triage" style={{ flexWrap: 'wrap' }}>
      <button className="btn btn-sm" disabled={busy.has('retest')} onClick={async () => {
        const d = await act('retest', () => api.invoke('findings:retest', id, f.id))
        if (d) onChange(d)
      }} data-tip="Repeats the request from the proof and tells you what it sees now. It never marks anything fixed by itself.">
        <RotateCcw size={13} /> {busy.has('retest') ? 'Checking…' : 'Re-test'}
      </button>
      {f.retest && (
        <span className="hint" role="status">
          {RETEST_TEXT[f.retest.state]}. {f.retest.detail} ({ago(f.retest.at)})
        </span>
      )}
      <button className="btn btn-sm" onClick={() => void copy('markdown')}>
        <Ticket size={13} /> Copy as ticket
      </button>
      <button className="btn btn-sm" onClick={() => void copy('jira')}>
        Jira text
      </button>
      <button className="btn btn-sm" onClick={() => setAsk((x) => !x)} aria-expanded={ask}>
        <Bug size={13} /> GitHub issue
      </button>
      {ask && (
        <span style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <input aria-label="Repository, owner/name" placeholder="owner/name" value={repo} onChange={(e) => setRepo(e.target.value)} />
          <button className="btn btn-sm btn-primary" disabled={!repo.trim() || busy.has('gh')} onClick={async () => {
            const r = await act('gh', () => api.invoke('findings:github-issue', id, f.id, repo.trim()))
            if (r) {
              setAsk(false)
              notify({ kind: 'info', text: `Created issue #${r.number}.` })
              void api.invoke('app:open-external', r.url)
            }
          }}>
            Create
          </button>
        </span>
      )}
    </div>
  )
}
