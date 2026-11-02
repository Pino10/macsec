import { useEffect, useMemo, useState } from 'react'
import { ArrowLeft, Bot, ChevronDown, ChevronRight, CircleStop, ExternalLink, FileDown, FileSearch, FolderOpen, Sparkles, Trash2, XCircle } from 'lucide-react'
import { SEVERITIES, type Finding, type FindingCategory, type SessionDetail, type Severity } from '@shared/types'
import { useApp } from '../store'
import { Answer } from '../components/Answer'
import { Counts, Empty, PageHead, Sev, SevTiles, StepIcon, ago, duration } from '../ui'

export default function Sessions(): React.JSX.Element {
  const { sessions, openSession, showSession } = useApp()
  const [q, setQ] = useState('')
  if (openSession) return <SessionView id={openSession} onBack={() => showSession(null)} />
  const list = sessions.filter((s) => !q.trim() || `${s.title} ${s.target}`.toLowerCase().includes(q.toLowerCase()))
  return (
    <>
      <PageHead title="Sessions" desc="Every test you ran, with its report. Each one lives in its own folder inside MacSec.">
        <button className="btn" onClick={() => void window.macsec.invoke('app:open-folder', 'sessions')}>
          <FolderOpen size={14} /> Open folder
        </button>
      </PageHead>
      {sessions.length === 0 ? (
        <Empty title="No sessions yet">Start a code review and it appears here.</Empty>
      ) : (
        <>
          <input className="input" placeholder="Filter by project" value={q} onChange={(e) => setQ(e.target.value)} style={{ marginBottom: 12 }} aria-label="Filter sessions" />
          <div className="panel">
            {list.map((s) => (
              <button key={s.id} className="ms-row" style={{ width: '100%', background: 'none', border: 0, color: 'inherit', font: 'inherit', textAlign: 'left', cursor: 'pointer' }} onClick={() => showSession(s.id)}>
                <StepIcon status={s.status === 'running' ? 'running' : s.status === 'done' ? 'done' : s.status === 'failed' ? 'failed' : 'skipped'} />
                <div className="grow">
                  <div className="row-title">{s.title}</div>
                  <div className="row-sub">
                    {s.target} · {ago(s.createdAt)} · {s.reviewer === 'claude' ? 'Claude Code' : s.reviewer === 'codex' ? 'Codex' : s.reviewer === 'model' ? 'Model' : 'Scanners'}
                    {s.depth ? ` · ${s.depth}` : ''}
                  </div>
                </div>
                {s.status === 'done' ? <Counts counts={s.counts} /> : <span className="hint">{s.status === 'running' ? 'Running' : s.status}</span>}
                <ChevronRight size={14} style={{ color: 'var(--ink-3)' }} />
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
  ['ai', 'AI review'],
  ['code', 'Code'],
  ['secret', 'Keys'],
  ['dependency', 'Packages'],
  ['config', 'Config']
]

function SessionView({ id, onBack }: { id: string; onBack: () => void }): React.JSX.Element {
  const { sessions, act, busy, setSessions, notify } = useApp()
  const api = window.macsec
  const [detail, setDetail] = useState<SessionDetail | null>(null)
  const [sevs, setSevs] = useState<Set<Severity>>(new Set(['critical', 'high', 'medium', 'low']))
  const [cat, setCat] = useState<FindingCategory | 'all'>('all')
  const [showFp, setShowFp] = useState(false)
  const [tab, setTab] = useState<'findings' | 'ai' | 'run'>('findings')
  const live = sessions.find((s) => s.id === id)

  // Reload the findings whenever the session moves on.
  const stamp = `${live?.status}|${live?.steps.map((s) => s.status).join(',')}`
  useEffect(() => {
    void api
      .invoke('sessions:get', id)
      .then(setDetail)
      .catch(() => setDetail(null))
  }, [api, id, stamp])

  const findings = useMemo(() => (detail?.findings ?? []).filter((f) => sevs.has(f.severity) && (cat === 'all' || f.category === cat) && (showFp || f.verdict !== 'false-positive')), [detail, sevs, cat, showFp])
  if (!detail) return <Empty title="Loading…" />
  const s = { ...detail, ...(live ?? {}) }
  const fp = detail.findings.filter((f) => f.verdict === 'false-positive').length
  const running = s.status === 'running'
  const hasCode = !!s.codePath

  return (
    <>
      <button className="link hint" onClick={onBack} style={{ marginBottom: 10, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
        <ArrowLeft size={13} /> All sessions
      </button>
      <PageHead title={s.title} desc={`${s.target} · ${new Date(s.createdAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' })}${s.files ? ` · ${s.files.toLocaleString()} files` : ''}${s.languages?.length ? ` · ${s.languages.slice(0, 3).join(', ')}` : ''}`}>
        {running ? (
          <button className="btn" onClick={() => void act('cancel', () => api.invoke('sessions:cancel', id))}>
            <CircleStop size={14} /> Stop
          </button>
        ) : (
          <>
            <button className="btn" disabled={busy.has('pdf')} onClick={() => void act('pdf', () => api.invoke('sessions:pdf', id)).then((p) => p && notify({ kind: 'info', text: 'Saved the PDF in the session folder.' }))}>
              <FileDown size={14} /> {busy.has('pdf') ? 'Making PDF…' : 'PDF'}
            </button>
            {hasCode && (
              <>
                <button className="btn" onClick={() => void act('claude', () => api.invoke('sessions:open', id, 'claude'))} data-tip="Opens Claude Code in Terminal, ready to fix the findings with you. Also reachable at claude.ai/code and on your phone.">
                  <Sparkles size={14} /> Continue in Claude Code
                </button>
                <button className="btn" onClick={() => void act('codex', () => api.invoke('sessions:open', id, 'codex'))}>
                  <Bot size={14} /> Codex
                </button>
              </>
            )}
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
      </PageHead>

      {s.error && (
        <div className="notice" style={{ marginBottom: 14, borderColor: 'color-mix(in srgb, var(--bad) 30%, transparent)', background: 'color-mix(in srgb, var(--bad) 8%, transparent)' }}>
          <XCircle size={16} style={{ color: 'var(--bad)', flexShrink: 0 }} /> {s.error}
        </div>
      )}

      <SevTiles counts={s.counts} />
      {s.codeKept && (
        <div className="hint" style={{ margin: '10px 2px 0' }}>
          The downloaded code is kept in this session so you can fix it.{' '}
          <button className="link" onClick={() => void act('discard', () => api.invoke('sessions:discard-code', id))}>
            Delete it now
          </button>
        </div>
      )}

      <div className="seg-tabs" role="tablist" style={{ margin: '18px 0 12px' }}>
        <button role="tab" aria-selected={tab === 'findings'} onClick={() => setTab('findings')}>
          Findings ({detail.findings.length - fp})
        </button>
        <button role="tab" aria-selected={tab === 'ai'} onClick={() => setTab('ai')} disabled={!detail.aiReport}>
          AI report
        </button>
        <button role="tab" aria-selected={tab === 'run'} onClick={() => setTab('run')}>
          What ran {running && '·'}
        </button>
      </div>

      {(tab === 'run' || (running && detail.findings.length === 0)) && (
        <div className="panel steps" style={{ padding: 6, marginBottom: 14 }}>
          {s.steps.map((st) => (
            <div key={st.id} className="step" data-status={st.status}>
              <StepIcon status={st.status} />
              <span>{st.label}</span>
              <span className="detail" title={st.detail}>
                {st.detail ?? ''}
                {st.ms ? ` · ${duration(st.ms)}` : ''}
              </span>
            </div>
          ))}
        </div>
      )}

      {tab === 'ai' && detail.aiReport && (
        <div className="panel" style={{ padding: '6px 22px 18px' }}>
          <Answer text={detail.aiReport} />
        </div>
      )}

      {tab === 'findings' && (
        <>
          <div style={{ display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap', marginBottom: 12 }}>
            <div className="chips" aria-label="Severity">
              {SEVERITIES.map((k) => (
                <button key={k} className="chip" aria-pressed={sevs.has(k)} onClick={() => setSevs((x) => (x.has(k) ? new Set([...x].filter((y) => y !== k)) : new Set([...x, k])))}>
                  {k} {detail.findings.filter((f) => f.severity === k && f.verdict !== 'false-positive').length}
                </button>
              ))}
            </div>
            <div className="chips" aria-label="Kind">
              {CATS.map(([k, l]) => (
                <button key={k} className="chip" aria-pressed={cat === k} onClick={() => setCat(k)}>
                  {l}
                </button>
              ))}
            </div>
            {fp > 0 && (
              <label style={{ fontSize: 12, color: 'var(--ink-2)', display: 'flex', gap: 6, alignItems: 'center' }}>
                <input type="checkbox" checked={showFp} onChange={(e) => setShowFp(e.target.checked)} /> Show {fp} ruled out by AI
              </label>
            )}
          </div>
          {findings.length === 0 ? (
            <Empty title={running ? 'Scanning…' : detail.findings.length ? 'Nothing matches these filters' : 'Nothing found'}>{running ? 'Findings appear here as each scanner finishes.' : ''}</Empty>
          ) : (
            findings.map((f) => <FindingRow key={f.id} f={f} id={id} canOpen={hasCode} />)
          )}
        </>
      )}
    </>
  )
}

function FindingRow({ f, id, canOpen }: { f: Finding; id: string; canOpen: boolean }): React.JSX.Element {
  const [open, setOpen] = useState(false)
  return (
    <div className="finding" data-fp={f.verdict === 'false-positive'}>
      <button className="finding-head" onClick={() => setOpen(!open)} aria-expanded={open}>
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        <Sev s={f.severity} />
        <span className="t">{f.title}</span>
        {f.verdict === 'confirmed' && <span className="sev" data-sev="ok">confirmed</span>}
        {f.verdict === 'false-positive' && <span className="hint">ruled out</span>}
        <span className="where">{f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : f.advisory ?? ''}</span>
      </button>
      {open && (
        <div className="finding-body">
          <div className="hint">
            {f.tool}
            {f.cwe && (
              <>
                {' · '}
                <button className="link" onClick={() => void window.macsec.invoke('app:open-external', `https://cwe.mitre.org/data/definitions/${f.cwe!.replace('CWE-', '')}.html`)}>
                  {f.cwe}
                </button>
              </>
            )}
            {f.advisory && ` · ${f.advisory}`}
            {f.url && /^https:/.test(f.url) && (
              <>
                {' · '}
                <button className="link" onClick={() => void window.macsec.invoke('app:open-external', f.url!)}>
                  Details <ExternalLink size={10} />
                </button>
              </>
            )}
            {canOpen && f.file && (
              <>
                {' · '}
                <button className="link" onClick={() => void window.macsec.invoke('sessions:open', id, 'file', f.file, f.line)}>
                  <FileSearch size={11} /> Open in editor
                </button>
              </>
            )}
          </div>
          {f.description && <div>{f.description}</div>}
          {f.snippet && <pre>{f.snippet}</pre>}
          {f.fix && (
            <div className="fix">
              <strong>Fix:</strong> {f.fix}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
