import { useEffect, useState } from 'react'
import { ArrowDownToLine, CheckCircle2, ChevronDown, Database, ExternalLink, RefreshCw, Wrench } from 'lucide-react'
import type { ReleaseNote, UpdateStatus } from '@shared/types'
import { useApp } from '../store'
import { PageHead } from '../ui'
import Markdown from '../components/Markdown'

const when = (ms: number | null): string => (ms ? new Date(ms).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' }) : 'not yet')
/** Notes start with their own "## MacSec x" heading; the page already says which version. */
const body = (notes: string): string => notes.replace(/^## [^\n]*\n+/, '').trim()
const day = (iso: string): string => new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })

/**
 * Everything MacSec keeps up to date, in one place, like Laramac's Updates page: MacSec itself
 * (with its notes, in the app), the scanners and their databases, and every past release.
 */
export default function Updates(): React.JSX.Element {
  const { act, busy, jobs, tools, setTools } = useApp()
  const api = window.macsec
  const [st, setSt] = useState<UpdateStatus | null>(null)
  const [history, setHistory] = useState<ReleaseNote[]>([])
  const [open, setOpen] = useState<string | null>(null)

  useEffect(() => {
    void api.invoke('app:update-status').then(setSt)
    void api.invoke('app:changelog').then(setHistory).catch(() => undefined)
    return api.on('app:update', () => void api.invoke('app:update-status').then(setSt))
  }, [api])

  const check = async (): Promise<void> => {
    await act('app-check', () => api.invoke('app:check-update'))
    setSt(await api.invoke('app:update-status'))
    setHistory(await api.invoke('app:changelog').catch(() => history))
  }
  const job = jobs.find((j) => j.label === 'Updating MacSec' && j.status === 'running')
  const u = st?.update
  const stale = tools.filter((t) => t.installed && t.updateAvailable)

  return (
    <>
      <PageHead title="Updates" desc="MacSec, its scanners and their databases. Every download is checked against its published checksum before it is used.">
        <button className="btn" disabled={busy.has('app-check')} onClick={check}>
          <RefreshCw size={14} className={busy.has('app-check') ? 'spin' : undefined} /> {busy.has('app-check') ? 'Checking…' : 'Check now'}
        </button>
      </PageHead>

      <section className={`upd-hero glass${u ? ' has' : ''}`}>
        <span className="upd-mark" aria-hidden>
          {u ? <ArrowDownToLine size={26} /> : <CheckCircle2 size={26} />}
        </span>
        <div className="upd-main">
          <h2>{!st ? 'Checking…' : u ? `MacSec ${u.version} is ready` : 'MacSec is up to date'}</h2>
          <p>
            {job
              ? `${job.label}${job.percent !== null ? `: ${Math.round(job.percent)}%` : '…'}`
              : u
                ? `You have ${u.current}. Released ${day(u.publishedAt)}. Your sessions, scanners and settings stay as they are.`
                : st
                  ? `You have ${st.current}, the newest version.`
                  : ''}
          </p>
          {job && job.percent !== null && (
            <div className="upd-bar" role="progressbar" aria-valuenow={job.percent} aria-valuemin={0} aria-valuemax={100}>
              <span style={{ width: `${job.percent}%` }} />
            </div>
          )}
          <span className="hint">
            Last checked {when(st?.checkedAt ?? null)}.{st?.error ? ` ${st.error}` : ''}
          </span>
        </div>
        {u && (
          <button className="btn btn-primary btn-lg" disabled={!!job || busy.has('app-update')} onClick={() => void act('app-update', () => api.invoke('app:install-update'))}>
            {job || busy.has('app-update') ? 'Updating…' : 'Update and restart'}
          </button>
        )}
      </section>

      {u && u.notes && (
        <section className="upd-notes glass">
          <h3>What’s new in {u.version}</h3>
          <Markdown text={body(u.notes)} />
        </section>
      )}

      <h2 className="section-title">Scanners</h2>
      <div className="panel">
        <div className="row">
          <span className="glyph" style={{ ['--g' as string]: '#38e1ff' }}>
            <Wrench size={18} />
          </span>
          <div className="grow">
            <div className="row-title">{stale.length ? `${stale.length} ${stale.length === 1 ? 'scanner has' : 'scanners have'} a newer version` : 'Every installed scanner is current'}</div>
            <div className="row-sub" style={{ whiteSpace: 'normal' }}>
              {stale.length ? stale.map((t) => `${t.name} ${t.version ?? ''} → ${t.latest ?? ''}`.trim()).join(' · ') : 'Checked once a day.'}
            </div>
          </div>
          {stale.length > 0 && (
            <button
              className="btn btn-sm btn-primary"
              disabled={busy.has('tools-up')}
              onClick={async () => {
                const r = await act('tools-up', () => api.invoke('tools:install', stale.map((t) => t.id)))
                if (r) setTools(r)
              }}
            >
              {busy.has('tools-up') ? 'Updating…' : 'Update all'}
            </button>
          )}
        </div>
        <div className="row">
          <span className="glyph" style={{ ['--g' as string]: '#8b6cff' }}>
            <Database size={18} />
          </span>
          <div className="grow">
            <div className="row-title">Vulnerability databases and templates</div>
            <div className="row-sub">Trivy, Grype, Nuclei templates and the rest. Scans fetch them as needed; refresh them here before a big test.</div>
          </div>
          <button className="btn btn-sm" disabled={busy.has('tools-data')} onClick={() => void act('tools-data', () => api.invoke('tools:update-data'))}>
            {busy.has('tools-data') ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

      <h2 className="section-title">Release history</h2>
      <div className="panel upd-history">
        {history.length === 0 && <div className="row hint">The list of releases appears after the first check.</div>}
        {history.map((r) => (
          <div key={r.version} className="upd-rel" data-open={open === r.version}>
            <button className="row upd-rel-head" aria-expanded={open === r.version} onClick={() => setOpen(open === r.version ? null : r.version)}>
              <strong>MacSec {r.version}</strong>
              {st && r.version === st.current && <span className="tag tag-ok">You have this</span>}
              <span className="hint grow">{day(r.publishedAt)}</span>
              <ChevronDown size={16} className="upd-chev" />
            </button>
            {open === r.version && (
              <div className="upd-rel-body">
                <Markdown text={body(r.notes) || 'No notes for this release.'} />
                <button className="link" onClick={() => void api.invoke('app:open-external', r.url)}>
                  <ExternalLink size={12} /> Open on GitHub
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </>
  )
}
