import { useEffect, useMemo, useState } from 'react'
import { ArrowDown, Boxes, ChevronRight, ExternalLink, RefreshCw } from 'lucide-react'
import type { AssetInfo, Chain } from '@shared/types'
import { useApp } from '../store'
import { Counts, Empty, PageHead, Sev, ago } from '../ui'

const KIND: Record<AssetInfo['kind'], string> = { site: 'Website', api: 'API', domain: 'Domain', app: 'Mobile app', project: 'Project', mac: 'This Mac', other: 'Other' }
const KINDS: (AssetInfo['kind'] | 'all')[] = ['all', 'site', 'api', 'domain', 'project', 'app', 'mac']

/** The colour of a score: the same bands the rest of the app uses. */
const band = (risk: number): string => (risk >= 70 ? 'var(--sev-critical)' : risk >= 45 ? 'var(--sev-medium)' : risk >= 20 ? 'var(--sev-low)' : 'var(--ok)')

function Spark({ points }: { points: number[] }): React.JSX.Element | null {
  if (points.length < 2) return null
  const w = 130
  const h = 30
  const max = Math.max(100, ...points)
  const d = points.map((p, i) => `${i ? 'L' : 'M'}${((i / (points.length - 1)) * w).toFixed(1)},${(h - (p / max) * h).toFixed(1)}`).join(' ')
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`Risk over ${points.length} tests: ${points.join(', ')}`}>
      <path d={d} fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  )
}

/** How a score is built, so nobody reads 43 as a grade. */
function Legend(): React.JSX.Element {
  return (
    <details className="panel" style={{ padding: '10px 14px', marginBottom: 14 }}>
      <summary className="hint" style={{ cursor: 'pointer' }}>How risk is worked out (higher is worse)</summary>
      <div style={{ display: 'flex', gap: 18, flexWrap: 'wrap', alignItems: 'center', marginTop: 10 }}>
        <span className="hint" style={{ flex: 1, minWidth: 260 }}>
          <b style={{ color: 'var(--ink)' }}>Risk is how exposed an asset is right now, from 0 (clean) to 100. Higher is worse.</b> Each open finding adds to it: severity counts, proof counts more, and fixing or marking a finding takes it back. The line is the same number after each test. (The Overview shows a different number, the posture score, where higher is better.)</span>
        <span className="hint">
          <b style={{ color: 'var(--ok)' }}>0</b> clean
        </span>
        <span className="hint">
          <b style={{ color: 'var(--sev-low)' }}>1-24</b> low
        </span>
        <span className="hint">
          <b style={{ color: 'var(--sev-medium)' }}>25-49</b> medium
        </span>
        <span className="hint">
          <b style={{ color: 'var(--sev-critical)' }}>50+</b> act
        </span>
      </div>
    </details>
  )
}

function Chain_({ c }: { c: Chain }): React.JSX.Element {
  return (
    <div style={{ borderLeft: '3px solid var(--line-2)', paddingLeft: 12 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <Sev s={c.severity} />
        <strong>{c.name}</strong>
        <span className="tag">{c.confidence}</span>
      </div>
      <div className="hint" style={{ marginTop: 2 }}>
        {c.story}
      </div>
      {c.impact ? <div className="hint">If it is used: {c.impact}</div> : null}
      {c.breakAt ? (
        <div className="hint" style={{ color: 'var(--ink-2)', marginTop: 2 }}>
          <b>Break it here:</b> {c.breakAt.title}. {c.breakAt.fix}
        </div>
      ) : null}
    </div>
  )
}

/** Every site, API, app and project MacSec has looked at, with one risk score and what to fix first. */
export default function Assets(): React.JSX.Element {
  const { showSession } = useApp()
  const api = window.macsec
  const [list, setList] = useState<AssetInfo[] | null>(null)
  const [kind, setKind] = useState<AssetInfo['kind'] | 'all'>('all')
  const [worstFirst, setWorstFirst] = useState(true)
  const [openPath, setOpenPath] = useState<string | null>(null)

  const load = (): void => {
    void api.invoke('assets:list').then(setList).catch(() => setList([]))
  }
  useEffect(() => {
    load()
    // Deliberately not on every session update: this page parses every session, so it loads when
    // opened and when Refresh is pressed, not twice a second during a scan.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api])

  const shown = useMemo(() => {
    const l = (list ?? []).filter((a) => kind === 'all' || a.kind === kind)
    return l.sort((a, b) => (worstFirst ? b.risk - a.risk || b.lastScan.localeCompare(a.lastScan) : b.lastScan.localeCompare(a.lastScan)))
  }, [list, kind, worstFirst])

  const withPaths = (list ?? []).filter((a) => a.chains.length > 0).length

  return (
    <>
      <PageHead title="Assets" desc="Everything you have tested, one line each. A site, its API, its apps and its recon count as one asset, so one score tells you how that thing stands today.">
        <button className="btn" disabled={list === null} onClick={load} aria-label="Refresh assets">
          <RefreshCw size={14} /> Refresh
        </button>
      </PageHead>

      <Legend />

      {(list ?? []).length > 0 && (
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 14 }}>
          <div className="chips">
            {KINDS.filter((k) => k === 'all' || (list ?? []).some((a) => a.kind === k)).map((k) => (
              <button key={k} className="chip" aria-pressed={kind === k} onClick={() => setKind(k)} style={{ textTransform: 'none' }}>
                {k === 'all' ? 'All' : KIND[k]} <i>{k === 'all' ? (list ?? []).length : (list ?? []).filter((a) => a.kind === k).length}</i>
              </button>
            ))}
          </div>
          <span style={{ flex: 1 }} />
          <button className="btn btn-sm" onClick={() => setWorstFirst((v) => !v)} aria-pressed={worstFirst} data-tip="Worst score first">
            <ArrowDown size={13} style={{ transform: worstFirst ? undefined : 'rotate(180deg)' }} /> {worstFirst ? 'Worst first' : 'Newest first'}
          </button>
        </div>
      )}

      {list === null && <Empty title="Reading your results…">One moment.</Empty>}
      {list && list.length === 0 && <Empty title="No assets yet">Run a code review, web scan, API review or recon and it shows up here with a score and what to fix first.</Empty>}
      {list && list.length > 0 && shown.length === 0 && <Empty title={`No ${kind === 'all' ? '' : KIND[kind as AssetInfo['kind']].toLowerCase() + ' '}assets`}>Try another kind.</Empty>}

      <div style={{ display: 'grid', gap: 14 }}>
        {shown.map((a) => (
          <section key={a.key} className="panel" aria-label={a.name} style={{ padding: 16 }}>
            <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
              <span className="glyph" style={{ ['--g' as string]: band(a.risk), width: 38, height: 38, borderRadius: 11 }}>
                <Boxes size={18} />
              </span>
              <div style={{ flex: 1, minWidth: 180 }}>
                <strong style={{ fontSize: 15 }}>{a.name}</strong>
                <div className="hint">
                  {KIND[a.kind]} · {a.scans} {a.scans === 1 ? 'test' : 'tests'} · last {ago(a.lastScan)}
                  {a.chains.length ? ` · ${a.chains.length} attack ${a.chains.length === 1 ? 'path' : 'paths'}` : ''}
                </div>
              </div>
              <div style={{ textAlign: 'center', minWidth: 64 }}>
                <div style={{ fontSize: 30, fontWeight: 650, color: band(a.risk), lineHeight: 1.1 }}>{a.risk}</div>
                <div className="hint">Risk: {a.riskLabel.toLowerCase()}</div>
              </div>
              <span style={{ color: band(a.risk) }} title="The score after each test">
                <Spark points={a.trend.map((t) => t.risk)} />
              </span>
              <button className="btn btn-sm" onClick={() => showSession(a.lastSession)}>
                Open latest <ChevronRight size={13} />
              </button>
            </div>

            <div style={{ marginTop: 12, display: 'flex', gap: 14, flexWrap: 'wrap', alignItems: 'center' }}>
              <Counts counts={a.open} empty="Nothing open" />
              {a.proven > 0 && <span className="tag tag-ok">{a.proven} proven</span>}
              {a.fixed > 0 && <span className="hint">{a.fixed} fixed{a.mttrDays !== undefined ? `, about ${a.mttrDays} ${a.mttrDays === 1 ? 'day' : 'days'} each` : ''}</span>}
              {a.dropIfDone > 0 && <span className="hint">The fixes below take the score up by about {a.dropIfDone}.</span>}
            </div>

            {a.actions.length > 0 ? (
              <>
                <h3 style={{ margin: '16px 0 6px', fontSize: 14 }}>Fix these first</h3>
                <ol style={{ margin: 0, paddingLeft: 20, display: 'grid', gap: 8 }}>
                  {a.actions.map((x, i) => (
                    <li key={x.ids.join()}>
                      <Sev s={x.worst} /> <strong>{x.title}</strong> <span className="hint">({x.count} finding{x.count === 1 ? '' : 's'}, takes off about {Math.round(x.drop)} points)</span>
                      {x.fix ? <div className="hint" style={{ marginTop: 2 }}>{x.fix}</div> : null}
                      {i === 0 && <span className="tag" style={{ marginLeft: 6 }}>start here</span>}
                    </li>
                  ))}
                </ol>
              </>
            ) : (
              <p className="hint" style={{ margin: '12px 0 0' }}>
                Nothing open needs fixing here. {a.fixed > 0 ? `You have fixed ${a.fixed} finding${a.fixed === 1 ? '' : 's'} on this asset.` : 'Run it again after your next change.'}
              </p>
            )}

            {a.chains.length > 0 && (
              <>
                <h3 style={{ margin: '16px 0 6px', fontSize: 14 }}>How a real attack could go, and where to break it</h3>
                <div style={{ display: 'grid', gap: 10 }}>
                  {(openPath === a.key ? a.chains : a.chains.slice(0, 2)).map((c) => (
                    <Chain_ key={c.id} c={c} />
                  ))}
                </div>
                {a.chains.length > 2 && (
                  <button className="link" style={{ marginTop: 6 }} onClick={() => setOpenPath(openPath === a.key ? null : a.key)}>
                    {openPath === a.key ? 'Show fewer' : `Show ${a.chains.length - 2} more`}
                  </button>
                )}
              </>
            )}

            <div style={{ display: 'flex', gap: 8, marginTop: 12, flexWrap: 'wrap' }}>
              <button className="btn btn-sm" onClick={() => showSession(a.lastSession)}>
                <ExternalLink size={12} /> The full result
              </button>
            </div>
          </section>
        ))}
      </div>

      {withPaths > 0 && (
        <p className="hint" style={{ marginTop: 14 }}>
          {withPaths} asset{withPaths === 1 ? '' : 's'} have an attack path where two or more findings add up. Those are worth fixing before the single findings, because an attacker only needs the path to work.
        </p>
      )}
    </>
  )
}
