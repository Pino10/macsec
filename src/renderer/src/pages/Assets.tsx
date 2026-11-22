import { useEffect, useState } from 'react'
import { Boxes } from 'lucide-react'
import type { AssetInfo } from '@shared/types'
import { useApp } from '../store'
import { Counts, Empty, PageHead, Sev, ago } from '../ui'

const KIND: Record<AssetInfo['kind'], string> = { site: 'Website', api: 'API', domain: 'Domain', app: 'Mobile app', project: 'Project', mac: 'This Mac', other: 'Other' }

function Spark({ points }: { points: number[] }): React.JSX.Element | null {
  if (points.length < 2) return null
  const w = 120
  const h = 28
  const max = Math.max(100, ...points)
  const d = points.map((p, i) => `${i ? 'L' : 'M'}${((i / (points.length - 1)) * w).toFixed(1)},${(h - (p / max) * h).toFixed(1)}`).join(' ')
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`Risk over ${points.length} scans: ${points.join(', ')}`}>
      <path d={d} fill="none" stroke="currentColor" strokeWidth="1.6" />
    </svg>
  )
}

/** Every site, API, app and project MacSec has looked at, with one risk score and what to fix first. */
export default function Assets(): React.JSX.Element {
  const { showSession, sessions } = useApp()
  const api = window.macsec
  const [list, setList] = useState<AssetInfo[] | null>(null)
  useEffect(() => {
    void api.invoke('assets:list').then(setList)
  }, [api, sessions])
  return (
    <>
      <PageHead title="Assets" desc="Everything you have tested, one line each. The risk score is 0 to 100 and goes down as you fix things. A site, its API and its recon count as one asset." />
      {list && !list.length && <Empty title="No assets yet">Run a test and it shows up here with a score.</Empty>}
      <div style={{ display: 'grid', gap: 14 }}>
        {(list ?? []).map((a) => (
          <section key={a.key} className="panel" aria-label={a.name}>
            <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
              <Boxes size={18} aria-hidden />
              <div style={{ flex: 1, minWidth: 160 }}>
                <strong>{a.name}</strong>
                <div className="hint">
                  {KIND[a.kind]} · {a.scans} {a.scans === 1 ? 'test' : 'tests'} · last {ago(a.lastScan)}
                </div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 28, fontWeight: 650 }}>{a.risk}</div>
                <div className="hint">{a.riskLabel}</div>
              </div>
              <Spark points={a.trend.map((t) => t.risk)} />
              <button className="btn btn-sm" onClick={() => showSession(a.lastSession)}>
                Open latest
              </button>
            </div>
            <div style={{ marginTop: 10, display: 'flex', gap: 14, flexWrap: 'wrap', alignItems: 'center' }}>
              <Counts counts={a.open} empty="Nothing open" />
              {a.proven > 0 && <span className="tag">{a.proven} proven</span>}
              {a.fixed > 0 && (
                <span className="hint">
                  {a.fixed} fixed{a.mttrDays !== undefined ? `, about ${a.mttrDays} ${a.mttrDays === 1 ? 'day' : 'days'} each` : ''}
                </span>
              )}
            </div>
            {a.actions.length > 0 && (
              <>
                <h3 style={{ margin: '14px 0 6px', fontSize: 14 }}>Fix these first{a.dropIfDone > 0 ? `: the score drops by about ${a.dropIfDone}` : ''}</h3>
                <ol style={{ margin: 0, paddingLeft: 20, display: 'grid', gap: 6 }}>
                  {a.actions.map((x) => (
                    <li key={x.ids.join()}>
                      <Sev s={x.worst} /> <strong>{x.title}</strong> <span className="hint">(takes off {Math.round(x.drop)} points)</span>
                      {x.fix && <div className="hint">{x.fix}</div>}
                    </li>
                  ))}
                </ol>
              </>
            )}
            {a.chains.length > 0 && (
              <>
                <h3 style={{ margin: '14px 0 6px', fontSize: 14 }}>How problems connect</h3>
                <div style={{ display: 'grid', gap: 8 }}>
                  {a.chains.map((c) => (
                    <div key={c.id}>
                      <Sev s={c.severity} /> <strong>{c.name}</strong>
                      <div className="hint">{c.story}</div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </section>
        ))}
      </div>
    </>
  )
}
