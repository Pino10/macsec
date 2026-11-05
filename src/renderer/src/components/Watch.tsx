import { useEffect, useState } from 'react'
import { Eye, RefreshCw } from 'lucide-react'
import type { WatchInfo } from '@shared/types'
import { useApp } from '../store'
import { Switch, ago } from '../ui'

/** Keeping watch: daily package alerts and the weekly re-test, with what they found. */
export default function Watch(): React.JSX.Element | null {
  const { act, busy, showSession } = useApp()
  const api = window.macsec
  const [w, setW] = useState<WatchInfo | null>(null)
  useEffect(() => {
    void api.invoke('watch:get').then(setW)
    return api.on('watch:alert', () => void api.invoke('watch:get').then(setW))
  }, [api])
  if (!w) return null
  const set = async (patch: { packages?: boolean; retest?: boolean }): Promise<void> => {
    const r = await act('watch', () => api.invoke('watch:set', patch))
    if (r) setW(r)
  }
  return (
    <>
      <h2 className="section-title" style={{ marginTop: 22 }}>
        <Eye size={15} /> Keeping watch
      </h2>
      <div className="panel watch">
        <div className="watch-row">
          <div>
            <strong>New flaws in your packages, daily</strong>
            <span className="hint">
              OSV-Scanner reads the lock files of the {w.projects === 1 ? 'project' : `${w.projects} projects`} you reviewed on this Mac and asks osv.dev about the versions. Only package names and versions leave the Mac. {w.lastPackages ? `Last checked ${ago(w.lastPackages)}.` : 'Not checked yet.'}
            </span>
          </div>
          <button className="btn btn-sm" disabled={busy.has('watch-now') || !w.projects} onClick={async () => {
            const r = await act('watch-now', () => api.invoke('watch:check-now'))
            if (r) setW(r)
          }}>
            <RefreshCw size={13} /> {busy.has('watch-now') ? 'Checking…' : 'Check now'}
          </button>
          <Switch on={w.packages} label="Daily package alerts" onChange={() => void set({ packages: !w.packages })} />
        </div>
        <div className="watch-row">
          <div>
            <strong>Test again every week</strong>
            <span className="hint">The newest code review of each project runs again while MacSec is open. You hear about it only when it finds serious problems that were not there before.</span>
          </div>
          <Switch on={w.retest} label="Weekly re-test" onChange={() => void set({ retest: !w.retest })} />
        </div>
        {w.alerts.length > 0 && (
          <div className="watch-alerts">
            {w.alerts.slice(0, 4).map((a) => (
              <button key={a.at + a.project} className="watch-alert" onClick={() => showSession(a.session)}>
                <b>{a.count} new</b>
                <span>
                  {a.project}: {a.titles.join('; ')}
                </span>
                <time>{ago(a.at)}</time>
              </button>
            ))}
          </div>
        )}
      </div>
    </>
  )
}
