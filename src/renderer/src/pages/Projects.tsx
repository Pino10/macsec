import { useEffect, useState } from 'react'
import { GitBranch, Globe, ShieldCheck, Workflow } from 'lucide-react'
import type { LocalProject } from '@shared/types'
import { useApp } from '../store'
import { PageHead } from '../ui'
import SourcePicker from '../components/SourcePicker'

export default function Projects(): React.JSX.Element {
  const { setPreset, setPage, act, notify } = useApp()
  const api = window.macsec
  const [local, setLocal] = useState<LocalProject[]>([])
  useEffect(() => {
    void api.invoke('projects:local').then(setLocal)
  }, [api])
  const saved = (p: string | null | undefined): void => {
    if (p) notify({ kind: 'info', text: `Saved ${p.split('/').slice(-2).join('/')}.` })
  }
  return (
    <>
      <PageHead title="Projects" desc="Everything you can test: your www folder (shared with Laramac), your GitHub repositories and your Azure DevOps organization." />
      <div className="ms-form glass">
        <SourcePicker
          action="Review"
          onPick={(s) => {
            setPreset(s)
            setPage('review')
          }}
        />
      </div>
      {local.length > 0 && (
        <>
          <h2 className="section-title">Keep them safe between reviews</h2>
          <p className="hint" style={{ marginBottom: 10 }}>
            A pre-commit hook stops a commit that contains a key or password. A CI workflow runs the same free scanners on every push. MacSec asks where to save each file, so nothing in your project changes without you.
          </p>
          <div className="panel">
            {local.map((p) => (
              <div key={p.path} className="row proj-row">
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="row-title">
                    {p.name} {p.git && <GitBranch size={12} style={{ opacity: 0.6 }} />}
                  </div>
                  <div className="row-sub">
                    {p.languages.join(', ') || 'No code found'}
                    {p.url ? <> · <span className="mono">{p.url.replace(/^https?:\/\//, '')}</span></> : null}
                  </div>
                </div>
                {p.url && (
                  <button className="btn btn-sm" title="Web scan this Laramac site" onClick={() => setPage('web')}>
                    <Globe size={13} /> Web scan
                  </button>
                )}
                <button className="btn btn-sm" disabled={!p.git} title={p.git ? 'Stops commits that contain keys' : 'This project is not a Git repository'} onClick={() => void act(`hook-${p.name}`, () => api.invoke('projects:save-hook', p.path)).then(saved)}>
                  <ShieldCheck size={13} /> Pre-commit hook
                </button>
                <select
                  className="input"
                  style={{ width: 150 }}
                  value=""
                  aria-label="CI workflow"
                  onChange={(e) => {
                    const k = e.target.value as 'github' | 'azure'
                    if (k) void act(`ci-${p.name}`, () => api.invoke('projects:save-ci', p.path, k)).then(saved)
                  }}
                >
                  <option value="">CI workflow…</option>
                  <option value="github">GitHub Actions</option>
                  <option value="azure">Azure Pipelines</option>
                </select>
                <Workflow size={14} style={{ opacity: 0.4 }} />
              </div>
            ))}
          </div>
        </>
      )}
    </>
  )
}
