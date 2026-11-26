import { useEffect, useState } from 'react'
import { GitBranch, Globe, Layers3, ShieldCheck } from 'lucide-react'
import type { LocalProject } from '@shared/types'
import { useApp } from '../store'
import { PageHead } from '../ui'
import SourcePicker from '../components/SourcePicker'

export default function Projects(): React.JSX.Element {
  const { setPreset, setPage, act, notify, busy, showSession } = useApp()
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
      <PageHead title="Projects" desc="Everything you can test: your www folder (shared with Laramac), your GitHub repositories and your Azure DevOps organization.">
        <button
          className="btn"
          disabled={busy.has('sweep')}
          title="Keys and passwords in files and Git history, and packages with known flaws, in every project at once"
          onClick={async () => {
            const s = await act('sweep', () => window.macsec.invoke('audit:start', { kind: 'portfolio' } as never))
            if (s) showSession(s.id)
          }}
        >
          <Layers3 size={15} /> {busy.has('sweep') ? 'Starting…' : 'Check every project'}
        </button>
      </PageHead>
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
          <h2 className="section-title">Your local projects ({local.length})</h2>
          <p className="hint" style={{ marginBottom: 10 }}>
            A pre-commit hook stops a commit that contains a key or password. A CI workflow runs the same free scanners on every push. MacSec asks where to save each file, so nothing in your project changes without you.
          </p>
          <div className="proj-grid">
            {local.map((p) => (
              <article key={p.path} className="proj-card">
                <header>
                  <strong title={p.name}>{p.name}</strong>
                  {p.git && <GitBranch size={12} style={{ opacity: 0.6 }} aria-label="Git repository" />}
                </header>
                <div className="row-sub" style={{ whiteSpace: 'normal' }}>
                  {p.languages.join(', ') || 'No code found'}
                  {p.url ? <> · <span className="mono">{p.url.replace(/^https?:\/\//, '')}</span></> : null}
                </div>
                <div className="proj-actions">
                  <button className="btn btn-sm" disabled={!p.git} title={p.git ? 'Stops commits that contain keys' : 'This project is not a Git repository'} onClick={() => void act(`hook-${p.name}`, () => api.invoke('projects:save-hook', p.path)).then(saved)}>
                    <ShieldCheck size={13} /> Pre-commit hook
                  </button>
                  <select
                    className="input"
                    value=""
                    aria-label={`CI workflow for ${p.name}`}
                    onChange={(e) => {
                      const k = e.target.value as 'github' | 'azure'
                      if (k) void act(`ci-${p.name}`, () => api.invoke('projects:save-ci', p.path, k)).then(saved)
                    }}
                  >
                    <option value="">CI workflow…</option>
                    <option value="github">GitHub Actions</option>
                    <option value="azure">Azure Pipelines</option>
                  </select>
                  {p.url && (
                    <button className="btn btn-sm" title="Web scan this Laramac site" onClick={() => setPage('web')}>
                      <Globe size={13} /> Web scan
                    </button>
                  )}
                </div>
              </article>
            ))}
          </div>
        </>
      )}
    </>
  )
}
