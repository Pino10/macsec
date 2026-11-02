import { useEffect, useMemo, useState } from 'react'
import { FolderInput, FolderOpen, GitBranch, Globe2, KeyRound, Laptop, Lock, RefreshCw, Search, Unplug } from 'lucide-react'
import type { Accounts, AzureProject, LocalProject, RemoteRepo } from '@shared/types'
import { useApp, type PresetSource } from '../store'
import { Seg, ago } from '../ui'

export type Tab = 'local' | 'github' | 'azure'

/**
 * Lists projects from the www folder, GitHub and Azure DevOps. `onPick` gets the chosen one;
 * `action` names the button ("Review") when the list is a launcher rather than a picker.
 */
export default function SourcePicker({ selected, onPick, action }: { selected?: PresetSource | null; onPick: (s: PresetSource) => void; action?: string }): React.JSX.Element {
  const { act, busy, settings, setSettings } = useApp()
  const api = window.macsec
  const [tab, setTab] = useState<Tab>(() => (selected?.kind === 'github' ? 'github' : selected?.kind === 'azure' ? 'azure' : 'local'))
  const [q, setQ] = useState('')
  const [local, setLocal] = useState<LocalProject[] | null>(null)
  const [acc, setAcc] = useState<Accounts | null>(null)
  const [gh, setGh] = useState<RemoteRepo[] | null>(null)
  const [az, setAz] = useState<AzureProject[] | null>(null)
  const [azPath, setAzPath] = useState('')
  const [token, setToken] = useState('')
  const [org, setOrg] = useState('')

  useEffect(() => {
    void api.invoke('projects:local').then(setLocal)
    void api.invoke('accounts:get').then((a) => {
      setAcc(a)
      setAzPath(a.azure.org ?? '')
    })
  }, [api, settings?.wwwPath])

  useEffect(() => {
    if (tab === 'github' && acc?.github.connected && !gh) void act('gh-repos', () => api.invoke('github:repos')).then((r) => r && setGh(r))
    if (tab === 'azure' && acc?.azure.connected && !az && acc.azure.org) void act('az-projects', () => api.invoke('azure:projects', acc.azure.org!)).then((r) => r && setAz(r))
  }, [tab, acc, gh, az, act, api])

  const match = (s: string): boolean => !q.trim() || s.toLowerCase().includes(q.trim().toLowerCase())
  const isSel = (s: PresetSource): boolean =>
    !!selected && selected.kind === s.kind && (s.kind === 'local' ? (selected as { path: string }).path === s.path : s.kind === 'github' ? (selected as { repo: string }).repo === s.repo : (selected as { url: string }).url === s.url)

  const azureCount = useMemo(() => az?.reduce((n, p) => n + p.repos.length, 0) ?? 0, [az])

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <Seg<Tab>
          label="Where"
          value={tab}
          onChange={(t) => {
            setTab(t)
            setQ('')
          }}
          options={[
            ['local', <><Laptop size={13} /> Your www{local ? ` (${local.length})` : ''}</>],
            ['github', <><GitBranch size={13} /> GitHub{gh ? ` (${gh.length})` : ''}</>],
            ['azure', <><Globe2 size={13} /> Azure DevOps{az ? ` (${azureCount})` : ''}</>]
          ]}
        />
        <div style={{ flex: 1, minWidth: 180, position: 'relative' }}>
          <Search size={14} style={{ position: 'absolute', left: 12, top: 11, color: 'var(--ink-3)' }} />
          <input className="input" style={{ paddingLeft: 34 }} placeholder="Filter" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter projects" />
        </div>
      </div>

      {tab === 'local' && (
        <>
          <div className="hint" style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <span className="mono">{settings?.wwwPath}</span>
            <button
              className="link"
              onClick={async () => {
                const s = await act('www', () => api.invoke('settings:choose-www'))
                if (s) setSettings(s)
              }}
            >
              Change
            </button>
            <span style={{ flex: 1 }} />
            <button
              className="btn btn-sm"
              disabled={busy.has('import')}
              onClick={async () => {
                const r = await act('import', () => api.invoke('projects:import'))
                if (r) setLocal(r)
              }}
            >
              <FolderInput size={13} /> Import a folder into www
            </button>
            <button
              className="btn btn-sm"
              onClick={async () => {
                const p = await act('pick', () => api.invoke('projects:pick'))
                if (p) onPick({ kind: 'local', path: p.path, name: p.name })
              }}
            >
              <FolderOpen size={13} /> Any other folder
            </button>
          </div>
          <div className="pick-list" role="listbox" aria-label="Projects">
            {local === null ? (
              <div className="pick-item hint">Loading…</div>
            ) : local.filter((p) => match(p.name)).length === 0 ? (
              <div className="pick-item hint">{local.length ? 'Nothing matches.' : 'No projects in this folder yet. Projects you make in Laramac appear here.'}</div>
            ) : (
              local
                .filter((p) => match(p.name))
                .map((p) => {
                  const s: PresetSource = { kind: 'local', path: p.path, name: p.name }
                  return (
                    <button key={p.path} className="pick-item" role="option" aria-selected={isSel(s)} onClick={() => onPick(s)}>
                      <Laptop size={15} style={{ color: 'var(--ink-3)' }} />
                      <span className="grow">
                        {p.name}
                        <span className="sub">{p.languages.join(', ') || 'No source files found'}{p.git ? ' · Git' : ''}</span>
                      </span>
                      {action && <span className="btn btn-sm">{action}</span>}
                    </button>
                  )
                })
            )}
          </div>
        </>
      )}

      {tab === 'github' &&
        (!acc?.github.connected ? (
          <div className="ms-form glass" style={{ marginBottom: 0 }}>
            <div className="hint">
              Paste a GitHub token once. MacSec keeps it in your Keychain and lists every repository you can read: your own, your organizations’, and ones shared with you. A fine-grained token with <strong>Contents: Read-only</strong> and <strong>Metadata: Read-only</strong> on all repositories is enough.{' '}
              <button className="link" onClick={() => void api.invoke('app:open-external', 'https://github.com/settings/personal-access-tokens/new')}>
                Make a token
              </button>
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <input className="input mono" type="password" autoComplete="off" placeholder="github_pat_… or ghp_…" value={token} onChange={(e) => setToken(e.target.value)} aria-label="GitHub token" style={{ flex: 1 }} />
              <button
                className="btn btn-primary"
                disabled={!token.trim() || busy.has('gh-connect')}
                onClick={async () => {
                  const a = await act('gh-connect', () => api.invoke('accounts:github', token))
                  setToken('')
                  if (a) setAcc(a)
                }}
              >
                <KeyRound size={14} /> {busy.has('gh-connect') ? 'Checking…' : 'Connect'}
              </button>
            </div>
          </div>
        ) : (
          <>
            <div className="hint" style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              Signed in as <strong>{acc.github.login}</strong>
              <button className="link" onClick={() => void act('gh-repos', () => api.invoke('github:repos')).then((r) => r && setGh(r))}>
                <RefreshCw size={11} /> Refresh
              </button>
              <span style={{ flex: 1 }} />
              <button
                className="link"
                onClick={async () => {
                  const a = await act('gh-off', () => api.invoke('accounts:github', null))
                  if (a) {
                    setAcc(a)
                    setGh(null)
                  }
                }}
              >
                <Unplug size={11} /> Disconnect
              </button>
            </div>
            <div className="pick-list" role="listbox" aria-label="GitHub repositories">
              {!gh ? (
                <div className="pick-item hint">{busy.has('gh-repos') ? 'Loading your repositories…' : 'No repositories loaded.'}</div>
              ) : (
                gh
                  .filter((r) => match(r.name))
                  .map((r) => {
                    const s: PresetSource = { kind: 'github', repo: r.name }
                    return (
                      <button key={r.name} className="pick-item" role="option" aria-selected={isSel(s)} onClick={() => onPick(s)}>
                        <GitBranch size={15} style={{ color: 'var(--ink-3)' }} />
                        <span className="grow">
                          {r.name} {r.private && <Lock size={11} style={{ color: 'var(--ink-3)' }} />}
                          <span className="sub">{[r.language, r.description, r.updatedAt && `pushed ${ago(r.updatedAt)}`].filter(Boolean).join(' · ')}</span>
                        </span>
                        {action && <span className="btn btn-sm">{action}</span>}
                      </button>
                    )
                  })
              )}
            </div>
          </>
        ))}

      {tab === 'azure' &&
        (!acc?.azure.connected ? (
          <div className="ms-form glass" style={{ marginBottom: 0 }}>
            <div className="hint">
              Enter your organization and a personal access token with <strong>Code (Read)</strong> and <strong>Project and Team (Read)</strong>. As an administrator you will see every project and repository. The token stays in your Keychain.
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr auto', gap: 10 }}>
              <input className="input mono" placeholder="Organization" value={org} onChange={(e) => setOrg(e.target.value)} aria-label="Organization" />
              <input className="input mono" type="password" autoComplete="off" placeholder="Personal access token" value={token} onChange={(e) => setToken(e.target.value)} aria-label="Personal access token" />
              <button
                className="btn btn-primary"
                disabled={!org.trim() || !token.trim() || busy.has('az-connect')}
                onClick={async () => {
                  const a = await act('az-connect', () => api.invoke('accounts:azure', org, token))
                  setToken('')
                  if (a) {
                    setAcc(a)
                    setAzPath(a.azure.org ?? '')
                  }
                }}
              >
                <KeyRound size={14} /> {busy.has('az-connect') ? 'Checking…' : 'Connect'}
              </button>
            </div>
          </div>
        ) : (
          <>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <span className="hint">dev.azure.com/</span>
              <input className="input mono" style={{ flex: 1 }} value={azPath} onChange={(e) => setAzPath(e.target.value)} placeholder="organization or organization/project" aria-label="Azure DevOps path" onKeyDown={(e) => e.key === 'Enter' && void act('az-projects', () => api.invoke('azure:projects', azPath)).then((r) => r && setAz(r))} />
              <button className="btn" disabled={busy.has('az-projects')} onClick={() => void act('az-projects', () => api.invoke('azure:projects', azPath)).then((r) => r && setAz(r))}>
                <RefreshCw size={13} /> {busy.has('az-projects') ? 'Loading…' : 'Load'}
              </button>
              <button
                className="link hint"
                onClick={async () => {
                  const a = await act('az-off', () => api.invoke('accounts:azure', null, null))
                  if (a) {
                    setAcc(a)
                    setAz(null)
                  }
                }}
              >
                <Unplug size={11} /> Disconnect
              </button>
            </div>
            <div className="pick-list" role="listbox" aria-label="Azure DevOps repositories" style={{ maxHeight: 360 }}>
              {!az ? (
                <div className="pick-item hint">{busy.has('az-projects') ? 'Loading every project and repository…' : 'Press Load.'}</div>
              ) : (
                az.map((p) => {
                  const repos = p.repos.filter((r) => match(r.name))
                  if (repos.length === 0) return null
                  return (
                    <div key={p.name}>
                      <div className="pick-item" style={{ cursor: 'default', fontSize: 12, fontWeight: 600, color: 'var(--ink-2)', background: 'rgba(255,255,255,0.02)' }}>
                        {p.name} <span className="hint">· {p.repos.length} {p.repos.length === 1 ? 'repository' : 'repositories'}</span>
                      </div>
                      {repos.map((r) => {
                        const s: PresetSource = { kind: 'azure', url: r.url, name: r.name }
                        return (
                          <button key={r.url} className="pick-item" role="option" aria-selected={isSel(s)} onClick={() => onPick(s)} style={{ paddingLeft: 28 }}>
                            <Globe2 size={15} style={{ color: 'var(--ink-3)' }} />
                            <span className="grow">
                              {r.name.split('/').slice(1).join('/')}
                              <span className="sub">{r.defaultBranch ?? ''}</span>
                            </span>
                            {action && <span className="btn btn-sm">{action}</span>}
                          </button>
                        )
                      })}
                    </div>
                  )
                })
              )}
            </div>
          </>
        ))}
    </div>
  )
}

export function sourceName(s: PresetSource): string {
  return s.kind === 'local' ? s.name : s.kind === 'github' ? s.repo : s.name
}
