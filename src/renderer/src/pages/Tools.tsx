import { useEffect, useState } from 'react'
import { ArrowUpCircle, Bot, Check, Cpu, Download, ExternalLink, FolderOpen, Globe2, KeyRound, Package, RefreshCw, Shield, Sparkles, Terminal, Trash2, Wrench } from 'lucide-react'
import type { AgentInfo, LocalLlm, ToolCategory, ToolInfo } from '@shared/types'
import { useApp } from '../store'
import { PageHead } from '../ui'

const GROUPS: { id: ToolCategory; title: string; icon: React.ReactNode }[] = [
  { id: 'code', title: 'Code', icon: <Shield size={18} /> },
  { id: 'secrets', title: 'Keys and passwords', icon: <KeyRound size={18} /> },
  { id: 'deps', title: 'Packages and configuration', icon: <Package size={18} /> },
  { id: 'web', title: 'Web and API', icon: <Globe2 size={18} /> },
  { id: 'runtime', title: 'Helpers', icon: <Wrench size={18} /> }
]

export default function Tools(): React.JSX.Element {
  const { tools, setTools, act, busy, settings, updateSettings, notify } = useApp()
  const api = window.macsec
  const [agents, setAgents] = useState<AgentInfo[]>([])
  const [llms, setLlms] = useState<LocalLlm[] | null>(null)

  const refreshAi = (): void => {
    void api.invoke('ai:agents').then(setAgents)
    void api.invoke('ai:detect').then(setLlms)
  }
  useEffect(() => {
    refreshAi()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api])

  const install = async (ids: string[], key: string): Promise<void> => {
    const r = await act(key, () => api.invoke('tools:install', ids))
    if (r) setTools(r)
  }
  const missing = tools.filter((t) => !t.installed && t.method !== 'app')
  const outdated = tools.filter((t) => t.updateAvailable)
  const allModels = (llms ?? []).flatMap((l) => l.models.map((m) => ({ server: l, model: m })))
  const chosen = settings?.llm

  return (
    <>
      <PageHead title="Tools" desc="Every scanner lives in the MacSec folder, checked against its published checksum. Nothing is installed anywhere else on your Mac.">
        <button className="btn" onClick={() => void api.invoke('app:open-folder', 'tools')}>
          <FolderOpen size={14} /> Open tools folder
        </button>
        <button
          className="btn"
          disabled={busy.has('check')}
          onClick={async () => {
            const r = await act('check', () => api.invoke('tools:check-updates'))
            if (r) {
              setTools(r)
              const n = r.filter((t) => t.updateAvailable).length
              notify({ kind: 'info', text: n ? `${n} ${n === 1 ? 'tool has' : 'tools have'} a newer version.` : 'Every tool is up to date.' })
            }
          }}
        >
          <RefreshCw size={14} className={busy.has('check') ? 'spin' : undefined} /> Check for updates
        </button>
        <button className="btn btn-primary" disabled={missing.length === 0 || busy.has('all')} onClick={() => install(['uv', ...missing.map((t) => t.id)], 'all')}>
          <Download size={14} /> {missing.length === 0 ? 'All installed' : busy.has('all') ? 'Installing…' : `Install ${missing.length} missing`}
        </button>
      </PageHead>

      {outdated.length > 0 && (
        <div className="notice info">
          <ArrowUpCircle size={17} style={{ color: 'var(--ion)', flexShrink: 0 }} />
          <span className="grow">
            Newer versions: {outdated.map((t) => `${t.name} ${t.latest}`).join(', ')}. Updating downloads them the same way, checked against their checksums, and refreshes the scanner databases.
          </span>
          <button
            className="btn btn-sm btn-primary"
            disabled={busy.has('upd')}
            onClick={async () => {
              const r = await act('upd', () => api.invoke('tools:install', outdated.map((t) => t.id)))
              if (r) setTools(r)
              await act('data', () => api.invoke('tools:update-data'))
            }}
          >
            {busy.has('upd') ? 'Updating…' : `Update ${outdated.length}`}
          </button>
        </div>
      )}

      <h2 className="section-title" style={{ marginTop: 6 }}>
        AI and your apps
      </h2>
      <div className="panel">
        {agents.map((a) => (
          <div key={a.id} className="arsenal-row" data-on={a.installed || !!a.app}>
            <span className="glyph" style={{ ['--g' as string]: a.id === 'claude' ? '#38e1ff' : a.id === 'codex' ? '#8b6cff' : a.id === 'burp' ? '#ff8a3d' : '#3ef0a8' }}>{a.id === 'claude' ? <Sparkles size={18} /> : a.id === 'codex' ? <Bot size={18} /> : a.id === 'lmstudio' ? <Cpu size={18} /> : <Terminal size={18} />}</span>
            <div>
              <div className="row-title">
                {a.name} {a.installed && <span className="tag tag-ok">{a.version ? `CLI ${a.version}` : 'Installed'}</span>} {a.app && (a.id === 'claude' || a.id === 'codex') && <span className="tag tag-ion">Desktop app</span>}
              </div>
              <div className="row-sub">{a.role}</div>
            </div>
            {a.installed && a.app ? (
              <button className="btn btn-sm" onClick={() => void act('open-app', () => api.invoke('ai:open-app', a.id))}>
                Open
              </button>
            ) : a.installed ? (
              <Check size={16} style={{ color: 'var(--ok)' }} />
            ) : a.id === 'claude' || a.id === 'codex' ? (
              <button className="btn btn-sm" onClick={() => void act('agent', () => api.invoke('ai:install-agent', a.id as 'claude' | 'codex')).then(() => notify({ kind: 'info', text: `Terminal is installing ${a.name}. Run it once there to sign in, then come back.` }))}>
                <Download size={13} /> {a.app ? 'Add the CLI' : 'Install'}
              </button>
            ) : (
              <button className="btn btn-sm" onClick={() => void api.invoke('app:open-external', a.id === 'burp' ? 'https://portswigger.net/burp/releases' : 'https://lmstudio.ai')}>
                Get it <ExternalLink size={12} />
              </button>
            )}
          </div>
        ))}
      </div>
      <p className="hint" style={{ margin: '8px 2px 0' }}>
        MacSec uses Claude Code’s command line tool (the Claude desktop app is separate). <strong>Continue in Claude Code</strong> on a session opens it in Terminal with Remote Control on, so you can carry on at claude.ai/code or on your phone. A session started on the web comes back to Terminal with <span className="mono">claude --teleport</span>.
      </p>

      <h2 className="section-title">Your model</h2>
      <div className="ms-form glass">
        <div className="hint">For the “Your model” reviewer. MacSec finds LM Studio, Ollama and other servers on this Mac by itself. Big-context models (100k tokens or more) read far more of the project at once.</div>
        <div style={{ display: 'flex', gap: 10 }}>
          <select
            className="input"
            style={{ flex: 1 }}
            value={chosen?.model ? `${chosen.baseUrl}|${chosen.model}` : ''}
            onChange={(e) => {
              const [baseUrl, ...m] = e.target.value.split('|')
              void updateSettings({ llm: { baseUrl, model: m.join('|') } })
            }}
            aria-label="Model"
          >
            <option value="">{llms === null ? 'Looking for models…' : allModels.length ? 'Choose a model' : 'No model servers found. Open LM Studio and start its server.'}</option>
            {allModels.map(({ server, model }) => (
              <option key={`${server.baseUrl}|${model}`} value={`${server.baseUrl}|${model}`}>
                {server.provider}: {model}
                {server.loaded.includes(model) ? ' (loaded)' : ''}
              </option>
            ))}
          </select>
          <button className="btn" onClick={refreshAi}>
            <RefreshCw size={13} /> Look again
          </button>
          <button
            className="btn"
            disabled={!chosen?.model || busy.has('test')}
            onClick={async () => {
              const r = await act('test', () => api.invoke('ai:test', chosen!.baseUrl, chosen!.model))
              if (r) notify({ kind: r.ok ? 'info' : 'error', text: r.ok ? `The model answered in ${(r.ms / 1000).toFixed(1)} s.` : (r.error ?? 'No answer.') })
            }}
          >
            {busy.has('test') ? 'Testing…' : 'Test'}
          </button>
        </div>
      </div>

      {GROUPS.map((g) => {
        const list = tools.filter((t) => t.category === g.id)
        if (!list.length) return null
        return (
          <div key={g.id}>
            <h2 className="section-title">{g.title}</h2>
            <div className="panel">
              {list.map((t) => (
                <ToolRow key={t.id} t={t} icon={g.icon} onInstall={() => install([t.id], `i-${t.id}`)} onRemove={async () => {
                  const r = await act(`r-${t.id}`, () => api.invoke('tools:remove', t.id))
                  if (r) setTools(r)
                }} busy={busy.has(`i-${t.id}`) || busy.has('all')} />
              ))}
            </div>
          </div>
        )
      })}
    </>
  )
}

function ToolRow({ t, icon, onInstall, onRemove, busy }: { t: ToolInfo; icon: React.ReactNode; onInstall: () => void; onRemove: () => void; busy: boolean }): React.JSX.Element {
  return (
    <div className="arsenal-row" data-on={t.installed}>
      <span className="glyph">{icon}</span>
      <div style={{ minWidth: 0 }}>
        <div className="row-title">
          {t.name} {t.installed && <span className="tag tag-ok">{t.version ?? 'Installed'}</span>} {t.updateAvailable && <span className="tag tag-ion">{t.latest} available</span>}
          {t.languages.length > 0 && <span className="hint" style={{ marginLeft: 6 }}>{t.languages.join(', ')}</span>}
        </div>
        <div className="row-sub">{t.purpose}</div>
      </div>
      <div style={{ display: 'flex', gap: 6 }}>
        <button className="icon-btn" data-tip="Website" aria-label={`${t.name} website`} onClick={() => void window.macsec.invoke('app:open-external', t.homepage)}>
          <ExternalLink />
        </button>
        {t.method === 'app' ? (
          !t.installed && (
            <button className="btn btn-sm" onClick={() => void window.macsec.invoke('app:open-external', t.homepage)}>
              Get it
            </button>
          )
        ) : t.installed && t.updateAvailable ? (
          <button className="btn btn-sm" disabled={busy} onClick={onInstall}>
            <ArrowUpCircle size={13} /> {busy ? 'Updating…' : 'Update'}
          </button>
        ) : t.installed ? (
          <button className="icon-btn danger-text" data-tip="Remove" aria-label={`Remove ${t.name}`} onClick={onRemove}>
            <Trash2 />
          </button>
        ) : (
          <button className="btn btn-sm" disabled={busy} onClick={onInstall}>
            <Download size={13} /> {busy ? 'Installing…' : 'Install'}
          </button>
        )}
      </div>
    </div>
  )
}
