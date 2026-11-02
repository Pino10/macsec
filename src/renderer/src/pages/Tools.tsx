import { useEffect, useState } from 'react'
import { Bot, Check, Cpu, Download, ExternalLink, FolderOpen, Globe2, KeyRound, Package, RefreshCw, Shield, Sparkles, Terminal, Trash2, Wrench } from 'lucide-react'
import type { AgentInfo, LocalLlm, ToolCategory, ToolInfo } from '@shared/types'
import { useApp } from '../store'
import { PageHead } from '../ui'

const GROUPS: { id: ToolCategory; title: string; icon: React.ReactNode }[] = [
  { id: 'code', title: 'Code', icon: <Shield size={18} /> },
  { id: 'secrets', title: 'Keys and passwords', icon: <KeyRound size={18} /> },
  { id: 'deps', title: 'Packages and configuration', icon: <Package size={18} /> },
  { id: 'web', title: 'Web (for Web scan, coming next)', icon: <Globe2 size={18} /> },
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
  const missing = tools.filter((t) => !t.installed && t.method !== 'app' && t.category !== 'web')
  const allModels = (llms ?? []).flatMap((l) => l.models.map((m) => ({ server: l, model: m })))
  const chosen = settings?.llm

  return (
    <>
      <PageHead title="Tools" desc="Every scanner lives in the MacSec folder, checked against its published checksum. Nothing is installed anywhere else on your Mac.">
        <button className="btn" onClick={() => void api.invoke('app:open-folder', 'tools')}>
          <FolderOpen size={14} /> Open tools folder
        </button>
        <button className="btn" disabled={busy.has('data')} onClick={() => void act('data', () => api.invoke('tools:update-data')).then(() => notify({ kind: 'info', text: 'Scanner databases are up to date.' }))}>
          <RefreshCw size={14} /> Update databases
        </button>
        <button className="btn btn-primary" disabled={missing.length === 0 || busy.has('all')} onClick={() => install(['uv', ...missing.map((t) => t.id)], 'all')}>
          <Download size={14} /> {missing.length === 0 ? 'All installed' : busy.has('all') ? 'Installing…' : `Install ${missing.length} missing`}
        </button>
      </PageHead>

      <h2 className="section-title" style={{ marginTop: 6 }}>
        AI reviewers
      </h2>
      <div className="panel">
        {agents.map((a) => (
          <div key={a.id} className="tool-card" data-installed={a.installed}>
            <span className="tool-icon">{a.id === 'claude' ? <Sparkles size={18} /> : a.id === 'codex' ? <Bot size={18} /> : a.id === 'lmstudio' ? <Cpu size={18} /> : <Terminal size={18} />}</span>
            <div>
              <div className="row-title">
                {a.name} {a.installed && <span className="tag tag-ok">{a.version ?? 'Installed'}</span>}
              </div>
              <div className="row-sub">{a.role}</div>
            </div>
            {a.installed ? (
              <Check size={16} style={{ color: 'var(--ok)' }} />
            ) : a.id === 'claude' || a.id === 'codex' ? (
              <button className="btn btn-sm" onClick={() => void act('agent', () => api.invoke('ai:install-agent', a.id as 'claude' | 'codex')).then(() => notify({ kind: 'info', text: `Terminal is installing ${a.name}. Run it once there to sign in, then come back.` }))}>
                <Download size={13} /> Install
              </button>
            ) : (
              <button className="btn btn-sm" onClick={() => void api.invoke('app:open-external', a.id === 'burp' ? 'https://portswigger.net/burp/releases' : a.id === 'zap' ? 'https://www.zaproxy.org/download/' : 'https://lmstudio.ai')}>
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
    <div className="tool-card" data-installed={t.installed}>
      <span className="tool-icon">{icon}</span>
      <div style={{ minWidth: 0 }}>
        <div className="row-title">
          {t.name} {t.installed && <span className="tag tag-ok">{t.version ?? 'Installed'}</span>}
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
