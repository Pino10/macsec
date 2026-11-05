import { useEffect, useState } from 'react'
import { Bell, Command, Copy, Download, ExternalLink, Network, Plug, RefreshCw, Trash2, Users, Workflow } from 'lucide-react'
import type { FreeLlmInfo, IntegrationsInfo, SkillPackInfo } from '@shared/types'
import { useApp } from '../store'
import { Switch } from '../ui'

/** Skills from Trail of Bits, Sentry, Cloudflare, Laravel and Anthropic, loaded into MacSec's Claude Code reviews. */
export function SkillPacks(): React.JSX.Element {
  const { act, busy } = useApp()
  const api = window.macsec
  const [packs, setPacks] = useState<SkillPackInfo[]>([])
  useEffect(() => {
    void api.invoke('packs:list').then(setPacks)
  }, [api])
  return (
    <div className="panel">
      {packs.map((p) => (
        <div key={p.id} className="arsenal-row" data-on={p.installed}>
          <span className="glyph" style={{ ['--g' as string]: '#f0a35b' }}>
            <Users size={18} />
          </span>
          <div>
            <div className="row-title">
              {p.name} skills <span className="tag">{p.license}</span> {p.installed && <span className="tag tag-ok">{p.loaded.length} loaded</span>}
            </div>
            <div className="row-sub" style={{ whiteSpace: 'normal' }}>
              {p.about}
              {p.commit ? ` Version ${p.commit.slice(0, 7)}.` : ''} Kept in MacSec’s folder; reviews stay read-only.
            </div>
          </div>
          <div style={{ display: 'flex', gap: 6 }}>
            <button className="icon-btn" aria-label={`${p.repo} on GitHub`} onClick={() => api.invoke('app:open-external', `https://github.com/${p.repo}`)}>
              <ExternalLink />
            </button>
            {p.installed && (
              <button className="icon-btn" aria-label={`Remove ${p.name} skills`} onClick={async () => setPacks((await act(`pk-${p.id}`, () => api.invoke('packs:remove', p.id))) ?? packs)}>
                <Trash2 />
              </button>
            )}
            <button className="btn btn-sm" disabled={busy.has(`pk-${p.id}`)} onClick={async () => setPacks((await act(`pk-${p.id}`, () => api.invoke('packs:install', p.id))) ?? packs)}>
              {p.installed ? <RefreshCw size={13} /> : <Download size={13} />} {busy.has(`pk-${p.id}`) ? 'Getting…' : p.installed ? 'Update' : 'Add'}
            </button>
          </div>
        </div>
      ))}
    </div>
  )
}

type Kind = 'slack' | 'teams' | 'discord' | 'generic'
const NAMES: Record<Kind, string> = { slack: 'Slack', teams: 'Teams', discord: 'Discord', generic: 'Other' }

/** MCP for AI tools, the macsec command, Raycast, Apple Shortcuts and team messages. */
export function Integrations(): React.JSX.Element {
  const { act, busy, notify } = useApp()
  const api = window.macsec
  const [info, setInfo] = useState<IntegrationsInfo | null>(null)
  const [kind, setKind] = useState<Kind>('slack')
  const [events, setEvents] = useState<'errors' | 'all'>('errors')
  const [url, setUrl] = useState('')
  useEffect(() => {
    void api.invoke('integrations:get').then((i) => {
      setInfo(i)
      if (i.webhook) {
        setKind(i.webhook.kind)
        setEvents(i.webhook.events)
      }
    })
  }, [api])
  if (!info) return <></>
  const copy = (t: string): void => {
    void navigator.clipboard.writeText(t)
    notify({ kind: 'info', text: 'Copied.' })
  }
  return (
    <div className="panel">
      <div className="arsenal-row" data-on={info.mcp.enabled}>
        <span className="glyph" style={{ ['--g' as string]: '#38e1ff' }}>
          <Plug size={18} />
        </span>
        <div>
          <div className="row-title">Let AI tools use MacSec (MCP)</div>
          <div className="row-sub" style={{ whiteSpace: 'normal' }}>
            Claude Code, Claude desktop and Cursor can read your sessions, compare them, start a code review of a project in www and run the Mac check-up. Only this Mac can reach it, with a private key. Turning it on also writes the macsec command into MacSec’s folder.
            {info.mcp.error && <span style={{ color: 'var(--bad)' }}> {info.mcp.error}</span>}
          </div>
          {info.mcp.enabled && (
            <div className="int-cmd">
              <code className="mono">{info.mcp.command.replace(/Bearer [a-f0-9]+/, 'Bearer ••••')}</code>
              <button className="btn btn-sm" onClick={() => copy(info.mcp.command)}>
                <Copy size={12} /> Copy for Claude Code
              </button>
            </div>
          )}
        </div>
        <Switch on={info.mcp.enabled} label="Let AI tools use MacSec" onChange={async () => setInfo((await act('mcp', () => api.invoke('mcp:enable', !info.mcp.enabled))) ?? info)} />
      </div>
      <div className="arsenal-row" data-on={!!info.webhook?.saved}>
        <span className="glyph" style={{ ['--g' as string]: '#8b6cff' }}>
          <Bell size={18} />
        </span>
        <div>
          <div className="row-title">Messages to your team {info.webhook?.saved && <span className="tag tag-ok">{NAMES[info.webhook.kind]}</span>}</div>
          <div className="row-sub" style={{ whiteSpace: 'normal' }}>A message when a session finds something critical or high, or fails{events === 'all' ? ', and when every session ends' : ''}. The address is kept in the Keychain.</div>
          <div className="int-form">
            <div className="seg" role="radiogroup">
              {(Object.keys(NAMES) as Kind[]).map((k) => (
                <button key={k} role="radio" aria-checked={kind === k} onClick={() => setKind(k)}>
                  {NAMES[k]}
                </button>
              ))}
            </div>
            <select className="input" value={events} onChange={(e) => setEvents(e.target.value as 'errors' | 'all')} aria-label="When">
              <option value="errors">Only problems</option>
              <option value="all">Every session</option>
            </select>
            <input className="input mono" type="password" placeholder={info.webhook?.saved ? 'Saved (paste to replace)' : 'Webhook address'} value={url} onChange={(e) => setUrl(e.target.value)} autoComplete="off" />
          </div>
        </div>
        <div style={{ display: 'grid', gap: 6 }}>
          <button className="btn btn-sm" disabled={busy.has('hook')} onClick={async () => { const r = await act('hook', () => api.invoke('webhook:set', { kind, events }, url || null)); if (r) { setInfo(r); setUrl('') } }}>
            Save
          </button>
          {info.webhook?.saved && (
            <button className="btn btn-sm" onClick={async () => { if ((await act('hookt', () => api.invoke('webhook:test'))) !== undefined) notify({ kind: 'info', text: 'Sent a test message.' }) }}>
              Test
            </button>
          )}
          {info.webhook && (
            <button className="btn btn-sm" onClick={async () => setInfo((await act('hookoff', () => api.invoke('webhook:set', null, null))) ?? info)}>
              Turn off
            </button>
          )}
        </div>
      </div>
      <div className="arsenal-row" data-on={info.raycastInstalled}>
        <span className="glyph" style={{ ['--g' as string]: '#ff6363' }}>
          <Command size={18} />
        </span>
        <div>
          <div className="row-title">Raycast</div>
          <div className="row-sub" style={{ whiteSpace: 'normal' }}>Script commands for sessions, the Mac check-up and reviews (needs “Let AI tools use MacSec”). In Raycast: Settings, Extensions, Script Commands, Add Directories, and choose the folder that opens.</div>
        </div>
        <button className="btn btn-sm" disabled={!info.mcp.enabled} onClick={async () => setInfo((await act('raycast', () => api.invoke('raycast:install'))) ?? info)}>
          {info.raycastInstalled ? 'Write again' : 'Add commands'}
        </button>
      </div>
      <div className="arsenal-row">
        <span className="glyph" style={{ ['--g' as string]: '#6fd18f' }}>
          <Workflow size={18} />
        </span>
        <div>
          <div className="row-title">Apple Shortcuts</div>
          <div className="row-sub" style={{ whiteSpace: 'normal' }}>Add a “Run Shell Script” action and paste one of these (needs “Let AI tools use MacSec”). Add --json to use the answer in later actions.</div>
          {info.shortcuts.map((s) => (
            <div key={s.title} className="int-cmd">
              <span>{s.title}</span>
              <code className="mono">{s.command}</code>
              <button className="icon-btn" aria-label={`Copy ${s.title}`} onClick={() => copy(s.command)}>
                <Copy />
              </button>
            </div>
          ))}
        </div>
        <span />
      </div>
    </div>
  )
}

/** Free LLM API: your free keys behind one address, for Claude Code reviews. The key goes to the Keychain. */
export function FreeLlmPanel(): React.JSX.Element {
  const { act, busy, notify } = useApp()
  const api = window.macsec
  const [s, setS] = useState<FreeLlmInfo | null>(null)
  const [url, setUrl] = useState('')
  const [model, setModel] = useState('auto')
  const [key, setKey] = useState('')
  useEffect(() => {
    void api.invoke('freellm:get').then((r) => {
      setS(r)
      setUrl(r.baseUrl)
      setModel(r.model)
      if (r.hasKey) void api.invoke('freellm:check').then(setS)
    })
  }, [api])
  if (!s) return <></>
  const save = async (k?: string | null): Promise<void> => {
    const r = await act('free', () => api.invoke('freellm:save', { baseUrl: url, model, ...(k !== undefined ? { key: k } : {}) }))
    if (!r) return
    setS(r)
    setKey('')
    notify({ kind: 'info', text: r.ok ? 'Free LLM API is connected. Choose “Claude Code on Free LLM API” when you start a review.' : r.note })
  }
  const models = s.models.includes(model) ? s.models : [model, ...s.models]
  return (
    <div className="panel">
      <div className="arsenal-row" data-on={s.ok === true}>
        <span className="glyph" style={{ ['--g' as string]: '#7cc4ff' }}>
          <Network size={18} />
        </span>
        <div>
          <div className="row-title">
            Free LLM API {s.ok === true && <span className="tag tag-ok">Connected</span>} {s.hasKey && s.ok === false && <span className="tag">Not answering</span>}
          </div>
          <div className="row-sub" style={{ whiteSpace: 'normal' }}>
            All the free keys you added to Free LLM API (Google AI Studio, Groq, NVIDIA, OpenRouter and more) behind one address. Claude Code reviews can run on it, next to your Claude account and LM Studio. {s.ok !== null && s.note}
            {!s.claudeCode && ' Needs Claude Code: install it above.'}
          </div>
          <div className="int-form">
            <input className="input mono" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="http://127.0.0.1:31415/v1" aria-label="Address" spellCheck={false} />
            <select className="input" value={model} onChange={(e) => setModel(e.target.value)} aria-label="Model">
              {models.map((m) => (
                <option key={m} value={m}>
                  {m === 'auto' ? 'auto: your routing chain' : m === 'auto:fast' ? 'auto:fast: the fastest' : m}
                </option>
              ))}
            </select>
            <input className="input mono" type="password" placeholder={s.hasKey ? 'Key saved (paste to replace)' : 'Unified key: freellmapi-…'} value={key} onChange={(e) => setKey(e.target.value)} autoComplete="off" aria-label="Unified key" />
          </div>
        </div>
        <div style={{ display: 'grid', gap: 6 }}>
          <button className="btn btn-sm" disabled={busy.has('free') || (!key.trim() && !s.hasKey)} onClick={() => save(key.trim() ? key.trim() : undefined)}>
            {s.hasKey ? 'Save' : 'Connect'}
          </button>
          {s.hasKey && (
            <button className="btn btn-sm" disabled={busy.has('freec')} onClick={async () => setS((await act('freec', () => api.invoke('freellm:check'))) ?? s)}>
              <RefreshCw size={13} /> Check
            </button>
          )}
          {s.hasKey && (
            <button className="btn btn-sm" onClick={() => save(null)}>
              Forget key
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
