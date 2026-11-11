import { useEffect, useState } from 'react'
import { Bell, Command, MonitorUp, Copy, Download, ExternalLink, Network, Plug, RefreshCw, Trash2, Users, Workflow } from 'lucide-react'
import type { FreeLlmInfo, IntegrationsInfo, ModelApi, ModelServer, PackUpdateInfo, SkillPackInfo } from '@shared/types'
import { useApp } from '../store'
import { Switch } from '../ui'

/** Skills from Trail of Bits, Sentry, Cloudflare, Laravel and Anthropic, loaded into MacSec's Claude Code reviews. */
export function SkillPacks(): React.JSX.Element {
  const { act, busy } = useApp()
  const api = window.macsec
  const [packs, setPacks] = useState<SkillPackInfo[]>([])
  const [updates, setUpdates] = useState<PackUpdateInfo[]>([])
  useEffect(() => {
    void api.invoke('packs:list').then(setPacks)
    void api.invoke('packs:updates').then(setUpdates)
  }, [api])
  const newer = (id: string): PackUpdateInfo | undefined => updates.find((u) => u.id === id && u.available)
  const checkedAt = updates.map((u) => u.checkedAt).filter(Boolean).sort().pop()
  const count = updates.filter((u) => u.available).length
  return (
    <div className="panel">
      <div className="row-sub" style={{ whiteSpace: 'normal', padding: '4px 4px 10px' }}>
        {count ? `${count} newer ${count === 1 ? 'version is' : 'versions are'} available.` : 'Everything is up to date.'} {checkedAt ? `Checked ${new Date(checkedAt).toLocaleString()}.` : 'Not checked yet.'} MacSec checks once a day and never updates a pack without you pressing Update.{' '}
        <button className="link" disabled={busy.has('pk-check')} onClick={async () => setUpdates((await act('pk-check', () => api.invoke('packs:check-updates'))) ?? updates)}>
          <RefreshCw size={11} /> {busy.has('pk-check') ? 'Checking…' : 'Check now'}
        </button>
      </div>
      {packs.map((p) => (
        <div key={p.id} className="arsenal-row" data-on={p.installed}>
          <span className="glyph" style={{ ['--g' as string]: '#f0a35b' }}>
            <Users size={18} />
          </span>
          <div>
            <div className="row-title">
              {p.name} skills <span className="tag">{p.license}</span> {p.installed && <span className="tag tag-ok">{p.loaded.length} loaded</span>} {newer(p.id) && <span className="tag tag-new">Update available</span>}
            </div>
            <div className="row-sub" style={{ whiteSpace: 'normal' }}>
              {p.about}
              {p.commit ? ` Version ${p.commit.slice(0, 7)}.` : ''} Kept in MacSec’s folder; reviews stay read-only.
              {newer(p.id) && (
                <>
                  {' '}Newer: {newer(p.id)!.latest!.slice(0, 7)}.{' '}
                  <button className="link" onClick={() => api.invoke('app:open-external', newer(p.id)!.changes!)}>
                    See what changed
                  </button>
                </>
              )}
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
            <button className="btn btn-sm" disabled={busy.has(`pk-${p.id}`)} onClick={async () => {
              setPacks((await act(`pk-${p.id}`, () => api.invoke('packs:install', p.id))) ?? packs)
              setUpdates(await api.invoke('packs:updates'))
            }}>
              {p.installed ? <RefreshCw size={13} /> : <Download size={13} />} {busy.has(`pk-${p.id}`) ? 'Getting…' : p.installed ? (newer(p.id) ? 'Update now' : 'Reinstall') : 'Add'}
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
  const [desk, setDesk] = useState<{ app: boolean; connected: boolean } | null>(null)
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
  useEffect(() => {
    void api.invoke('desktop:status').then(setDesk)
  }, [api, info?.mcp.enabled])
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
      <div className="arsenal-row" data-on={!!desk?.connected}>
        <span className="glyph" style={{ ['--g' as string]: '#7cc4ff' }}>
          <MonitorUp size={18} />
        </span>
        <div>
          <div className="row-title">Claude Desktop {desk?.connected && <span className="tag tag-ok">Connected</span>}</div>
          <div className="row-sub" style={{ whiteSpace: 'normal' }}>
            Adds MacSec to the Claude app, so you can ask it about your sessions or to review a project. It uses a tiny helper that talks to MacSec on this Mac only, with your private key read when it runs. This also turns on “Let AI tools use MacSec”. Restart the Claude app afterwards.
            {desk && !desk.app && ' The Claude desktop app was not found on this Mac: get it at claude.ai/download.'}
          </div>
        </div>
        <button className="btn btn-sm" disabled={busy.has('desktop')} onClick={async () => {
          await act('desktop', () => api.invoke('desktop:connect'))
          setDesk(await api.invoke('desktop:status'))
          setInfo(await api.invoke('integrations:get'))
        }}>
          {busy.has('desktop') ? 'Connecting…' : desk?.connected ? 'Repair connection' : 'Connect'}
        </button>
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

/** Ready-made addresses, so the address never has to be typed or remembered. The model list is read from the server itself. */
const SERVER_PRESETS: { id: string; name: string; baseUrl: string; api: ModelApi; hint: string }[] = [
  { id: 'deepseek', name: 'DeepSeek', baseUrl: 'https://api.deepseek.com', api: 'openai', hint: 'Key from platform.deepseek.com. Your code and findings are sent to DeepSeek.' },
  { id: 'openrouter', name: 'OpenRouter', baseUrl: 'https://openrouter.ai/api/v1', api: 'openai', hint: 'One key for many models.' },
  { id: 'groq', name: 'Groq', baseUrl: 'https://api.groq.com/openai/v1', api: 'openai', hint: 'Fast, with a free tier.' },
  { id: 'custom', name: '', baseUrl: '', api: 'openai', hint: 'Any server that speaks the OpenAI or Anthropic format, on this Mac, your network or https.' }
]

/** Model servers you add yourself (DeepSeek, OpenRouter, your own). Keys go to the Keychain and never to the window. */
export function ModelServersPanel({ onChange }: { onChange?: () => void }): React.JSX.Element {
  const { act, busy, notify } = useApp()
  const api = window.macsec
  const [list, setList] = useState<ModelServer[]>([])
  const [preset, setPreset] = useState('deepseek')
  const [name, setName] = useState('DeepSeek')
  const [url, setUrl] = useState('https://api.deepseek.com')
  const [format, setFormat] = useState<ModelApi>('openai')
  const [key, setKey] = useState('')
  useEffect(() => {
    void api.invoke('ai:servers').then(setList)
  }, [api])
  const pick = (id: string): void => {
    const p = SERVER_PRESETS.find((x) => x.id === id)!
    setPreset(id)
    setName(p.name)
    setUrl(p.baseUrl)
    setFormat(p.api)
  }
  const add = async (): Promise<void> => {
    const r = await act('addserver', () => api.invoke('ai:save-server', { name, baseUrl: url, api: format, ...(key.trim() ? { key: key.trim() } : {}) }))
    if (!r) return
    setList(r)
    setKey('')
    notify({ kind: 'info', text: `${name} was added. Choose its model in the list above.` })
    onChange?.()
  }
  const hint = SERVER_PRESETS.find((x) => x.id === preset)?.hint
  return (
    <div className="panel">
      {list.map((m) => (
        <div key={m.id} className="arsenal-row" data-on>
          <span className="glyph" style={{ ['--g' as string]: '#7cc4ff' }}>
            <Network size={18} />
          </span>
          <div>
            <div className="row-title">
              {m.name} {m.hasKey && <span className="tag tag-ok">Key saved</span>}
            </div>
            <div className="row-sub mono">{m.baseUrl}</div>
          </div>
          <button
            className="btn btn-sm"
            onClick={async () => {
              setList((await act(`delserver-${m.id}`, () => api.invoke('ai:delete-server', m.id))) ?? list)
              onChange?.()
            }}
          >
            <Trash2 size={13} /> Remove
          </button>
        </div>
      ))}
      <div className="arsenal-row">
        <span className="glyph" style={{ ['--g' as string]: '#7cc4ff' }}>
          <Plug size={18} />
        </span>
        <div>
          <div className="row-title">Add a model server</div>
          <div className="row-sub" style={{ whiteSpace: 'normal' }}>
            {hint} Servers outside your network must use https. The key is stored in the macOS Keychain.
          </div>
          <div className="int-form">
            <select className="input" value={preset} onChange={(e) => pick(e.target.value)} aria-label="Provider">
              {SERVER_PRESETS.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.id === 'custom' ? 'Another server' : p.name}
                </option>
              ))}
            </select>
            {preset === 'custom' && <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Name" aria-label="Name" />}
            <input className="input mono" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://api.example.com/v1" aria-label="Address" spellCheck={false} />
            {preset === 'custom' && (
              <select className="input" value={format} onChange={(e) => setFormat(e.target.value as ModelApi)} aria-label="Format">
                <option value="openai">OpenAI format</option>
                <option value="anthropic">Anthropic format</option>
              </select>
            )}
            <input className="input mono" type="password" placeholder="API key" value={key} onChange={(e) => setKey(e.target.value)} autoComplete="off" aria-label="API key" />
          </div>
        </div>
        <button className="btn btn-sm" disabled={busy.has('addserver') || !name.trim() || !url.trim()} onClick={() => void add()}>
          Add
        </button>
      </div>
    </div>
  )
}
