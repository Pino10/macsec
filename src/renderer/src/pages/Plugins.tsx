import { useEffect, useState } from 'react'
import { Play, Plus, Trash2, Wrench } from 'lucide-react'
import type { PluginDef, Reviewer } from '@shared/types'
import { useApp } from '../store'
import { PageHead } from '../ui'

/** Bring-your-own tools: a declared binary, args, parser, no shell and no automatic run. */
export default function Plugins(): React.JSX.Element {
  const { sessions, showSession, act, notify } = useApp()
  const api = window.macsec
  const [list, setList] = useState<PluginDef[]>([])
  const [presets, setPresets] = useState<{ name: string; bin: string; args: string[]; parser: PluginDef['parser']; pattern?: string; severity: string; description: string; install: string; metering?: 'proxy' | 'none' }[]>([])
  const [preset, setPreset] = useState('')
  const [session, setSession] = useState('')
  const [plugin, setPlugin] = useState('')
  const [ok, setOk] = useState(false)
  const [busy, setBusy] = useState(false)
  const [form, setForm] = useState({ name: '', bin: '', args: '["--target","{target}"]', parser: 'json' as PluginDef['parser'], severity: 'medium', pattern: '', description: '', metering: 'none' as 'proxy' | 'none' })
  useEffect(() => {
    void api.invoke('plugins:list').then(setList).catch(() => setList([]))
    void api.invoke('plugins:presets').then(setPresets).catch(() => setPresets([]))
  }, [api])
  const finished = sessions.filter((s) => s.status !== 'running').slice(0, 30)
  useEffect(() => {
    if (!session && finished[0]) setSession(finished[0].id)
    if (!plugin && list[0]) setPlugin(list[0].id)
  }, [finished, list, session, plugin])
  const save = async (): Promise<void> => {
    let args: string[]
    try {
      args = JSON.parse(form.args) as string[]
      if (!Array.isArray(args) || args.some((a) => typeof a !== 'string')) throw new Error('Args must be a JSON array of strings.')
    } catch (e) {
      notify({ kind: 'error', text: `Arguments: ${(e as Error).message}` })
      return
    }
    const r = await act('plugin-save', () => api.invoke('plugins:save', { name: form.name, bin: form.bin, args, parser: form.parser, pattern: form.pattern || undefined, severity: form.severity, description: form.description, metering: form.metering }))
    if (r) {
      setList(r)
      setForm({ ...form, name: '', bin: '', description: '' })
      notify({ kind: 'info', text: 'Plugin saved. It runs only when you press Run and confirm.' })
    }
  }
  const run = async (): Promise<void> => {
    setBusy(true)
    try {
      const r = await act('plugin-run', () => api.invoke('plugins:run', session, plugin, ok))
      if (r) {
        notify({ kind: r.exceeded ? 'error' : 'info', text: `${r.added} finding${r.added === 1 ? '' : 's'} added. ${r.metered ? `${r.requests} request${r.requests === 1 ? '' : 's'} counted${r.exceeded ? '; budget exhausted' : ''}.` : 'Unmetered: raw tool traffic is not counted.'}` })
        showSession(session)
      }
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <PageHead title="Plugins" desc="Bring a tool MacSec does not know. You declare the binary, its arguments, how to read its output and whether HTTP traffic can be metered through MacSec's local proxy. There is no shell, no automatic run and no sandbox; a remote target needs an engagement that covers it." />
      <div className="split" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div className="panel" style={{ padding: 16, display: 'grid', gap: 10 }}>
          <strong>Add a plugin</strong>
          <div style={{ display: 'flex', gap: 8 }}>
            <select className="input" value={preset} onChange={(e) => setPreset(e.target.value)} aria-label="Plugin preset">
              <option value="">Start from a preset…</option>
              {presets.map((x) => (<option key={x.name} value={x.name}>{x.name}</option>))}
            </select>
            <button
              className="btn btn-sm"
              disabled={!preset}
              onClick={() => {
                const x = presets.find((v) => v.name === preset)
                if (!x) return
                setForm({ name: x.name, bin: x.bin, args: JSON.stringify(x.args), parser: x.parser, severity: x.severity, pattern: x.pattern ?? '', description: `${x.description} Install: ${x.install}`, metering: x.metering ?? 'none' })
              }}
            >
              Use preset
            </button>
          </div>
          <p className="hint">Presets are templates, not installed tools. Install the tool first; MacSec never installs a plugin binary.</p>
          <p className="hint">The binary must be an absolute path. Placeholders: <span className="mono">{'{target}'}</span>, <span className="mono">{'{host}'}</span>, <span className="mono">{'{url}'}</span>, <span className="mono">{'{session}'}</span>. Arguments are a JSON array; there is no shell.</p>
          <input className="input" placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} aria-label="Plugin name" />
          <input className="input mono" placeholder="/usr/local/bin/tool" value={form.bin} onChange={(e) => setForm({ ...form, bin: e.target.value })} aria-label="Binary" />
          <textarea className="input mono" rows={2} value={form.args} onChange={(e) => setForm({ ...form, args: e.target.value })} aria-label="Arguments JSON" />
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <select className="input" value={form.parser} onChange={(e) => setForm({ ...form, parser: e.target.value as PluginDef['parser'] })} aria-label="Parser">
              <option value="json">JSON array</option>
              <option value="jsonl">JSONL (one JSON object per line)</option>
              <option value="lines">One finding per line</option>
              <option value="regex">Regex per line</option>
            </select>
            <select className="input" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })} aria-label="Default severity">
              {['critical', 'high', 'medium', 'low', 'info'].map((s) => (<option key={s} value={s}>{s}</option>))}
            </select>
            {form.parser === 'regex' && <input className="input mono" placeholder="Pattern with one capture group" value={form.pattern} onChange={(e) => setForm({ ...form, pattern: e.target.value })} aria-label="Pattern" />}
            <select className="input" value={form.metering} onChange={(e) => setForm({ ...form, metering: e.target.value as 'proxy' | 'none' })} aria-label="Metering">
              <option value="none">Unmetered (raw TCP tools)</option>
              <option value="proxy">Metered proxy (HTTP/HTTPS tools)</option>
            </select>
          </div>
          <input className="input" placeholder="What it does (optional)" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} aria-label="Description" />
          <button className="btn btn-primary" disabled={!form.name.trim() || !form.bin.trim()} onClick={() => void save()}>
            <Plus size={14} /> Save plugin
          </button>
        </div>

        <div className="panel" style={{ padding: 16, display: 'grid', gap: 10 }}>
          <strong>Run a plugin</strong>
          <select className="input" value={session} onChange={(e) => setSession(e.target.value)} aria-label="Session">
            {finished.length === 0 && <option value="">No finished result</option>}
            {finished.map((s) => (<option key={s.id} value={s.id}>{s.title} · {s.target}</option>))}
          </select>
          <select className="input" value={plugin} onChange={(e) => setPlugin(e.target.value)} aria-label="Plugin">
            {list.length === 0 && <option value="">No plugin saved</option>}
            {list.map((p) => (<option key={p.id} value={p.id}>{p.name} ({p.parser})</option>))}
          </select>
          <label className="consent">
            <input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} />
            <span>I am allowed to run this tool against this target, and I understand MacSec cannot count the requests this external tool sends.</span>
          </label>
          <button className="btn btn-primary" disabled={!session || !plugin || !ok || busy} onClick={() => void run()}>
            <Play size={14} /> {busy ? 'Running…' : 'Run plugin'}
          </button>
          <p className="hint">The run is local, uses an argument array, has a 10-minute cap and adds its findings to the selected result as possible. A remote target needs a live engagement that covers the host.</p>
        </div>
      </div>

      {list.length > 0 && (
        <div className="panel" style={{ marginTop: 16 }}>
          {list.map((p) => (
            <div key={p.id} className="row" style={{ cursor: 'default' }}>
              <Wrench size={15} />
              <span className="grow">
                <span className="row-title">{p.name}</span>
                <span className="row-sub mono">{p.bin} {p.args.join(' ')}</span>
              </span>
              <button className="icon-btn danger-text" aria-label={`Delete ${p.name}`} onClick={async () => { const r = await act('plugin-del', () => api.invoke('plugins:delete', p.id)); if (r) setList(r) }}>
                <Trash2 size={14} />
              </button>
            </div>
          ))}
        </div>
      )}
    </>
  )
}
