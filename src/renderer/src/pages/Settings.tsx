import { useEffect, useState } from 'react'
import { FolderOpen } from 'lucide-react'
import type { Reviewer, StorageInfo } from '@shared/types'
import { useApp } from '../store'
import { PageHead, Seg, Switch } from '../ui'

export default function Settings(): React.JSX.Element {
  const { settings, updateSettings, setSettings, act, appInfo, setPage, notify } = useApp()
  const [check, setCheck] = useState<string | null>(null)
  const [eds, setEds] = useState<{ found: { id: string; name: string }[]; current: string | null } | null>(null)
  const [have, setHave] = useState<string[] | null>(null)
  const [ignored, setIgnored] = useState<Awaited<ReturnType<typeof window.macsec.invoke<'ignored:list'>>>>([])
  const [storage, setStorage] = useState<StorageInfo | null>(null)
  const [days, setDays] = useState(90)
  const [pruneSure, setPruneSure] = useState(false)
  const size = (b: number): string => (b >= 1_000_000_000 ? `${(b / 1_000_000_000).toFixed(1)} GB` : b >= 1_000_000 ? `${Math.round(b / 1_000_000)} MB` : `${Math.max(1, Math.round(b / 1024))} KB`)
  useEffect(() => {
    void window.macsec.invoke('editors:list').then(setEds)
    void window.macsec.invoke('ignored:list').then(setIgnored)
    void window.macsec.invoke('ai:agents').then((a) => setHave(a.filter((x) => x.installed).map((x) => x.id)))
    void window.macsec.invoke('app:storage').then(setStorage).catch(() => undefined)
  }, [])
  const api = window.macsec
  if (!settings) return <></>
  return (
    <>
      <PageHead title="Settings" />
      <h2 className="section-title" style={{ marginTop: 0 }}>Appearance</h2>
      <div className="panel">
        <div className="ms-row">
          <div className="grow">
            <div className="row-title">Look</div>
            <div className="row-sub">Dark is MacSec’s own look. Light is easier in a bright room.</div>
          </div>
          <Seg<'dark' | 'light' | 'auto'>
            label="Look"
            value={settings.look ?? 'dark'}
            onChange={(v) => void updateSettings({ look: v })}
            options={[
              ['dark', 'Dark'],
              ['light', 'Light'],
              ['auto', 'Like my Mac']
            ]}
          />
        </div>
        <div className="ms-row">
          <div className="grow">
            <div className="row-title">Accent colour</div>
            <div className="row-sub">For buttons, the page you are on and highlights. Severity colours stay the same.</div>
          </div>
          <div className="swatches" role="radiogroup" aria-label="Accent colour">
            {(
              [
                ['ion', 'Ion blue', '#38e1ff'],
                ['violet', 'Violet', '#a78bfa'],
                ['green', 'Green', '#3ef0a8'],
                ['amber', 'Amber', '#ffc94a'],
                ['rose', 'Rose', '#ff7aa8']
              ] as const
            ).map(([id, name, c]) => (
              <button key={id} className="swatch" role="radio" aria-checked={(settings.accent ?? 'ion') === id} aria-label={name} title={name} style={{ ['--sw' as string]: c }} onClick={() => void updateSettings({ accent: id })} />
            ))}
          </div>
        </div>
        <div className="ms-row">
          <div className="grow">
            <div className="row-title">Text size</div>
            <div className="row-sub">Larger makes everything a little bigger.</div>
          </div>
          <Seg<'normal' | 'large'>
            label="Text size"
            value={settings.textSize ?? 'normal'}
            onChange={(v) => void updateSettings({ textSize: v })}
            options={[
              ['normal', 'Normal'],
              ['large', 'Larger']
            ]}
          />
        </div>
        <div className="ms-row">
          <div className="grow">
            <div className="row-title">Explain findings simply</div>
            <div className="row-sub">Leads with what could happen and what to do, in everyday words. Scanner names and reference numbers are folded away.</div>
          </div>
          <Switch on={!!settings.explainSimply} label="Explain findings simply" onChange={() => void updateSettings({ explainSimply: !settings.explainSimply })} />
        </div>
      </div>
      <h2 className="section-title">Things you told MacSec to ignore</h2>
      <div className="panel">
        {ignored.length === 0 ? (
          <div className="ms-row">
            <div className="grow row-sub">Nothing yet. When you open a finding and choose “Not a problem, remember”, it shows up here and later scans leave it alone.</div>
          </div>
        ) : (
          ignored.map((r) => (
            <div className="ms-row" key={r.key}>
              <div className="grow">
                <div className="row-title">{r.title}</div>
                <div className="row-sub">
                  {r.scope === 'everywhere' ? 'Everywhere' : 'This site only'}
                  {r.place ? `: ${r.place}` : ''}
                </div>
              </div>
              <button className="btn btn-sm" onClick={async () => { const l = await act('ignored', () => api.invoke('ignored:remove', r.key)); if (l) setIgnored(l) }}>
                Report it again
              </button>
            </div>
          ))
        )}
      </div>
      <h2 className="section-title">General</h2>
      <div className="panel">
        <div className="ms-row">
          <div className="grow">
            <div className="row-title">Projects folder</div>
            <div className="row-sub mono">{settings.wwwPath}</div>
          </div>
          <button
            className="btn btn-sm"
            onClick={async () => {
              const s = await act('www', () => api.invoke('settings:choose-www'))
              if (s) setSettings(s)
            }}
          >
            Change
          </button>
        </div>
        <div className="ms-row">
          <div className="grow">
            <div className="row-title">Default reviewer</div>
            <div className="row-sub">Chosen first on the Code review page.</div>
          </div>
          <Seg<Reviewer>
            label="Default reviewer"
            value={settings.reviewer}
            onChange={(r) => void updateSettings({ reviewer: r })}
            options={(
              [
                ['claude', 'Claude Code'],
                ['codex', 'Codex'],
                ['gemini', 'Gemini CLI'],
                ['model', 'Your model'],
                ['none', 'Scanners only']
              ] as [Reviewer, string][]
            ).filter(([id]) => id === 'none' || id === settings.reviewer || (id === 'model' ? !!settings.llm.model : (have ?? []).includes(id)))}
          />
        </div>
        <div className="ms-row">
          <div className="grow">
            <div className="row-title">Notifications</div>
            <div className="row-sub">Tell me when a long review finishes.</div>
          </div>
          <Switch label="Notifications" on={settings.notifications} onChange={() => void updateSettings({ notifications: !settings.notifications })} />
        </div>
        <div className="ms-row">
          <div className="grow">
            <div className="row-title">Code editor</div>
            <div className="row-sub">Where “Open in editor” takes you, at the line of the finding. {eds ? (eds.found.length ? `${eds.found.length} found on this Mac.` : 'None found: choose an app.') : ''}</div>
          </div>
          <select
            className="input"
            style={{ minWidth: 220 }}
            aria-label="Code editor"
            value={settings?.editor && (settings.editor === 'custom' || eds?.found.some((e) => e.id === settings.editor)) ? settings.editor : 'auto'}
            onChange={async (e) => {
              if (e.target.value === 'choose') {
                const r = await act('ed-app', () => window.macsec.invoke('editors:choose-app'))
                if (r) setSettings(await window.macsec.invoke('settings:get'))
              } else await updateSettings({ editor: e.target.value })
              setEds(await window.macsec.invoke('editors:list'))
            }}
          >
            <option value="auto">{eds?.found[0] ? `Automatic (${eds.found[0].name})` : 'Automatic'}</option>
            {eds?.found.map((e) => (
              <option key={e.id} value={e.id}>
                {e.name}
              </option>
            ))}
            {settings?.editor === 'custom' && settings.editorApp && <option value="custom">{settings.editorApp.split('/').pop()!.replace(/\.app$/, '')}</option>}
            <option value="choose">Choose another app…</option>
          </select>
        </div>
        <div className="ms-row">
          <div className="grow">
            <div className="row-title">The MacSec folder</div>
            <div className="row-sub mono">{appInfo?.root}</div>
          </div>
          <button className="btn btn-sm" onClick={() => void api.invoke('app:open-folder', 'root')}>
            <FolderOpen size={13} /> Open
          </button>
        </div>
        <div className="ms-row">
          <div className="grow">
            <div className="row-title">Your own rules and templates</div>
            <div className="row-sub">Drop Semgrep rules (.yml) into extensions/semgrep-rules and they run in every review. Nuclei templates and AI skills go next to them.</div>
          </div>
          <button className="btn btn-sm" onClick={() => void api.invoke('app:open-folder', 'extensions')}>
            <FolderOpen size={13} /> Open
          </button>
        </div>
        <div className="ms-row">
          <div className="grow">
            <div className="row-title">What MacSec keeps</div>
            <div className="row-sub">
              {storage ? `${size(storage.bytes)} in the MacSec folder, ${storage.sessions} sessions, about ${storage.findings} findings. Sessions are the only part that grows without a limit.` : 'Measuring the MacSec folder…'}
            </div>
          </div>
          <button className="btn btn-sm" onClick={() => void api.invoke('app:storage').then(setStorage).catch(() => undefined)}>
            Measure
          </button>
        </div>
        <div className="ms-row">
          <div className="grow">
            <div className="row-title">Delete old sessions</div>
            <div className="row-sub">Removes finished sessions older than the number of days you choose, with their raw scanner output. Findings and reports go with them. This cannot be undone.</div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 6 }}>
              <input className="input" type="number" min={7} max={3650} value={days} onChange={(e) => setDays(Number(e.target.value))} style={{ width: 96 }} aria-label="Days" />
              <span className="hint">days</span>
            </div>
          </div>
          {pruneSure ? (
            <div style={{ display: 'flex', gap: 6 }}>
              <button
                className="btn btn-sm btn-danger"
                onClick={async () => {
                  const r = await act('prune', () => api.invoke('sessions:prune', days))
                  if (r) {
                    setStorage(r.info)
                    setPruneSure(false)
                    notify({ kind: 'info', text: `Removed ${r.removed} session${r.removed === 1 ? '' : 's'} older than ${days} days.` })
                  }
                }}
              >
                Delete for good
              </button>
              <button className="btn btn-sm" onClick={() => setPruneSure(false)}>
                Keep them
              </button>
            </div>
          ) : (
            <button className="btn btn-sm" onClick={() => setPruneSure(true)}>
              Delete older than {days} days
            </button>
          )}
        </div>
        <div className="ms-row">
          <div className="grow">
            <div className="row-title">Logs for support</div>
            <div className="row-sub">Everything MacSec did, line by line. Useful when something fails and you want to know why.</div>
          </div>
          <button className="btn btn-sm" onClick={() => setPage('logs')}>
            Open logs
          </button>
        </div>
        <div className="ms-row">
          <div className="grow">
            <div className="row-title">How MacSec stays safe</div>
            <div className="row-sub">What MacSec reads, what it only does inside a written scope, and what it never does. Written for security teams you share it with.</div>
          </div>
          <button className="btn btn-sm" onClick={() => setPage('safety')}>
            Open
          </button>
        </div>
      </div>
      <p className="hint" style={{ marginTop: 14 }}>
        MacSec {appInfo?.version}. Use it only on code and systems you own or are allowed to test.{' '}
        <button
          className="link"
          onClick={async () => {
            const u = await act('chk', () => window.macsec.invoke('app:check-update'))
            setCheck(u === undefined ? null : u ? `MacSec ${u.version} is ready: see Updates.` : 'You have the newest MacSec.')
          }}
        >
          Check for updates
        </button>
        {check && <span> {check}</span>}
      </p>
    </>
  )
}
