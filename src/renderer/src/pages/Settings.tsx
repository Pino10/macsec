import { useEffect, useState } from 'react'
import { FolderOpen } from 'lucide-react'
import type { Reviewer } from '@shared/types'
import { useApp } from '../store'
import { PageHead, Seg, Switch } from '../ui'

export default function Settings(): React.JSX.Element {
  const { settings, updateSettings, setSettings, act, appInfo } = useApp()
  const [check, setCheck] = useState<string | null>(null)
  const [eds, setEds] = useState<{ found: { id: string; name: string }[]; current: string | null } | null>(null)
  useEffect(() => {
    void window.macsec.invoke('editors:list').then(setEds)
  }, [])
  const api = window.macsec
  if (!settings) return <></>
  return (
    <>
      <PageHead title="Settings" />
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
            options={[
              ['claude', 'Claude Code'],
              ['codex', 'Codex'],
              ['model', 'Your model'],
              ['none', 'Scanners only']
            ]}
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
