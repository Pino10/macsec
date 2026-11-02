import { FolderOpen } from 'lucide-react'
import type { Reviewer } from '@shared/types'
import { useApp } from '../store'
import { PageHead, Seg, Switch } from '../ui'

export default function Settings(): React.JSX.Element {
  const { settings, updateSettings, setSettings, act, appInfo } = useApp()
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
        MacSec {appInfo?.version}. Use it only on code and systems you own or are allowed to test.
      </p>
    </>
  )
}
