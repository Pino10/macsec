import { useEffect, useState } from 'react'
import { Bug, ExternalLink, FolderOpen, Play, Power, Trash2 } from 'lucide-react'
import type { MobsfStatus } from '@shared/types'
import { useApp } from '../store'
import { PageHead } from '../ui'

/** Full MobSF in its own MacSec window. Uses your own MobSF folder, one that is already running, or Docker. */
export default function Mobsf(): React.JSX.Element {
  const { act, notify } = useApp()
  const api = window.macsec
  const [st, setSt] = useState<MobsfStatus | null>(null)
  const [reports, setReports] = useState(false)
  const [image, setImage] = useState(false)
  useEffect(() => {
    void api.invoke('mobsf:status').then(setSt).catch(() => setSt(null))
  }, [api])
  const apply = async (key: string, call: () => Promise<MobsfStatus>): Promise<void> => {
    const r = await act(key, call)
    if (r) setSt(r)
  }
  return (
    <>
      <PageHead title="MobSF" desc="The full Mobile Security Framework, running locally and opened in its own MacSec window. MacSec looks for your MobSF folder first, then Docker. Upload an APK, IPA or source zip and use the complete MobSF UI: static analysis, manifests, certificates, trackers and reports." />
      <div className="panel" style={{ padding: 20, display: 'grid', gap: 14, maxWidth: 820 }}>
        <div className="row" style={{ cursor: 'default', gap: 14 }}>
          <Bug size={26} />
          <div className="grow">
            <strong>MobSF {st?.running ? 'is running' : 'is not running'}</strong>
            <p className="hint">
              {st?.mode === 'outside' ? 'MobSF was already running on this Mac, so MacSec only opens it. MacSec never stops it.' : st?.mode === 'folder' ? 'Running from your MobSF folder.' : st?.mode === 'docker' ? 'Running in a Docker container.' : st?.folder ? 'Ready to start from your MobSF folder.' : 'No MobSF folder found. Choose one below, or MacSec will use Docker.'}
              {st?.folder ? <> Folder: <span className="mono">{st.folder}</span>.</> : null} Local only at <span className="mono">{st?.url ?? 'http://127.0.0.1:8765'}</span>. Login with <span className="mono">{st?.username ?? 'mobsf'} / {st?.password ?? 'mobsf'}</span>.
            </p>
          </div>
          <span className={`tag ${st?.running ? 'tag-ok' : ''}`}>{st?.running ? 'On' : 'Off'}</span>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button className="btn btn-primary" disabled={st?.running} onClick={() => void apply('mobsf-start', () => api.invoke('mobsf:start'))}>
            <Play size={15} /> {st?.running ? 'Running' : 'Start MobSF'}
          </button>
          <button className="btn" disabled={!st?.running} onClick={async () => { await api.invoke('mobsf:open'); notify({ kind: 'info', text: 'MobSF opened in its own window.' }) }}>
            <ExternalLink size={15} /> Open full MobSF
          </button>
          <button className="btn" disabled={!st?.running} onClick={() => void apply('mobsf-stop', () => api.invoke('mobsf:stop'))}>
            <Power size={15} /> Stop
          </button>
          <button className="btn" disabled={st?.mode === 'folder' || st?.mode === 'outside'} onClick={async () => {
            const r = await act('mobsf-choose', () => api.invoke('mobsf:choose'))
            if (r) { notify({ kind: 'info', text: 'MobSF folder saved.' }); setSt(await api.invoke('mobsf:status')) }
          }}>
            <FolderOpen size={15} /> Choose MobSF folder
          </button>
          {st?.mode === 'docker' || !st?.folder ? <button className="btn danger-text" onClick={async () => {
            if (!window.confirm('Remove the MobSF container? The container is deleted; the reports volume is kept unless you tick the box.')) return
            const r = await act('mobsf-remove', () => api.invoke('mobsf:remove', true, reports, image))
            if (r) notify({ kind: 'info', text: `${reports ? 'Container and reports volume removed.' : 'Container removed; reports volume kept.'}${image ? ' Image removed too.' : ' The image is kept for the next start.'}` })
          }}>
            <Trash2 size={15} /> Remove container
          </button> : null}
        </div>
        <label className="consent">
          <input type="checkbox" checked={reports} onChange={(e) => setReports(e.target.checked)} />
          <span>Docker only: also delete the MobSF reports volume. This cannot be undone.</span>
        </label>
        <label className="consent">
          <input type="checkbox" checked={image} onChange={(e) => setImage(e.target.checked)} />
          <span>Also remove the MobSF Docker image (about 1 GB; the next start downloads it again).</span>
        </label>
        <p className="hint">The first start can take a while: MacSec pulls the official MobSF image and waits for the web UI. Docker mode needs Docker or Colima running (Tools → Container runtime). A MobSF folder needs its setup done once (./setup.sh).</p>
      </div>
    </>
  )
}
