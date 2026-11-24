import { useEffect, useState } from 'react'
import { Box, Play, Power, Save, Trash2 } from 'lucide-react'
import type { ContainerStatus } from '@shared/types'
import { useApp } from '../store'

/** The optional Docker/Colima runtime used by container plugins. */
export default function ContainerRuntime(): React.JSX.Element {
  const { act, notify } = useApp()
  const api = window.macsec
  const [st, setSt] = useState<ContainerStatus | null>(null)
  const [form, setForm] = useState({ dockerPath: '', dockerHost: '', home: '', colimaHome: '', limaHome: '', managedDir: '' })
  const [open, setOpen] = useState(false)
  useEffect(() => {
    void api.invoke('container:status').then((s) => {
      setSt(s)
      setForm({ dockerPath: s.dockerPath === 'docker' ? '' : s.dockerPath, dockerHost: s.dockerHost, home: s.home, colimaHome: '', limaHome: '', managedDir: s.managed })
    })
  }, [api])
  const apply = async (key: string, call: () => Promise<ContainerStatus>): Promise<void> => {
    const r = await act(key, call)
    if (r) setSt(r)
  }
  return (
    <div className="panel" style={{ padding: 16, display: 'grid', gap: 10, marginBottom: 16 }}>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
        <Box size={18} />
        <div className="grow">
          <strong>Container runtime</strong>
          <div className="hint">Used only by container plugins. {st?.running ? `Docker is running${st.version ? ` (${st.version})` : ''}.` : 'Docker is not reachable.'} {st?.colima ? 'Colima is running.' : 'Colima is not running.'}</div>
        </div>
        {st && <span className={`tag ${st.running ? 'tag-ok' : ''}`}>{st.running ? 'On' : 'Off'}</span>}
      </div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button className="btn btn-sm" disabled={!st?.colima} onClick={() => void apply('container-start', () => api.invoke('container:start'))}>
          <Play size={13} /> Start
        </button>
        <button className="btn btn-sm" disabled={!st?.colima} onClick={() => void apply('container-stop', () => api.invoke('container:stop'))}>
          <Power size={13} /> Stop
        </button>
        <button className="link" onClick={() => setOpen((o) => !o)}>{open ? 'Hide settings' : 'Set the runtime path'}</button>
      </div>
      {open && (
        <div style={{ display: 'grid', gap: 8 }}>
          <input className="input mono" placeholder="Docker binary, for example /opt/homebrew/bin/docker" value={form.dockerPath} onChange={(e) => setForm({ ...form, dockerPath: e.target.value })} aria-label="Docker binary" />
          <input className="input mono" placeholder="Docker host, for example unix:///Users/me/.colima/default/docker.sock" value={form.dockerHost} onChange={(e) => setForm({ ...form, dockerHost: e.target.value })} aria-label="Docker host" />
          <details>
            <summary className="hint">Colima and Lima homes, and a managed folder</summary>
            <div style={{ display: 'grid', gap: 8, marginTop: 8 }}>
              <input className="input mono" placeholder="HOME for the runtime (optional)" value={form.home} onChange={(e) => setForm({ ...form, home: e.target.value })} aria-label="Runtime HOME" />
              <input className="input mono" placeholder="COLIMA_HOME (optional)" value={form.colimaHome} onChange={(e) => setForm({ ...form, colimaHome: e.target.value })} aria-label="Colima home" />
              <input className="input mono" placeholder="LIMA_HOME (optional)" value={form.limaHome} onChange={(e) => setForm({ ...form, limaHome: e.target.value })} aria-label="Lima home" />
              <input className="input mono" placeholder="Managed folder MacSec may delete on uninstall" value={form.managedDir} onChange={(e) => setForm({ ...form, managedDir: e.target.value })} aria-label="Managed folder" />
            </div>
          </details>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-sm btn-primary" onClick={() => void apply('container-save', () => api.invoke('container:configure', form))}>
              <Save size={13} /> Save runtime
            </button>
            <button className="btn btn-sm danger-text" onClick={async () => {
              if (!window.confirm('Remove the MacSec container runtime link? A managed folder is deleted; an external Colima/Docker install is left in place. This does not touch your images unless you delete them yourself.')) return
              const r = await act('container-uninstall', () => api.invoke('container:uninstall', true))
              if (r) {
                notify({ kind: 'info', text: r.note })
                const s = await api.invoke('container:status')
                setSt(s)
              }
            }}>
              <Trash2 size={13} /> Uninstall runtime
            </button>
          </div>
          <p className="hint">MacSec deletes only a folder under its own MacSec folder. An external install is stopped and unlinked, never deleted behind your back.</p>
        </div>
      )}
    </div>
  )
}
