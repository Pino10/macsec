import { useEffect, useState } from 'react'
import { Download, FileUp, Radio, Square } from 'lucide-react'
import type { TrafficStatus } from '@shared/types'
import { useApp } from '../store'

/** Watch what an app sends over the network, with mitmproxy, or read a capture file you already have. */
export default function TrafficCapture(): React.JSX.Element {
  const { act, busy, showSession } = useApp()
  const api = window.macsec
  const [st, setSt] = useState<TrafficStatus | null>(null)
  const [host, setHost] = useState('127.0.0.1')
  const [ok, setOk] = useState(false)
  const [title, setTitle] = useState('')

  const refresh = async (): Promise<void> => setSt(await api.invoke('traffic:status'))
  useEffect(() => {
    void refresh()
  }, [])

  return (
    <div className="glass" style={{ padding: 18, marginTop: 18, display: 'grid', gap: 12 }}>
      <h3 style={{ margin: 0 }}>
        <Radio size={16} /> Watch the app’s network traffic (optional)
      </h3>
      <p className="hint">
        Finds plain http, passwords and tokens sent in the clear, and secrets in web addresses. MacSec only listens on this Mac. You set the proxy on your own test phone or emulator, and MacSec never touches the phone. The captured file can hold secrets, so it is deleted as soon as it has been read, and only names (never values) are kept.
      </p>
      {st && !st.installed && (
        <div>
          <button className="btn" disabled={busy.has('mitm')} onClick={() => void act('mitm', async () => { await api.invoke('tools:install', ['uv', 'mitmproxy']); await refresh() })}>
            <Download size={14} /> Install mitmproxy (free, stays inside MacSec)
          </button>
        </div>
      )}
      {st?.installed && !st.running && (
        <div style={{ display: 'grid', gap: 10 }}>
          <label className="consent">
            <span>
              Listen on{' '}
              <select value={host} onChange={(e) => setHost(e.target.value)}>
                <option value="127.0.0.1">this Mac only (an emulator on this Mac)</option>
                {st.lan.map((a) => (
                  <option key={a} value={a}>
                    {a} (a phone on the same wifi)
                  </option>
                ))}
              </select>
            </span>
          </label>
          <label className="consent">
            <input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} />
            <span>This is my own app on my own test phone, or I am allowed to test it.</span>
          </label>
          <div>
            <button className="btn btn-primary" disabled={!ok || busy.has('traffic')} onClick={() => void act('traffic', async () => setSt(await api.invoke('traffic:start', host)))}>
              <Radio size={14} /> Start listening
            </button>
          </div>
        </div>
      )}
      {st?.running && (
        <div style={{ display: 'grid', gap: 10 }}>
          <p>
            Listening on <span className="mono">{st.host}:{st.port}</span>. On the test phone:
          </p>
          <ol className="hint" style={{ margin: 0, paddingLeft: 20 }}>
            <li>Set the wifi proxy to <span className="mono">{st.host === '127.0.0.1' ? '10.0.2.2 (an Android emulator’s name for this Mac)' : st.host}</span>, port <span className="mono">{st.port}</span>.</li>
            <li>Open <span className="mono">mitm.it</span> in the phone’s browser, install the certificate, and use the app.</li>
            <li>Come back here and press Stop.</li>
          </ol>
          <p className="hint">If the app shows no traffic at all, it may use certificate pinning, which is a good sign. Android apps from Android 7 on may also ignore a user certificate unless the test build allows it.</p>
          <input className="input" placeholder="Name for this check (optional)" value={title} onChange={(e) => setTitle(e.target.value)} />
          <div>
            <button className="btn btn-primary" disabled={busy.has('traffic')} onClick={async () => { const s = await act('traffic', () => api.invoke('traffic:stop', title)); await refresh(); if (s) showSession(s.id) }}>
              <Square size={14} /> Stop and check the traffic
            </button>
          </div>
        </div>
      )}
      <div>
        <button className="btn" disabled={busy.has('traffic-file')} onClick={async () => { const s = await act('traffic-file', () => api.invoke('traffic:import')); if (s) showSession(s.id) }}>
          <FileUp size={14} /> Or check a capture file I already have (.har)
        </button>
      </div>
    </div>
  )
}
