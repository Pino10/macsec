import { useEffect, useState } from 'react'
import { FileBox, FolderOpen, Play, Plus, RefreshCw, Smartphone } from 'lucide-react'
import type { LiveSetupInfo, LocalProject, Reviewer } from '@shared/types'
import { useApp } from '../store'
import { FlowStep, PageHead } from '../ui'
import ReviewerChoice from '../components/ReviewerChoice'

/** Choosing a mobile app and starting the check. Used on its own page and in Special audits. */
export function MobileFlow({ start = 1 }: { start?: number }): React.JSX.Element {
  const { settings, act, busy, showSession } = useApp()
  const api = window.macsec
  const [projects, setProjects] = useState<LocalProject[]>([])
  const [path, setPath] = useState('')
  const [reviewer, setReviewer] = useState<Reviewer>(settings?.reviewer ?? 'none')
  const [liveOn, setLiveOn] = useState(false)
  const [onlineOn, setOnlineOn] = useState(false)
  const [setup, setSetup] = useState<LiveSetupInfo | null>(null)
  const [serial, setSerial] = useState('')
  const [ok, setOk] = useState(false)
  useEffect(() => {
    void api.invoke('projects:local').then(setProjects)
  }, [api])
  const isApk = /\.apk$/i.test(path)
  const refresh = async (): Promise<void> => {
    const r = await act('live-setup', () => api.invoke('mobile:live-setup'))
    if (r) {
      setSetup(r)
      if (!r.devices.some((d) => d.serial === serial && d.state === 'device')) setSerial(r.devices.find((d) => d.state === 'device')?.serial ?? '')
    }
  }
  useEffect(() => {
    if (liveOn && !setup) void refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveOn])
  const device = setup?.devices.find((d) => d.serial === serial)
  const liveReady = !liveOn || (isApk && !!device && device.state === 'device' && ok)
  const name = path.split('/').pop() ?? ''
  const kind = /\.apk$/i.test(path) ? 'Android app (.apk)' : /\.ipa$/i.test(path) ? 'iOS app (.ipa)' : path ? 'Source folder' : ''
  const choose = async (what: 'folder' | 'file'): Promise<void> => {
    const p = await act('mpick', () => api.invoke('mobile:pick', what))
    if (p) setPath(p)
  }

  return (
    <div className="flow">
      <FlowStep n={start} title="Which app" help="Android or iOS source code (Java, Kotlin, Swift, Objective-C, Flutter, React Native), or a built .apk or .ipa. A built app is unpacked inside the session and removed afterwards." state={path ? 'done' : 'current'}>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <select className="input" style={{ maxWidth: 300 }} value={projects.some((p) => p.path === path) ? path : ''} onChange={(e) => setPath(e.target.value)} aria-label="Project">
            <option value="">A project in your www folder…</option>
            {projects.map((p) => (
              <option key={p.path} value={p.path}>
                {p.name}
              </option>
            ))}
          </select>
          <button className="btn" onClick={() => void choose('folder')}>
            <FolderOpen size={15} /> Another folder
          </button>
          <button className="btn" onClick={() => void choose('file')}>
            <FileBox size={15} /> An .apk or .ipa
          </button>
        </div>
        {path && (
          <p className="hint" style={{ marginTop: 10 }}>
            {kind}: <span className="mono">{name}</span>
          </p>
        )}
      </FlowStep>
      {isApk && (
        <FlowStep n={start + 1} title="Run it on a test phone (optional)" help="Installs the app on an Android emulator or a phone you own, starts it, and watches what it does: which servers it talks to, plain HTTP, certificate pinning, root checks, and passwords or tokens in the log or in its files. Frida only watches. Nothing is tapped or typed, and the app is removed again afterwards." state="current">
          <label className="consent">
            <input type="checkbox" checked={liveOn} onChange={(e) => setLiveOn(e.target.checked)} />
            <span>Also run this app on a test phone</span>
          </label>
          {liveOn && (
            <div style={{ display: 'grid', gap: 10, marginTop: 10 }}>
              {setup && !setup.adb && <p className="hint">The Android tools were not found. Install Android Studio (free) once, or run <span className="mono">brew install --cask android-platform-tools</span> in Terminal, then press Refresh.</p>}
              {setup?.devices.length === 0 && setup.adb && <p className="hint">No phone or emulator is connected. Start a test phone below, or plug in a phone with USB debugging on.</p>}
              {setup?.devices.map((d) => (
                <label key={d.serial} className="consent">
                  <input type="radio" name="device" checked={serial === d.serial} disabled={d.state !== 'device'} onChange={() => setSerial(d.serial)} />
                  <span>
                    <strong style={{ color: 'var(--ink)' }}>{d.model || d.serial}</strong> {d.kind === 'emulator' ? '(test phone)' : '(a real phone)'} {d.state !== 'device' ? `: ${d.state}, unlock it and accept the prompt` : ''}
                  </span>
                </label>
              ))}
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                {setup?.avds.map((a) => (
                  <button key={a} className="btn" onClick={() => void act('avd', async () => { setSetup(await api.invoke('mobile:avd-start', a)) })}>
                    <Play size={14} /> Start {a}
                  </button>
                ))}
                {setup?.canCreate && (
                  <button className="btn" onClick={() => void act('avd', async () => { setSetup(await api.invoke('mobile:avd-create')) })} disabled={busy.has('avd')}>
                    <Plus size={14} /> Build a test phone
                  </button>
                )}
                <button className="btn" onClick={() => void refresh()}>
                  <RefreshCw size={14} /> Refresh
                </button>
              </div>
              {setup && !setup.canCreate && !setup.avds.length && <p className="hint">To build a test phone, install Android Studio once and open it, so Android’s tools are on this Mac. A test phone with Google APIs allows root, which Frida needs.</p>}
              {device?.kind === 'phone' && <p className="hint">A real phone must be rooted for Frida to watch the app. Without root, only the log and files are checked where Android allows it.</p>}
              <label className="consent">
                <input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} />
                <span>
                  <strong style={{ color: 'var(--ink)' }}>I am allowed to test this app{device?.kind === 'phone' ? ' on this phone' : ''}.</strong> It will be installed, started and watched for about half a minute. Secret values it finds are never saved.
                </span>
              </label>
            </div>
          )}
        </FlowStep>
      )}
      {(isApk || path.toLowerCase().endsWith('.ipa')) && (
        <label className="consent" style={{ margin: '0 0 14px' }}>
          <input type="checkbox" checked={onlineOn} onChange={(e) => setOnlineOn(e.target.checked)} />
          <span>
            <strong style={{ color: 'var(--ink)' }}>Also ask once whether the cloud addresses inside the app are open (optional).</strong> For each Firebase, S3 or Google Storage address found in the app, MacSec makes one read-only request without signing in. Nothing is changed, and file names are not saved. Only do this for apps you are allowed to test.
          </span>
        </label>
      )}
      <FlowStep n={start + (isApk ? 2 : 1)} title="Who writes the report" state="current">
        <ReviewerChoice value={reviewer} onChange={setReviewer} what="findings" />
      </FlowStep>
      <div className="flow-go glass">
        <span className="hint grow">
          {kind === 'Source folder' || !path ? 'mobsfscan rules, manifest and Info.plist settings, and keys in the code.' : 'Settings, signing, what the app’s code names (pinning, root checks, weak crypto), hardening, and keys inside the app. All from the file.'} {liveOn && isApk ? 'The app will also run on the test phone you chose.' : 'Nothing is run or installed on a phone.'}
        </span>
        <button
          className="btn btn-primary btn-lg"
          disabled={!path || !liveReady || busy.has('mobile')}
          onClick={async () => {
            const s = await act('mobile', () => api.invoke('mobile:start', { path, reviewer, live: liveOn && isApk ? { serial, confirmed: ok } : undefined, online: onlineOn && (isApk || path.toLowerCase().endsWith('.ipa')) }))
            if (s) showSession(s.id)
          }}
        >
          <Smartphone size={17} /> Check the app
        </button>
      </div>
    </div>
  )
}

export default function Mobile(): React.JSX.Element {
  return (
    <>
      <PageHead title="Mobile apps" desc="Android and iOS apps, from source or a built file. MacSec reads the app. For an Android .apk you can also run it on a test phone and watch what it does." />
      <MobileFlow />
    </>
  )
}
