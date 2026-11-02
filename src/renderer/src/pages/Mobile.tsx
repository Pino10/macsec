import { useEffect, useState } from 'react'
import { FileBox, FolderOpen, Smartphone } from 'lucide-react'
import type { LocalProject, Reviewer } from '@shared/types'
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
  useEffect(() => {
    void api.invoke('projects:local').then(setProjects)
  }, [api])
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
      <FlowStep n={start + 1} title="Who writes the report" state="current">
        <ReviewerChoice value={reviewer} onChange={setReviewer} what="findings" />
      </FlowStep>
      <div className="flow-go glass">
        <span className="hint grow">
          {kind === 'Source folder' || !path ? 'mobsfscan rules, manifest and Info.plist settings, and keys in the code.' : 'Settings, compiled code hardening, and keys inside the app.'} Nothing is run or installed on a phone.
        </span>
        <button
          className="btn btn-primary btn-lg"
          disabled={!path || busy.has('mobile')}
          onClick={async () => {
            const s = await act('mobile', () => api.invoke('mobile:start', { path, reviewer }))
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
      <PageHead title="Mobile apps" desc="Android and iOS apps, from source or a built file. Read-only: MacSec reads the app, it never runs it." />
      <MobileFlow />
    </>
  )
}
