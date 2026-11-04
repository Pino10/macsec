import { useEffect, useState } from 'react'
import { Download, Plus } from 'lucide-react'
import type { UpdateInfo } from '@shared/types'
import { AppProvider, useApp } from './store'
import Rail, { PAGE_ORDER } from './components/Rail'
import ThisMac from './pages/ThisMac'
import JobsBar from './components/JobsBar'
import { overall } from './components/LiveRun'
import Overview from './pages/Overview'
import Projects from './pages/Projects'
import CodeReview from './pages/CodeReview'
import WebScan from './pages/WebScan'
import ApiSecurity from './pages/ApiSecurity'
import Audits from './pages/Audits'
import Mobile from './pages/Mobile'
import Recon from './pages/Recon'
import Sessions from './pages/Sessions'
import Tools from './pages/Tools'
import Logs from './pages/Logs'
import Settings from './pages/Settings'

function EngineBar(): React.JSX.Element {
  const { sessions, tools, updates, setPage, showSession } = useApp()
  const running = sessions.filter((s) => s.status === 'running')
  const ready = tools.filter((t) => t.installed && t.method !== 'app').length
  const total = tools.filter((t) => t.method !== 'app').length
  return (
    <header className="enginebar drag">
      <button className="engine-state glass" style={{ border: 0, cursor: 'pointer' }} onClick={() => (running[0] ? showSession(running[0].id) : setPage('tools'))}>
        <span className="dot" data-s={running.length ? 'busy' : ready < total ? 'warn' : 'ok'} />
        {running.length ? (
          <>
            <b>Scanning</b> {running[0].title}
            {running.length > 1 ? ` and ${running.length - 1} more` : ''}
            <span className="engine-step">
              {running[0].steps.find((x) => x.status === 'running')?.label ?? 'Starting'}, {overall(running[0])}%
            </span>
          </>
        ) : (
          <>
            <b>Engine ready</b> {ready} of {total} scanners installed{updates.length ? `, ${updates.length} with updates` : ''}
          </>
        )}
      </button>
      <span style={{ flex: 1 }} />
      <button className="btn btn-primary" onClick={() => setPage('review')}>
        <Plus size={15} /> New test
      </button>
    </header>
  )
}

/** MacSec's own update: offered here, installed in place, then MacSec restarts. */
function UpdateBar(): React.JSX.Element | null {
  const { act, busy } = useApp()
  const [u, setU] = useState<UpdateInfo | null>(null)
  const [later, setLater] = useState(false)
  useEffect(() => {
    void window.macsec.invoke('app:check-update').then(setU).catch(() => undefined)
    return window.macsec.on('app:update', setU)
  }, [])
  if (!u || later) return null
  return (
    <div className="update-bar glass">
      <Download size={16} style={{ color: 'var(--ion)' }} />
      <span className="grow">
        <b>MacSec {u.version}</b> is ready (you have {u.current}). Your sessions, tools and settings stay as they are.
      </span>
      <button className="link" onClick={() => void window.macsec.invoke('app:open-external', u.url)}>
        What’s new
      </button>
      <button className="btn btn-sm" onClick={() => setLater(true)}>
        Later
      </button>
      <button className="btn btn-sm btn-primary" disabled={busy.has('app-update')} onClick={() => void act('app-update', () => window.macsec.invoke('app:install-update'))}>
        {busy.has('app-update') ? 'Updating…' : 'Update and restart'}
      </button>
    </div>
  )
}

function Shell(): React.JSX.Element {
  const { page, setPage, toast } = useApp()
  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if (!(e.metaKey || e.ctrlKey) || e.altKey) return
      const target = PAGE_ORDER[Number(e.key) - 1]
      if (/^[1-9]$/.test(e.key) && target) {
        e.preventDefault()
        setPage(target)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [setPage])

  return (
    <>
      <div className="space" aria-hidden />
      <div className="app">
        <Rail />
        <main className="main">
          <EngineBar />
          <div className="scroll">
            <div className="page" key={page}>
              <UpdateBar />
              {page === 'overview' && <Overview />}
              {page === 'projects' && <Projects />}
              {page === 'review' && <CodeReview />}
              {page === 'web' && <WebScan />}
              {page === 'api' && <ApiSecurity />}
              {page === 'mobile' && <Mobile />}
              {page === 'recon' && <Recon />}
              {page === 'audit' && <Audits />}
              {page === 'mac' && <ThisMac />}
              {page === 'sessions' && <Sessions />}
              {page === 'tools' && <Tools />}
              {page === 'logs' && <Logs />}
              {page === 'settings' && <Settings />}
            </div>
          </div>
        </main>
      </div>
      <JobsBar />
      {toast && (
        <div className="toast" data-kind={toast.kind} role="status">
          {toast.text}
        </div>
      )}
    </>
  )
}

export default function App(): React.JSX.Element {
  return (
    <AppProvider>
      <Shell />
    </AppProvider>
  )
}
