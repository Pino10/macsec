import { useEffect } from 'react'
import { AppProvider, useApp } from './store'
import Sidebar, { PAGE_ORDER } from './components/Sidebar'
import JobsBar from './components/JobsBar'
import Overview from './pages/Overview'
import Projects from './pages/Projects'
import CodeReview from './pages/CodeReview'
import Sessions from './pages/Sessions'
import Tools from './pages/Tools'
import Logs from './pages/Logs'
import Settings from './pages/Settings'

function Shell(): React.JSX.Element {
  const { page, setPage, toast, appInfo } = useApp()

  useEffect(() => {
    document.documentElement.dataset.material = appInfo?.material ?? 'none'
    document.documentElement.dataset.glass = 'smoke'
    document.documentElement.dataset.tone = 'dark'
  }, [appInfo])

  useEffect(() => {
    const onKey = (e: KeyboardEvent): void => {
      if (!(e.metaKey || e.ctrlKey) || e.altKey) return
      if (/^[1-9]$/.test(e.key) && PAGE_ORDER[Number(e.key) - 1]) {
        e.preventDefault()
        setPage(PAGE_ORDER[Number(e.key) - 1])
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [setPage])

  return (
    <>
      <div className="canvas" aria-hidden />
      <div className="shell">
        <Sidebar />
        <main className="main">
          <header className="topbar drag" />
          <div className="scroll">
            <div className="main-inner" data-page={page} key={page}>
              {page === 'overview' && <Overview />}
              {page === 'projects' && <Projects />}
              {page === 'review' && <CodeReview />}
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
