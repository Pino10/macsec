import { Boxes, ChevronRight, FileSearch, Globe, PlusCircle, Radar, ShieldQuestion, Smartphone, Wrench } from 'lucide-react'
import { useApp, type Page } from '../store'
import { PageHead } from '../ui'
import { ago, kindName } from '../ui'

const STARTS: { page: Page; icon: React.ReactNode; g: string; title: string; text: string }[] = [
  { page: 'review', icon: <FileSearch size={22} />, g: '#38e1ff', title: 'Code review', text: 'Every scanner that fits a project, then an AI reviewer that checks the results and looks for what scanners miss.' },
  { page: 'web', icon: <Globe size={22} />, g: '#8b6cff', title: 'Web scan', text: 'A site you own: headers, exposed files, known problems, and optional proofs. Signed in or out.' },
  { page: 'api', icon: <Radar size={22} />, g: '#ff3d7f', title: 'API security', text: 'Load a Postman, OpenAPI or HAR file and see what the API gives away.' },
  { page: 'audit', icon: <ShieldQuestion size={22} />, g: '#3ef0a8', title: 'Special audits', text: 'Only your changes, the code plus its live site, a whole portfolio, a cloud account or a server.' }
]

const ALSO: { page: Page; icon: React.ReactNode; title: string }[] = [
  { page: 'recon', icon: <Radar size={16} />, title: 'Recon a domain' },
  { page: 'mobile', icon: <Smartphone size={16} />, title: 'Check a mobile app' },
  { page: 'mac', icon: <Boxes size={16} />, title: 'Check this Mac' },
  { page: 'impact', icon: <ShieldQuestion size={16} />, title: 'Prove an impact' },
  { page: 'assets', icon: <Boxes size={16} />, title: 'See your assets' }
]

/** One place to start anything, so the rail is not a maze of near-identical entries. */
export default function NewTest(): React.JSX.Element {
  const { setPage, showSession, sessions, tools } = useApp()
  const missing = tools.filter((t) => !t.installed && t.method !== 'app').length
  const recent = sessions.filter((s) => s.status !== 'running').slice(0, 4)
  return (
    <>
      <PageHead title="Start a test" desc="Pick the kind of thing you want to check. Every test is read-only by default, saved as a result you can come back to, and explained in plain words.">
        <button className="btn" onClick={() => setPage('tools')}>
          <Wrench size={14} /> Tools
        </button>
      </PageHead>

      {missing > 0 && (
        <div className="notice" style={{ marginBottom: 16 }}>
          <span className="grow">
            {missing} scanner{missing === 1 ? ' is' : 's are'} not installed yet. MacSec installs what a test needs as it goes, or you can install them all first.
          </span>
          <button className="btn btn-sm" onClick={() => setPage('tools')}>
            Open Tools
          </button>
        </div>
      )}

      <div className="start-grid">
        {STARTS.map((c) => (
          <button key={c.page} className="start-card" onClick={() => setPage(c.page)}>
            <span className="glyph" style={{ ['--g' as string]: c.g, width: 46, height: 46, borderRadius: 14 }}>
              {c.icon}
            </span>
            <strong>{c.title}</strong>
            <span className="hint">{c.text}</span>
            <span className="start-go">
              Start <ChevronRight size={13} />
            </span>
          </button>
        ))}
      </div>

      <div className="start-also">
        <span className="hint">Also:</span>
        {ALSO.map((a) => (
          <button key={a.page} className="chip" onClick={() => setPage(a.page)}>
            {a.icon} {a.title}
          </button>
        ))}
        <button className="chip" onClick={() => setPage('new')} aria-hidden style={{ display: 'none' }}>
          <PlusCircle size={14} />
        </button>
      </div>

      {recent.length > 0 && (
        <div className="panel" style={{ marginTop: 20, overflow: 'hidden' }}>
          <div className="row" style={{ cursor: 'default' }}>
            <span className="grow">
              <span className="row-title">Pick up where you left off</span>
              <span className="row-sub">The last four finished results.</span>
            </span>
            <button className="link" onClick={() => setPage('sessions')}>
              All results
            </button>
          </div>
          {recent.map((s) => (
            <button key={s.id} className="row" onClick={() => showSession(s.id)}>
              <span className="grow">
                <span className="row-title" style={{ display: 'block' }}>
                  {s.title}
                </span>
                <span className="row-sub">
                  {kindName(s.kind)} · {ago(s.createdAt)}
                </span>
              </span>
              <ChevronRight size={15} />
            </button>
          ))}
        </div>
      )}
    </>
  )
}
