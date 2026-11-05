import { useMemo, useState } from 'react'
import { ChevronRight, Cookie, FileCode2, FormInput, Link2, ShieldCheck, ShieldX } from 'lucide-react'
import type { ReconPage } from '@shared/types'

const HEADER_NAMES: Record<string, string> = {
  'content-security-policy': 'Content-Security-Policy',
  'strict-transport-security': 'Strict-Transport-Security',
  'x-frame-options': 'X-Frame-Options',
  'x-content-type-options': 'X-Content-Type-Options',
  'referrer-policy': 'Referrer-Policy',
  'permissions-policy': 'Permissions-Policy'
}
const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const

/** The crawl, page by page: what each page has on it and how it is protected. Everything here was only read. */
export function ReconPages({ pages }: { pages: ReconPage[] }): React.JSX.Element | null {
  const [open, setOpen] = useState<string | null>(null)
  const [filter, setFilter] = useState<'all' | 'forms' | 'notes'>('all')
  const list = useMemo(() => {
    const l = pages.filter((p) => (filter === 'forms' ? p.forms.length > 0 : filter === 'notes' ? p.notes.some((n) => n.severity !== 'info') : true))
    return l.slice().sort((a, b) => (RANK[a.notes[0]?.severity ?? 'info'] ?? 4) - (RANK[b.notes[0]?.severity ?? 'info'] ?? 4))
  }, [pages, filter])
  if (!pages.length) return null
  const withForms = pages.filter((p) => p.forms.length).length
  return (
    <div className="panel rpages">
      <div className="rpages-head">
        <div className="section-title">
          {pages.length} pages, one by one
          <span className="hint" style={{ marginLeft: 10, fontWeight: 400 }}>
            {withForms} with forms · {pages.filter((p) => p.notes.some((n) => n.severity !== 'info')).length} worth a look
          </span>
        </div>
        <div className="seg" role="radiogroup" aria-label="Show">
          {(
            [
              ['all', 'All'],
              ['notes', 'Worth a look'],
              ['forms', 'With forms']
            ] as const
          ).map(([k, l]) => (
            <button key={k} role="radio" aria-checked={filter === k} onClick={() => setFilter(k)}>
              {l}
            </button>
          ))}
        </div>
      </div>
      {list.map((p) => {
        const isOpen = open === p.url
        const worst = p.notes[0]?.severity
        return (
          <div key={p.url} className="rpage" data-open={isOpen}>
            <button className="rpage-row" onClick={() => setOpen(isOpen ? null : p.url)} aria-expanded={isOpen}>
              <ChevronRight size={14} className="rpage-chev" />
              <span className={`rpage-status s${String(p.status)[0]}`}>{p.status}</span>
              <span className="grow">
                <span className="row-title mono">{p.url.replace(/^https?:\/\//, '')}</span>
                <span className="row-sub">{p.redirect ? `Goes to ${p.redirect}` : p.title || p.type || 'No title'}</span>
              </span>
              <span className="rpage-chips">
                {p.forms.length > 0 && (
                  <span className="tag">
                    <FormInput size={11} /> {p.forms.length}
                  </span>
                )}
                {p.cookies.length > 0 && (
                  <span className="tag">
                    <Cookie size={11} /> {p.cookies.length}
                  </span>
                )}
                {worst && worst !== 'info' && <span className="sev" data-sev={worst}>{p.notes.filter((n) => n.severity !== 'info').length}</span>}
                <span className="hint">{p.ms} ms</span>
              </span>
            </button>
            {isOpen && (
              <div className="rpage-body">
                {p.notes.length > 0 && (
                  <ul className="rpage-notes">
                    {p.notes.map((n) => (
                      <li key={n.text}>
                        <span className="sev" data-sev={n.severity}>{n.severity}</span> {n.text}
                      </li>
                    ))}
                  </ul>
                )}
                <div className="rpage-grid">
                  <section>
                    <h4>Security headers</h4>
                    {p.headers.map((h) => (
                      <div key={h.name} className="rpage-kv" title={h.value}>
                        {h.present ? <ShieldCheck size={13} className="ok" /> : <ShieldX size={13} className="bad" />}
                        <span>{HEADER_NAMES[h.name] ?? h.name}</span>
                      </div>
                    ))}
                  </section>
                  <section>
                    <h4>Forms</h4>
                    {!p.forms.length && <span className="hint">None</span>}
                    {p.forms.map((f, i) => (
                      <div key={i} className="rpage-form">
                        <div className="mono">
                          <b>{f.method.toUpperCase()}</b> {new URL(f.action).pathname}
                          {f.offsite && ` (${new URL(f.action).hostname})`}
                        </div>
                        <div className="hint">
                          {f.inputs.map((x) => `${x.name}${x.type !== 'text' ? ` (${x.type})` : ''}`).join(', ') || 'no fields'}
                        </div>
                        <div className="hint">{f.method === 'post' ? (f.csrf ? 'Has a CSRF token field' : 'No CSRF token field') : 'Sends in the address (GET)'}</div>
                      </div>
                    ))}
                  </section>
                  <section>
                    <h4>Cookies</h4>
                    {!p.cookies.length && <span className="hint">None set</span>}
                    {p.cookies.map((c) => (
                      <div key={c.name} className="rpage-kv">
                        <span className="mono">{c.name}</span>
                        <span className="hint">{[c.secure ? 'Secure' : 'not Secure', c.httpOnly ? 'HttpOnly' : 'readable by JS', c.sameSite ? `SameSite=${c.sameSite}` : 'no SameSite'].join(' · ')}</span>
                      </div>
                    ))}
                  </section>
                  <section>
                    <h4>Scripts and parameters</h4>
                    <div className="rpage-kv">
                      <FileCode2 size={13} /> {p.scripts.total} scripts, {p.scripts.inline} inline
                    </div>
                    {p.scripts.external.length > 0 && <div className="hint">From: {p.scripts.external.join(', ')}</div>}
                    {p.params.length > 0 && (
                      <div className="rpage-kv">
                        <Link2 size={13} /> <span className="mono">{p.params.join(', ')}</span>
                      </div>
                    )}
                    {p.tech.length > 0 && <div className="hint">Runs on: {p.tech.join(', ')}</div>}
                  </section>
                </div>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
