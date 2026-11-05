import { useEffect, useState } from 'react'
import { ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import type { OwaspChecklistInfo } from '@shared/types'

const TEST: Record<string, string> = { 'code-review': 'code review', sast: 'code scanners', secrets: 'secrets scan', dependencies: 'dependency audit', 'web-scan': 'web scan', headers: 'header check', api: 'API scan' }

/** The OWASP Top 10 (2025) as a checklist: problems found, checked and fine, or not checked yet. */
export function OwaspList({ list, title = 'OWASP Top 10' }: { list: OwaspChecklistInfo; title?: string }): React.JSX.Element {
  const issues = list.items.filter((i) => i.status === 'issues').length
  return (
    <div className="panel owasp">
      <div className="owasp-head">
        <div>
          <div className="row-title">{title} (2025)</div>
          <div className="row-sub">
            {issues ? `${issues} of the 10 need work.` : 'Nothing to fix in what was checked.'} {list.covered} of 10 checked by this run{list.other ? `, ${list.other} other ${list.other === 1 ? 'finding' : 'findings'}` : ''}.
          </div>
        </div>
        <div className="owasp-meter" aria-hidden>
          {list.items.map((i) => (
            <i key={i.id} data-s={i.status} title={`${i.id} ${i.name}`} />
          ))}
        </div>
      </div>
      <div className="owasp-grid">
        {list.items.map((i) => (
          <details key={i.id} className="owasp-item" data-s={i.status}>
            <summary>
              {i.status === 'issues' ? <ShieldAlert size={15} /> : i.status === 'checked' ? <ShieldCheck size={15} /> : <ShieldQuestion size={15} />}
              <span className="owasp-id mono">{i.id}</span>
              <span className="owasp-name">{i.name}</span>
              <span className="owasp-state">{i.status === 'issues' ? `${i.count} to fix` : i.status === 'checked' ? 'Checked' : 'Not checked'}</span>
            </summary>
            <p>{i.about}</p>
            {i.examples.length > 0 && (
              <ul>
                {i.examples.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            )}
            <p className="hint">{i.status === 'not-checked' ? `To check it: ${i.howToCheck}` : i.checkedBy.length ? `Checked by the ${i.checkedBy.map((t) => TEST[t] ?? t).join(' and ')}.` : 'Seen in the findings.'}</p>
          </details>
        ))}
      </div>
    </div>
  )
}

/** The checklist of a session. */
export function SessionOwasp({ id, stamp }: { id: string; stamp?: unknown }): React.JSX.Element | null {
  const [list, setList] = useState<OwaspChecklistInfo | null>(null)
  useEffect(() => {
    void window.macsec.invoke('sessions:owasp', id).then(setList).catch(() => setList(null))
  }, [id, stamp])
  return list ? <OwaspList list={list} /> : null
}
