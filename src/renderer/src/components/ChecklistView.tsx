import { useEffect, useState } from 'react'
import type { ChecklistData, ChecklistItemInfo, ChecklistState } from '@shared/types'
import { useApp } from '../store'

const LABEL: Record<ChecklistState, string> = { found: 'Problem found', clear: 'Tested, nothing found', 'ai-issue': 'AI sees a problem', 'ai-ok': 'AI sees no problem', manual: 'For you to test' }
const TAG: Record<ChecklistState, string> = { found: 'tag tag-warn', clear: 'tag tag-ok', 'ai-issue': 'tag tag-warn', 'ai-ok': 'tag', manual: 'tag' }
const FILTERS: [ChecklistState | 'all' | 'todo', string][] = [['all', 'Everything'], ['todo', 'Left for me'], ['found', 'Problems'], ['clear', 'Tested clear'], ['ai-ok', 'AI: fine'], ['manual', 'Manual']]

/** Your checklist, walked for this scan: what MacSec tested, what the AI judged, and what is left for you. */
export default function ChecklistView({ id }: { id: string }): React.JSX.Element {
  const api = window.macsec
  const { act } = useApp()
  const [d, setD] = useState<ChecklistData | null>(null)
  const [filter, setFilter] = useState<ChecklistState | 'all' | 'todo'>('todo')
  const [onlyRelevant, setOnlyRelevant] = useState(true)
  const [open, setOpen] = useState<number | null>(null)
  useEffect(() => {
    void api.invoke('sessions:checklist', id).then(setD)
  }, [api, id])
  if (!d) return <div className="panel empty-state">Loading the checklist.</div>
  if (!d.checklist) return <div className="panel empty-state">This test has no checklist walk. Web scans made with MacSec 1.6 or later have one.</div>
  const c = d.checklist
  const mine = (i: ChecklistItemInfo): 'done' | 'problem' | 'na' | undefined => d.user[i.id]?.state
  const all = c.sections.flatMap((s) => s.items)
  const settled = all.filter((i) => mine(i) || i.state !== 'manual').length
  const set = async (i: ChecklistItemInfo, state: 'done' | 'problem' | 'na' | null): Promise<void> => {
    const r = await act('checklist', () => api.invoke('sessions:checklist-set', id, i.id, state))
    if (r) setD(r)
  }
  const show = (i: ChecklistItemInfo): boolean => {
    if (filter === 'all') return true
    if (filter === 'todo') return i.state === 'manual' && !mine(i)
    return i.state === filter
  }
  return (
    <div className="panel">
      <p className="hint" style={{ marginTop: 0 }}>
        {settled} of {all.length} items settled ({all.filter((i) => i.state === 'found' || i.state === 'ai-issue').length} problems). “Tested” means MacSec ran that check and found nothing, not that the site is safe. The AI only reads the scan's evidence: its answers are opinions, never tests.
      </p>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 10 }}>
        {FILTERS.map(([k, t]) => (
          <button key={k} className="btn btn-sm" aria-pressed={filter === k} onClick={() => setFilter(k)}>{t}</button>
        ))}
        <label className="hint" style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
          <input type="checkbox" checked={onlyRelevant} onChange={(e) => setOnlyRelevant(e.target.checked)} /> Only sections that fit this site
        </label>
      </div>
      {c.sections
        .filter((s) => (!onlyRelevant || s.relevant) && s.items.some(show))
        .map((s) => (
          <div key={s.n} style={{ marginBottom: 6 }}>
            <button className="link" style={{ fontWeight: 600 }} aria-expanded={open === s.n} onClick={() => setOpen(open === s.n ? null : s.n)}>
              {open === s.n ? '▾' : '▸'} {s.n}. {s.title} <span className="hint">({s.items.filter((i) => i.state !== 'manual' || mine(i)).length} of {s.items.length} settled)</span>
            </button>
            {open === s.n && (
              <div style={{ display: 'grid', gap: 8, margin: '8px 0 8px 14px' }}>
                {s.items.filter(show).map((i) => (
                  <div key={i.id}>
                    <div>
                      <span className="hint">{i.id}</span> {i.text}{' '}
                      <span className={TAG[i.state]}>{LABEL[i.state]}</span>
                      {mine(i) && <span className="tag tag-ok"> You: {mine(i) === 'done' ? 'done' : mine(i) === 'problem' ? 'problem' : 'not applicable'}</span>}
                    </div>
                    {i.note && <div className="hint">{i.note}</div>}
                    <div style={{ display: 'flex', gap: 6, marginTop: 2 }}>
                      {(['done', 'problem', 'na'] as const).map((k) => (
                        <button key={k} className="btn btn-sm" aria-pressed={mine(i) === k} onClick={() => void set(i, mine(i) === k ? null : k)}>
                          {k === 'done' ? 'Done' : k === 'problem' ? 'Problem' : 'Not applicable'}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
    </div>
  )
}
