import { useEffect, useState } from 'react'
import { BookmarkPlus, X } from 'lucide-react'
import type { SavedProfile } from '@shared/types'
import { useApp } from '../store'

/**
 * Saved options for this page. A profile holds choices only: never a target, never a cookie. Applying
 * one changes the options, not who you are signed in as.
 */
export default function ProfileBar({ kind, current, onApply }: { kind: 'web' | 'review'; current: Record<string, unknown>; onApply: (o: Record<string, unknown>) => void }): React.JSX.Element {
  const { act } = useApp()
  const api = window.macsec
  const [list, setList] = useState<SavedProfile[]>([])
  const [saving, setSaving] = useState(false)
  const [name, setName] = useState('')
  useEffect(() => {
    void api.invoke('profiles:list').then(setList).catch(() => setList([]))
  }, [api])
  const mine = list.filter((p) => p.kind === kind)
  return (
    <div className="profile-bar">
      <span className="hint">Profiles:</span>
      {mine.length === 0 && !saving && <span className="hint">none saved yet</span>}
      {mine.map((p) => (
        <span key={p.id} className="chip-wrap">
          <button className="chip" onClick={() => onApply(p.options)} title={`Apply ${p.name}`}>
            {p.name}
          </button>
          <button
            className="chip-x"
            aria-label={`Delete the profile ${p.name}`}
            onClick={async () => {
              const r = await act(`pf-${p.id}`, () => api.invoke('profiles:delete', p.id))
              if (r) setList(r)
            }}
          >
            <X size={11} />
          </button>
        </span>
      ))}
      {saving ? (
        <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
          <input className="input" style={{ height: 30, width: 180 }} placeholder="Profile name" value={name} onChange={(e) => setName(e.target.value)} aria-label="Profile name" autoFocus />
          <button
            className="btn btn-sm btn-primary"
            disabled={!name.trim()}
            onClick={async () => {
              const r = await act('pf-save', () => api.invoke('profiles:save', { name: name.trim(), kind, options: current }))
              if (r) {
                setList(r)
                setName('')
                setSaving(false)
              }
            }}
          >
            Save
          </button>
          <button className="btn btn-sm" onClick={() => setSaving(false)}>
            Cancel
          </button>
        </span>
      ) : (
        <button className="link" style={{ display: 'inline-flex', gap: 4, alignItems: 'center' }} onClick={() => setSaving(true)}>
          <BookmarkPlus size={13} /> Save these options
        </button>
      )}
    </div>
  )
}
