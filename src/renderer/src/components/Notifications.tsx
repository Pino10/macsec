import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { AlertTriangle, Bell, CheckCircle2, Info, Trash2, X } from 'lucide-react'
import { useApp, type Notice } from '../store'

const ICON = { error: <AlertTriangle size={16} />, success: <CheckCircle2 size={16} />, info: <Info size={16} /> }
const heading = (n: Notice): string => n.title ?? (n.kind === 'error' ? 'Something went wrong' : n.kind === 'success' ? 'Done' : 'Note')
const when = (iso: string): string => new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })

/** One pop-up. Errors stay until closed; the rest fade after a while, and hovering pauses that. */
function Pop({ n, onOpen }: { n: Notice; onOpen: () => void }): React.JSX.Element {
  const { dismiss } = useApp()
  const [hover, setHover] = useState(false)
  useEffect(() => {
    if (n.kind === 'error' || hover) return
    const t = setTimeout(() => dismiss(n.id), n.kind === 'success' ? 8000 : 12000)
    return () => clearTimeout(t)
  }, [n.id, n.kind, hover, dismiss])
  return (
    <div className="note glass" data-kind={n.kind} role={n.kind === 'error' ? 'alert' : 'status'} onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}>
      <button className="note-body" onClick={onOpen} aria-label={`${heading(n)}. Open the full message`}>
        <span className="note-ic">{ICON[n.kind]}</span>
        <span>
          <strong>{heading(n)}</strong>
          {n.text && <span className="note-text">{n.text}</span>}
        </span>
      </button>
      <button className="icon-btn" aria-label="Close" onClick={() => dismiss(n.id)}>
        <X size={14} />
      </button>
    </div>
  )
}

/** The big view of one message, with everything it says. */
function Detail({ n, onClose }: { n: Notice; onClose: () => void }): React.JSX.Element {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    ref.current?.focus()
    const k = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', k)
    return () => window.removeEventListener('keydown', k)
  }, [onClose])
  return createPortal(
    <div className="note-scrim" onClick={onClose}>
      <div className="note-detail glass" data-kind={n.kind} role="dialog" aria-modal="true" aria-label={heading(n)} tabIndex={-1} ref={ref} onClick={(e) => e.stopPropagation()}>
        <div className="note-detail-head">
          <span className="note-ic">{ICON[n.kind]}</span>
          <div>
            <strong>{heading(n)}</strong>
            <small>{new Date(n.at).toLocaleString()}</small>
          </div>
          <button className="icon-btn" aria-label="Close" onClick={onClose}>
            <X size={16} />
          </button>
        </div>
        <div className="note-detail-text">{n.text || 'No more details.'}</div>
        <div className="end">
          {n.text && (
            <button className="btn btn-sm" onClick={() => void navigator.clipboard.writeText(`${heading(n)}\n${n.text}`)}>
              Copy
            </button>
          )}
          <button className="btn btn-primary btn-sm" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>,
    document.body
  )
}

/** Pop-ups at the top right, where you look, plus the full-size message view. */
export function NotificationLayer(): React.JSX.Element {
  const { notices, markRead } = useApp()
  const [open, setOpen] = useState<number | null>(null)
  const shown = notices.filter((n) => n.popup).slice(0, 4)
  const detail = notices.find((n) => n.id === open)
  return (
    <>
      {createPortal(
        <div className="note-stack" aria-live="polite">
          {shown.map((n) => (
            <Pop
              key={n.id}
              n={n}
              onOpen={() => {
                markRead(n.id)
                setOpen(n.id)
              }}
            />
          ))}
        </div>,
        document.body
      )}
      {detail && <Detail n={detail} onClose={() => setOpen(null)} />}
    </>
  )
}

/** The bell in the sidebar: a count of unread messages and the history. */
export function Bell_(): React.JSX.Element {
  const { notices, markRead, clearNotices } = useApp()
  const [list, setList] = useState(false)
  const [open, setOpen] = useState<number | null>(null)
  const unread = notices.filter((n) => !n.read).length
  const detail = notices.find((n) => n.id === open)
  return (
    <>
      <button className="rail-item" aria-expanded={list} onClick={() => setList((v) => !v)}>
        <span className="ri">
          <Bell size={16} />
        </span>
        Messages
        {unread > 0 && <span className="count">{unread}</span>}
      </button>
      {list &&
        createPortal(
          <div className="note-scrim note-scrim-soft" onClick={() => setList(false)}>
            <div className="note-history glass" role="dialog" aria-label="Messages" onClick={(e) => e.stopPropagation()}>
              <div className="note-detail-head">
                <strong>Messages</strong>
                <span className="grow" />
                {notices.length > 0 && (
                  <button className="btn btn-sm" onClick={() => clearNotices()}>
                    <Trash2 size={12} /> Clear
                  </button>
                )}
                <button className="icon-btn" aria-label="Close" onClick={() => setList(false)}>
                  <X size={16} />
                </button>
              </div>
              {notices.length === 0 && <p className="hint">Nothing yet. Updates, finished tests and problems will show up here.</p>}
              {notices.map((n) => (
                <button
                  key={n.id}
                  className="note-row"
                  data-kind={n.kind}
                  data-unread={!n.read}
                  onClick={() => {
                    markRead(n.id)
                    setOpen(n.id)
                  }}
                >
                  <span className="note-ic">{ICON[n.kind]}</span>
                  <span className="note-row-main">
                    <strong>{heading(n)}</strong>
                    {n.text && <span>{n.text}</span>}
                  </span>
                  <small>{when(n.at)}</small>
                </button>
              ))}
            </div>
          </div>,
          document.body
        )}
      {detail && <Detail n={detail} onClose={() => setOpen(null)} />}
    </>
  )
}
