import { useEffect, useState } from 'react'
import { Bot, Combine, FileCheck2, FolderOpen, Play, ShieldCheck } from 'lucide-react'
import type { LoopState, Reviewer } from '@shared/types'
import { useApp } from '../store'

/**
 * The review loop for a mobile result: tools, then a blind AI review, then the merge, then a
 * verifier. The AI findings are possible, never confirmed; the person decides at the end.
 */
export default function ReviewDesk({ id, reviewer, toolCount }: { id: string; reviewer: Reviewer; toolCount: number }): React.JSX.Element {
  const { act, notify } = useApp()
  const api = window.macsec
  const [state, setState] = useState<LoopState | null>(null)
  const [busy, setBusy] = useState('')
  useEffect(() => {
    void api.invoke('loop:state', id).then(setState).catch(() => setState(null))
  }, [api, id])
  const run = async (key: string, call: () => Promise<LoopState>): Promise<void> => {
    setBusy(key)
    try {
      const r = await act(key, call)
      if (r) setState(r)
    } catch (e) {
      notify({ kind: 'error', text: (e as Error).message })
    } finally {
      setBusy('')
    }
  }
  const s = state
  const verified = s?.combined.filter((c) => c.verifier).length ?? 0
  const conflict = s?.combined.filter((c) => c.conflict).length ?? 0
  return (
    <div className="loop">
      <div className="loop-head">
        <ShieldCheck size={18} />
        <div className="grow">
          <strong>Review loop</strong>
          <div className="hint">Tools first, then an AI review that does not see the tool findings. The merge keeps both sides; the verifier is a second opinion. Nothing here confirms a finding.</div>
        </div>
        <button className="btn btn-sm" onClick={() => void api.invoke('sessions:open', id, 'folder')}>
          <FolderOpen size={13} /> Session folder
        </button>
      </div>

      <div className="loop-stages">
        <div className="loop-stage" data-done={toolCount > 0}>
          <FileCheck2 size={15} />
          <div>
            <strong>1. Tools</strong>
            <span className="hint">{toolCount} finding{toolCount === 1 ? '' : 's'} from the scan. {s?.evidence ? 'Evidence pack saved.' : 'Run the scan again to keep the evidence pack.'}</span>
          </div>
        </div>
        <div className="loop-stage" data-done={(s?.blind.length ?? 0) > 0}>
          <Bot size={15} />
          <div>
            <strong>2. Blind AI review</strong>
            <span className="hint">{s?.blind.length ? `${s.blind.length} AI finding${s.blind.length === 1 ? '' : 's'}, all possible.` : 'The AI sees the app evidence only, never the tool findings.'}</span>
            <button className="btn btn-sm" disabled={busy !== '' || reviewer === 'none'} onClick={() => void run('blind', () => api.invoke('loop:blind', id, reviewer))}>
              <Play size={12} /> {busy === 'blind' ? 'Reviewing…' : 'Run blind review'}
            </button>
            {reviewer === 'none' && <span className="hint">Start the scan with an AI reviewer to use this.</span>}
          </div>
        </div>
        <div className="loop-stage" data-done={(s?.combined.length ?? 0) > 0}>
          <Combine size={15} />
          <div>
            <strong>3. Combine</strong>
            <span className="hint">{s?.combined.length ? `${s.combined.length} combined, ${s.combined.filter((c) => c.agreement).length} agreed, ${conflict} conflict${conflict === 1 ? '' : 's'}.` : 'Match by place and title; keep both sources; never delete one side.'}</span>
            <button className="btn btn-sm" disabled={busy !== '' || !s?.blind.length} onClick={() => void run('combine', () => api.invoke('loop:combine', id))}>
              <Combine size={12} /> {busy === 'combine' ? 'Combining…' : 'Combine'}
            </button>
            {!s?.blind.length && (
              <button className="link" disabled={busy !== ''} onClick={() => void run('combine', () => api.invoke('loop:combine', id))}>
                Skip the blind AI and combine tool findings only
              </button>
            )}
          </div>
        </div>
        <div className="loop-stage" data-done={verified > 0}>
          <ShieldCheck size={15} />
          <div>
            <strong>4. Re-review</strong>
            <span className="hint">{verified ? `${verified} verified by the second AI, without being told the source.` : 'The verifier sees the combined list without the source labels.'}</span>
            <button className="btn btn-sm" disabled={busy !== '' || !s?.combined.length || reviewer === 'none'} onClick={() => void run('verify', () => api.invoke('loop:verify', id, reviewer))}>
              <ShieldCheck size={12} /> {busy === 'verify' ? 'Verifying…' : 'Verify combined'}
            </button>
          </div>
        </div>
      </div>

      {!!s?.combined.length && (
        <div className="panel loop-table">
          {s.combined.map((c) => (
            <div key={c.id} className="loop-row">
              <span className="sev" data-sev={c.severity}>{c.severity}</span>
              <span className="grow">
                <strong>{c.title}</strong>
                <span className="hint">{c.locations[0]} · {c.sources.join(' + ')}{c.conflict ? ' · conflict' : ''}</span>
              </span>
              <span className={`tag ${c.verifier?.verdict === 'supported' ? 'tag-ok' : c.verifier?.verdict === 'refuted' ? 'tag-warn' : ''}`}>{c.verifier?.verdict ?? 'not verified'}</span>
            </div>
          ))}
        </div>
      )}
      <p className="hint">
        AI findings and verifier answers are possible, not confirmed. A finding becomes confirmed only with evidence or your decision. If you skip the blind AI, this is a single-source review: the verifier is only a second opinion, not an independent discovery pass. The report is saved as review-loop.md in the session folder.
      </p>
    </div>
  )
}
