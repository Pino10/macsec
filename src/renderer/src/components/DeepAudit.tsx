import { useEffect, useState } from 'react'
import { Cpu, Eye, FileCheck2, FolderLock, Layers, Microscope, MonitorUp, Network, Sparkles, Timer } from 'lucide-react'
import type { AgentInfo, DeepEngine, DeepPlanLine, DeepReviewerKind } from '@shared/types'
import { useApp } from '../store'

const ENGINES: { id: DeepEngine; title: string; text: string; time: string }[] = [
  { id: 'cloudflare', title: 'Cloudflare security audit', text: 'The most thorough. AI agents map the project, hunt each kind of attack, and a fresh agent tries to disprove every candidate before it counts.', time: '45 min to 3 h' },
  { id: 'anthropic', title: 'Claude Code security review', text: 'Anthropic’s own review. One careful pass that reports only high-confidence problems.', time: '5 to 25 min' },
  { id: 'both', title: 'Both, one after the other', text: 'Anthropic’s quick pass, then Cloudflare’s full audit. The most coverage.', time: '50 min to 3.5 h' }
]
const ICON: Record<string, React.ReactNode> = { Reads: <Eye size={14} />, Writes: <FolderLock size={14} />, Checks: <FileCheck2 size={14} />, Time: <Timer size={14} />, AI: <Sparkles size={14} />, Method: <Microscope size={14} /> }

/**
 * A deeper review with two published methods, through the AI you pick. It says exactly what will
 * run, where the code goes and what it may touch before anything starts.
 */
export default function DeepAudit({ engine, onEngine, ai, onAi, projectPath }: { engine: DeepEngine | null; onEngine: (e: DeepEngine | null) => void; ai: DeepReviewerKind; onAi: (a: DeepReviewerKind) => void; projectPath: string | null }): React.JSX.Element {
  const { settings, setPage } = useApp()
  const api = window.macsec
  const [agents, setAgents] = useState<AgentInfo[]>([])
  const [free, setFree] = useState(false)
  const [desktop, setDesktop] = useState(false)
  const [plan, setPlan] = useState<DeepPlanLine[]>([])
  useEffect(() => {
    void api.invoke('ai:agents').then(setAgents)
    void api.invoke('freellm:get').then((f) => setFree(f.hasKey))
    void api.invoke('desktop:status').then((d) => setDesktop(d.app))
  }, [api])
  useEffect(() => {
    if (!engine) return
    void api
      .invoke('review:deep-plan', { engine, reviewer: ai })
      .then(setPlan)
      .catch(() => setPlan([]))
  }, [api, engine, ai, settings?.llm.model])
  const claude = agents.find((a) => a.id === 'claude')?.installed ?? false
  const model = settings?.llm.model
  const choices: { id: DeepReviewerKind; title: string; text: string; icon: React.ReactNode; ok: boolean }[] = [
    { id: 'claude', title: 'Claude Code', text: claude ? 'Your Claude account. The strongest choice for the long audit.' : 'Needs its command line tool: set it up on Tools.', icon: <Sparkles size={16} />, ok: claude },
    { id: 'claude-desktop', title: 'Claude Desktop', text: projectPath ? 'Copies the request and opens the Claude app: you paste it in its Code tab.' : 'Needs a project on this Mac: the Claude app reads folders on this Mac.', icon: <MonitorUp size={16} />, ok: desktop && !!projectPath },
    { id: 'claude-local', title: model ? `claudelm: ${model.split('/').pop()}` : 'claudelm', text: model && claude ? 'Claude Code on your model in LM Studio. Private, but slower and shallower.' : 'Needs Claude Code and a model chosen on Tools.', icon: <Cpu size={16} />, ok: claude && !!model },
    { id: 'claude-free', title: 'claudefree', text: claude && free ? 'Claude Code on Free LLM API. Free, with the limits of your free keys. The code goes to the provider your chain picks.' : 'Needs Claude Code and Free LLM API connected on Tools.', icon: <Network size={16} />, ok: claude && free }
  ]
  return (
    <div className="deep">
      <label className="check">
        <input type="checkbox" checked={!!engine} onChange={(e) => onEngine(e.target.checked ? 'cloudflare' : null)} /> <Microscope size={14} /> <strong>Deep audit</strong>: run a published security review instead of the standard AI step
      </label>
      {engine && (
        <>
          <div className="choices" role="radiogroup" aria-label="Method">
            {ENGINES.map((e) => (
              <button key={e.id} className="choice" role="radio" aria-checked={engine === e.id} onClick={() => onEngine(e.id)}>
                <strong>{e.title}</strong>
                <span>{e.text}</span>
                <small>
                  <Timer size={11} /> {e.time}
                </small>
              </button>
            ))}
          </div>
          <div className="deep-label">Run it with</div>
          <div className="choices" role="radiogroup" aria-label="AI">
            {choices.map((c) => (
              <button key={c.id} className="choice" role="radio" aria-checked={ai === c.id} disabled={!c.ok} onClick={() => onAi(c.id)} title={c.ok ? undefined : 'Not ready yet'}>
                <strong>
                  {c.icon} {c.title}
                </strong>
                <span>
                  {c.text}
                  {!c.ok && c.id !== 'claude-desktop' && (
                    <>
                      {' '}
                      <a
                        className="link"
                        onClick={(e) => {
                          e.stopPropagation()
                          setPage('tools')
                        }}
                      >
                        Open Tools
                      </a>
                    </>
                  )}
                </span>
              </button>
            ))}
          </div>
          {plan.length > 0 && (
            <div className="deep-plan" aria-label="What will run">
              <div className="deep-label">What will run</div>
              {plan.map((l) => (
                <div key={l.label} className="deep-line">
                  <span className="deep-key">
                    {ICON[l.label] ?? <Layers size={14} />} {l.label}
                  </span>
                  <span>{l.text}</span>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}
