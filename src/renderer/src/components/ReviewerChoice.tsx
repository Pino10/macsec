import { useEffect, useState } from 'react'
import { Bot, Cpu, Layers, Sparkles } from 'lucide-react'
import type { AgentInfo, Reviewer } from '@shared/types'
import { useApp } from '../store'

/** Who reads the results: Claude Code, Codex, your own model, or nobody. */
export default function ReviewerChoice({ value, onChange, what }: { value: Reviewer; onChange: (r: Reviewer) => void; what: 'code' | 'findings' }): React.JSX.Element {
  const { settings, setPage } = useApp()
  const [agents, setAgents] = useState<AgentInfo[]>([])
  useEffect(() => {
    void window.macsec.invoke('ai:agents').then(setAgents)
  }, [])
  const has = (id: string): boolean => agents.find((a) => a.id === id)?.installed ?? false
  const model = settings?.llm.model
  const list: { id: Reviewer; icon: React.ReactNode; title: string; text: string; ok: boolean }[] = [
    { id: 'claude', icon: <Sparkles size={16} />, title: 'Claude Code', text: has('claude') ? (what === 'code' ? 'Reads the whole project, read-only.' : 'Reads the findings and explains what matters.') : 'Needs its command line tool: set it up on Tools.', ok: has('claude') },
    { id: 'codex', icon: <Bot size={16} />, title: 'Codex', text: has('codex') ? 'OpenAI’s agent, read-only.' : 'Not installed: set it up on Tools.', ok: has('codex') },
    { id: 'model', icon: <Cpu size={16} />, title: model ? model.split('/').pop()! : 'Your model', text: model ? 'LM Studio or your own server. Stays on this Mac.' : 'Choose a model on Tools first.', ok: !!model },
    { id: 'none', icon: <Layers size={16} />, title: 'No AI', text: 'Scanners only. Findings still come with fixes.', ok: true }
  ]
  return (
    <div className="choices" role="radiogroup" aria-label="AI reviewer">
      {list.map((r) => (
        <button key={r.id} className="choice" role="radio" aria-checked={value === r.id} disabled={!r.ok} onClick={() => onChange(r.id)} title={!r.ok ? 'Set it up on the Tools page' : undefined}>
          <strong>
            {r.icon} {r.title}
          </strong>
          <span>
            {r.text}
            {!r.ok && r.id !== 'none' && (
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
  )
}
