import { useEffect, useState } from 'react'
import { Bot, Cpu, Layers, Network, Sparkles } from 'lucide-react'
import type { AgentInfo, Reviewer } from '@shared/types'
import { useApp } from '../store'

/** Who reads the results: Claude Code, Codex, your own model, or nobody. */
export default function ReviewerChoice({ value, onChange, what }: { value: Reviewer; onChange: (r: Reviewer) => void; what: 'code' | 'findings' }): React.JSX.Element {
  const { settings, setPage } = useApp()
  const [agents, setAgents] = useState<AgentInfo[]>([])
  const [free, setFree] = useState(false)
  useEffect(() => {
    void window.macsec.invoke('ai:agents').then(setAgents)
    void window.macsec.invoke('freellm:get').then((f) => setFree(f.hasKey))
  }, [])
  const has = (id: string): boolean => agents.find((a) => a.id === id)?.installed ?? false
  const model = settings?.llm.model
  const G: Record<Reviewer, string> = { claude: '#38e1ff', 'claude-local': '#5ef0ff', 'claude-free': '#7cc4ff', codex: '#8b6cff', gemini: '#ffc94a', model: '#3ef0a8', none: '#8c95b8' }
  const list: { id: Reviewer; icon: React.ReactNode; title: string; text: string; ok: boolean }[] = [
    { id: 'claude', icon: <Sparkles size={18} />, title: 'Claude Code', text: has('claude') ? (what === 'code' ? 'Reads the project and every scanner result, with MacSec’s security skills. Saved as your Claude Code session.' : 'Reads every finding and writes the report.') : 'Needs its command line tool: set it up on Tools.', ok: has('claude') },
    { id: 'claude-local', icon: <Sparkles size={18} />, title: model ? `Claude Code on ${model.split('/').pop()}` : 'Claude Code on your model', text: has('claude') && model ? 'Claude Code with all its tools and MacSec’s skills, talking to your model in LM Studio (0.4.1 or newer). Nothing leaves this Mac.' : !has('claude') ? 'Needs Claude Code: set it up on Tools.' : 'Choose a model on Tools first.', ok: has('claude') && !!model },
    { id: 'claude-free', icon: <Network size={18} />, title: 'Claude Code on Free LLM API', text: has('claude') && free ? 'Claude Code with MacSec’s skills, through Free LLM API: your free keys (Google AI Studio, Groq, NVIDIA, OpenRouter and more) behind one address. The code goes to the provider your chain picks.' : !has('claude') ? 'Needs Claude Code: set it up on Tools.' : 'Connect Free LLM API on Tools first.', ok: has('claude') && free },
    { id: 'gemini', icon: <Bot size={18} />, title: 'Gemini CLI', text: has('gemini') ? 'Google’s agent, in read-only plan mode, with MacSec’s review method.' : 'Not installed: npm install -g @google/gemini-cli', ok: has('gemini') },
    { id: 'codex', icon: <Bot size={18} />, title: 'Codex', text: has('codex') ? 'OpenAI’s agent, read-only.' : 'Not installed: set it up on Tools.', ok: has('codex') },
    { id: 'model', icon: <Cpu size={18} />, title: model ? model.split('/').pop()! : 'Your model', text: model ? 'LM Studio on this Mac: reads the riskiest files and every scanner result.' : 'Choose a model on Tools first.', ok: !!model },
    { id: 'none', icon: <Layers size={18} />, title: 'Scanners only', text: 'No AI. Findings still come with their code and fixes.', ok: true }
  ]
  return (
    <div className="choices" role="radiogroup" aria-label="AI reviewer">
      {list.map((r) => (
        <button key={r.id} className="choice" role="radio" aria-checked={value === r.id} disabled={!r.ok} onClick={() => onChange(r.id)} title={!r.ok ? 'Set it up on the Tools page' : undefined}>
          <span className="ci" style={{ ['--g' as string]: G[r.id] }}>
            {r.icon}
          </span>
          <strong>{r.title}</strong>
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
