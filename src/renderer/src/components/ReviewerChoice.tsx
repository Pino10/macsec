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
  const list: { id: Reviewer; group: 'mac' | 'cloud' | 'none'; icon: React.ReactNode; title: string; short: string; long: string; ok: boolean }[] = [
    { id: 'claude-local', group: 'mac', icon: <Sparkles size={17} />, title: model ? `Claude Code on ${model.split('/').pop()}` : 'Claude Code on your model', short: 'Claude Code with your local model', long: has('claude') && model ? 'Claude Code with all its tools and MacSec’s skills, talking to your model in LM Studio (0.4.1 or newer). Nothing leaves this Mac.' : !has('claude') ? 'Needs Claude Code: set it up on Tools.' : 'Choose a model on Tools first.', ok: has('claude') && !!model },
    { id: 'model', group: 'mac', icon: <Cpu size={17} />, title: model ? model.split('/').pop()! : 'Your model', short: 'LM Studio on this Mac', long: model ? 'LM Studio on this Mac reads the riskiest files and every scanner result. Nothing leaves this Mac.' : 'Choose a model on Tools first.', ok: !!model },
    { id: 'claude', group: 'cloud', icon: <Sparkles size={17} />, title: 'Claude Code', short: 'Your Claude account', long: has('claude') ? (what === 'code' ? 'Reads the project and every scanner result, with MacSec’s security skills. Saved as your Claude Code session.' : 'Reads every finding and writes the report, with MacSec’s security skills.') : 'Needs its command line tool: set it up on Tools.', ok: has('claude') },
    { id: 'claude-free', group: 'cloud', icon: <Network size={17} />, title: 'Claude Code on Free LLM API', short: 'Your free provider keys', long: has('claude') && free ? 'Claude Code with MacSec’s skills, through Free LLM API: your free keys (Google AI Studio, Groq, NVIDIA, OpenRouter and more) behind one address. The findings go to the provider your chain picks.' : !has('claude') ? 'Needs Claude Code: set it up on Tools.' : 'Connect Free LLM API on Tools first.', ok: has('claude') && free },
    { id: 'gemini', group: 'cloud', icon: <Bot size={17} />, title: 'Gemini CLI', short: 'Google’s agent, read-only', long: has('gemini') ? 'Google’s agent, in read-only plan mode, with MacSec’s review method.' : 'Not installed: npm install -g @google/gemini-cli', ok: has('gemini') },
    { id: 'codex', group: 'cloud', icon: <Bot size={17} />, title: 'Codex', short: 'OpenAI’s agent, read-only', long: has('codex') ? 'OpenAI’s agent, read-only.' : 'Not installed: set it up on Tools.', ok: has('codex') },
    { id: 'none', group: 'none', icon: <Layers size={17} />, title: 'Scanners only', short: 'No AI. Fixes still come with each finding', long: 'No AI. Every finding still comes with its proof, its code and its fix, and web scans still get the test plan.', ok: true }
  ]
  // Only what is ready to use is offered. Anything else appears here by itself once it is set up on Tools.
  const ready = list.filter((r) => r.ok)
  const hidden = list.length - ready.length
  useEffect(() => {
    if (agents.length && !ready.some((r) => r.id === value)) onChange('none')
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agents, free, model])
  const groups: [typeof list[number]['group'], string][] = [['mac', 'On this Mac: nothing leaves it'], ['cloud', 'Cloud AI: the findings are sent to the provider'], ['none', 'No AI']]
  const chosen = ready.find((r) => r.id === value)
  return (
    <div className="choices tidy" role="radiogroup" aria-label="AI reviewer">
      {groups.map(([g, label]) => {
        const items = ready.filter((r) => r.group === g)
        if (!items.length) return null
        return (
          <div key={g} className="choice-group">
            <span className="choice-label">{label}</span>
            <div className="choice-row">
              {items.map((r) => (
                <button key={r.id} className="choice" role="radio" aria-checked={value === r.id} onClick={() => onChange(r.id)}>
                  <span className="ci" style={{ ['--g' as string]: G[r.id] }}>
                    {r.icon}
                  </span>
                  <strong>{r.title}</strong>
                  <span>{r.short}</span>
                </button>
              ))}
            </div>
          </div>
        )
      })}
      {chosen && <p className="hint choice-detail">{chosen.long}</p>}
      {hidden > 0 && (
        <p className="hint" style={{ margin: '2px 2px 0' }}>
          More AI options ({hidden}) appear here once they are set up.{' '}
          <a className="link" onClick={() => setPage('tools')}>
            Open Tools
          </a>
        </p>
      )}
    </div>
  )
}
