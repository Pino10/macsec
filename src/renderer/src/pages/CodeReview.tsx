import { useEffect, useState } from 'react'
import { Bot, Cpu, FileSearch, Gauge, Layers, Microscope, Radar, Sparkles, Zap } from 'lucide-react'
import type { AgentInfo, ReviewDepth, ReviewFocus, Reviewer } from '@shared/types'
import { useApp, type PresetSource } from '../store'
import { PageHead, Seg } from '../ui'
import SourcePicker, { sourceName } from '../components/SourcePicker'

const DEPTHS: { id: ReviewDepth; icon: React.ReactNode; title: string; text: string }[] = [
  { id: 'quick', icon: <Zap size={15} />, title: 'Quick', text: 'Core Semgrep rules, keys in files, known flaws in packages. A few minutes.' },
  { id: 'standard', icon: <Gauge size={15} />, title: 'Standard', text: 'Adds language rule sets, Bearer’s data-flow checks, TruffleHog and Trivy.' },
  { id: 'deep', icon: <Microscope size={15} />, title: 'Deep', text: 'Everything, plus the whole Git history and the full audit rules. The AI follows every entry point.' }
]

export default function CodeReview(): React.JSX.Element {
  const { preset, setPreset, settings, act, busy, showSession, tools, setPage } = useApp()
  const api = window.macsec
  const [source, setSource] = useState<PresetSource | null>(preset)
  const [reviewer, setReviewer] = useState<Reviewer>(settings?.reviewer ?? 'claude')
  const [depth, setDepth] = useState<ReviewDepth>('standard')
  const [focus, setFocus] = useState<ReviewFocus>('security')
  const [keep, setKeep] = useState(false)
  const [agents, setAgents] = useState<AgentInfo[]>([])

  useEffect(() => {
    void api.invoke('ai:agents').then(setAgents)
  }, [api])
  useEffect(() => {
    if (preset) {
      setSource(preset)
      setPreset(null)
    }
  }, [preset, setPreset])

  const has = (id: string): boolean => agents.find((a) => a.id === id)?.installed ?? false
  const model = settings?.llm.model
  const missing = tools.filter((t) => !t.installed && ['code', 'secrets', 'deps'].includes(t.category)).length
  const remote = source && source.kind !== 'local'

  const start = async (): Promise<void> => {
    if (!source) return
    const s = await act('review', () =>
      api.invoke('review:start', {
        source: source.kind === 'local' ? { kind: 'local', path: source.path } : source.kind === 'github' ? { kind: 'github', repo: source.repo } : { kind: 'azure', url: source.url },
        reviewer,
        depth,
        focus,
        keepCode: keep
      })
    )
    if (s) showSession(s.id)
  }

  const reviewers: { id: Reviewer; icon: React.ReactNode; title: string; text: string; ok: boolean }[] = [
    { id: 'claude', icon: <Sparkles size={15} />, title: 'Claude Code', text: has('claude') ? 'Reads the whole project, read-only.' : 'Not installed: set it up on Tools.', ok: has('claude') },
    { id: 'codex', icon: <Bot size={15} />, title: 'Codex', text: has('codex') ? 'OpenAI’s agent in a read-only sandbox.' : 'Not installed: set it up on Tools.', ok: has('codex') },
    { id: 'model', icon: <Cpu size={15} />, title: model ? model.split('/').pop()! : 'Your model', text: model ? 'LM Studio or your own server. Stays on this Mac.' : 'Pick a model on Tools first.', ok: !!model },
    { id: 'none', icon: <Layers size={15} />, title: 'Scanners only', text: 'No AI. Fast, and the findings still come with fixes.', ok: true }
  ]

  return (
    <>
      <PageHead title="Code review" desc="Every free scanner that fits your code, then an AI reviewer that checks their findings and hunts for what scanners miss. Each review is a session you can come back to." />

      {missing > 0 && (
        <div className="notice" style={{ marginBottom: 16 }}>
          <span>
            {missing} scanner{missing === 1 ? ' is' : 's are'} not installed yet. The review installs what it needs as it goes, or{' '}
            <button className="link" onClick={() => setPage('tools')}>
              install them all now
            </button>
            .
          </span>
        </div>
      )}

      <div className="ms-form glass">
        <div className="field">
          <span className="field-label">1. What to review</span>
          {source ? (
            <div className="pick-list" style={{ maxHeight: 'none' }}>
              <div className="pick-item" aria-selected style={{ cursor: 'default' }}>
                <FileSearch size={15} style={{ color: 'var(--accent-text)' }} />
                <span className="grow">
                  {sourceName(source)}
                  <span className="sub">{source.kind === 'local' ? source.path : source.kind === 'github' ? `github.com/${source.repo}` : source.url.replace(/^https:\/\/[^@/]+@/, 'https://')}</span>
                </span>
                <button className="btn btn-sm" onClick={() => setSource(null)}>
                  Change
                </button>
              </div>
            </div>
          ) : (
            <SourcePicker selected={source} onPick={setSource} />
          )}
        </div>

        <div className="field">
          <span className="field-label">2. Reviewer</span>
          <div className="choices" role="radiogroup" aria-label="Reviewer">
            {reviewers.map((r) => (
              <button key={r.id} className="choice" role="radio" aria-checked={reviewer === r.id} disabled={!r.ok} onClick={() => setReviewer(r.id)}>
                <strong>
                  {r.icon} {r.title}
                </strong>
                <span>{r.text}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="field">
          <span className="field-label">3. How deep</span>
          <div className="choices" role="radiogroup" aria-label="Depth">
            {DEPTHS.map((d) => (
              <button key={d.id} className="choice" role="radio" aria-checked={depth === d.id} onClick={() => setDepth(d.id)}>
                <strong>
                  {d.icon} {d.title}
                </strong>
                <span>{d.text}</span>
              </button>
            ))}
          </div>
        </div>

        <div style={{ display: 'flex', gap: 24, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div className="field">
            <span className="field-label">Look for</span>
            <Seg<ReviewFocus>
              label="Focus"
              value={focus}
              onChange={setFocus}
              options={[
                ['security', 'Security'],
                ['bugs', 'Bugs'],
                ['all', 'Everything']
              ]}
            />
          </div>
          {remote && (
            <label className="check" style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13, paddingBottom: 6 }}>
              <input type="checkbox" checked={keep} onChange={(e) => setKeep(e.target.checked)} />
              Keep the downloaded code afterwards, to fix it here
            </label>
          )}
          <span style={{ flex: 1 }} />
          <button className="btn btn-primary btn-lg" disabled={!source || busy.has('review') || !reviewers.find((r) => r.id === reviewer)?.ok} onClick={start}>
            <Radar size={15} /> Start review
          </button>
        </div>
        <div className="hint">
          {remote
            ? `MacSec downloads a private copy into this session${depth === 'deep' ? ' with its full history' : ''}. ${keep ? 'It stays until you remove it.' : 'It is deleted the moment the review ends; the report stays.'} Nothing is changed in your repository.`
            : 'Your project is read in place. Nothing in it is changed, and scanner caches stay in the MacSec folder.'}
        </div>
      </div>
    </>
  )
}
