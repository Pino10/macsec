import { useEffect, useState } from 'react'
import { LeakKit } from '../components/LeakKit'
import { AuditFlow, type AuditKind } from './Audits'
import { FileSearch, Gauge, Microscope, Radar, Zap } from 'lucide-react'
import type { ReviewDepth, ReviewFocus, Reviewer } from '@shared/types'
import { useApp, type PresetSource } from '../store'
import { FlowStep, PageHead, Seg } from '../ui'
import SourcePicker, { sourceName } from '../components/SourcePicker'
import ReviewerChoice from '../components/ReviewerChoice'
import SkillPicker from '../components/SkillPicker'

const DEPTHS: { id: ReviewDepth; icon: React.ReactNode; title: string; text: string }[] = [
  { id: 'quick', icon: <Zap size={18} />, title: 'Quick', text: 'Core Semgrep rules, keys in files, known flaws in packages. A few minutes.' },
  { id: 'standard', icon: <Gauge size={18} />, title: 'Standard', text: 'Adds language rule sets, Bearer’s data-flow checks, TruffleHog and Trivy.' },
  { id: 'deep', icon: <Microscope size={18} />, title: 'Deep', text: 'Everything, the whole Git history and the full audit rules. The AI follows every entry point.' }
]

export default function CodeReview(): React.JSX.Element {
  const { preset, setPreset, settings, act, busy, showSession, tools, setPage } = useApp()
  const api = window.macsec
  const [source, setSource] = useState<PresetSource | null>(preset)
  const [reviewer, setReviewer] = useState<Reviewer>(settings?.reviewer ?? 'claude')
  const [depth, setDepth] = useState<ReviewDepth>('standard')
  const [focus, setFocus] = useState<ReviewFocus>('security')
  const [keep, setKeep] = useState(false)
  const [mode, setMode] = useState<'project' | 'changes' | 'full'>('project')
  const [skills, setSkills] = useState<string[] | undefined>(undefined)

  useEffect(() => {
    if (preset) {
      setSource(preset)
      setPreset(null)
    }
  }, [preset, setPreset])

  const missing = tools.filter((t) => !t.installed && ['code', 'secrets', 'deps'].includes(t.category)).length
  const remote = source && source.kind !== 'local'

  return (
    <>
      <PageHead title="Code review" desc="Every free scanner that fits your code, then an AI reviewer that checks their findings and looks for what scanners miss: broken access checks, logic flaws, unsafe flows across files." />

      <div className="mode-pick">
        <Seg
          label="What to review"
          value={mode}
          onChange={setMode}
          options={[
            ['project', 'Whole project'],
            ['changes', 'Just my changes'],
            ['full', 'Code and its live site']
          ]}
        />
        <span className="hint">
          {mode === 'project' ? 'Every file, every scanner, then the AI reviewer.' : mode === 'changes' ? 'Only what changed on the current Git branch, with Claude Code’s own /security-review. Good before you merge.' : 'A code review and a web scan of the same project, joined in one AI report.'}
        </span>
      </div>

      {mode !== 'project' ? (
        <AuditFlow kinds={mode === 'changes' ? CHANGES : FULL} start="Start review" />
      ) : (
      <>

      {missing > 0 && (
        <div className="notice">
          <span className="grow">
            {missing} code scanner{missing === 1 ? ' is' : 's are'} not installed. The review installs what it needs as it goes, or you can{' '}
            <button className="link" onClick={() => setPage('tools')}>
              install them all now
            </button>
            .
          </span>
        </div>
      )}

      <div className="flow">
        <FlowStep n={1} title="What to review" help="A project in your www folder, a GitHub repository or an Azure DevOps repository." state={source ? 'done' : 'current'}>
          {source ? (
            <div className="pick-list" style={{ maxHeight: 'none' }}>
              <div className="pick-item" aria-selected style={{ cursor: 'default' }}>
                <FileSearch size={18} style={{ color: 'var(--ion)' }} />
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
        </FlowStep>

        <FlowStep n={2} title="Who reads the results" help="The scanners always run first. The AI then reads the code and every scanner result, decides what is real, and writes the report." state={source ? 'current' : 'todo'}>
          <ReviewerChoice value={reviewer} onChange={setReviewer} what="code" />
          {reviewer.startsWith('claude') && <SkillPicker site={source?.kind === 'local' ? source.path : null} reviewer={reviewer} onChange={setSkills} />}
        </FlowStep>

        <FlowStep n={3} title="How deep" state={source ? 'current' : 'todo'}>
          <div className="choices" role="radiogroup" aria-label="Depth">
            {DEPTHS.map((d) => (
              <button key={d.id} className="choice" role="radio" aria-checked={depth === d.id} onClick={() => setDepth(d.id)}>
                <span className="ci">{d.icon}</span>
                <strong>{d.title}</strong>
                <span>{d.text}</span>
              </button>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 18, alignItems: 'center', flexWrap: 'wrap' }}>
            <Seg<ReviewFocus>
              label="Look for"
              value={focus}
              onChange={setFocus}
              options={[
                ['security', 'Security'],
                ['bugs', 'Bugs'],
                ['all', 'Both']
              ]}
            />
            {remote && (
              <label className="check">
                <input type="checkbox" checked={keep} onChange={(e) => setKeep(e.target.checked)} /> Keep the downloaded code to fix it here
              </label>
            )}
          </div>
        </FlowStep>

        <div className="flow-go glass">
          <span className="hint grow">
            {!source ? 'Choose what to review to begin.' : remote ? (keep ? 'A private copy is downloaded and kept until you remove it.' : 'A private copy is downloaded and deleted when the review ends. The report keeps the code it quotes.') : 'Read in place. Nothing in your project changes.'}
          </span>
          <button
            className="btn btn-primary btn-lg"
            disabled={!source || busy.has('review')}
            onClick={async () => {
              if (!source) return
              const s = await act('review', () =>
                api.invoke('review:start', {
                  source: source.kind === 'local' ? { kind: 'local', path: source.path } : source.kind === 'github' ? { kind: 'github', repo: source.repo } : { kind: 'azure', url: source.url },
                  reviewer,
                  depth,
                  focus,
                  keepCode: keep,
                  skills: reviewer.startsWith('claude') ? skills : undefined
                })
              )
              if (s) showSession(s.id)
            }}
          >
            <Radar size={17} /> Start review
          </button>
        </div>
      </div>
      </>
      )}
      <LeakKit />
    </>
  )
}
const CHANGES: AuditKind[] = ['changes']
const FULL: AuditKind[] = ['full']
