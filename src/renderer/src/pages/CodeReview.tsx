import { useEffect, useState } from 'react'
import { LeakKit } from '../components/LeakKit'
import { FileSearch, Gauge, Microscope, Radar, ShieldQuestion, Zap } from 'lucide-react'
import type { DeepEngine, DeepReviewerKind, ReviewDepth, ReviewFocus, Reviewer } from '@shared/types'
import { useApp, type PresetSource } from '../store'
import { estimateReview, minutesText, tokensText } from '@shared/estimate'
import { FlowStep, PageHead, Seg } from '../ui'
import SourcePicker, { sourceName } from '../components/SourcePicker'
import ReviewerChoice from '../components/ReviewerChoice'
import ProfileBar from '../components/ProfileBar'
import SkillPicker from '../components/SkillPicker'
import DeepAudit from '../components/DeepAudit'

const DEPTHS: { id: ReviewDepth; icon: React.ReactNode; title: string; text: string }[] = [
  { id: 'quick', icon: <Zap size={18} />, title: 'Quick', text: 'Core Semgrep rules, keys in files, known flaws in packages. A few minutes.' },
  { id: 'standard', icon: <Gauge size={18} />, title: 'Standard', text: 'Adds language rule sets, Bearer’s data-flow checks, TruffleHog and Trivy.' },
  { id: 'deep', icon: <Microscope size={18} />, title: 'Deep', text: 'Everything, the whole Git history and the full audit rules. The AI follows every entry point.' }
]

const TOOLS: { id: string; name: string }[] = [
  { id: 'semgrep', name: 'Semgrep' },
  { id: 'bearer', name: 'Bearer' },
  { id: 'bandit', name: 'Bandit' },
  { id: 'gosec', name: 'gosec' },
  { id: 'zizmor', name: 'zizmor' },
  { id: 'hadolint', name: 'Hadolint' },
  { id: 'checkov', name: 'Checkov' },
  { id: 'syft', name: 'Syft' },
  { id: 'grype', name: 'Grype' },
  { id: 'gitleaks', name: 'Gitleaks' },
  { id: 'trufflehog', name: 'TruffleHog' },
  { id: 'osv-scanner', name: 'OSV-Scanner' },
  { id: 'trivy', name: 'Trivy' }
]

export default function CodeReview(): React.JSX.Element {
  const { preset, setPreset, settings, act, busy, showSession, tools, setPage } = useApp()
  const api = window.macsec
  const [source, setSource] = useState<PresetSource | null>(preset)
  const [reviewer, setReviewer] = useState<Reviewer>(settings?.reviewer ?? 'claude')
  const [depth, setDepth] = useState<ReviewDepth>('standard')
  const [focus, setFocus] = useState<ReviewFocus>('security')
  const [keep, setKeep] = useState(false)
  const [skills, setSkills] = useState<string[] | undefined>(undefined)
  const [skip, setSkip] = useState<string[]>([])
  const [skipHistory, setSkipHistory] = useState(false)
  const [deep, setDeep] = useState<DeepEngine | null>(null)
  const [deepAi, setDeepAi] = useState<DeepReviewerKind>('claude')
  const localPath = source?.kind === 'local' ? source.path : null
  const desktopHandoff = !!deep && deepAi === 'claude-desktop'

  useEffect(() => {
    if (preset) {
      setSource(preset)
      setPreset(null)
    }
  }, [preset, setPreset])

  const missing = tools.filter((t) => !t.installed && ['code', 'secrets', 'deps'].includes(t.category)).length
  const remote = source && source.kind !== 'local'
  const applyProfile = (o: Record<string, unknown>): void => {
    if (o.depth === 'quick' || o.depth === 'standard' || o.depth === 'deep') setDepth(o.depth)
    if (o.focus === 'security' || o.focus === 'bugs' || o.focus === 'all') setFocus(o.focus)
    if (o.reviewer === 'none' || o.reviewer === 'claude' || o.reviewer === 'claude-local' || o.reviewer === 'claude-free' || o.reviewer === 'codex' || o.reviewer === 'gemini' || o.reviewer === 'model') setReviewer(o.reviewer)
    if (Array.isArray(o.skip)) setSkip(o.skip.filter((x): x is string => typeof x === 'string'))
    setSkipHistory(o.skipHistory === true)
  }
  const profileOptions = { depth, focus, reviewer, skip, skipHistory }

  return (
    <>
      <PageHead title="Code review" desc="Every free scanner that fits your code, then an AI reviewer that checks their findings and looks for what scanners miss: broken access checks, logic flaws, unsafe flows across files." />

      <div className="mode-pick">
        <span className="hint grow">
          Every file, every scanner that fits, then the AI reviewer. Want only your branch’s changes, or the code and its live site in one test? Those are special audits.
        </span>
        <button className="btn btn-sm" onClick={() => setPage('audit')}>
          <ShieldQuestion size={14} /> Open special audits
        </button>
      </div>

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

      <ProfileBar kind="review" current={profileOptions} onApply={applyProfile} />
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
          {!deep && <ReviewerChoice value={reviewer} onChange={setReviewer} what="code" />}
          {!deep && reviewer.startsWith('claude') && <SkillPicker site={source?.kind === 'local' ? source.path : null} reviewer={reviewer} onChange={setSkills} />}
          <details className="advanced">
            <summary>Advanced: a published deep audit instead of the standard review</summary>
            <p className="hint">
              Cloudflare’s and Anthropic’s own security reviews, using the AI you pick there. They replace the reviewer above, take much longer, and are the most thorough option.
            </p>
            <DeepAudit engine={deep} onEngine={setDeep} ai={deepAi} onAi={setDeepAi} projectPath={localPath} />
          </details>
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
          {!deep && (
            <p className="hint">
              The AI reads about {tokensText(estimateReview({ depth, reviewer }).tokens)} tokens: roughly {minutesText(estimateReview({ depth, reviewer }).minutes)} in all. {estimateReview({ depth, reviewer }).note}
            </p>
          )}
          <details className="advanced">
            <summary>Scanners and Git history</summary>
            <p className="hint">Turn off what you do not need. A quick review of a huge repository is often faster without the history or the dependency databases.</p>
            <div className="scan-toggles">
              {TOOLS.map((t) => (
                <label key={t.id} className="check">
                  <input
                    type="checkbox"
                    checked={!skip.includes(t.id)}
                    onChange={(e) => setSkip((prev) => (e.target.checked ? prev.filter((x) => x !== t.id) : [...prev, t.id]))}
                  />
                  {t.name}
                </label>
              ))}
            </div>
            {depth === 'deep' && (
              <label className="check">
                <input type="checkbox" checked={skipHistory} onChange={(e) => setSkipHistory(e.target.checked)} /> Skip the Git history (keys in old commits are not looked for)
              </label>
            )}
          </details>
        </FlowStep>

        <div className="flow-go glass">
          <span className="hint grow">
            {!source ? 'Choose what to review to begin.' : remote ? (keep ? 'A private copy is downloaded and kept until you remove it.' : 'A private copy is downloaded and deleted when the review ends. The report keeps the code it quotes.') : 'Read in place. Nothing in your project changes.'}
          </span>
          <button
            className="btn btn-primary btn-lg"
            disabled={!source || busy.has('review') || (desktopHandoff && !localPath)}
            onClick={async () => {
              if (!source) return
              if (desktopHandoff && localPath) {
                await act('review', () => api.invoke('review:deep-handoff', { engine: deep!, path: localPath }))
                return
              }
              const s = await act('review', () =>
                api.invoke('review:start', {
                  source: source.kind === 'local' ? { kind: 'local', path: source.path } : source.kind === 'github' ? { kind: 'github', repo: source.repo } : { kind: 'azure', url: source.url },
                  reviewer: deep ? (deepAi as Reviewer) : reviewer,
                  ...(deep ? { deep: { engine: deep } } : {}),
                  depth,
                  focus,
                  keepCode: keep,
                  skip,
                  ...(skipHistory ? { skipHistory: true } : {}),
                  skills: !deep && reviewer.startsWith('claude') ? skills : undefined
                })
              )
              if (s) showSession(s.id)
            }}
          >
            <Radar size={17} /> {desktopHandoff ? 'Copy the request and open Claude' : deep ? 'Start deep audit' : 'Start review'}
          </button>
        </div>
      </div>
      <LeakKit />
    </>
  )
}
