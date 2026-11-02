import { useEffect, useState } from 'react'
import { FileSearch, Gauge, Microscope, Radar, Zap } from 'lucide-react'
import type { ReviewDepth, ReviewFocus, Reviewer } from '@shared/types'
import { useApp, type PresetSource } from '../store'
import { PageHead, Seg } from '../ui'
import SourcePicker, { sourceName } from '../components/SourcePicker'
import ReviewerChoice from '../components/ReviewerChoice'

const DEPTHS: { id: ReviewDepth; icon: React.ReactNode; title: string; text: string }[] = [
  { id: 'quick', icon: <Zap size={16} />, title: 'Quick', text: 'Core Semgrep rules, keys in files, known flaws in packages. A few minutes.' },
  { id: 'standard', icon: <Gauge size={16} />, title: 'Standard', text: 'Adds language rule sets, Bearer’s data-flow checks, TruffleHog and Trivy.' },
  { id: 'deep', icon: <Microscope size={16} />, title: 'Deep', text: 'Everything, the whole Git history and the full audit rules. The AI follows every entry point.' }
]

export default function CodeReview(): React.JSX.Element {
  const { preset, setPreset, settings, act, busy, showSession, tools, setPage } = useApp()
  const api = window.macsec
  const [source, setSource] = useState<PresetSource | null>(preset)
  const [reviewer, setReviewer] = useState<Reviewer>(settings?.reviewer ?? 'claude')
  const [depth, setDepth] = useState<ReviewDepth>('standard')
  const [focus, setFocus] = useState<ReviewFocus>('security')
  const [keep, setKeep] = useState(false)

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

      <div className="setup glass">
        <div className="field">
          <span className="field-label">What to review</span>
          {source ? (
            <div className="pick-list" style={{ maxHeight: 'none' }}>
              <div className="pick-item" aria-selected style={{ cursor: 'default' }}>
                <FileSearch size={17} style={{ color: 'var(--ion)' }} />
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
          <span className="field-label">AI reviewer</span>
          <ReviewerChoice value={reviewer} onChange={setReviewer} what="code" />
        </div>

        <div className="field">
          <span className="field-label">How deep</span>
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

        <div className="go-bar">
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
          {remote ? (
            <label className="check">
              <input type="checkbox" checked={keep} onChange={(e) => setKeep(e.target.checked)} /> Keep the downloaded code to fix it
            </label>
          ) : null}
          <span className="hint grow" style={{ textAlign: 'right' }}>
            {remote ? (keep ? 'The private copy stays until you remove it.' : 'The private copy is deleted when the review ends.') : source ? 'Read in place. Nothing in your project changes.' : ''}
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
                  keepCode: keep
                })
              )
              if (s) showSession(s.id)
            }}
          >
            <Radar size={16} /> Start review
          </button>
        </div>
      </div>
    </>
  )
}
