import { useEffect, useMemo, useState } from 'react'
import { BookOpen, ChevronDown, Clock, Sparkles } from 'lucide-react'
import type { SkillPlan } from '@shared/types'

const SPEED: Record<string, number> = { claude: 1, 'claude-free': 1.6, 'claude-local': 3, codex: 1.1, gemini: 1.1, coderabbit: 0.6, model: 2.5 }

/** A rough range in minutes (the same sum as seckit/skillplan's estimateMinutes). */
function estimate(files: number, skills: number, guides: number, reviewer: string): [number, number] {
  const m = (2 + files / 140 + skills * 0.3 + guides * 0.08) * (SPEED[reviewer] ?? 1.2)
  const lo = Math.max(2, Math.round(m * 0.8))
  return [lo, Math.max(lo + 1, Math.round(m * 1.4))]
}

const STACK_NAMES: Record<string, string> = {
  php: 'PHP', laravel: 'Laravel', wordpress: 'WordPress', symfony: 'Symfony', js: 'JavaScript', ts: 'TypeScript', react: 'React', vue: 'Vue', next: 'Next.js', 'node-api': 'Node API',
  electron: 'Electron', ai: 'AI features', python: 'Python', django: 'Django', go: 'Go', rust: 'Rust', c: 'C/C++', solidity: 'Solidity', android: 'Android', ios: 'iOS', docker: 'Docker',
  terraform: 'Infrastructure as code', gha: 'GitHub Actions', supabase: 'Supabase', firebase: 'Firebase', claude: 'Claude settings', mobile: 'Mobile'
}

/**
 * Which skills the reviewer loads. The ones that fit the project are on; switch any on or off,
 * and the estimate follows. Without changes, the review uses the recommended set.
 */
export default function SkillPicker({ site, reviewer, onChange }: { site: string | null; reviewer: string; onChange: (ids: string[] | undefined) => void }): React.JSX.Element | null {
  const [plan, setPlan] = useState<SkillPlan | null>(null)
  const [chosen, setChosen] = useState<Set<string>>(new Set())
  const [open, setOpen] = useState(false)
  const [custom, setCustom] = useState(false)
  useEffect(() => {
    void window.macsec.invoke('review:skill-plan', site).then((p) => {
      setPlan(p)
      setChosen(new Set(p.recommended))
      setCustom(false)
      onChange(undefined)
    })
    // onChange is stable enough; re-plan only when the project changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [site])
  const groups = useMemo(() => {
    const g = new Map<string, SkillPlan['items']>()
    for (const i of plan?.items ?? []) g.set(i.source, [...(g.get(i.source) ?? []), i])
    return [...g.entries()]
  }, [plan])
  if (!plan) return null
  const picked = plan.items.filter((i) => chosen.has(i.id))
  const guides = picked.reduce((n, i) => n + i.guides, 0)
  const [lo, hi] = estimate(plan.files, picked.length, guides, reviewer)
  const set = (next: Set<string>): void => {
    setChosen(next)
    setCustom(true)
    onChange([...next])
  }
  const toggle = (id: string): void => {
    const next = new Set(chosen)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    set(next)
  }
  return (
    <div className="skillpick">
      <button className="skillpick-head" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span className="skillpick-icon">
          <Sparkles size={15} />
        </span>
        <span className="skillpick-main">
          <strong>
            {picked.length} of {plan.items.length} skills{custom ? ', your choice' : ', recommended'}
            {guides > 0 && <small> · {guides} reference guides</small>}
          </strong>
          <span>{plan.stack.length ? `Picked for ${plan.stack.map((s) => STACK_NAMES[s] ?? s).join(', ')}.` : 'Picked for any web project.'} Switch any on or off.</span>
        </span>
        <span className="skillpick-time">
          <Clock size={13} /> About {lo} to {hi} min
        </span>
        <ChevronDown size={16} className="skillpick-chev" />
      </button>
      {open && (
        <div className="skillpick-body">
          <div className="skillpick-quick">
            <button className="btn btn-sm" onClick={() => set(new Set(plan.recommended))}>
              Recommended
            </button>
            <button className="btn btn-sm" onClick={() => set(new Set(plan.items.map((i) => i.id)))}>
              All
            </button>
            <button className="btn btn-sm btn-quiet" onClick={() => set(new Set())}>
              None
            </button>
            <span className="hint">More skills is not always better: each one costs the reviewer time and attention.</span>
          </div>
          {groups.map(([source, items]) => (
            <div key={source} className="skillpick-group">
              <div className="skillpick-source">
                {source} <span>{items.filter((i) => chosen.has(i.id)).length} of {items.length}</span>
              </div>
              <div className="skillpick-chips">
                {items.map((i) => (
                  <button key={i.id} className="skill-chip" aria-pressed={chosen.has(i.id)} title={i.about} onClick={() => toggle(i.id)}>
                    {i.name}
                    {i.guides > 0 && (
                      <span className="skill-guides">
                        <BookOpen size={11} /> {i.guides}
                      </span>
                    )}
                    {plan.recommended.includes(i.id) && <span className="skill-rec" aria-label="Recommended" />}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
