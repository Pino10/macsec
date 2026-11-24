/**
 * Running an approved plan. This is the only place a controlled proof is executed, and it is
 * deliberately boring:
 *
 *   1. The phrase EXPLOIT <host> must be typed.
 *   2. The engagement must be live, cover the host and allow every goal.
 *   3. Only the steps the person ticked run, and a write step also needs the leftover acknowledgement.
 *   4. Steps run in order, one at a time. When every goal is proven, the run stops there.
 *   5. Every request is logged. Writes clean up, or are listed as leftovers with a way to remove them.
 */
import { randomBytes } from 'crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import type { Engagement, ImpactClass, ImpactPlan, ImpactRun, ImpactStepResult, PlannedStep } from '../../shared/impact'
import { dirs } from '../paths'
import { engagementProblem, engagementUsage, hostKey } from '../engagement'
import { NetGuard } from '../netguard'
import { ValidationError, phraseMatches } from '../validate'
import { ImpactClient, ImpactRefused, clearStop, isStopped } from './client'
import { RUNNERS } from './actions'

export interface CampaignInput {
  plan: ImpactPlan
  engagement: Engagement
  approved: string[]
  phrase: string
  acceptLeftovers: boolean
  fetchImpl?: typeof fetch
  delayMs?: number
  guard?: NetGuard | false
  now?: () => number
  cancelled?: () => boolean
  onStep?: (r: ImpactStepResult) => void
  onLine?: (line: string) => void
}

const planDir = (): string => join(dirs.root(), 'impact-plans')
const runDir = (): string => join(dirs.root(), 'impact-runs')
const safeDir = (d: string): string => {
  mkdirSync(d, { recursive: true, mode: 0o700 })
  return d
}
const idSafe = (id: string): boolean => /^[a-z0-9-]{8,64}$/.test(id)

export function savePlan(plan: ImpactPlan): ImpactPlan {
  safeDir(planDir())
  writeFileSync(join(planDir(), `${plan.id}.json`), JSON.stringify(plan, null, 2), { mode: 0o600 })
  return plan
}

export function loadPlan(id: string): ImpactPlan {
  if (!idSafe(id)) throw new ValidationError('That plan is not on this Mac.')
  try {
    return JSON.parse(readFileSync(join(planDir(), `${id}.json`), 'utf8')) as ImpactPlan
  } catch {
    throw new ValidationError('That plan is not on this Mac any more. Make a new one.')
  }
}

export function saveRun(run: ImpactRun): ImpactRun {
  safeDir(runDir())
  writeFileSync(join(runDir(), `${run.id}.json`), JSON.stringify(run, null, 2), { mode: 0o600 })
  return run
}

export function listRuns(limit = 20): ImpactRun[] {
  const dir = runDir()
  if (!existsSync(dir)) return []
  return readdirSync(dir)
    .filter((f) => idSafe(f.replace(/\.json$/, '')))
    .map((f) => {
      try {
        return JSON.parse(readFileSync(join(dir, f), 'utf8')) as ImpactRun
      } catch {
        return null
      }
    })
    .filter((r): r is ImpactRun => !!r)
    .sort((a, b) => b.startedAt.localeCompare(a.startedAt))
    .slice(0, limit)
}

/** Everything that must be true before the first request. Returns a sentence, or null when it may run. */
export function runProblem(input: Pick<CampaignInput, 'plan' | 'engagement' | 'approved' | 'phrase' | 'acceptLeftovers'>, now = Date.now()): string | null {
  const { plan, engagement, approved, phrase, acceptLeftovers } = input
  const host = hostKey(plan.target)
  if (!phraseMatches(phrase, host)) return `Type the phrase exactly: EXPLOIT ${host}`
  if (plan.engagementId !== engagement.id) return 'That plan was made under a different engagement. Make the plan again.'
  const bad = engagementProblem(engagement, host, plan.goal, now)
  if (bad) return bad
  const ids = new Set(plan.steps.map((s) => s.id))
  const chosen = [...new Set(approved)].filter((id) => ids.has(id))
  if (!chosen.length) return 'Tick at least one step to run.'
  const writeSteps = plan.steps.filter((s) => chosen.includes(s.id) && s.write)
  if (writeSteps.length && !engagement.allowed.includes('integrity')) return 'A ticked step can change data, and the authority does not allow integrity. Untick it, or write a new engagement.'
  if (writeSteps.length && !acceptLeftovers) return 'One of the steps you ticked can leave a file behind. Confirm that you accept that first.'
  const remainingWrites = engagement.caps.writes - engagement.used.writes
  if (writeSteps.length > remainingWrites) return `This engagement has ${remainingWrites} write${remainingWrites === 1 ? '' : 's'} left, and ${writeSteps.length} write step${writeSteps.length === 1 ? ' is' : 's are'} ticked.`
  const remainingRequests = engagement.caps.requests - engagement.used.requests
  if (remainingRequests < 1) return 'This engagement has no requests left.'
  return null
}

const newRunId = (now: number): string => `run-${now.toString(36)}-${randomBytes(3).toString('hex')}`

export async function runCampaign(input: CampaignInput): Promise<ImpactRun> {
  const problem = runProblem(input, input.now?.() ?? Date.now())
  if (problem) throw new ValidationError(problem)
  clearStop()
  const startedAt = new Date(input.now?.() ?? Date.now()).toISOString()
  const t0 = input.now?.() ?? Date.now()
  const host = hostKey(input.plan.target)
  const origin = new URL(input.plan.target).origin
  // The stored runs are the truth about what was already spent, not the object the window holds.
  const used = engagementUsage(input.engagement.id)
  const remaining = {
    requests: input.engagement.caps.requests - used.requests,
    writes: input.engagement.caps.writes - used.writes
  }
  const client = new ImpactClient({
    engagement: input.engagement,
    budget: remaining,
    origin,
    allowWrites: input.engagement.allowed.includes('integrity'),
    ...(input.fetchImpl ? { fetchImpl: input.fetchImpl } : {}),
    ...(input.guard !== undefined ? { guard: input.guard } : {}),
    delayMs: input.delayMs ?? 250,
    ...(input.cancelled ? { cancelled: input.cancelled } : {}),
    ...(input.now ? { now: input.now } : {})
  })
  const chosen = new Set(input.approved)
  const steps = input.plan.steps.filter((s) => chosen.has(s.id))
  const provenSteps = new Set<string>()
  const proven = new Set<ImpactClass>()
  const results: ImpactStepResult[] = []
  const leftover: ImpactRun['leftover'] = []
  let stopped = ''
  let failures = 0
  const deadline = t0 + input.plan.caps.minutes * 60_000
  const line = (text: string): void => input.onLine?.(text)

  const skipped = (step: PlannedStep, why: string): ImpactStepResult => ({
    step: step.id,
    action: step.action,
    aims: step.aims,
    status: 'skipped',
    title: step.why,
    detail: why,
    ms: 0
  })

  for (const step of steps) {
    if (proven.size === input.plan.goal.length && input.plan.goal.every((g) => proven.has(g))) {
      stopped = `Every goal was proven (${input.plan.goal.join(', ')}), so the run stopped there.`
      break
    }
    if (isStopped() || input.cancelled?.()) {
      stopped = 'Stopped by you.'
      break
    }
    if ((input.now?.() ?? Date.now()) > deadline) {
      stopped = `The ${input.plan.caps.minutes} minute limit was reached.`
      break
    }
    const missing = (step.after ?? []).filter((id) => !provenSteps.has(id))
    if (missing.length) {
      const r = skipped(step, `It chains from ${missing.join(', ')}, which is not proven, so it was not sent.`)
      results.push(r)
      input.onStep?.(r)
      continue
    }
    line(`${step.action}: ${step.why}`)
    const t = input.now?.() ?? Date.now()
    let result: ImpactStepResult
    try {
      const runner = RUNNERS[step.action]
      if (!runner) throw new ImpactRefused(`No runner for ${step.action}.`)
      const out = await runner({ client, step, line })
      result = { step: step.id, action: step.action, aims: step.aims, status: out.status, title: out.title, detail: out.detail, ms: (input.now?.() ?? Date.now()) - t, ...(out.evidence ? { evidence: out.evidence } : {}), ...(out.cleanup ? { cleanup: out.cleanup } : {}) }
      if (out.leftover) leftover.push(out.leftover)
    } catch (e) {
      const why = (e as Error).message
      result = {
        step: step.id,
        action: step.action,
        aims: step.aims,
        status: client.stopped ? 'failed' : e instanceof ImpactRefused ? 'failed' : 'failed',
        title: step.why,
        detail: why.slice(0, 400),
        ms: (input.now?.() ?? Date.now()) - t
      }
      failures++
      if (client.stopped) {
        results.push(result)
        input.onStep?.(result)
        stopped = client.stopped
        break
      }
      if (failures >= 3) {
        results.push(result)
        input.onStep?.(result)
        stopped = 'Three steps in a row could not run, so the run stopped.'
        break
      }
    }
    results.push(result)
    input.onStep?.(result)
    line(`${step.id}: ${result.status}. ${result.detail.slice(0, 160)}`)
    if (result.status === 'proven') {
      provenSteps.add(step.id)
      proven.add(step.aims)
      failures = 0
    } else if (result.status === 'failed') failures++
  }

  if (!stopped) {
    if (isStopped()) stopped = 'Stopped by you.'
    else if (input.plan.goal.every((g) => proven.has(g))) stopped = 'Every goal was proven.'
    else stopped = 'Every approved step was run. Nothing more was sent.'
  }

  const run: ImpactRun = {
    id: newRunId(t0),
    planId: input.plan.id,
    engagementId: input.engagement.id,
    target: input.plan.target,
    startedAt,
    finishedAt: new Date(input.now?.() ?? Date.now()).toISOString(),
    goal: input.plan.goal,
    proven: [...proven],
    steps: results,
    leftover,
    stopped,
    requests: client.requests,
    writes: client.writes
  }
  saveRun(run)
  input.onLine?.(`run finished: ${run.stopped} ${run.requests} requests, ${run.proven.length} goal${run.proven.length === 1 ? '' : 's'} proven.`)
  return run
}

/** A one line summary for the UI and the report: which letters were proven. */
export function ciaLine(run: Pick<ImpactRun, 'goal' | 'proven'>): string {
  const mark = (g: ImpactClass): string => (run.proven.includes(g) ? 'proven' : 'not proven')
  return `Confidentiality ${mark('confidentiality')}, integrity ${mark('integrity')}, availability ${mark('availability')}, against a goal of ${run.goal.join(', ')}.`
}
