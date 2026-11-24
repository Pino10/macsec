/**
 * Planning a controlled campaign, cheaply.
 *
 * Rules first: the findings a scan already produced are enough to propose most steps, with no AI
 * call at all. The AI planner is optional, sees only a short digest of findings (never code), is
 * called once, and its answer is only ever a list of catalogue ids and addresses. MacSec validates
 * every field afterwards, so a model cannot invent a payload or a host.
 */
import type { Finding } from '../../shared/types'
import type { EngagementCaps, ImpactActionId, ImpactClass, ImpactMethod, PlannedStep } from '../../shared/impact'
import { actionInfo, actionIds } from './catalog'
import { previewOf } from './actions'
import { validUrl } from '../validate'

export interface PlanRulesInput {
  target: string
  goal: ImpactClass[]
  findings: Finding[]
  caps: EngagementCaps
}

export interface PlanDraft {
  target: string
  goal: ImpactClass[]
  steps: PlannedStep[]
  notes: string[]
}

const paramOf = (url: string): string | null => {
  try {
    const u = new URL(url)
    for (const k of u.searchParams.keys()) if (/^[A-Za-z][\w.[\]-]{0,60}$/.test(k)) return k
    return null
  } catch {
    return null
  }
}

const pageOf = (url: string): string => {
  try {
    const u = new URL(url)
    return `${u.origin}${u.pathname}`
  } catch {
    return url
  }
}

const isOpen = (f: Finding): boolean => f.verdict !== 'false-positive' && !f.triage && !!f.url

/** Finds worth a proof, most severe first, one per page and kind of proof. */
export function candidateFindings(findings: Finding[], target: string, limit = 8): Finding[] {
  const origin = (() => {
    try {
      return new URL(target).origin
    } catch {
      return ''
    }
  })()
  const weight: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
  return findings
    .filter((f) => isOpen(f) && !!f.url && (() => {
      try {
        return new URL(f.url!).origin === origin
      } catch {
        return false
      }
    })())
    .sort((a, b) => (weight[b.severity] ?? 0) - (weight[a.severity] ?? 0))
    .slice(0, limit)
}

interface Rule {
  re: RegExp
  action: ImpactActionId
  aims: ImpactClass
  why: string
}

const RULES: Rule[] = [
  { re: /path traversal|directory traversal|lfi|local file inclusion|file read|arbitrary file/i, action: 'traversal-read', aims: 'confidentiality', why: 'The scan found a parameter that looks like it reaches the file system. Ask it for a system file.' },
  { re: /template injection|ssti|server-side template|engine evaluates|calculates an expression/i, action: 'ssti-marker', aims: 'integrity', why: 'The scan says the server evaluates input as a template. Show the smallest calculation it will do.' },
  { re: /upload|attachment|avatar|profile picture|media/i, action: 'upload-write', aims: 'integrity', why: 'The scan found an upload. Write one harmless text file and read it back.' },
  { re: /expensive|slow|timeout|rate limit|unbounded|export|report|generate|pdf render/i, action: 'availability-probe', aims: 'availability', why: 'The scan flagged a costly operation. Time one request against its baseline, without flooding it.' }
]

export function planFromRules(input: PlanRulesInput): PlanDraft {
  const { target, goal, findings, caps } = input
  const origin = new URL(target).origin
  const steps: PlannedStep[] = []
  const notes: string[] = []
  const seen = new Set<string>()
  const push = (s: Omit<PlannedStep, 'id' | 'preview'>): PlannedStep | null => {
    if (steps.length >= 6) return null
    const key = `${s.action}|${s.url}|${s.param ?? ''}`
    if (seen.has(key)) return null
    seen.add(key)
    const step: PlannedStep = { ...s, id: `s${steps.length + 1}`, preview: [] }
    step.preview = previewOf(step)
    steps.push(step)
    return step
  }

  const candidates = candidateFindings(findings, target, 12)
  for (const f of candidates) {
    if (steps.length >= 6) break
    const url = f.url!
    const param = paramOf(url)
    const rule = RULES.find((r) => r.re.test(`${f.title} ${f.description ?? ''} ${f.aiNote ?? ''}`))
    if (!rule || !goal.includes(rule.aims)) continue
    if (rule.action === 'upload-write') {
      if (!param && !/upload|file|media|avatar/i.test(url)) continue
      push({
        action: 'upload-write',
        aims: 'integrity',
        url,
        param: 'file',
        verifyUrl: '',
        from: f.id,
        why: rule.why,
        write: true,
        undo: 'Delete the one file that is written, from the uploads folder or media library.',
        after: []
      })
      notes.push('For the upload proof, fill in the address the file can be read back from (put {name} where the file name goes). Without it the upload cannot be proven.')
      continue
    }
    if (rule.action === 'availability-probe') {
      push({ action: rule.action, aims: rule.aims, url: pageOf(url), from: f.id, why: rule.why, write: false, after: [] })
      continue
    }
    if (!param) continue
    const page = pageOf(url)
    push({ action: rule.action, aims: rule.aims, url: page, param, from: f.id, why: rule.why, write: false, after: [] })
  }

  // Escalation: after a read proof on a page, the next rung is a write, and only the person can
  // paste that request. The plan says so instead of inventing one.
  const readStep = steps.find((s) => s.aims === 'confidentiality')
  if (readStep && goal.includes('integrity')) {
    notes.push(`After the read on ${pageOf(readStep.url)} is proven, the next rung is a write on the same page. Use the replay proof and paste the request you want to send, with the undo step written down. MacSec does not invent a write.`)
  }
  if (!steps.length) {
    notes.push(
      'No finding on this target matches a built-in proof. That is not a failure: the replay proof takes any request you paste (from Burp, or copied from a finding), sends it once and looks for the string you name.'
    )
  }
  if (caps.writes === 0 && goal.includes('integrity')) notes.push('The engagement has no writes, so integrity can only be shown by a read that proves it (for example template evaluation). Raise the write cap in the engagement to write one file.')
  return { target, goal, steps, notes }
}

// ---------------------------------------------------------------- The optional AI planner

export interface AiPlanInput extends PlanRulesInput {
  ask: (prompt: string) => Promise<string>
}

/** The prompt is small on purpose: findings only, never source code, one call, hard limits. */
export function aiPlannerPrompt(input: PlanRulesInput): string {
  const candidates = candidateFindings(input.findings, input.target, 10).map((f) => {
    const param = f.url ? paramOf(f.url) : null
    return `- id=${f.id} [${f.severity}] ${f.title.slice(0, 140)} | ${(f.url ?? '').slice(0, 160)} | param=${param ?? 'none'} | ${f.confidence ?? 'unconfirmed'}`
  })
  const menu = actionIds()
    .map((id) => {
      const a = actionInfo(id)
      return `- ${id} (${a.impact.join('/')}): ${a.what} Needs: ${a.needs.join(', ')}. Sends: ${a.sends}`
    })
    .join('\n')
  return `You plan controlled proofs on a website the person is engaged to test. You do not send anything and you do not write findings. You choose steps from a fixed menu, and MacSec checks and runs them.

Target: ${input.target}
Goal: prove ${input.goal.join(', ')}. Stop at the first proof of each.
Caps for this engagement: ${input.caps.requests} requests, ${input.caps.writes} writes, ${input.caps.minutes} minutes.

Menu:
${menu}

Findings the scan already made (the only things you know):
${candidates.join('\n') || '(none)'}

Rules:
- Every url must be on the target's own origin. Use the page the finding is on, not a new guess.
- Only propose a step the evidence supports. If nothing supports a proof, return an empty list.
- At most 5 steps. Order them so a read proof comes before a write proof on the same page.
- A write step needs "undo" written in one sentence. Never propose a request body or a payload: for replay-request, leave the body empty and say so in "why" (the person fills it in).
- Prefer one strong step over several weak ones. Prefer cheap: no AI, no extra rounds.

Answer with one fenced json block only:
{"steps":[{"action":"traversal-read","aims":"confidentiality","url":"https://site/path","param":"name","why":"one sentence","undo":""}]}`
}

const METHODS: ImpactMethod[] = ['GET', 'POST', 'PUT', 'PATCH']
const PARAM = /^[A-Za-z][\w.[\]-]{0,60}$/

/** Checks one step, whatever wrote it. Returns the step it will actually run, or a reason it will not. */
export function checkStep(raw: unknown, target: string): { step: PlannedStep } | { reason: string } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { reason: 'not an object' }
  const o = raw as Record<string, unknown>
  const action = String(o.action ?? '') as ImpactActionId
  if (!actionIds().includes(action)) return { reason: `unknown proof ${String(o.action)}` }
  const info = actionInfo(action)
  let url: string
  try {
    url = validUrl(o.url)
  } catch {
    return { reason: 'the address is not a full http(s) address' }
  }
  let origin = ''
  try {
    origin = new URL(target).origin
  } catch {
    return { reason: 'the target is not an address' }
  }
  if (new URL(url).origin !== origin) return { reason: `the address is not on ${origin}` }
  const aims: ImpactClass = info.impact.includes(o.aims as ImpactClass) ? (o.aims as ImpactClass) : info.impact[0]
  const param = typeof o.param === 'string' && PARAM.test(o.param) ? o.param : undefined
  if (info.needs.includes('param') && !param) return { reason: `${action} needs a parameter name` }
  const method = METHODS.includes(o.method as ImpactMethod) ? (o.method as ImpactMethod) : action === 'replay-request' ? 'GET' : undefined
  const write = action === 'upload-write' || (action === 'replay-request' && method !== 'GET')
  const undo = typeof o.undo === 'string' ? o.undo.slice(0, 300) : undefined
  if (write && !undo) return { reason: `${action} can change data, so it needs an undo sentence` }
  const verifyUrl = typeof o.verifyUrl === 'string' && o.verifyUrl.includes('{name}') ? o.verifyUrl.replace('{name}', 'x') : ''
  if (action === 'upload-write' && verifyUrl) {
    try {
      validUrl(verifyUrl)
    } catch {
      return { reason: 'the read-back address is not a full http(s) address' }
    }
  }
  const expect = typeof o.expect === 'string' ? o.expect.trim().slice(0, 200) : undefined
  if (action === 'replay-request' && !expect) return { reason: 'replay-request needs the string the answer must contain' }
  const step: PlannedStep = {
    id: typeof o.id === 'string' && /^[\w-]{1,64}$/.test(o.id) ? o.id : 's',
    action,
    aims,
    url: new URL(url).href,
    ...(param ? { param } : {}),
    ...(method ? { method } : {}),
    ...(o.headers && typeof o.headers === 'object' && !Array.isArray(o.headers) ? { headers: Object.fromEntries(Object.entries(o.headers as Record<string, unknown>).filter(([, v]) => typeof v === 'string').slice(0, 24).map(([k, v]) => [k, String(v).slice(0, 4000)])) } : {}),
    ...(typeof o.body === 'string' ? { body: o.body.slice(0, 20000) } : {}),
    ...(typeof o.verifyUrl === 'string' && o.verifyUrl.includes('{name}') ? { verifyUrl: o.verifyUrl.slice(0, 500) } : {}),
    ...(expect ? { expect } : {}),
    ...(typeof o.from === 'string' ? { from: o.from.slice(0, 64) } : {}),
    why: typeof o.why === 'string' ? o.why.slice(0, 300) : info.what,
    preview: [],
    ...(write ? { write: true } : {}),
    ...(undo ? { undo } : {}),
    ...(Array.isArray(o.after) ? { after: o.after.filter((x): x is string => typeof x === 'string').slice(0, 5) } : {})
  }
  step.preview = previewOf(step)
  return { step }
}

export function parseAiPlan(text: string, input: PlanRulesInput): { steps: PlannedStep[]; notes: string[] } {
  const block = [...text.matchAll(/```(?:json)?\s*([\s\S]*?)```/gi)].pop() ?? /(\{[\s\S]*\})/.exec(text)
  const notes: string[] = []
  if (!block) return { steps: [], notes: ['The AI answer had no JSON block, so no step was taken from it.'] }
  let parsed: unknown
  try {
    parsed = JSON.parse(block[1])
  } catch {
    return { steps: [], notes: ['The AI answer was not valid JSON, so no step was taken from it.'] }
  }
  const list = (parsed as { steps?: unknown }).steps
  if (!Array.isArray(list)) return { steps: [], notes: ['The AI answer had no steps list, so no step was taken from it.'] }
  const steps: PlannedStep[] = []
  const seen = new Set<string>()
  list.slice(0, 5).forEach((raw, i) => {
    const r = checkStep({ ...(raw as object), id: `s${i + 1}` }, input.target)
    if ('reason' in r) {
      notes.push(`One AI step was not used: ${r.reason}.`)
      return
    }
    const key = `${r.step.action}|${r.step.url}|${r.step.param ?? ''}`
    if (seen.has(key)) return
    seen.add(key)
    const aimsOk = input.goal.includes(r.step.aims)
    steps.push({ ...r.step, ...(aimsOk ? {} : { aims: input.goal[0] }) })
  })
  if (!steps.length) notes.push('None of the AI steps could be used on this target, so the plan is empty.')
  return { steps, notes }
}

/** The estimate the UI shows: about four characters to a token, and a hard cap on the prompt. */
export function aiPlanCost(prompt: string): { chars: number; tokens: number; calls: number } {
  const chars = prompt.length
  return { chars, tokens: Math.ceil(chars / 4), calls: 1 }
}
