import type { Finding, SessionInfo, SessionKind, Severity } from './types'
import { latestPerTarget } from './latest'

/**
 * What the Overview says beyond the score: what was never tested, which findings to fix first,
 * and whether a project is getting safer. Pure, so it is easy to test.
 */

export type Area = 'code' | 'web' | 'api' | 'mac'
export interface CoverageItem {
  area: Area
  /** As it reads in a sentence: "website", "API". */
  name: string
  /** The page that runs this kind of test. */
  page: 'review' | 'web' | 'api' | 'mac'
  /** How many finished tests of this kind there are. */
  tests: number
}

const AREAS: { area: Area; name: string; page: CoverageItem['page']; kinds: SessionKind[] }[] = [
  { area: 'code', name: 'code', page: 'review', kinds: ['code-review', 'audit'] },
  { area: 'web', name: 'website', page: 'web', kinds: ['web-scan', 'recon', 'audit'] },
  { area: 'api', name: 'API', page: 'api', kinds: ['api-scan'] },
  { area: 'mac', name: 'this Mac', page: 'mac', kinds: [] }
]

/** What the score is based on, and what has not been looked at yet. */
export function coverage(sessions: Pick<SessionInfo, 'id' | 'kind' | 'target' | 'status' | 'children'>[], macChecked: boolean): CoverageItem[] {
  const latest = latestPerTarget(sessions)
  return AREAS.map((a) => ({ area: a.area, name: a.name, page: a.page, tests: a.area === 'mac' ? (macChecked ? 1 : 0) : latest.filter((s) => a.kinds.includes(s.kind)).length }))
}

/** One honest line under the score. */
export function coverageText(items: CoverageItem[]): { basedOn: string; missing: CoverageItem[] } {
  const done = items.filter((i) => i.tests > 0)
  const missing = items.filter((i) => i.tests === 0)
  const unit: Record<Area, [string, string]> = { code: ['code review', 'code reviews'], web: ['website test', 'website tests'], api: ['API test', 'API tests'], mac: ['', ''] }
  const part = (i: CoverageItem): string => (i.area === 'mac' ? 'a check of this Mac' : `${i.tests} ${unit[i.area][i.tests === 1 ? 0 : 1]}`)
  return { basedOn: done.length ? `Based on ${done.map(part).join(', ')}.` : 'Nothing has been tested yet.', missing }
}

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export interface TopFinding {
  session: string
  sessionTitle: string
  id: string
  title: string
  severity: Severity
  where?: string
}

/** A finding still counts when nobody dealt with it and the AI did not rule it out. */
export const isOpen = (f: Pick<Finding, 'triage' | 'verdict'>): boolean => !f.triage && f.verdict !== 'false-positive'

/** The few findings to fix first, across the newest test of every target. Confirmed ones lead within a severity. */
export function topFindings(list: { session: Pick<SessionInfo, 'id' | 'title'>; findings: Finding[] }[], n = 3): TopFinding[] {
  return list
    .flatMap(({ session, findings }) => findings.filter(isOpen).map((f) => ({ f, session })))
    .sort((a, b) => ORDER.indexOf(a.f.severity) - ORDER.indexOf(b.f.severity) || Number(b.f.verdict === 'confirmed') - Number(a.f.verdict === 'confirmed'))
    .slice(0, n)
    .map(({ f, session }) => ({ session: session.id, sessionTitle: session.title, id: f.id, title: f.title, severity: f.severity, ...(f.file ? { where: f.line ? `${f.file}:${f.line}` : f.file } : f.url ? { where: f.url } : {}) }))
}

export interface Trend {
  key: string
  title: string
  /** Oldest first. */
  points: { at: string; score: number }[]
  /** Newest score minus the one before: above zero means safer. */
  change: number
}

/** The score of every finished test of the same target, oldest first, for targets tested more than once. */
export function trends(sessions: Pick<SessionInfo, 'id' | 'kind' | 'target' | 'title' | 'status' | 'createdAt' | 'counts' | 'children'>[], scoreOf: (c: Record<Severity, number>) => number, max = 12): Trend[] {
  const children = new Set(sessions.flatMap((s) => s.children ?? []))
  const groups = new Map<string, typeof sessions>()
  for (const s of sessions) {
    if (s.status !== 'done' || children.has(s.id)) continue
    const key = `${s.kind}|${s.target}`
    groups.set(key, [...(groups.get(key) ?? []), s])
  }
  const out: Trend[] = []
  for (const [key, list] of groups) {
    if (list.length < 2) continue
    const sorted = [...list].sort((a, b) => a.createdAt.localeCompare(b.createdAt)).slice(-max)
    const points = sorted.map((s) => ({ at: s.createdAt, score: scoreOf(s.counts) }))
    out.push({ key, title: sorted[sorted.length - 1].title, points, change: points[points.length - 1].score - points[points.length - 2].score })
  }
  return out.sort((a, b) => b.points[b.points.length - 1].at.localeCompare(a.points[a.points.length - 1].at))
}

/** Points for a small line chart, in a box of w by h, as an SVG path. */
export function sparkPath(scores: number[], w: number, h: number): string {
  if (!scores.length) return ''
  const step = scores.length > 1 ? w / (scores.length - 1) : 0
  return scores.map((s, i) => `${i ? 'L' : 'M'}${(i * step).toFixed(1)} ${(h - (Math.max(0, Math.min(100, s)) / 100) * h).toFixed(1)}`).join(' ')
}

/**
 * A finding as text for an issue tracker. Secrets never go in: for a leaked key only the kind,
 * the file and the line are named, and code snippets are left out.
 */
export function issueText(f: Pick<Finding, 'title' | 'severity' | 'category' | 'file' | 'line' | 'url' | 'cwe' | 'advisory' | 'description' | 'impact' | 'fix' | 'verify' | 'tool'>, from: string): string {
  const where = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : f.url
  const lines = [`## ${f.title}`, '', `**Severity:** ${f.severity}`]
  if (where) lines.push(`**Where:** \`${where}\``)
  const refs = [f.cwe, f.advisory].filter(Boolean).join(', ')
  if (refs) lines.push(`**Reference:** ${refs}`)
  if (f.description && f.category !== 'secret') lines.push('', '### What is wrong', f.description)
  if (f.category === 'secret') lines.push('', '### What is wrong', 'A secret is stored in this file. The value is left out here on purpose: rotate it, then remove it from the file and from the history.')
  if (f.impact) lines.push('', '### What could happen', f.impact)
  if (f.fix) lines.push('', '### How to fix', f.fix)
  if (f.verify) lines.push('', '### How to check the fix', f.verify)
  lines.push('', `Found by MacSec (${f.tool}) in ${from}.`)
  return lines.join('\n')
}
