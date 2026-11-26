/**
 * Assets, risk and trends: the view a vulnerability manager gives you. Every site, API, domain, app,
 * project and Mac MacSec has looked at becomes an asset with a risk score, its open findings, how that
 * score moved over time, and how long fixed findings took to fix. It is built from the saved sessions,
 * so nothing new is stored.
 */
import type { Action, AssetInfo, Finding, SessionInfo, Severity } from '../shared/types'
export type { Action, AssetInfo }
import { chainsOf } from './chains'
import { postureScore } from '../shared/posture'
import { findingKey } from './watch'

const BASE: Record<Severity, number> = { critical: 90, high: 70, medium: 45, low: 20, info: 0 }
const SEVS: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

const isOpen = (f: Finding): boolean => f.verdict !== 'false-positive' && !f.triage && f.severity !== 'info'

/** The one score shown everywhere (Overview, Assets, reports): 100 means nothing open, higher is better. */
export const scoreOf = (fs: Finding[]): number => postureScore(Object.fromEntries(SEVS.map((v) => [v, fs.filter((f) => isOpen(f) && f.severity === v).length])) as Record<Severity, number>)

/** 0 to 100. Each open finding adds a share, so a few serious ones weigh more than many small ones, and it never passes 100. */
export function riskScore(findings: Finding[]): number {
  let keep = 1
  for (const f of findings.filter(isOpen)) keep *= 1 - Math.min(0.5, (f.exploit?.risk ?? BASE[f.severity]) / 200)
  return Math.round(100 * (1 - keep))
}

export const riskLabel = (n: number): 'Critical' | 'High' | 'Medium' | 'Low' | 'Clean' => (n >= 75 ? 'Critical' : n >= 50 ? 'High' : n >= 25 ? 'Medium' : n > 0 ? 'Low' : 'Clean')

// ---------------------------------------------------------------- What to fix first


const norm = (s: string): string => s.toLowerCase().replace(/https?:\/\/\S+|\/\S*|\d+|[`'"]/g, '').replace(/\s+/g, ' ').trim()
const firstSentence = (s: string): string => (/^(.{20,160}?[.!?])(\s|$)/.exec(s)?.[1] ?? s.slice(0, 160)).trim()

/** The few actions that remove the most risk: findings with the same fix are grouped, and each group is ranked by how many points it takes off. */
export function remediationPlan(findings: Finding[], top = 5): { actions: Action[]; before: number; after: number } {
  const open = findings.filter(isOpen)
  const groups = new Map<string, Finding[]>()
  for (const f of open) {
    const key = f.fix ? norm(firstSentence(f.fix)) : `t:${norm(f.title)}`
    ;(groups.get(key) ?? groups.set(key, []).get(key)!).push(f)
  }
  const before = riskScore(open)
  const actions: Action[] = [...groups.values()].map((g) => {
    const worst = SEVS.find((s) => g.some((f) => f.severity === s)) ?? 'low'
    const rest = open.filter((f) => !g.includes(f))
    return { title: g.length === 1 ? g[0].title : `${firstSentence(g[0].fix ?? g[0].title)} (${g.length} findings)`, fix: g[0].fix ?? '', count: g.length, worst, drop: before - riskScore(rest), ids: g.map((f) => f.id) }
  })
  actions.sort((a, b) => b.drop - a.drop || SEVS.indexOf(a.worst) - SEVS.indexOf(b.worst) || b.count - a.count)
  const chosen = actions.slice(0, top)
  const keepIds = new Set(chosen.flatMap((a) => a.ids))
  return { actions: chosen, before, after: riskScore(open.filter((f) => !keepIds.has(f.id))) }
}

// ---------------------------------------------------------------- Assets


const KIND: Record<string, AssetInfo['kind']> = { 'web-scan': 'site', 'api-scan': 'api', recon: 'domain', 'mobile-scan': 'app', 'code-review': 'project', audit: 'mac' }

function hostOf(target: string): string {
  try {
    return new URL(/^https?:\/\//i.test(target) ? target : `https://${target}`).host.toLowerCase()
  } catch {
    return target.toLowerCase()
  }
}

/** The asset a session belongs to: web, API and recon of the same host are one asset. */
export function assetKey(s: Pick<SessionInfo, 'kind' | 'target' | 'title'>): { key: string; name: string; kind: AssetInfo['kind'] } {
  if (s.kind === 'web-scan' || s.kind === 'api-scan' || s.kind === 'recon') {
    const h = hostOf(s.target)
    return { key: `host:${h}`, name: h, kind: s.kind === 'api-scan' ? 'api' : s.kind === 'recon' ? 'domain' : 'site' }
  }
  return { key: `${s.kind}:${s.target || s.title}`, name: s.title || s.target, kind: KIND[s.kind] ?? 'other' }
}

export function buildAssets(sessions: SessionInfo[], findingsOf: (id: string) => Finding[]): AssetInfo[] {
  const groups = new Map<string, { name: string; kind: AssetInfo['kind']; list: SessionInfo[] }>()
  for (const s of sessions.filter((x) => x.status === 'done')) {
    const a = assetKey(s)
    const g = groups.get(a.key) ?? groups.set(a.key, { name: a.name, kind: a.kind, list: [] }).get(a.key)!
    // A site that has been scanned and also mapped is one asset: the scan wins the label.
    if (a.kind === 'site') g.kind = 'site'
    g.list.push(s)
  }
  const out: AssetInfo[] = []
  for (const [key, g] of groups) {
    const list = g.list.sort((a, b) => a.createdAt.localeCompare(b.createdAt)).slice(-30)
    const seen = new Map<string, string>()
    const fixedDays: number[] = []
    let prev = new Set<string>()
    const trend: AssetInfo['trend'] = []
    // Every session of a kind is compared with the one before it of the same kind, so a web scan does not "fix" what only a recon had.
    const byKind = new Map<string, Set<string>>()
    let latest: Finding[] = []
    for (const s of list) {
      const fs = findingsOf(s.id)
      const keys = new Set(fs.filter(isOpen).map(findingKey))
      for (const k of keys) if (!seen.has(k)) seen.set(k, s.createdAt)
      const before = byKind.get(s.kind) ?? prev
      for (const k of before) if (!keys.has(k) && seen.has(k)) fixedDays.push(Math.max(0, (Date.parse(s.createdAt) - Date.parse(seen.get(k)!)) / 86400000))
      byKind.set(s.kind, keys)
      prev = keys
      trend.push({ at: s.createdAt, risk: riskScore(fs), score: scoreOf(fs), open: fs.filter(isOpen).length })
      latest = fs
    }
    // Where scans of several kinds exist, the open picture is the newest finished scan of each kind put together.
    const newest = [...byKind.keys()].map((k) => list.filter((s) => s.kind === k).pop()!).filter(Boolean)
    const current = newest.length > 1 ? newest.flatMap((s) => findingsOf(s.id)) : latest
    const open = Object.fromEntries(SEVS.map((v) => [v, current.filter((f) => isOpen(f) && f.severity === v).length])) as Record<Severity, number>
    const plan = remediationPlan(current)
    const last = list[list.length - 1]
    const risk = riskScore(current)
    const score = scoreOf(current)
    out.push({ key, name: g.name, kind: g.kind, scans: list.length, lastScan: last.createdAt, lastSession: last.id, open, proven: current.filter((f) => isOpen(f) && f.exploit?.state === 'proven').length, risk, riskLabel: riskLabel(risk), score, trend, fixed: fixedDays.length, ...(fixedDays.length ? { mttrDays: Math.round((fixedDays.reduce((a, b) => a + b, 0) / fixedDays.length) * 10) / 10 } : {}), actions: plan.actions, dropIfDone: plan.before - plan.after, chains: chainsOf(current) })
  }
  return out.sort((a, b) => a.score - b.score || b.risk - a.risk || a.name.localeCompare(b.name))
}
