/**
 * The engagement: the written authority a controlled-exploitation run stands on. Nothing in
 * ~/MacSec/impact runs without one that covers the host, the window and the kind of impact.
 *
 * Stored in ~/MacSec/config/engagements.json (0600). A run's own record in ~/MacSec/impact-runs
 * says which engagement it used, so the audit trail is complete on this Mac.
 */
import { createHash, randomBytes } from 'crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import type { Engagement, EngagementDraft, ImpactClass } from '../shared/impact'
import { IMPACT_CLASSES } from '../shared/impact'
import { dirs } from './paths'
import { ValidationError, hostCovers, validCaps, validImpacts, validScopeHost, validShortText, validWindow } from './validate'

const file = (): string => join(dirs.config(), 'engagements.json')

export function loadEngagements(): Engagement[] {
  try {
    const raw = JSON.parse(readFileSync(file(), 'utf8')) as Engagement[]
    return Array.isArray(raw) ? raw.filter((e) => e && typeof e.id === 'string') : []
  } catch {
    return []
  }
}

function write(list: Engagement[]): void {
  mkdirSync(dirs.config(), { recursive: true, mode: 0o700 })
  writeFileSync(file(), JSON.stringify(list, null, 2), { mode: 0o600 })
}

/** Requests and writes already spent by the runs stored on this Mac. */
export function engagementUsage(id: string): { requests: number; writes: number } {
  const out = { requests: 0, writes: 0 }
  const dir = join(dirs.root(), 'impact-runs')
  if (!existsSync(dir)) return out
  for (const f of readdirSync(dir)) {
    if (!/^[a-z0-9-]{8,64}\.json$/.test(f)) continue
    try {
      const r = JSON.parse(readFileSync(join(dir, f), 'utf8')) as { engagementId?: string; requests?: number; writes?: number }
      if (r.engagementId !== id) continue
      out.requests += Number(r.requests) || 0
      out.writes += Number(r.writes) || 0
    } catch {
      // A partial file: it counts for nothing.
    }
  }
  return out
}

export function withUsage(e: Engagement): Engagement {
  return { ...e, used: engagementUsage(e.id) }
}

export function listEngagements(): Engagement[] {
  return loadEngagements().map(withUsage).sort((a, b) => b.createdAt.localeCompare(a.createdAt))
}

/** The engagement the person is working under: the newest one that is not revoked or expired. */
export function currentEngagement(now = Date.now()): Engagement | null {
  const live = listEngagements().filter((e) => !e.revokedAt && new Date(e.endsAt).getTime() > now)
  return live[0] ?? null
}

export function engagementById(id: string): Engagement | null {
  return listEngagements().find((e) => e.id === id) ?? null
}

/** Reads and validates a draft. Every value that matters is normalised here, never at the call site. */
export function normaliseDraft(input: unknown, now = Date.now()): EngagementDraft {
  const d = (input ?? {}) as Record<string, unknown>
  const hostList = Array.isArray(d.hosts)
    ? d.hosts
    : typeof d.hosts === 'string'
      ? String(d.hosts).split(/[\s,;]+/)
      : []
  const hosts = [...new Set(hostList.filter((h) => typeof h === 'string' && h.trim()).map((h) => validScopeHost(h)))].slice(0, 40)
  if (!hosts.length) throw new ValidationError('Name at least one host the authority covers, such as shop.example.com or *.example.com.')
  const window = validWindow(d.startsAt, d.endsAt, now)
  const profile = ['pentest', 'bounty', 'red-team', 'internal', 'lab'].includes(String(d.profile)) ? (String(d.profile) as EngagementDraft['profile']) : 'pentest'
  return {
    profile,
    client: validShortText(d.client, 'the client or project', 120),
    authorityRef: validShortText(d.authorityRef, 'the authority reference', 160),
    authorizedBy: validShortText(d.authorizedBy, 'who gave the authority', 120),
    hosts,
    allowPrivate: d.allowPrivate === true,
    ...window,
    caps: validCaps(d.caps),
    allowed: validImpacts(d.allowed),
    notes: typeof d.notes === 'string' ? d.notes.slice(0, 2000) : undefined
  }
}

export function saveEngagement(input: unknown, now = Date.now()): Engagement {
  const draft = normaliseDraft(input, now)
  const { caps } = draft
  if (draft.caps.writes > 0 && !draft.allowed.includes('integrity')) {
    // Writes are allowed by the cap but not by the authority: impossible combination.
    throw new ValidationError('Writes are enabled but integrity is not allowed. Add integrity, or set writes to 0.')
  }
  if (caps.requests < 1) throw new ValidationError('The request cap must be at least one.')
  const engagement: Engagement = {
    ...draft,
    id: `eng-${randomBytes(4).toString('hex')}`,
    createdAt: new Date(now).toISOString(),
    used: { requests: 0, writes: 0 }
  }
  write([engagement, ...loadEngagements()])
  return engagement
}

export function revokeEngagement(id: string): Engagement {
  const list = loadEngagements()
  const e = list.find((x) => x.id === id)
  if (!e) throw new ValidationError('That engagement is not on this Mac.')
  e.revokedAt = new Date().toISOString()
  write(list)
  return withUsage(e)
}

export type EngagementProblem = string | null

/** Every reason a run may not happen under this engagement, in one place, in plain words. */
export function engagementProblem(e: Engagement | null, host: string, goal: ImpactClass[], now = Date.now()): EngagementProblem {
  if (!e) return 'There is no engagement on this Mac. Write one first: it is the authority a run stands on.'
  if (e.revokedAt) return `The engagement ${e.id} was revoked on ${e.revokedAt.slice(0, 10)}. Write a new one before testing anything.`
  const t = now
  if (t < new Date(e.startsAt).getTime()) return `The authority starts on ${e.startsAt.slice(0, 10)}. A run cannot happen before that.`
  if (t > new Date(e.endsAt).getTime()) return `The authority ended on ${e.endsAt.slice(0, 10)}. Extend it in writing before testing anything.`
  if (!hostCovers(e.hosts, host)) return `${host} is not one of the hosts the authority covers (${e.hosts.join(', ')}).`
  const missing = goal.filter((g) => !e.allowed.includes(g))
  if (missing.length) return `The authority does not allow ${missing.join(', ')}. It allows ${e.allowed.join(', ')}.`
  if (!goal.length) return 'Choose at least one of confidentiality, integrity and availability.'
  if (goal.some((g) => !IMPACT_CLASSES.includes(g))) return 'That goal is not one of confidentiality, integrity or availability.'
  const used = engagementUsage(e.id)
  if (used.requests >= e.caps.requests) return `This engagement has used all ${e.caps.requests} of its requests. Raise the cap in writing, or write a new engagement.`
  if (e.caps.writes > 0 && used.writes >= e.caps.writes) return `This engagement has used all ${e.caps.writes} of its writes. Raise the cap in writing, or write a new engagement.`
  return null
}

/** A stable key for a host, for the approval phrase and the UI. */
export const hostKey = (target: string): string => {
  try {
    return new URL(target).host.toLowerCase()
  } catch {
    return String(target ?? '').toLowerCase()
  }
}

/** A short fingerprint of the engagement, printed with a run so a report can name it. */
export const engagementRef = (e: Engagement): string => `${e.id}:${createHash('sha256').update(`${e.id}|${e.client}|${e.authorityRef}|${e.hosts.join(',')}`).digest('hex').slice(0, 12)}`
