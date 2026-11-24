/**
 * Every check the window's input must pass, as pure functions. Nothing here imports Electron, so
 * the rules are testable on their own (index.ts only wires them to the IPC door).
 */
import type { EngagementCaps, ImpactClass } from '../shared/impact'
import { IMPACT_CLASSES } from '../shared/impact'

/** An error the person caused: shown as a sentence, never logged as a crash. */
export class ValidationError extends Error {}

export const pick = <T extends string>(v: unknown, ok: readonly T[], d: T): T => (ok.includes(v as T) ? (v as T) : d)

const text = (v: unknown, max: number): string | undefined => (typeof v === 'string' && v.trim() ? v.replace(/[\r\n\t]+/g, ' ').trim().slice(0, max) : undefined)

/** A host name or IP address only: never something a tool could read as an option. */
export function validHost(v: unknown): string {
  const h = typeof v === 'string' ? v.trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/[/:].*$/, '') : ''
  if (!h || h.length > 253 || h.startsWith('-') || !/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(h)) throw new ValidationError('Enter a server name or IP address, such as example.com or 203.0.113.10.')
  return h
}

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/

/** An engagement host: an exact name, an IPv4 address, or a leading wildcard (*.example.com). */
export function validScopeHost(v: unknown): string {
  const raw = typeof v === 'string' ? v.trim().toLowerCase() : ''
  if (!raw || raw.length > 253) throw new ValidationError('Every host needs a name, such as shop.example.com, or *.example.com for its subdomains.')
  const wild = raw.startsWith('*.')
  const h = wild ? raw.slice(2) : raw
  if (h.startsWith('*.') || h.includes('*') || h.includes('/') || h.includes('@') || h.includes(':')) throw new ValidationError(`"${raw}" is not a plain host name. Put the address in the target field instead.`)
  const bare = validHost(h)
  if (wild && IPV4.test(bare)) throw new ValidationError('A wildcard covers subdomains, so it cannot be an IP address.')
  return wild ? `*.${bare}` : bare
}

/** A host is covered by an exact entry, or by a wildcard entry for a subdomain (never the apex). */
export function hostCovers(hosts: string[], host: string): boolean {
  const h = String(host ?? '').trim().toLowerCase().replace(/^\[|\]$/g, '')
  if (!h) return false
  return hosts.some((p) => {
    const entry = String(p ?? '').trim().toLowerCase()
    if (!entry) return false
    if (!entry.startsWith('*.')) return entry === h
    const rest = entry.slice(1)
    return h.endsWith(rest) && h.length > rest.length
  })
}

export function validUrl(v: unknown): string {
  const s = typeof v === 'string' ? v.trim() : ''
  if (!/^https?:\/\/[^\s'"<>]+$/.test(s)) throw new ValidationError('Enter the full address, starting with http:// or https://.')
  const u = new URL(s)
  if (u.username || u.password) throw new ValidationError('Take the user name and password out of the address.')
  return u.href
}

const when = (v: unknown): Date | null => {
  if (typeof v !== 'string' || !v.trim()) return null
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? null : d
}

export function validWindow(startsAt: unknown, endsAt: unknown, now = Date.now()): { startsAt: string; endsAt: string } {
  const a = when(startsAt)
  const b = when(endsAt)
  if (!a || !b) throw new ValidationError('Set when the authority starts and when it ends.')
  if (b.getTime() <= a.getTime()) throw new ValidationError('The end of the authority must be after its start.')
  if (b.getTime() - a.getTime() > 366 * 24 * 3600 * 1000) throw new ValidationError('An engagement cannot last more than a year. Split it in two.')
  if (b.getTime() <= now) throw new ValidationError('That authority has already ended. Check the dates.')
  return { startsAt: a.toISOString(), endsAt: b.toISOString() }
}

const whole = (v: unknown, min: number, max: number, fallback: number): number => {
  const n = Math.round(Number(v))
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback
}

/** Caps are clamped to sane ranges, so no plan can be given an unlimited budget. */
export function validCaps(v: unknown): EngagementCaps {
  const o = (v ?? {}) as Partial<EngagementCaps>
  return { requests: whole(o.requests, 1, 20000, 400), writes: whole(o.writes, 0, 200, 10), minutes: whole(o.minutes, 1, 480, 20) }
}

export function validImpacts(v: unknown): ImpactClass[] {
  const list = Array.isArray(v) ? v.filter((x): x is ImpactClass => IMPACT_CLASSES.includes(x as ImpactClass)) : []
  const out = [...new Set(list)]
  if (!out.length) throw new ValidationError('Choose at least one of confidentiality, integrity and availability.')
  return out
}

export function validShortText(v: unknown, name: string, max: number): string {
  const s = text(v, max)
  if (!s) throw new ValidationError(`Fill in ${name}.`)
  return s
}

/** The phrase that unlocks a run: EXPLOIT <host>. The host is the target's own name. */
export function exploitPhrase(host: string): string {
  return `EXPLOIT ${String(host ?? '').toLowerCase()}`
}

export function phraseMatches(given: unknown, host: string): boolean {
  return typeof given === 'string' && given.trim() === exploitPhrase(host)
}
