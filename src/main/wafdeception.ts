/**
 * WAF honeypots and deception: what shields do to waste a scanner's time, and how MacSec tells it
 * from a real problem.
 *
 * The behaviour below is described in public research and by the people who run these systems:
 *   - a shield, a port-mimic or a tarpit accepts every connection, so a port scan sees every port
 *     open on that address, often with the same banner everywhere;
 *   - dynamic path spoofing: random paths answer 200 with a nearly identical page, so a directory
 *     scanner "finds" thousands of pages. Response lengths are shifted a little to defeat a filter
 *     on exact length, so MacSec compares structure, not size;
 *   - decoy files (.env, .sql, dumps) are served on purpose to catch scanners, often with the same
 *     page for many names;
 *   - a slow drip (tarpit) holds the scanner open; a WAF may also add its own headers and cookies
 *     and block after a few requests.
 *
 * MacSec never hides what it saw. It turns a finding that matches these signs down to info with the
 * reason, adds one note that says what the site is doing, and leaves the rest to a person.
 */
import type { Finding } from '../shared/types'
import { DECOY_NAMES, detectWaf, spoofedPorts } from './decoys'

export interface PageSample {
  url: string
  status: number
  length: number
  body: string
  ms?: number
}

export interface DeceptionVerdict {
  deceptive: boolean
  confidence: 'likely' | 'strong'
  reasons: string[]
  vendor: string | null
  /** True when random paths answer with the same page: the classic dynamic path spoofing. */
  sameStructure: boolean
  /** True when most random paths answer at all. */
  everyPathAnswers: boolean
  /** True when the answer looked slow, as a tarpit does. */
  tarpit: boolean
  advice: string
}

/** A page with the noise removed: no scripts, numbers, hex or whitespace runs. */
export function structureOf(body: string): string {
  return body
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/[0-9a-f]{12,}/gi, '#')
    .replace(/\d+/g, '#')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 6000)
}

const words = (s: string): Set<string> => new Set(s.split(/[^a-z]+/i).filter((w) => w.length > 2).slice(0, 400))

/** Two pages are the "same page" when their words overlap heavily and their size is close. */
export function sameStructure(a: string, b: string): boolean {
  if (!a || !b) return false
  const wa = words(a)
  const wb = words(b)
  if (wa.size < 8 || wb.size < 8) return false
  let hit = 0
  for (const w of wa) if (wb.has(w)) hit++
  const overlap = hit / Math.max(wa.size, wb.size)
  const lengthClose = Math.abs(a.length - b.length) <= Math.max(60, Math.max(a.length, b.length) * 0.08)
  return overlap >= 0.85 && lengthClose
}

const median = (xs: number[]): number => {
  if (!xs.length) return 0
  const s = [...xs].sort((a, b) => a - b)
  return s[Math.floor(s.length / 2)]
}

export interface WebDeceptionInput {
  /** The home page. */
  home: PageSample
  /** Paths that cannot exist. */
  random: PageSample[]
  /** How many known decoy names answered in this scan. */
  decoyHits?: number
  /** Names wafw00f or the headers gave away. */
  vendors?: string[]
}

export function assessWebDeception(i: WebDeceptionInput): DeceptionVerdict {
  const reasons: string[] = []
  const answered = i.random.filter((s) => s.status === 200 || s.status === 206)
  const everyPathAnswers = i.random.length >= 4 && answered.length / i.random.length >= 0.75
  const homeStructure = structureOf(i.home.body)
  const matches = answered.length >= 3 ? answered.map((s) => sameStructure(homeStructure, structureOf(s.body))) : []
  const sameAsHome = matches.filter(Boolean).length >= Math.max(3, Math.ceil(answered.length * 0.8))
  const tarpit = median(i.random.map((s) => s.ms ?? 0)) >= 2500
  const decoyHits = i.decoyHits ?? 0
  if (everyPathAnswers) reasons.push(`${answered.length} of ${i.random.length} paths that cannot exist answered with a page instead of "not found".`)
  if (sameAsHome) reasons.push('Those pages have the same structure as the home page, which is what dynamic path spoofing looks like: the shield makes up a page for every name.')
  if (decoyHits >= 4) reasons.push(`${decoyHits} sensitive file names answered in this scan, which is what a honeypot does to catch scanners.`)
  if (tarpit) reasons.push(`The answers were slow (median ${Math.round(median(i.random.map((s) => s.ms ?? 0)))} ms), which is what a tarpit does to hold a scanner open.`)
  const vendor = i.vendors?.[0] ?? null
  if (vendor) reasons.push(`${vendor} identifies itself in the headers or the page.`)
  const deceptive = everyPathAnswers || sameAsHome || decoyHits >= 4 || tarpit
  const confidence: DeceptionVerdict['confidence'] = sameAsHome || decoyHits >= 6 || (everyPathAnswers && decoyHits >= 3) ? 'strong' : 'likely'
  const advice = deceptive
    ? 'This looks like a shield or honeypot wasting a scanner\'s time, not a site full of leaked files. Do not send these about as findings. Open the one or two that matter by hand, and mark the rest "Not a problem, remember".'
    : 'The site answers honestly: pages that do not exist say so, and the names MacSec asked for are not all served.'
  return { deceptive, confidence, reasons, vendor, sameStructure: sameAsHome, everyPathAnswers, tarpit, advice }
}

export interface PortSample {
  port: number
  service?: string
}

/** Port-level deception: every port open, or a crowd of ports with the same banner. */
export function assessPortDeception(open: PortSample[], scanned: number): { spoofed: boolean; reason: string; mimic: boolean } {
  const base = spoofedPorts(open.map((p) => p.port), scanned)
  const named = open.filter((p) => !!p.service)
  const counts = new Map<string, number>()
  for (const p of named) counts.set(p.service as string, (counts.get(p.service as string) ?? 0) + 1)
  const worst = [...counts.entries()].sort((a, b) => b[1] - a[1])[0]
  const mimic = named.length >= 8 && !!worst && worst[1] >= 8 && !/^(unknown|tcpwrapped)$/i.test(worst[0])
  if (mimic) {
    return {
      spoofed: true,
      mimic: true,
      reason: base.spoofed
        ? `${base.reason} Also, ${worst![1]} of those ports answered as "${worst![0]}": a port mimic answers every connection the same way.`
        : `${worst![1]} ports on one address answered as "${worst![0]}", which a real server does not do. A port mimic or shield is answering every connection.`
    }
  }
  return { spoofed: base.spoofed, mimic: false, reason: base.reason }
}

/** The one note a scan adds when the site looks like a decoy, and the text a report can quote. */
export function deceptionFinding(target: string, v: DeceptionVerdict, kind: 'web' | 'network'): Finding {
  const host = (() => {
    try {
      return new URL(target).host
    } catch {
      return target
    }
  })()
  return {
    id: `deception-${host}`,
    tool: 'MacSec deception check',
    category: kind === 'web' ? 'web' : 'network',
    severity: 'info',
    confidence: 'possible',
    title: `WAF honeypot or decoy behaviour on ${host}: do not treat this as findings`,
    url: target,
    file: host,
    description: `${v.reasons.join(' ')} ${v.advice}${v.vendor ? ` The shield is ${v.vendor}.` : ''}`,
    fix: 'Nothing to fix. This is the site defending itself. If you are testing your own shield, this is it working.'
  }
}

/** What the AI reviewer is told when it reads scan results: judge noise as noise. */
export const WAF_DECEPTION_NOTE = `Judge scanner noise as noise. A shield or honeypot often accepts every connection (all ports open), answers random paths with 200 and a nearly identical page, serves decoy .env and .sql files, or answers slowly to hold a scanner open. When the results show that pattern, say so plainly, call it deception rather than findings, and do not count those items as problems. Point out the one or two results that do not fit the pattern, because those are the real ones.`

/** Names worth sampling when checking for decoy files. */
export const DECOY_SAMPLES = DECOY_NAMES.filter((n) => /\.env$|\.sql$|\.git\/config|phpinfo|trace\.axd|id_rsa|\.htpasswd/.test(n)).slice(0, 8)

/** A short sentence about the shield, for a scan step line. */
export function vendorLine(headers: Headers, body: string, cookie: string): string {
  const found = detectWaf(headers, body, cookie)
  return found.length ? found.map((w) => w.name).join(', ') : ''
}
