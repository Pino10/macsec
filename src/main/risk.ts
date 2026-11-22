/**
 * How far each finding is proven, in the words a report uses. It is the same idea as an exploit
 * validation in a commercial scanner, kept safe: nothing here runs an exploit. "Proven" means a
 * harmless request showed the problem itself and the proof can be repeated.
 *
 *   proven           the problem was seen, with a repeatable proof (a control confirmation, a public file, a signed fact)
 *   known-exploited  the software version is listed on CISA's known-exploited list (a version match, not a test)
 *   likely           the version is listed and EPSS puts the chance of use in 30 days at 10% or more
 *   unproven         a rule matched or the evidence points at it, but nothing was repeated
 *
 * The honesty guard: a finding that says "confirmed" without a proof is turned into "possible", so a
 * report can never claim more than it can show.
 */
import type { Finding, Severity } from '../shared/types'
import { checkIdOf } from './checks'

const BASE: Record<Severity, number> = { critical: 90, high: 70, medium: 45, low: 20, info: 0 }
const KINDS = new Set(['web', 'api', 'mobile', 'recon', 'network', 'cloud'])

/** A finding that says confirmed must carry its proof. Anything else is only possible. */
export function honest(f: Finding): Finding {
  return f.confidence === 'confirmed' && !f.proof ? { ...f, confidence: 'possible' } : f
}

export function labelExploit(f: Finding): Finding['exploit'] | undefined {
  if (f.severity === 'info' || !KINDS.has(f.category)) return undefined
  const base = BASE[f.severity]
  if (f.cves?.kev) return { state: 'known-exploited', label: 'Known exploited', why: `${f.cves.kev} of the ${f.cves.count} flaws listed for this version are on CISA's known-exploited list. This is a version match: check the build you run before acting.`, risk: Math.max(base, 85) }
  if (f.confidence === 'confirmed' && f.proof) return { state: 'proven', label: 'Proven', why: `A harmless request showed it: ${f.proof.shows[0] ?? 'see the proof'}. Repeat it with the command in the proof.`, risk: Math.min(100, base + 10) }
  if (f.cves && f.cves.topEpss >= 0.1) return { state: 'likely', label: 'Likely', why: `The version is listed for known flaws, and the most likely one has a ${(f.cves.topEpss * 100).toFixed(0)}% chance of being used in the next 30 days (EPSS). Not tested.`, risk: Math.min(100, base + 10) }
  return { state: 'unproven', label: 'Not proven', why: f.proof ? 'The evidence points at it, but nothing was repeated to show it.' : f.tool === 'MacSec' ? 'The evidence points at it, but nothing was tested to show it.' : `A scanner rule (${f.tool}) matched. MacSec has not repeated it, so treat it as a lead.`, risk: Math.max(0, base - 10) }
}

/** Applies the honesty guard and the exploit label to every finding. */
export function label(findings: Finding[]): Finding[] {
  return findings.map((x) => {
    const h = honest(x)
    const e = labelExploit(h)
    const withId = { ...h, checkId: h.checkId ?? checkIdOf(h) }
    return e ? { ...withId, exploit: e } : withId
  })
}

export function exploitCounts(findings: Finding[]): Record<'proven' | 'known-exploited' | 'likely' | 'unproven', number> {
  const c = { proven: 0, 'known-exploited': 0, likely: 0, unproven: 0 }
  for (const f of findings) if (f.exploit && f.verdict !== 'false-positive' && !f.triage) c[f.exploit.state]++
  return c
}
