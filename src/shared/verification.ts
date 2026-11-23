/**
 * How far a finding is established, in the words a report uses, and the OWASP ASVS chapter it belongs to.
 *
 *   Confirmed   the problem itself was seen (a proof), or an AI reader confirmed it from the code and a scanner agrees.
 *   Likely      an AI reader confirmed it from the code, or two different scanners found the same thing.
 *   Suspected   one scanner found it and nothing else backs it up yet.
 *   Unverified  the reviewer has not looked at it (a lead, or a version match).
 *   Ruled out   the reviewer or the person says it is not a problem.
 * Nothing here sends a request.
 */
import type { Finding } from './types'

export type Verification = 'confirmed' | 'likely' | 'suspected' | 'unverified' | 'ruled-out'

export const VERIFICATION_TEXT: Record<Verification, string> = {
  confirmed: 'Confirmed: the problem itself was seen',
  likely: 'Likely: a reviewer or a second scanner backs it up',
  suspected: 'Suspected: one scanner found it, nothing else backs it up yet',
  unverified: 'Unverified: nobody has checked it yet',
  'ruled-out': 'Ruled out: marked as not a problem'
}

export function verificationOf(f: Finding): Verification {
  if (f.verdict === 'false-positive' || f.triage === 'not-a-problem') return 'ruled-out'
  if (f.confidence === 'confirmed' && f.proof) return 'confirmed'
  const also = f.alsoFoundBy?.length ?? 0
  if (f.verdict === 'confirmed') return f.confidence === 'confirmed' || also > 0 ? 'confirmed' : 'likely'
  if (also > 0) return 'likely'
  if (f.severity === 'info') return 'unverified'
  if (f.verdict === 'unreviewed' || f.confidence === 'possible' || !f.confidence) return f.tool === 'MacSec' || /lead|possible/i.test(f.title) ? 'unverified' : 'suspected'
  return 'suspected'
}

/** OWASP ASVS 4.0 chapters by CWE, at chapter level so that no requirement number is guessed. */
const ASVS: [number[], string][] = [
  [[287, 288, 289, 290, 294, 304, 306, 307, 308, 521, 522, 620, 640, 798, 259, 1391], 'V2 Authentication'],
  [[384, 613, 614, 1004, 1275], 'V3 Session Management'],
  [[22, 23, 24, 35, 639, 862, 863, 284, 285, 269, 266, 276, 352, 425, 566, 915, 1230], 'V4 Access Control'],
  [[20, 74, 77, 78, 79, 80, 88, 89, 90, 91, 93, 94, 95, 98, 113, 116, 117, 134, 470, 502, 601, 611, 643, 652, 776, 917], 'V5 Validation, Sanitization and Encoding'],
  [[295, 319, 757], 'V9 Communication'],
  [[310, 311, 312, 316, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 338, 347, 916, 1240], 'V6 Stored Cryptography'],
  [[117, 223, 532, 778], 'V7 Error Handling and Logging'],
  [[200, 201, 209, 215, 359, 497, 538, 598], 'V8 Data Protection'],
  [[506, 507, 510, 511, 912], 'V10 Malicious Code'],
  [[400, 799, 840, 841], 'V11 Business Logic'],
  [[73, 434, 494, 646, 918], 'V12 Files and Resources'],
  [[1059, 1104, 1357, 937, 942, 1275, 16, 693, 1021, 489, 668], 'V14 Configuration']
]

/** The ASVS chapter for a CWE ("CWE-89" or 89), or null when the mapping is not clear. */
export function asvsOf(cwe: string | number | undefined): string | null {
  const n = typeof cwe === 'number' ? cwe : Number(/\d+/.exec(String(cwe ?? ''))?.[0])
  if (!Number.isFinite(n) || !n) return null
  // The first chapter in the list that names this CWE.
  return ASVS.find(([list]) => list.includes(n))?.[1] ?? null
}
