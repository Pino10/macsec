/**
 * The OWASP Top 10 (2025) as a checklist. Every finding from a code review, a scanner or a web
 * scan is put under one of the ten (by its CWE number when it has one, otherwise by its words), and
 * each of the ten says whether it had problems, was checked and looked fine, or was not checked by
 * the tests that ran. Shared by Laramac and MacSec: keep this file identical in both.
 */

export type OwaspId = 'A01' | 'A02' | 'A03' | 'A04' | 'A05' | 'A06' | 'A07' | 'A08' | 'A09' | 'A10'
export type OwaspSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

/** Kinds of test, and what each can see. */
export type OwaspTest = 'code-review' | 'sast' | 'secrets' | 'dependencies' | 'web-scan' | 'headers' | 'api'

export interface OwaspCategory {
  id: OwaspId
  name: string
  /** What it means, in plain words. */
  about: string
  /** Which test to run to check it. */
  howToCheck: string
}

export const OWASP_TOP10: OwaspCategory[] = [
  { id: 'A01', name: 'Broken Access Control', about: 'People can see or do things they should not: other users’ data, admin pages, files outside the app, or requests the server makes for them (SSRF).', howToCheck: 'A code review, or a web scan for exposed files and pages.' },
  { id: 'A02', name: 'Security Misconfiguration', about: 'Unsafe settings: debug mode on, missing security headers, default pages, loose cookies or XML that loads outside files.', howToCheck: 'A web scan, or a code review of the config.' },
  { id: 'A03', name: 'Software Supply Chain Failures', about: 'Packages and tools with known holes, out of date, or from places that cannot be trusted.', howToCheck: 'A dependency audit (Composer, npm, OSV-Scanner).' },
  { id: 'A04', name: 'Cryptographic Failures', about: 'Data not protected well enough: no HTTPS, weak hashing or ciphers, guessable random numbers.', howToCheck: 'A code review, or a web scan for HTTPS and HSTS.' },
  { id: 'A05', name: 'Injection', about: 'Input that ends up as code: SQL injection, cross-site scripting (XSS), shell commands or templates built from user text.', howToCheck: 'A code review with Semgrep, or a web scan.' },
  { id: 'A06', name: 'Insecure Design', about: 'Problems in how a feature was planned: no limits, trust in the browser, unsafe file uploads or business rules that can be abused.', howToCheck: 'A code review (only a reviewer can judge design).' },
  { id: 'A07', name: 'Authentication Failures', about: 'Weak login: no rate limits, weak passwords allowed, sessions that never end, or keys and passwords written in the code.', howToCheck: 'A code review and a secrets scan.' },
  { id: 'A08', name: 'Software or Data Integrity Failures', about: 'Trusting data or code that was not checked: unserialize on user input, scripts from CDNs without integrity, mass assignment, unsafe CI.', howToCheck: 'A code review.' },
  { id: 'A09', name: 'Security Logging and Alerting Failures', about: 'Attacks go unnoticed: important events are not logged, or logs hold passwords and tokens.', howToCheck: 'A code review (logging is in the code).' },
  { id: 'A10', name: 'Mishandling of Exceptional Conditions', about: 'Errors handled badly: stack traces shown to visitors, failures that let requests through, or crashes on odd input.', howToCheck: 'A code review, or a web scan for error pages.' }
]

/** CWE numbers for each category, from OWASP's 2025 mapping (the common ones). */
const CWES: Record<OwaspId, number[]> = {
  A01: [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 918, 922, 1275],
  A02: [2, 11, 13, 15, 16, 260, 315, 489, 520, 526, 537, 541, 547, 611, 614, 693, 776, 942, 1004, 1021, 1032, 1174],
  A03: [937, 1035, 1104, 1329, 1357, 1395],
  A04: [261, 296, 310, 311, 312, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916],
  A05: [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917, 1336],
  A06: [73, 183, 213, 235, 256, 257, 266, 269, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1173],
  A07: [255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216],
  A08: [345, 353, 426, 494, 502, 565, 784, 829, 830, 915],
  A09: [117, 223, 532, 778],
  A10: [209, 248, 252, 280, 369, 390, 391, 394, 396, 397, 460, 476, 478, 484, 550, 636, 703, 754, 755, 756]
}
const BY_CWE = new Map<number, OwaspId>()
for (const [id, list] of Object.entries(CWES) as [OwaspId, number[]][]) for (const n of list) if (!BY_CWE.has(n)) BY_CWE.set(n, id)

/** Words, checked in this order when a finding has no CWE. The first that matches wins. */
const WORDS: [OwaspId, RegExp][] = [
  ['A03', /\bcve-\d{4}-\d+|\bghsa-|known vulnerab|vulnerable (package|dependenc|version|component|library|plugin)|outdated (package|dependenc|version|component|library|plugin|software)|end[- ]of[- ]life|\beol\b|supply[- ]chain|typosquat|abandoned package|composer audit|npm audit|\bosv\b/i],
  ['A08', /deseriali[sz]|unserialize|subresource integrity|\bsri\b|integrity (check|attribute)|mass[- ]assignment|\$guarded|\$fillable|pull_request_target|untrusted (script|cdn|source)|unsigned (update|package|download)|auto[- ]?update without/i],
  ['A05', /injection|\bsqli\b|\bxss\b|cross[- ]site scripting|\bssti\b|\beval\b|command exec|os command|shell (command|exec)|unescaped|\{!!|innerhtml|dangerouslysetinnerhtml|v-html|raw (sql|query|output|html)|whereRaw|DB::raw|prototype pollution|header splitting|\bcrlf\b/i],
  ['A04', /\bcrypt|cipher|weak hash|\bmd5\b|\bsha-?1\b|\btls\b|\bssl\b|\bhsts\b|strict-transport|plain ?text password|cleartext|over http\b|not (use|served over) https|no https|mixed content|insecure transport|predictable|weak random|mt_rand|math\.random|\bentropy\b|certificate/i],
  ['A01', /access control|authori[sz]|\bidor\b|insecure direct object|privilege|path traversal|directory traversal|\blfi\b|local file inclusion|file inclusion|\bssrf\b|server[- ]side request|open redirect|\bcsrf\b|cross[- ]site request forgery|\bcors\b|directory listing|forced browsing|exposed (file|folder|directory|\.git|\.env|backup|admin|panel|endpoint)|\.git\/|\.env\b|backup file|source ?map|missing (policy|gate|middleware)|without (auth|permission)/i],
  ['A07', /authenticat|\blog ?in\b|password|credential|brute[- ]?force|session (fixation|timeout|expir|hijack)|\bmfa\b|\b2fa\b|two[- ]factor|\bjwt\b|default (login|credential|password)|hard[- ]?coded|api[- ]?key|secret key|private key|access token|leaked (key|token|secret)|\bsecret\b|\btoken\b/i],
  ['A10', /exception|stack ?trace|error (message|handling|page|disclosure)|unhandled|uncaught|fails? open|null (pointer|reference)|division by zero|swallow|empty catch|catch[- ]all|crash/i],
  ['A09', /\blogg(ing|ed)\b|\blogs?\b(?! ?in)|audit (trail|log)|monitoring|alerting|log injection/i],
  ['A02', /misconfig|security header|missing header|\bheaders?\b|x-frame-options|content-security-policy|\bcsp\b|clickjack|x-content-type|referrer-policy|permissions-policy|httponly|samesite|secure flag|cookie (flag|attribute|without)|debug|app_debug|phpinfo|default (page|config|install|setting)|server (banner|version)|version disclos|\bxxe\b|xml external|tech(nology)? detect|exposed (config|setting)/i],
  ['A06', /insecure design|business logic|race condition|file upload|unrestricted upload|trust boundary|rate[- ]limit|no limit|abuse|replay|enumerat/i]
]

export interface OwaspInput {
  title: string
  /** Any more words: description, rule id, tags, template id. */
  text?: string
  severity?: string
  /** CWE numbers or strings like "CWE-79". */
  cwe?: (number | string)[]
}

const cweNumbers = (f: OwaspInput): number[] => {
  const out: number[] = []
  for (const c of f.cwe ?? []) {
    const n = typeof c === 'number' ? c : Number(/(\d+)/.exec(String(c))?.[1])
    if (Number.isFinite(n)) out.push(n)
  }
  for (const m of `${f.title} ${f.text ?? ''}`.matchAll(/\bCWE[- :]?(\d{1,4})\b/gi)) out.push(Number(m[1]))
  return out
}

/** The category a finding belongs to, or null when nothing fits (it then counts as other). */
export function owaspCategory(f: OwaspInput): OwaspId | null {
  // The reviewer named it ("OWASP: A05 Injection" or "A05:2025").
  const named = /(?:\bOWASP\b[^A-Za-z0-9]{0,12}|^\s*)(A0[1-9]|A10)\b|\b(A0[1-9]|A10):2025\b/i.exec(f.text ?? '') ?? /\b(A0[1-9]|A10):2025\b/i.exec(f.title)
  if (named) return (named[1] ?? named[2]).toUpperCase() as OwaspId
  for (const n of cweNumbers(f)) {
    const id = BY_CWE.get(n)
    if (id) return id
  }
  // The title says the most; the longer text only when the title alone does not fit.
  for (const text of [f.title, `${f.title} ${f.text ?? ''}`]) for (const [id, re] of WORDS) if (re.test(text)) return id
  return null
}

/** What each kind of test can see. A category is "checked" when one of the tests that ran covers it. */
export const OWASP_COVERAGE: Record<OwaspTest, OwaspId[]> = {
  'code-review': ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'],
  sast: ['A01', 'A02', 'A04', 'A05', 'A07', 'A08', 'A10'],
  secrets: ['A07'],
  dependencies: ['A03'],
  'web-scan': ['A01', 'A02', 'A03', 'A04', 'A05', 'A07', 'A10'],
  headers: ['A02', 'A04'],
  api: ['A01', 'A02', 'A05', 'A07']
}

export const OWASP_TEST_NAMES: Record<OwaspTest, string> = {
  'code-review': 'Code review',
  sast: 'Code scanners',
  secrets: 'Secrets scan',
  dependencies: 'Dependency audit',
  'web-scan': 'Web scan',
  headers: 'Header check',
  api: 'API scan'
}

export interface OwaspItem extends OwaspCategory {
  status: 'issues' | 'checked' | 'not-checked'
  count: number
  worst: OwaspSeverity | null
  /** Titles of up to five of its findings, worst first. */
  examples: string[]
  /** The tests that ran and cover it. */
  checkedBy: OwaspTest[]
}

export interface OwaspChecklist {
  items: OwaspItem[]
  /** Findings that fit none of the ten. */
  other: number
  /** How many of the ten were checked (with or without problems). */
  covered: number
}

const RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const sev = (s?: string): OwaspSeverity => (s && s.toLowerCase() in RANK ? (s.toLowerCase() as OwaspSeverity) : 'info')

/**
 * The checklist for one run: findings put under the ten, and which of the ten the tests that ran
 * could see. Info-only findings are listed but do not turn a category red.
 */
export function owaspChecklist(findings: OwaspInput[], tests: OwaspTest[]): OwaspChecklist {
  const ran = [...new Set(tests)].filter((t) => t in OWASP_COVERAGE)
  const groups = new Map<OwaspId, OwaspInput[]>()
  let other = 0
  for (const f of findings) {
    const id = owaspCategory(f)
    if (!id) {
      other++
      continue
    }
    groups.set(id, [...(groups.get(id) ?? []), f])
  }
  const items = OWASP_TOP10.map((c): OwaspItem => {
    const list = (groups.get(c.id) ?? []).slice().sort((a, b) => RANK[sev(b.severity)] - RANK[sev(a.severity)])
    const real = list.filter((f) => sev(f.severity) !== 'info')
    const checkedBy = ran.filter((t) => OWASP_COVERAGE[t].includes(c.id))
    return {
      ...c,
      status: real.length ? 'issues' : checkedBy.length || list.length ? 'checked' : 'not-checked',
      count: real.length,
      worst: list.length ? sev(list[0].severity) : null,
      examples: [...new Set(list.map((f) => f.title))].slice(0, 5),
      checkedBy
    }
  })
  return { items, other, covered: items.filter((i) => i.status !== 'not-checked').length }
}

/** The checklist as Markdown, for reports. */
export function owaspMarkdown(list: OwaspChecklist): string {
  const mark = (i: OwaspItem): string => (i.status === 'issues' ? `${i.count} to fix (worst: ${i.worst})` : i.status === 'checked' ? 'Checked, nothing found' : `Not checked: ${i.howToCheck}`)
  return ['## OWASP Top 10 (2025)', '', '| | Category | Result |', '|---|---|---|', ...list.items.map((i) => `| ${i.id} | ${i.name} | ${mark(i)} |`), ''].join('\n')
}
