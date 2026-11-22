/**
 * The checklist walk. Your own web checklist (52 sections, about 640 items) is gone through item by
 * item for one scan, and every item ends in one of these states:
 *
 *   found     MacSec tested it and found a problem (the findings are linked)
 *   clear     MacSec tested it and found nothing. That is "tested, nothing found", not a guarantee
 *   ai-ok     the AI read the evidence and sees no problem. An opinion, not a test
 *   ai-issue  the AI read the evidence and sees a problem, and names the finding that shows it
 *   manual    nothing MacSec ran speaks to it: do it by hand (the first step is given when the AI could say)
 *
 * The AI only reads the scan's evidence. It cannot attack, and an "issue" without a finding id that
 * really exists is turned back into "manual", so the AI cannot invent a problem. You can set any
 * item yourself (done, problem, not applicable); your answer always wins.
 */
import type { Finding } from '../shared/types'
import { SECTIONS, sectionsFor, type Profile } from './testplan'

export type ItemState = 'found' | 'clear' | 'ai-ok' | 'ai-issue' | 'manual'

export interface ChecklistItem {
  id: string
  text: string
  state: ItemState
  by: 'macsec' | 'ai' | 'none'
  /** Which MacSec check covered it. */
  covered?: string
  /** Finding ids that show a problem. */
  findings?: string[]
  note?: string
}

export interface ChecklistSection {
  n: number
  title: string
  /** Whether this section fits what the scan saw (a login page, a shop, an API). */
  relevant: boolean
  items: ChecklistItem[]
}

export interface Checklist {
  at: string
  ai: boolean
  sections: ChecklistSection[]
}

interface Rule {
  label: string
  item: RegExp
  /** The scan step that must have run for "clear" to be said. null means it always runs. */
  step: string | null
  finding: RegExp
}

export const RULES: Rule[] = [
  { label: 'Security headers', item: /security header|hsts|strict-transport|content-security-policy|\bcsp\b|x-frame|clickjack|x-content-type|referrer-policy|permissions-policy|cache-control/i, step: null, finding: /header|HSTS|Content-Security|framing|clickjack/i },
  { label: 'Cookie flags', item: /cookie.*(secure|httponly|samesite|flag)|(secure|httponly|samesite).*cookie/i, step: null, finding: /Cookie/i },
  { label: 'TLS and certificate', item: /\btls\b|\bssl\b|certificate|cipher|weak protocol|https (only|enforce)|mixed content/i, step: 'tls', finding: /TLS|certificate|HTTPS|HSTS|SSL/i },
  { label: 'Exposed files', item: /backup file|\.git\b|\.env\b|sensitive file|exposed file|directory listing|config(uration)? file|source (code )?disclosure|old file|default file/i, step: 'files', finding: /public|Hidden page|Folder lists|exposed|\.git|\.env|backup/i },
  { label: 'Public JavaScript', item: /javascript|api key|hard-?coded (secret|key|credential)|source ?map|client-side (secret|key)|secrets? in (the )?(front|client)/i, step: 'js', finding: /JavaScript|Source map|key|secret|token/i },
  { label: 'Known flaws in versions', item: /outdated|vulnerable (component|version|librar)|known vulnerabilit|\bcve\b|third-party (component|librar)|version (disclosure|banner)|software version/i, step: 'cves', finding: /known flaw|CVE|version|outdated|KEV/i },
  { label: 'Firewall, hosting and DNS', item: /\bwaf\b|firewall|cdn|\bdns\b|\bspf\b|dmarc|dkim|subdomain takeover|email security|zone transfer/i, step: 'infra', finding: /firewall|CDN|DNS|SPF|DMARC|CAA|takeover|hosting/i },
  { label: 'DevOps tools left open', item: /jenkins|docker|kubernetes|grafana|prometheus|terraform|ci\/cd|container registry|cloud (storage|bucket|metadata)|etcd|consul/i, step: 'devops', finding: /Jenkins|Docker|Kubernetes|Grafana|Prometheus|Terraform|registry|etcd|Consul|Elasticsearch|open without/i },
  { label: 'Injection tests', item: /\bxss\b|cross-?site scripting|sql ?injection|\bsqli\b|template injection|\bssti\b|crlf|header injection|html injection|input (is )?(not )?(sanitis|sanitiz|escap)|reflected|special characters|error-?based/i, step: 'inject', finding: /without escaping|database error|calculates an expression|line break in/i },
  { label: 'Verbose errors', item: /(stack ?trace|verbose error|error message|debug (mode|page)|information (leak|disclosure))/i, step: 'inject', finding: /database error|stack|debug|error page|phpinfo/i },
  { label: 'Hidden pages and parameters', item: /hidden (page|file|param|endpoint)|forced brows|content discovery|directory (brute|enum)|parameter (discovery|fuzz)|unlinked/i, step: 'fuzz', finding: /Hidden page|Hidden parameter|parameter/i },
  { label: 'Web firewall tests', item: /bypass.*waf|waf bypass|web application firewall/i, step: 'waf', finding: /firewall|WAF/i },
  { label: 'Login checks', item: /(user(name)? )?enumerat|lockout|account lock|rate limit|brute|wrong (password|guess)|throttl/i, step: 'login', finding: /usernames exist|emails have an account|does not slow down|wrong (codes|passwords)|rate/i },
  { label: 'Two-account access check', item: /idor|insecure direct object|horizontal|vertical privilege|access control|bola|cross-?tenant|privilege escalation|forced browsing to (admin|private)/i, step: 'authz', finding: /Another account can open|Shows the same content|private|admin|access/i },
  { label: 'Business logic checks', item: /open redirect|redirect (to|parameter)|host header|forwarded host|\botp\b|one.?time (code|password)|\bpin\b|skip(ping)? (a )?(step|stage)|workflow|password reset poison/i, step: 'logic', finding: /Open redirect|forwarded host|wrong codes|late step|values the server should decide/i }
]

/** Mark items from the scan itself. `ran` lists the steps that ran; findings are the open ones. */
export function autoMark(findings: Finding[], ran: string[], profile: Profile): Checklist {
  const open = findings.filter((f) => f.verdict !== 'false-positive' && !f.triage)
  const relevant = new Set(sectionsFor(profile))
  const sections: ChecklistSection[] = SECTIONS.map((s) => ({
    n: s.n,
    title: s.title,
    relevant: relevant.has(s.n),
    items: s.items.map((text, i) => {
      const item: ChecklistItem = { id: `${s.n}.${i + 1}`, text, state: 'manual', by: 'none' }
      for (const r of RULES) {
        if (!r.item.test(text)) continue
        if (r.step && !ran.includes(r.step)) continue
        const hits = open.filter((f) => r.finding.test(f.title)).slice(0, 6)
        item.covered = r.label
        if (hits.length) {
          item.state = 'found'
          item.by = 'macsec'
          item.findings = hits.map((h) => h.id)
          item.note = `${r.label}: ${hits.map((h) => h.title).slice(0, 2).join('; ')}`
        } else {
          item.state = 'clear'
          item.by = 'macsec'
          item.note = `${r.label} ran and found nothing.`
        }
        break
      }
      return item
    })
  }))
  return { at: new Date().toISOString(), ai: false, sections }
}

export function counts(c: Checklist): Record<ItemState, number> & { total: number } {
  const out = { found: 0, clear: 0, 'ai-ok': 0, 'ai-issue': 0, manual: 0, total: 0 }
  for (const s of c.sections) for (const i of s.items) (out[i.state]++, out.total++)
  return out
}

// ---------------------------------------------------------------- The AI walk

export interface AiAnswer {
  id: string
  state: 'ok' | 'issue' | 'unknown'
  evidence?: string[]
  note?: string
  first?: string
}

/** The JSON array in the AI's answer, in the shape asked for. Anything else is ignored. */
export function parseAnswers(text: string): AiAnswer[] {
  const m = /```(?:json)?\s*([\s\S]*?)```/i.exec(text) ?? /(\[[\s\S]*\])/.exec(text)
  if (!m) return []
  try {
    const arr = JSON.parse(m[1]) as unknown
    if (!Array.isArray(arr)) return []
    return arr
      .filter((x): x is Record<string, unknown> => !!x && typeof x === 'object')
      .map((x) => ({ id: String(x.id ?? ''), state: (['ok', 'issue', 'unknown'].includes(String(x.state)) ? String(x.state) : 'unknown') as AiAnswer['state'], evidence: Array.isArray(x.evidence) ? x.evidence.map(String).slice(0, 6) : [], note: typeof x.note === 'string' ? x.note.slice(0, 300) : undefined, first: typeof x.first === 'string' ? x.first.slice(0, 300) : undefined }))
      .filter((x) => /^\d+\.\d+$/.test(x.id))
  } catch {
    return []
  }
}

/** Applies the AI's answers. An issue must name a finding that exists, otherwise it is "manual". */
export function applyAnswers(c: Checklist, answers: AiAnswer[], findings: Finding[]): number {
  const ids = new Set(findings.map((f) => f.id))
  const by = new Map(answers.map((a) => [a.id, a]))
  let n = 0
  for (const s of c.sections)
    for (const i of s.items) {
      const a = by.get(i.id)
      if (!a || i.state !== 'manual') continue
      if (a.state === 'issue') {
        const real = (a.evidence ?? []).filter((e) => ids.has(e))
        if (!real.length) {
          i.note = a.first ? `Try by hand: ${a.first}` : undefined
          continue
        }
        i.state = 'ai-issue'
        i.by = 'ai'
        i.findings = real
        i.note = a.note
        n++
      } else if (a.state === 'ok') {
        // "No problem" is only believed when the AI points at evidence that exists too: silence is not a pass.
        const real = (a.evidence ?? []).filter((e) => ids.has(e) || e === 'profile')
        if (!real.length) {
          i.note = a.first ? `Try by hand: ${a.first}` : undefined
          continue
        }
        i.state = 'ai-ok'
        i.by = 'ai'
        i.note = a.note
        n++
      } else if (a.first) i.note = `Try by hand: ${a.first}`
    }
  return n
}

/** The prompt for one batch of items. Evidence is the scan's findings and what ran, nothing else. */
export function walkPrompt(target: string, evidence: { findings: Finding[]; ran: string[]; profileText: string }, items: { id: string; text: string }[]): string {
  const list = evidence.findings
    .filter((f) => f.severity !== 'info' || /not tested|not linked/i.test(f.title))
    .slice(0, 120)
    .map((f) => `- id=${f.id} [${f.severity}] ${f.title}${f.url ? ` at ${f.url}` : ''}`)
    .join('\n')
  return `You are helping a security tester go through their own web checklist for ${target}. A scan has run. You can only read its evidence below: you cannot visit the site, and you must not guess.

What the scan ran: ${evidence.ran.join(', ') || 'the basic checks'}.
${evidence.profileText}

Scan findings (the only evidence you may cite):
${list || '(none)'}

For each checklist item below, decide:
- "issue": a finding above shows this problem. You MUST list its id in "evidence".
- "ok": the scan's evidence shows this is fine. You MUST list at least one finding id in "evidence" that supports it, or the word "profile" if the profile above shows it (for example no login page was seen, so a login item does not apply). Do not say ok when nothing was tested.
- "unknown": the evidence says nothing about it (most items). Then give "first": the single most useful first step for a person to try by hand (under 25 words, concrete).
Be strict: it is far better to say "unknown" than to guess. Never invent a finding id.

Reply with one fenced json array only, one object per item: [{"id":"3.2","state":"unknown","evidence":[],"note":"","first":"..."}]

Items:
${items.map((i) => `${i.id} ${i.text}`).join('\n')}`
}

export const BATCH = 45
