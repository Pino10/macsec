/**
 * A test plan from the person's own web checklist (52 sections, about 640 items). The scan's
 * pages and signals decide which sections matter for this site: a login page brings the login
 * page tests, a shop brings the shop and checkout logic tests, and so on. The result is a plan
 * to work through by hand, with the checks MacSec already ran marked, and the same facts are
 * given to the AI so it can say what to try first and why.
 */
import list from './data/webchecklist.json'

export interface Section {
  n: number
  title: string
  items: string[]
}

export const SECTIONS = (list as { sections: Section[] }).sections
const sec = (n: number): Section | undefined => SECTIONS.find((s) => s.n === n)

export type PageKind = 'login' | 'register' | 'otp' | 'forgot' | 'profile' | 'password' | 'upload' | 'search' | 'admin' | 'checkout'

const PAGES: { kind: PageKind; label: string; re: RegExp; main: number; more: number[] }[] = [
  { kind: 'login', label: 'Login page', re: /(^|[/_.-])(log-?in|sign-?in|signon|session|wp-login)([/_.?-]|$)/i, main: 39, more: [1, 49] },
  { kind: 'register', label: 'Registration page', re: /(register|sign-?up|join|create-?account|new-?account)/i, main: 40, more: [1] },
  { kind: 'otp', label: 'OTP or MFA page', re: /([/_.-])(otp|2fa|mfa|two-?factor|verify|verification|passcode)([/_.?-]|$)/i, main: 41, more: [1, 49] },
  { kind: 'forgot', label: 'Forgot password page', re: /(forgot|recover|reset-?pass|password-?reset|lost-?pass)/i, main: 42, more: [1] },
  { kind: 'password', label: 'Change password page', re: /(change-?pass|update-?pass|password\/(change|update))/i, main: 44, more: [1, 50] },
  { kind: 'profile', label: 'Profile and account settings', re: /([/_.-])(profile|account|settings|preferences|my-?account|me)([/_.?-]|$)/i, main: 43, more: [2] },
  { kind: 'upload', label: 'File upload', re: /(upload|attachment|import|avatar|dropzone)/i, main: 45, more: [4] },
  { kind: 'search', label: 'Search and filter', re: /([/_.-])(search|filter|query|find)([/_.?=-]|$)|[?&](q|query|search|s)=/i, main: 46, more: [3, 51] },
  { kind: 'admin', label: 'Admin panel', re: /([/_.-])(admin|administrator|backoffice|staff|manage|console)([/_.?-]|$)/i, main: 47, more: [2] },
  { kind: 'checkout', label: 'Checkout and payment', re: /(checkout|basket|cart|payment|billing|pay\b|invoice)/i, main: 48, more: [24, 25] }
]

const SIGNALS: { label: string; re: RegExp; sections: number[] }[] = [
  { label: 'GraphQL', re: /graphql|\/gql\b/i, sections: [36] },
  { label: 'webhooks', re: /webhook|\/hooks?\//i, sections: [37] },
  { label: 'OAuth or single sign-on', re: /oauth|\/authorize|sso|saml|openid|\/callback/i, sections: [19] },
  { label: 'an API', re: /\/api\/|\/v[1-3]\/|\/rest\//i, sections: [7, 52] },
  { label: 'an AI or chat feature', re: /\/(chat|assistant|copilot|completions?|prompt|ai)(\/|$|\?)/i, sections: [38] }
]

const DOMAINS: { label: string; re: RegExp; section: number }[] = [
  { label: 'online banking or finance', re: /\b(iban|loan|transfer|beneficiary|statement|mortgage)\b|banking/i, section: 23 },
  { label: 'a shop', re: /\b(cart|basket|product|products|shop|store|wishlist|coupon|catalog)\b/i, section: 25 },
  { label: 'a software-as-a-service product with teams', re: /\b(tenant|workspace|organi[sz]ation|team|teams|seats|plan|billing)\b/i, section: 26 },
  { label: 'a health or patient portal', re: /\b(patient|appointment|prescription|clinic|health|medical)\b/i, section: 27 },
  { label: 'an HR or payroll system', re: /\b(payroll|leave|employee|employees|timesheet|hr)\b/i, section: 28 },
  { label: 'gaming, betting or rewards', re: /\b(game|games|bet|betting|casino|reward|rewards|loyalty|points)\b/i, section: 29 },
  { label: 'logistics or delivery', re: /\b(delivery|shipment|shipping|driver|dispatch|tracking|courier)\b/i, section: 30 },
  { label: 'travel or ticketing', re: /\b(booking|flight|flights|hotel|ticket|tickets|reservation|itinerary)\b/i, section: 31 },
  { label: 'a social or content platform', re: /\b(feed|follow|followers|comment|comments|post|posts|timeline)\b/i, section: 32 },
  { label: 'crypto or digital wallets', re: /\b(crypto|swap|withdraw|deposit|wallet|token|tokens)\b/i, section: 33 }
]

export interface Profile {
  pages: Partial<Record<PageKind, string[]>>
  signals: { label: string; sections: number[] }[]
  domains: { label: string; section: number }[]
}

/** What kind of site this looks like, from the addresses the scan found. */
export function profileSite(urls: string[]): Profile {
  const pages: Profile['pages'] = {}
  const paths = [...new Set(urls)].map((u) => {
    try {
      const p = new URL(u)
      return { u, text: p.pathname + p.search }
    } catch {
      return { u, text: u }
    }
  })
  for (const { u, text } of paths) for (const r of PAGES) if (r.re.test(text)) (pages[r.kind] ??= []).push(u)
  const all = paths.map((p) => p.text).join('\n')
  const signals = SIGNALS.filter((s) => s.re.test(all)).map((s) => ({ label: s.label, sections: s.sections }))
  const domains = DOMAINS.filter((d) => d.re.test(all.replace(/[/_.-]/g, ' '))).map((d) => ({ label: d.label, section: d.section }))
  for (const k of Object.keys(pages) as PageKind[]) pages[k] = [...new Set(pages[k])].slice(0, 4)
  return { pages, signals, domains: domains.slice(0, 3) }
}

/** Which of MacSec's own confirmations covers an item, so the person does not repeat work already done. */
const COVERS: { key: 'fuzz' | 'waf' | 'auth' | 'authz' | 'logic' | 'inject' | 'proto'; label: string; re: RegExp }[] = [
  { key: 'auth', label: 'Login checks', re: /enumerat|lockout|account lock|rate limit|brute|wrong (password|guess)/i },
  { key: 'fuzz', label: 'Hidden pages and parameters', re: /directory|hidden (page|file|param|endpoint)|content discovery|forced brows|backup file|parameter (discovery|fuzz)/i },
  { key: 'waf', label: 'Web firewall tests', re: /\bwaf\b|web application firewall/i },
  { key: 'logic', label: 'Business logic checks', re: /open redirect|redirect (to|parameter)|host header|forwarded host|otp|one.?time (code|password)|pin\b.*(limit|guess)|skip(ping)? (a )?(step|stage)|workflow|order of steps|hidden (price|field)|client-?side (price|total)/i },
  { key: 'inject', label: 'Injection tests', re: /\bxss\b|cross-?site scripting|sql ?injection|template injection|\bssti\b|crlf|header injection|html injection|reflected input/i },
  { key: 'proto', label: 'OAuth, token, GraphQL, CORS, CSRF and session checks', re: /oauth.*\bstate\b|redirect_uri|\bpkce\b|\bjwt\b|json web token|alg(orithm)?.{0,20}none|introspection|graphiql|playground|\bcors\b|session fixation/i },
  { key: 'authz', label: 'Two-account access check', re: /idor|direct object|horizontal|vertical privilege|access control|bola|cross-?tenant/i }
]

export const coveredBy = (item: string, ran: string[]): string | null => COVERS.find((c) => ran.includes(c.key) && c.re.test(item))?.label ?? null

const trim = (s: string, n: number): string => (s.length <= n ? s : `${s.slice(0, s.lastIndexOf(' ', n))}…`)

/** Which section numbers a profile calls for, most specific first. */
export function sectionsFor(p: Profile): number[] {
  const out: number[] = []
  const add = (n: number): void => {
    if (!out.includes(n) && sec(n)) out.push(n)
  }
  for (const r of PAGES) if (p.pages[r.kind]) [r.main, ...r.more].forEach(add)
  p.signals.forEach((s) => s.sections.forEach(add))
  p.domains.forEach((d) => add(d.section))
  // Business logic that applies to every site with accounts.
  ;[22, 34, 35].forEach(add)
  return out
}

/** The plan, as Markdown for the session's report tab. */
export function planMarkdown(p: Profile, target: string, ran: string[] = []): string {
  const lines: string[] = [`# Test plan from your checklist: ${target}`, '']
  const seen: string[] = []
  for (const r of PAGES) if (p.pages[r.kind]) seen.push(`${r.label} (${p.pages[r.kind]!.map((u) => { try { return new URL(u).pathname } catch { return u } }).join(', ')})`)
  lines.push('## What the scan saw', '')
  lines.push(seen.length ? `- Pages: ${seen.join('; ')}` : '- No sign-in, account or checkout pages were found by the scan, so the general sections come first. Sign in above and scan again to reach more.')
  if (p.signals.length) lines.push(`- Also: ${p.signals.map((s) => s.label).join(', ')}`)
  if (p.domains.length) lines.push(`- It looks like: ${p.domains.map((d) => d.label).join(' or ')} (a guess from the addresses, so check it)`)
  if (ran.length) lines.push(`- MacSec already ran: ${COVERS.filter((c) => ran.includes(c.key)).map((c) => c.label).join(', ')}. Items they cover are marked, and their results are in the findings.`)
  lines.push('')
  const mark = (item: string): string => {
    const c = coveredBy(item, ran)
    return c ? ` *(MacSec ran: ${c})*` : ''
  }
  const order = sectionsFor(p)
  const start = order.filter((n) => PAGES.some((r) => p.pages[r.kind] && (r.main === n || r.more.includes(n))) || p.signals.some((s) => s.sections.includes(n)) || p.domains.some((d) => d.section === n))
  lines.push('## Work through these, in this order', '')
  for (const n of order) {
    const s = sec(n)!
    lines.push(`### ${s.n}. ${s.title}`, '')
    s.items.forEach((it, i) => lines.push(`${i + 1}. ${it}${mark(it)}`))
    lines.push('')
  }
  const notSeen = PAGES.filter((r) => !p.pages[r.kind]).map((r) => r.label)
  if (notSeen.length) lines.push('## Not seen on this site', '', `The scan did not find: ${notSeen.join(', ')}. Skip their sections unless you know they exist (the scan only sees what is linked or crawled).`, '')
  lines.push(`_${start.length} of ${order.length} sections come from pages or features the scan saw; the rest apply to most sites with accounts._`)
  return lines.join('\n')
}

/** A short version for the AI: the site profile and the checklist items, trimmed. */
export function planContext(p: Profile, ran: string[] = [], maxItems = 140): string {
  const parts: string[] = []
  const pages = PAGES.filter((r) => p.pages[r.kind]).map((r) => `${r.label}: ${p.pages[r.kind]!.join(', ')}`)
  parts.push(`Pages the scan found: ${pages.join(' | ') || 'none of the usual account pages'}.`)
  if (p.signals.length) parts.push(`Features seen: ${p.signals.map((s) => s.label).join(', ')}.`)
  if (p.domains.length) parts.push(`The addresses suggest: ${p.domains.map((d) => d.label).join(' or ')}.`)
  const items: string[] = []
  for (const n of sectionsFor(p)) {
    const s = sec(n)!
    for (const it of s.items) {
      if (coveredBy(it, ran)) continue
      if (items.length < maxItems) items.push(`[${s.n}] ${trim(it, 230)}`)
    }
  }
  return `${parts.join('\n')}\nChecklist items that fit (section number in brackets):\n${items.join('\n')}`
}
