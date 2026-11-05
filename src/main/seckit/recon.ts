/**
 * Recon: map what a domain exposes, without attacking it. Shared by Laramac and MacSec (keep the
 * two copies of src/main/seckit the same).
 *
 * Every request is an ordinary read: DNS lookups, public archives and certificate logs, and plain
 * GETs at a gentle rate. Nothing is fuzzed, guessed, brute-forced or exploited, and nothing outside
 * the domain and its subdomains is touched.
 *
 *   passive   certificate transparency (crt.sh), the Wayback Machine, subfinder's passive sources and
 *             DNS. Nothing is sent to the target's own servers.
 *   standard  + which hosts answer and what they run, a light crawl, every JavaScript file checked
 *             for source maps, endpoints and keys, and a short list of files that should not be public
 *   deep      + more hosts, pages and scripts, and archived JavaScript too
 */
import { promises as dns } from 'dns'
import { createHash } from 'crypto'

export type ReconDepth = 'passive' | 'standard' | 'deep'
export type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface ReconFinding {
  id: string
  severity: Sev
  title: string
  url?: string
  description?: string
  fix?: string
  /** What kind of check found it. */
  kind: 'subdomain' | 'sourcemap' | 'secret' | 'exposure' | 'headers' | 'takeover' | 'endpoint' | 'tech'
}

export interface HostInfo {
  host: string
  ips: string[]
  cname?: string
  live?: { url: string; status: number; title?: string; server?: string; poweredBy?: string; tech: string[]; redirect?: string }
  sources: string[]
}

export interface JsInfo {
  url: string
  bytes: number
  sourceMap?: { url: string; files: number; sample: string[] }
  endpoints: string[]
  secrets: { kind: string; masked: string }[]
}

/** One page read during the crawl, broken down: what is on it and how it is protected. */
export interface PageInfo {
  url: string
  status: number
  title?: string
  type: string
  bytes: number
  ms: number
  redirect?: string
  forms: { action: string; method: string; inputs: { name: string; type: string }[]; csrf: boolean; password: boolean; offsite: boolean; insecure: boolean }[]
  /** Names of query parameters in the page's links and its own address. */
  params: string[]
  scripts: { total: number; inline: number; external: string[]; withoutSri: number }
  headers: { name: string; present: boolean; value?: string }[]
  /** Cookie names and flags only: never their values. */
  cookies: { name: string; secure: boolean; httpOnly: boolean; sameSite: string | null }[]
  tech: string[]
  /** http:// resources on an https page. */
  mixed: number
  /** What stands out, in plain words, worst first. */
  notes: { severity: Sev; text: string }[]
}

export interface ReconResult {
  domain: string
  hosts: HostInfo[]
  urls: string[]
  params: string[]
  js: JsInfo[]
  endpoints: string[]
  findings: ReconFinding[]
  /** Every page the crawl read, one by one. */
  pages?: PageInfo[]
}

export interface ReconContext {
  depth: ReconDepth
  /** Step progress for the window: id, label, status and an optional note. */
  step: (id: string, label: string, status: 'running' | 'done' | 'skipped' | 'failed', detail?: string) => void
  line: (text: string) => void
  cancelled: () => boolean
  /** Path to an installed tool (subfinder), or null. */
  tool: (name: string) => string | null
  run: (bin: string, args: string[], timeoutMs: number) => Promise<string>
  userAgent?: string
}

const LIMITS: Record<ReconDepth, { hosts: number; pages: number; js: number; archive: number; archivedJs: number }> = {
  passive: { hosts: 0, pages: 0, js: 0, archive: 5000, archivedJs: 0 },
  standard: { hosts: 60, pages: 40, js: 80, archive: 10000, archivedJs: 0 },
  deep: { hosts: 250, pages: 150, js: 300, archive: 50000, archivedJs: 100 }
}

export const fid = (...p: unknown[]): string => createHash('sha1').update(p.map(String).join('|')).digest('hex').slice(0, 12)

/** A domain from whatever was typed: "https://www.shop.example.com/x" becomes shop.example.com's apex guess. */
export function normalizeTarget(input: string): { domain: string; url: string } {
  const raw = input.trim().toLowerCase()
  const host = raw.replace(/^[a-z]+:\/\//, '').replace(/[/?#:].*$/, '').replace(/^\*\./, '').replace(/\.$/, '')
  if (!/^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(host) && !/^[a-z0-9-]+\.(test|localhost)$/.test(host)) throw new Error('Enter a domain, such as example.com.')
  const domain = host.replace(/^www\./, '')
  return { domain, url: /^https?:\/\//.test(raw) ? raw.replace(/\/+$/, '') : `https://${host}` }
}

export const inScope = (host: string, domain: string): boolean => host === domain || host.endsWith(`.${domain}`)

async function pool<T, R>(items: T[], n: number, fn: (t: T) => Promise<R>, cancelled: () => boolean): Promise<R[]> {
  const out: R[] = []
  let i = 0
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (i < items.length && !cancelled()) {
        const t = items[i++]
        out.push(await fn(t))
      }
    })
  )
  return out
}

// ---------------------------------------------------------------- Passive sources

export function parseCrtSh(json: string, domain: string): string[] {
  let rows: { name_value?: string; common_name?: string }[] = []
  try {
    rows = JSON.parse(json)
  } catch {
    return []
  }
  const names = new Set<string>()
  for (const r of rows) for (const n of `${r.name_value ?? ''}\n${r.common_name ?? ''}`.split('\n')) {
    const h = n.trim().toLowerCase().replace(/^\*\./, '')
    if (h && inScope(h, domain) && !/[^a-z0-9.-]/.test(h)) names.add(h)
  }
  return [...names].sort()
}

/** More free passive sources. None of them contacts the target; each needs no account. */
export const PASSIVE_SOURCES: { id: string; name: string; url: (d: string) => string }[] = [
  { id: 'certspotter', name: 'CertSpotter', url: (d) => `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(d)}&include_subdomains=true&expand=dns_names` },
  { id: 'otx', name: 'AlienVault OTX', url: (d) => `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(d)}/passive_dns` },
  { id: 'hackertarget', name: 'HackerTarget', url: (d) => `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(d)}` },
  { id: 'urlscan', name: 'urlscan.io', url: (d) => `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(d)}&size=200` },
  { id: 'anubis', name: 'Anubis', url: (d) => `https://jldc.me/anubis/subdomains/${encodeURIComponent(d)}` }
]

/** Host names from one passive source's answer, only those inside the domain. */
export function parsePassive(id: string, text: string, domain: string): string[] {
  const names = new Set<string>()
  const add = (n: unknown): void => {
    if (typeof n !== 'string') return
    const h = n.trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '')
    if (h && inScope(h, domain) && !/[^a-z0-9.-]/.test(h)) names.add(h)
  }
  try {
    if (id === 'hackertarget') {
      // "host,ip" per line, or an error sentence.
      for (const line of text.split('\n')) if (line.includes(',')) add(line.split(',')[0])
    } else {
      const j = JSON.parse(text) as unknown
      if (id === 'certspotter' && Array.isArray(j)) for (const r of j as { dns_names?: string[] }[]) (r.dns_names ?? []).forEach(add)
      if (id === 'otx') for (const r of ((j as { passive_dns?: { hostname?: string }[] }).passive_dns ?? [])) add(r.hostname)
      if (id === 'urlscan') for (const r of ((j as { results?: { page?: { domain?: string }; task?: { domain?: string } }[] }).results ?? [])) {
        add(r.page?.domain)
        add(r.task?.domain)
      }
      if (id === 'anubis' && Array.isArray(j)) (j as unknown[]).forEach(add)
    }
  } catch {
    return []
  }
  return [...names].sort()
}

/** Rows from the Wayback Machine's CDX API (JSON output): the first row is the header. */
export function parseWayback(json: string, domain: string): string[] {
  let rows: string[][] = []
  try {
    rows = JSON.parse(json)
  } catch {
    return []
  }
  const out = new Set<string>()
  for (const r of rows.slice(1)) {
    const u = r[0]
    try {
      const h = new URL(u).hostname.toLowerCase()
      if (inScope(h, domain)) out.add(u.replace(/:80\//, '/').replace(/:443\//, '/'))
    } catch {
      // Not a URL.
    }
  }
  return [...out]
}

export function parseSubfinder(jsonl: string, domain: string): string[] {
  const out = new Set<string>()
  for (const line of jsonl.split('\n')) {
    const t = line.trim()
    if (!t) continue
    let h = t
    if (t.startsWith('{')) {
      try {
        h = (JSON.parse(t) as { host?: string }).host ?? ''
      } catch {
        continue
      }
    }
    h = h.toLowerCase()
    if (inScope(h, domain)) out.add(h)
  }
  return [...out]
}

// ---------------------------------------------------------------- What URLs tell us

const INTERESTING = /\.(env|sql|bak|old|zip|tar|gz|tgz|7z|log|conf|config|ini|ya?ml|json|xml|pem|key|p12|pfx|swp|db|sqlite|csv|xlsx?)(\?|$)|\/(admin|administrator|wp-admin|phpmyadmin|adminer|backup|debug|internal|private|swagger|api-docs|openapi|graphql|graphiql|actuator|console|_profiler|telescope|horizon|\.git)(\/|\?|$)/i

/** Parameter names seen in URLs: the places worth testing by hand. */
export function paramsOf(urls: string[]): string[] {
  const out = new Map<string, number>()
  for (const u of urls) {
    try {
      for (const k of new URL(u).searchParams.keys()) if (/^[\w.[\]-]{1,40}$/.test(k)) out.set(k, (out.get(k) ?? 0) + 1)
    } catch {
      // Skip.
    }
  }
  return [...out.entries()].sort((a, b) => b[1] - a[1]).map(([k]) => k)
}

export const interestingUrls = (urls: string[]): string[] => urls.filter((u) => INTERESTING.test(u))

// ---------------------------------------------------------------- Takeover hints

/** Services where a CNAME to a deleted resource can be claimed by someone else. */
export const TAKEOVER: [RegExp, string][] = [
  [/\.s3(-website)?[.-][a-z0-9-]*\.amazonaws\.com$|\.s3\.amazonaws\.com$/, 'Amazon S3'],
  [/\.cloudfront\.net$/, 'Amazon CloudFront'],
  [/\.elasticbeanstalk\.com$/, 'AWS Elastic Beanstalk'],
  [/\.azurewebsites\.net$/, 'Azure App Service'],
  [/\.cloudapp\.(net|azure\.com)$/, 'Azure Cloud Service'],
  [/\.blob\.core\.windows\.net$/, 'Azure Blob Storage'],
  [/\.trafficmanager\.net$/, 'Azure Traffic Manager'],
  [/\.azureedge\.net$/, 'Azure CDN'],
  [/\.herokuapp\.com$|\.herokudns\.com$/, 'Heroku'],
  [/\.github\.io$/, 'GitHub Pages'],
  [/\.netlify\.(app|com)$/, 'Netlify'],
  [/\.vercel\.app$|cname\.vercel-dns\.com$/, 'Vercel'],
  [/\.myshopify\.com$/, 'Shopify'],
  [/\.ghost\.io$/, 'Ghost'],
  [/\.surge\.sh$/, 'Surge'],
  [/\.readthedocs\.io$/, 'Read the Docs'],
  [/\.fly\.dev$/, 'Fly.io'],
  [/\.zendesk\.com$/, 'Zendesk'],
  [/\.wpengine\.com$/, 'WP Engine'],
  [/\.pantheonsite\.io$/, 'Pantheon']
]
export const takeoverService = (cname: string): string | null => TAKEOVER.find(([re]) => re.test(cname.toLowerCase()))?.[1] ?? null

// ---------------------------------------------------------------- Pages

export function titleOf(html: string): string | undefined {
  return /<title[^>]*>([^<]{0,200})<\/title>/i.exec(html)?.[1]?.trim().replace(/\s+/g, ' ')
}

/** Rough technology hints from headers and the page, like Wappalyzer's simplest rules. */
export function techOf(headers: Headers, html: string): string[] {
  const t = new Set<string>()
  const h = (k: string): string => headers.get(k) ?? ''
  const server = h('server')
  if (server) t.add(server.split(' ')[0])
  if (h('x-powered-by')) t.add(h('x-powered-by'))
  const gen = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i.exec(html)?.[1]
  if (gen) t.add(gen)
  const rules: [RegExp, string][] = [
    [/\/_next\/static\//, 'Next.js'],
    [/__NUXT__|\/_nuxt\//, 'Nuxt'],
    [/wp-content\/|wp-includes\//, 'WordPress'],
    [/laravel_session|XSRF-TOKEN/i, 'Laravel'],
    [/ng-version=|ng-app/, 'Angular'],
    [/data-reactroot|__REACT_DEVTOOLS|react-dom/, 'React'],
    [/data-v-[a-f0-9]{8}|__VUE__/, 'Vue'],
    [/\/static\/js\/main\.[a-f0-9]+\.js/, 'Create React App'],
    [/cdn\.shopify\.com/, 'Shopify'],
    [/__sveltekit|svelte-/, 'SvelteKit'],
    [/astro-island|data-astro/, 'Astro'],
    [/firebaseapp\.com|firebaseio\.com/, 'Firebase'],
    [/supabase\.co/, 'Supabase']
  ]
  const blob = `${html.slice(0, 200000)}\n${h('set-cookie')}`
  for (const [re, name] of rules) if (re.test(blob)) t.add(name)
  if (h('cf-ray')) t.add('Cloudflare')
  if (h('x-vercel-id')) t.add('Vercel')
  if (h('x-amz-cf-id')) t.add('CloudFront')
  if (/AzureWebsites|ARRAffinity/i.test(h('set-cookie'))) t.add('Azure App Service')
  return [...t]
}

/** Links and scripts in a page that stay on the domain. */
export function linksOf(html: string, base: string, domain: string): { pages: string[]; scripts: string[] } {
  const pages = new Set<string>()
  const scripts = new Set<string>()
  for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) add(m[1], scripts)
  for (const m of html.matchAll(/<a[^>]+href=["']([^"'#]+)["']/gi)) add(m[1], pages)
  for (const m of html.matchAll(/<link[^>]+href=["']([^"']+\.js[^"']*)["']/gi)) add(m[1], scripts)
  function add(href: string, set: Set<string>): void {
    try {
      const u = new URL(href, base)
      if (/^https?:$/.test(u.protocol) && inScope(u.hostname, domain)) set.add(u.href.replace(/#.*$/, ''))
    } catch {
      // Not a URL.
    }
  }
  return { pages: [...pages], scripts: [...scripts] }
}

const SECURITY_HEADERS = ['content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy']
const CSRF_NAME = /csrf|xsrf|authenticity_token|^_token$|requestverificationtoken|__requestdigest|^nonce$|form_key|_wpnonce/i

const attr = (tag: string, name: string): string | undefined => new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag)?.slice(1).find((v) => v !== undefined)

/** The cookies a response sets: names and flags only. */
export function cookiesOf(headers: Headers): PageInfo['cookies'] {
  const raw = typeof headers.getSetCookie === 'function' ? headers.getSetCookie() : (headers.get('set-cookie') ?? '').split(/,(?=\s*[^;,=\s]+=)/)
  return raw
    .filter((c) => c.trim())
    .map((c) => {
      const [pair, ...flags] = c.split(';').map((x) => x.trim())
      const f = flags.map((x) => x.toLowerCase())
      // A cookie that is being deleted (empty, or expiring now) is not a risk.
      const deleting = /=\s*$/.test(pair) || f.some((x) => x === 'max-age=0')
      return { name: pair.split('=')[0].trim(), secure: f.includes('secure'), httpOnly: f.includes('httponly'), sameSite: f.find((x) => x.startsWith('samesite='))?.slice(9) ?? null, deleting }
    })
    .filter((c) => c.name && !c.deleting)
    .map(({ deleting: _d, ...c }) => c)
}

/** The forms in a page: where they send, how, which fields, and whether a CSRF token is there. */
export function formsOf(html: string, base: string): PageInfo['forms'] {
  const out: PageInfo['forms'] = []
  for (const m of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const tag = m[1]
    const method = (attr(tag, 'method') ?? 'get').toLowerCase()
    let action = base
    try {
      action = new URL(attr(tag, 'action') ?? '', base).href
    } catch {
      /* keep the page */
    }
    const inputs: { name: string; type: string }[] = []
    for (const i of m[2].matchAll(/<(input|select|textarea)\b([^>]*)>/gi)) {
      const name = attr(i[2], 'name')
      if (!name) continue
      inputs.push({ name, type: i[1].toLowerCase() === 'input' ? (attr(i[2], 'type') ?? 'text').toLowerCase() : i[1].toLowerCase() })
    }
    const b = new URL(base)
    const a = new URL(action)
    out.push({
      action: a.href,
      method,
      inputs: inputs.slice(0, 40),
      csrf: inputs.some((x) => x.type === 'hidden' && CSRF_NAME.test(x.name)),
      password: inputs.some((x) => x.type === 'password'),
      offsite: a.hostname !== b.hostname,
      insecure: a.protocol === 'http:'
    })
  }
  return out
}

/** One page, broken down. Read only: it looks at what the server already sent. */
export function pageInfo(url: string, status: number, headers: Headers, html: string, ms: number, redirect?: string): PageInfo {
  const https = url.startsWith('https:')
  const host = new URL(url).hostname
  const forms = formsOf(html, url)
  const params = new Set<string>()
  for (const u of [url, ...[...html.matchAll(/<a[^>]+href=["']([^"'#]+)["']/gi)].map((m) => m[1])]) {
    try {
      const x = new URL(u.replace(/&amp;/g, '&'), url)
      if (x.hostname === host) for (const k of x.searchParams.keys()) params.add(k)
    } catch {
      /* not a link */
    }
  }
  const tags = [...html.matchAll(/<script\b([^>]*)>/gi)].map((m) => m[1])
  const ext = tags.filter((t) => attr(t, 'src'))
  const externalHosts = new Set<string>()
  let withoutSri = 0
  for (const t of ext) {
    try {
      const u = new URL(attr(t, 'src')!, url)
      if (u.hostname !== host) {
        externalHosts.add(u.hostname)
        if (!attr(t, 'integrity')) withoutSri++
      }
    } catch {
      /* odd src */
    }
  }
  const sec = SECURITY_HEADERS.map((name) => ({ name, present: headers.has(name), ...(headers.get(name) ? { value: headers.get(name)!.slice(0, 300) } : {}) }))
  const cookies = cookiesOf(headers)
  const mixed = https ? [...html.matchAll(/<(?:script|img|iframe|link|audio|video|source)\b[^>]+(?:src|href)=["']http:\/\/[^"']+/gi)].length : 0
  const notes: PageInfo['notes'] = []
  const isHtml = /html/i.test(headers.get('content-type') ?? '')
  for (const f of forms) {
    if (f.password && (f.insecure || !https)) notes.push({ severity: 'high', text: `A password form sends over plain http (${f.action}).` })
    if (f.method === 'post' && !f.csrf) notes.push({ severity: f.password ? 'medium' : 'low', text: `A ${f.password ? 'login ' : ''}form posting to ${new URL(f.action).pathname} has no CSRF token field. The site may protect it another way (SameSite cookies, a header): check it.` })
    if (f.offsite) notes.push({ severity: 'info', text: `A form sends to another site: ${new URL(f.action).hostname}.` })
  }
  if (isHtml && status < 400) {
    if (!headers.has('content-security-policy')) notes.push({ severity: 'low', text: 'No Content-Security-Policy: nothing limits which scripts can run if one gets injected.' })
    if (!headers.has('x-frame-options') && !/frame-ancestors/i.test(headers.get('content-security-policy') ?? '')) notes.push({ severity: 'low', text: 'Other sites can put this page in a frame (no X-Frame-Options or frame-ancestors).' })
    if (https && !headers.has('strict-transport-security')) notes.push({ severity: 'low', text: 'No Strict-Transport-Security, so a first visit can be downgraded to http.' })
  }
  for (const c of cookies) {
    if (https && !c.secure) notes.push({ severity: 'low', text: `Cookie ${c.name} can travel over plain http (no Secure).` })
    if (!c.httpOnly && /sess|auth|token|sid|remember/i.test(c.name)) notes.push({ severity: 'medium', text: `Cookie ${c.name} looks like a session, and JavaScript can read it (no HttpOnly).` })
  }
  if (mixed) notes.push({ severity: 'medium', text: `${mixed} ${mixed === 1 ? 'file loads' : 'files load'} over plain http on this https page.` })
  if (withoutSri) notes.push({ severity: 'info', text: `${withoutSri} ${withoutSri === 1 ? 'script comes' : 'scripts come'} from other sites without an integrity check (SRI).` })
  const rank: Record<Sev, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  notes.sort((a, b) => rank[a.severity] - rank[b.severity])
  return {
    url,
    status,
    title: isHtml ? titleOf(html) : undefined,
    type: (headers.get('content-type') ?? '').split(';')[0].trim(),
    bytes: html.length,
    ms: Math.round(ms),
    ...(redirect ? { redirect } : {}),
    forms,
    params: [...params].slice(0, 60),
    scripts: { total: tags.length, inline: tags.length - ext.length, external: [...externalHosts].slice(0, 30), withoutSri },
    headers: sec,
    cookies,
    tech: isHtml ? techOf(headers, html) : [],
    mixed,
    notes
  }
}

// ---------------------------------------------------------------- JavaScript

/** Paths and URLs written in JavaScript, like LinkFinder: where the front end talks to. */
export function endpointsIn(js: string): string[] {
  const out = new Set<string>()
  const re = /["'`]((?:https?:\/\/[a-z0-9.-]+(?::\d+)?)?\/(?:api|v\d|graphql|rest|internal|admin|auth|oauth|user|users|account|accounts|payment|payments|order|orders|upload|uploads|file|files|webhook|webhooks|search|export|import|config|settings|private|debug)[a-z0-9_\-/.{}:$]*)(?:\?[^"'`\s]*)?["'`]/gi
  for (const m of js.matchAll(re)) {
    const e = m[1]
    if (e.length > 2 && e.length < 200 && !/\.(png|jpe?g|svg|gif|css|woff2?)$/i.test(e)) out.add(e)
  }
  for (const m of js.matchAll(/["'`](https?:\/\/[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?(?:\/[^"'`\s]*)?)["'`]/gi)) {
    const u = m[1]
    if (!/(w3\.org|schema\.org|googleapis\.com\/css|fonts\.|reactjs\.org|mozilla\.org|github\.com\/[^/]+\/[^/]+\/(issues|blob))/.test(u) && u.length < 200) out.add(u)
  }
  return [...out].sort()
}

const KEYS: [RegExp, string, Sev][] = [
  [/\bAKIA[0-9A-Z]{16}\b/g, 'AWS access key id', 'high'],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, 'Google API key', 'medium'],
  [/\bsk_live_[0-9a-zA-Z]{20,}\b/g, 'Stripe secret key', 'critical'],
  [/\brk_live_[0-9a-zA-Z]{20,}\b/g, 'Stripe restricted key', 'high'],
  [/\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, 'Slack token', 'high'],
  [/\bgh[pousr]_[0-9A-Za-z]{36,}\b/g, 'GitHub token', 'critical'],
  [/\bglpat-[0-9A-Za-z_-]{20,}\b/g, 'GitLab token', 'critical'],
  [/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, 'Private key', 'critical'],
  [/\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b/g, 'SendGrid key', 'high'],
  [/\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/g, 'OpenAI key', 'critical'],
  [/\bsk-ant-[A-Za-z0-9_-]{32,}\b/g, 'Anthropic key', 'critical'],
  [/\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql):\/\/[^:\s"'`]+:[^@\s"'`]{3,}@[^\s"'`]+/g, 'Database URL with a password', 'critical'],
  [/\beyJhbGciOi[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, 'JSON Web Token', 'medium'],
  [/\bhttps:\/\/hooks\.slack\.com\/services\/[A-Z0-9/]+/g, 'Slack webhook', 'medium']
]

export const mask = (v: string): string => `${v.slice(0, 4)}••••••••`

/** Keys left in public JavaScript: the kind and the first four characters only. */
export function secretsIn(text: string): { kind: string; masked: string; severity: Sev }[] {
  const out: { kind: string; masked: string; severity: Sev }[] = []
  for (const [re, kind, severity] of KEYS) for (const m of text.matchAll(re)) {
    // A Supabase anon key or Firebase web key is meant to be public: still listed, at info.
    const v = m[0]
    if (out.some((o) => o.masked === mask(v) && o.kind === kind)) continue
    const publicJwt = kind === 'JSON Web Token' && /"?role"?\s*:\s*"anon"/.test(Buffer.from(v.split('.')[1] ?? '', 'base64').toString('utf8'))
    out.push({ kind: publicJwt ? 'Supabase anon key (public by design)' : kind, masked: mask(v), severity: publicJwt || kind === 'Google API key' ? 'info' : severity })
  }
  return out
}

/** The source map a script points to, from its last line or its SourceMap header. */
export function sourceMapUrl(js: string, jsUrl: string, header?: string | null): string | null {
  const ref = header || /\/[/*][#@]\s*sourceMappingURL=([^\s*]+)/.exec(js.slice(-2000))?.[1]
  if (!ref || ref.startsWith('data:')) return null
  try {
    return new URL(ref, jsUrl).href
  } catch {
    return null
  }
}

export function parseSourceMap(text: string): { files: number; sample: string[]; hasContent: boolean } | null {
  try {
    type Map = { version?: number; sources?: string[]; sourcesContent?: unknown[]; sections?: { map?: Map }[] }
    const m = JSON.parse(text) as Map
    if (!m.version) return null
    // An indexed map (Turbopack, some bundlers) keeps its files in sections.
    const parts: Map[] = Array.isArray(m.sections) ? m.sections.map((s) => s.map ?? {}) : [m]
    const sources = parts.flatMap((p) => p.sources ?? [])
    if (!Array.isArray(m.sources) && !m.sections) return null
    const clean = (s: string): string => s.replace(/^(webpack|turbopack):\/\/(\[[^\]]+\]\/)?\/?(\.\/)?|^\.\.\//, '').replace(/^[a-z-]+\/\.\//, '')
    const real = sources.filter((s) => !/node_modules|webpack\/(bootstrap|runtime)|^\(webpack\)/.test(s))
    return { files: sources.length, sample: [...new Set((real.length ? real : sources).map(clean))].slice(0, 12), hasContent: parts.some((p) => Array.isArray(p.sourcesContent) && p.sourcesContent.some(Boolean)) }
  } catch {
    return null
  }
}

// ---------------------------------------------------------------- Files that should not be public

export const EXPOSURE_PATHS = ['.git/HEAD', '.env', '.DS_Store', 'server-status', 'phpinfo.php', '.well-known/security.txt', 'robots.txt', 'sitemap.xml', 'swagger.json', 'openapi.json', 'v2/api-docs', 'api/swagger.json', 'graphql', 'actuator', 'actuator/env', 'crossdomain.xml', 'wp-json/wp/v2/users']

/** Only content that really is the file counts, never a "not found" page that answers 200. */
export function exposureReal(path: string, status: number, body: string, notFound: { status: number; length: number } | null): boolean {
  if (status !== 200) return false
  const b = body.slice(0, 4000)
  if (notFound && notFound.status === 200 && Math.abs(notFound.length - body.length) < 60) return false
  if (path === '.git/HEAD') return /^ref: refs\//.test(b)
  if (path === '.env') return /^[A-Z][A-Z0-9_]+=/m.test(b) && !/<html/i.test(b)
  if (path === '.DS_Store') return b.includes('Bud1')
  if (path === 'server-status') return /Apache Server Status/i.test(b)
  if (path === 'phpinfo.php') return /phpinfo\(\)|PHP Version/i.test(b)
  if (/swagger|openapi|api-docs/.test(path)) return /"(openapi|swagger)"\s*:/.test(b)
  if (path === 'graphql') return /graphql|"errors"\s*:/i.test(b) && !/<html/i.test(b)
  if (path.startsWith('actuator')) return /"(_links|activeProfiles|propertySources)"/.test(b)
  if (path === 'wp-json/wp/v2/users') return /^\s*\[\s*\{\s*"id"/.test(b)
  if (path === 'crossdomain.xml') return /<cross-domain-policy/i.test(b)
  return !/<html/i.test(b.slice(0, 200)) || /robots|sitemap|security\.txt/.test(path)
}

const EXPOSURE_RATING: Record<string, [Sev, string, string]> = {
  '.git/HEAD': ['high', 'The Git folder can be downloaded', 'The whole source code and its history can be rebuilt from /.git. Block the folder in the web server and redeploy without it.'],
  '.env': ['critical', 'The .env file is public', 'It usually holds database passwords and API keys. Remove it from the web root, deny dotfiles, and change every key in it.'],
  '.DS_Store': ['low', 'A .DS_Store file lists folder contents', 'Delete it and deny dotfiles in the web server.'],
  'server-status': ['medium', 'Apache server-status is public', 'It shows every request in progress, including addresses and URLs. Allow it only from localhost.'],
  'phpinfo.php': ['medium', 'phpinfo() is public', 'It reveals paths, versions and settings. Delete the file.'],
  'swagger.json': ['info', 'An API description is public', 'Fine if intended. Check every endpoint in it needs sign-in where it should.'],
  'openapi.json': ['info', 'An API description is public', 'Fine if intended. Check every endpoint in it needs sign-in where it should.'],
  'v2/api-docs': ['info', 'An API description is public', 'Fine if intended. Check every endpoint in it needs sign-in where it should.'],
  'api/swagger.json': ['info', 'An API description is public', 'Fine if intended.'],
  graphql: ['info', 'A GraphQL endpoint answers', 'Check introspection is off in production and every resolver checks access.'],
  actuator: ['medium', 'Spring Boot actuator is public', 'Expose only health, and only to monitoring.'],
  'actuator/env': ['high', 'Spring Boot /actuator/env is public', 'It can reveal configuration and secrets. Turn off the env endpoint.'],
  'crossdomain.xml': ['low', 'A Flash cross-domain policy exists', 'Remove it if it allows "*".'],
  'wp-json/wp/v2/users': ['low', 'WordPress lists its users', 'User names help password guessing. Limit the users endpoint to signed-in users.'],
  'robots.txt': ['info', 'robots.txt', 'Read it: it often names private areas.'],
  'sitemap.xml': ['info', 'sitemap.xml', 'A list of pages to include in the map.'],
  '.well-known/security.txt': ['info', 'security.txt', 'Contact details for reporting problems.']
}

// ---------------------------------------------------------------- The run

export async function runRecon(target: string, ctx: ReconContext): Promise<ReconResult> {
  const { domain, url: startUrl } = normalizeTarget(target)
  const L = LIMITS[ctx.depth]
  const UA = { 'User-Agent': ctx.userAgent ?? 'Recon (read-only)' }
  const res: ReconResult = { domain, hosts: [], urls: [], params: [], js: [], endpoints: [], findings: [], pages: [] }
  const hostMap = new Map<string, HostInfo>()
  const addHost = (h: string, src: string): void => {
    const e = hostMap.get(h) ?? { host: h, ips: [], sources: [] }
    if (!e.sources.includes(src)) e.sources.push(src)
    hostMap.set(h, e)
  }
  addHost(domain, 'target')
  addHost(new URL(startUrl).hostname, 'target')
  const get = async (u: string, ms = 12000, extra: Record<string, string> = {}): Promise<{ status: number; headers: Headers; text: string; location?: string }> => {
    const r = await fetch(u, { redirect: 'manual', headers: { ...UA, ...extra }, signal: AbortSignal.timeout(ms) })
    const text = r.status >= 300 && r.status < 400 ? '' : (await r.text()).slice(0, 3_000_000)
    return { status: r.status, headers: r.headers, text, location: r.headers.get('location') ?? undefined }
  }
  const step = async (id: string, label: string, fn: () => Promise<string | void>): Promise<void> => {
    if (ctx.cancelled()) return ctx.step(id, label, 'skipped')
    ctx.step(id, label, 'running')
    try {
      ctx.step(id, label, 'done', (await fn()) ?? undefined)
    } catch (e) {
      ctx.step(id, label, 'failed', (e as Error).message.slice(0, 200))
    }
  }

  // 1. Certificate transparency.
  await step('crtsh', 'Subdomains from certificate logs (crt.sh)', async () => {
    const r = await fetch(`https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`, { headers: UA, signal: AbortSignal.timeout(60000) })
    const text = await r.text()
    if (!r.ok || !text.trim().startsWith('[')) throw new Error(`crt.sh did not answer (${r.status}). It is often busy: try again later.`)
    const names = parseCrtSh(text, domain)
    names.forEach((n) => addHost(n, 'crt.sh'))
    return `${names.length} names`
  })

  // 1b. More public sources, side by side. Each one may be busy or limited; the rest still count.
  await step('passive', 'Subdomains from more public sources (CertSpotter, OTX, HackerTarget, urlscan.io, Anubis)', async () => {
    const counts: string[] = []
    await Promise.all(
      PASSIVE_SOURCES.map(async (src) => {
        try {
          const r = await fetch(src.url(domain), { headers: { ...UA, Accept: 'application/json' }, signal: AbortSignal.timeout(45000) })
          if (!r.ok) return
          const names = parsePassive(src.id, await r.text(), domain)
          names.forEach((n) => addHost(n, src.id))
          counts.push(`${src.name} ${names.length}`)
        } catch {
          // This source is busy; the others still count.
        }
      })
    )
    return counts.length ? counts.join(', ') : 'None answered'
  })

  // 2. subfinder's passive sources, when it is installed.
  const sf = ctx.tool('subfinder')
  await step('subfinder', sf ? 'Subdomains from public sources (subfinder)' : 'Subdomains from public sources (install subfinder to add this)', async () => {
    if (!sf) return 'Skipped'
    const out = await ctx.run(sf, ['-d', domain, '-silent', '-all', '-oJ', '-timeout', '20', '-max-time', ctx.depth === 'deep' ? '10' : '4'], 12 * 60_000)
    const names = parseSubfinder(out, domain)
    names.forEach((n) => addHost(n, 'subfinder'))
    return `${names.length} names`
  })

  // 3. The Wayback Machine: old URLs, parameters and hosts.
  await step('wayback', 'Old pages and files from the Wayback Machine', async () => {
    const r = await fetch(`https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json&fl=original&collapse=urlkey&limit=${L.archive}`, { headers: UA, signal: AbortSignal.timeout(120000) })
    const text = await r.text()
    if (!r.ok || !text.trim().startsWith('[')) throw new Error(`The Wayback Machine did not answer (${r.status}).`)
    res.urls = parseWayback(text, domain)
    for (const u of res.urls) addHost(new URL(u).hostname.toLowerCase(), 'wayback')
    res.params = paramsOf(res.urls)
    for (const u of interestingUrls(res.urls).slice(0, 80)) res.findings.push({ id: fid('wb', u), kind: 'endpoint', severity: 'info', title: `Archived: ${new URL(u).pathname.slice(0, 90)}`, url: u, description: 'Seen in the Wayback Machine. Check whether it still answers and should be public.' })
    return `${res.urls.length} URLs, ${res.params.length} parameter names`
  })

  // 4. DNS for every name found, and takeover hints.
  await step('dns', 'Resolve every name (DNS)', async () => {
    const hosts = [...hostMap.values()]
    await pool(
      hosts,
      20,
      async (h) => {
        const [a0, cname] = await Promise.all([dns.resolve4(h.host).catch(() => [] as string[]), dns.resolveCname(h.host).catch(() => [] as string[])])
        // The system resolver as well: it knows /etc/hosts and local .test domains.
        const a = a0.length ? a0 : await dns.lookup(h.host, { all: true }).then((r) => r.map((x) => x.address)).catch(() => [] as string[])
        h.ips = a
        h.cname = cname[0]
        if (h.cname) {
          const svc = takeoverService(h.cname)
          if (svc && !a.length)
            res.findings.push({ id: fid('to', h.host), kind: 'takeover', severity: 'high', title: `${h.host} points to ${svc} but nothing answers there`, url: h.host, description: `The CNAME ${h.cname} does not resolve. If the ${svc} resource was deleted, someone else may be able to claim it and serve content on your subdomain.`, fix: `Remove the DNS record for ${h.host}, or recreate the ${svc} resource.` })
        }
        ctx.line(`${h.host} ${a.join(', ') || (h.cname ? `→ ${h.cname}` : 'no address')}`)
      },
      ctx.cancelled
    )
    const resolved = hosts.filter((h) => h.ips.length || h.cname)
    return `${resolved.length} of ${hosts.length} resolve`
  })

  if (ctx.depth === 'passive') {
    res.hosts = [...hostMap.values()].sort((a, b) => a.host.localeCompare(b.host))
    res.findings.push(...subdomainFindings(res.hosts))
    return res
  }

  // 5. Which hosts answer, and what they run.
  await step('probe', `See which hosts answer and what they run (up to ${L.hosts})`, async () => {
    const hosts = [...hostMap.values()].filter((h) => h.ips.length || h.cname).slice(0, L.hosts)
    await pool(
      hosts,
      8,
      async (h) => {
        for (const scheme of ['https', 'http']) {
          try {
            const r = await get(`${scheme}://${h.host}/`, 10000)
            h.live = { url: `${scheme}://${h.host}/`, status: r.status, title: titleOf(r.text), server: r.headers.get('server') ?? undefined, poweredBy: r.headers.get('x-powered-by') ?? undefined, tech: techOf(r.headers, r.text), redirect: r.location }
            ctx.line(`${h.live.url} ${r.status} ${h.live.title ?? ''} ${h.live.tech.join(', ')}`)
            if (scheme === 'https' || r.status) break
          } catch {
            // Try the next scheme.
          }
        }
      },
      ctx.cancelled
    )
    return `${hosts.filter((h) => h.live).length} answer`
  })

  // 6. A light crawl of the hosts that answer, for pages and scripts.
  const scripts = new Set<string>()
  await step('crawl', `Read the pages and collect their scripts (up to ${L.pages} pages)`, async () => {
    const live = [...hostMap.values()].filter((h) => h.live && h.live.status < 400)
    const queue = live.map((h) => h.live!.url)
    const seen = new Set<string>()
    let pages = 0
    while (queue.length && pages < L.pages && !ctx.cancelled()) {
      const u = queue.shift()!
      if (seen.has(u)) continue
      seen.add(u)
      try {
        const t0 = Date.now()
        const r = await get(u, 12000)
        pages++
        try {
          res.pages!.push(pageInfo(u, r.status, r.headers, r.text, Date.now() - t0, r.location ? new URL(r.location, u).href : undefined))
        } catch {
          // A page that cannot be broken down still counts for the crawl.
        }
        if (r.location) {
          const next = new URL(r.location, u)
          if (inScope(next.hostname, domain)) queue.push(next.href)
          continue
        }
        if (!/html/i.test(r.headers.get('content-type') ?? '')) continue
        const { pages: links, scripts: js } = linksOf(r.text, u, domain)
        js.forEach((s) => scripts.add(s))
        for (const l of links) if (!seen.has(l) && !/\.(png|jpe?g|gif|svg|pdf|zip|mp4|css|ico)(\?|$)/i.test(l)) queue.push(l)
        ctx.line(`${u} ${js.length} scripts`)
        await new Promise((r2) => setTimeout(r2, 150))
      } catch {
        // Unreachable page.
      }
    }
    if (L.archivedJs) for (const u of res.urls.filter((x) => /\.js(\?|$)/.test(x)).slice(0, L.archivedJs)) scripts.add(u)
    return `${pages} pages, ${scripts.size} scripts`
  })

  // 7. Every script: source maps, endpoints and keys.
  await step('js', `Check the JavaScript for source maps, endpoints and keys (up to ${L.js})`, async () => {
    const list = [...scripts].filter((s) => !/(googletagmanager|google-analytics|gstatic|facebook\.net|hotjar|cdn\.jsdelivr|unpkg|cdnjs)/.test(s)).slice(0, L.js)
    await pool(
      list,
      6,
      async (u) => {
        try {
          const r = await get(u, 15000)
          if (r.status !== 200) return
          // Framework and library bundles name their own internals: only the app's own code is mined for endpoints.
          const vendor = /node_modules|vendor|chunk-vendors|framework-|polyfills|webpack-runtime|turbopack/i.test(u)
          const info: JsInfo = { url: u, bytes: r.text.length, endpoints: vendor ? [] : endpointsIn(r.text), secrets: [] }
          for (const s of secretsIn(r.text)) {
            info.secrets.push({ kind: s.kind, masked: s.masked })
            res.findings.push({ id: fid('key', u, s.kind, s.masked), kind: 'secret', severity: s.severity, title: `${s.kind} in public JavaScript`, url: u, description: `Starts with ${s.masked}. Anyone can read this file.`, fix: s.severity === 'info' ? 'Meant to be public: make sure the rules behind it (Row Level Security, Firebase rules, API restrictions) are strict.' : 'Revoke the key at its provider, move it to the server side, and redeploy.' })
          }
          const mapUrl = sourceMapUrl(r.text, u, r.headers.get('sourcemap') ?? r.headers.get('x-sourcemap')) ?? `${u.replace(/\?.*$/, '')}.map`
          const m = await get(mapUrl, 15000).catch(() => null)
          const parsed = m && m.status === 200 ? parseSourceMap(m.text) : null
          if (parsed) {
            info.sourceMap = { url: mapUrl, files: parsed.files, sample: parsed.sample }
            res.findings.push({ id: fid('map', mapUrl), kind: 'sourcemap', severity: parsed.hasContent ? 'medium' : 'low', title: `Source map public: ${parsed.files} original files`, url: mapUrl, description: `The original source code${parsed.hasContent ? ', including its full text,' : ''} can be rebuilt from this file. Files include: ${parsed.sample.join(', ')}.`, fix: 'Stop uploading .map files to production (productionBrowserSourceMaps: false in Next.js, build.sourcemap: false in Vite), or upload them only to your error tracker.' })
            ctx.line(`Source map: ${mapUrl} (${parsed.files} files)`)
          }
          res.js.push(info)
        } catch {
          // Unreachable script.
        }
      },
      ctx.cancelled
    )
    res.endpoints = [...new Set(res.js.flatMap((j) => j.endpoints))].sort()
    const internal = res.endpoints.filter((e) => /\/(admin|internal|debug|private)\b/.test(e))
    for (const e of internal.slice(0, 30)) res.findings.push({ id: fid('ep', e), kind: 'endpoint', severity: 'info', title: `Front end mentions ${e.slice(0, 100)}`, url: e, description: 'An internal or admin path named in public JavaScript. Check it needs sign-in and the right role.' })
    return `${res.js.length} scripts, ${res.js.filter((j) => j.sourceMap).length} source maps, ${res.endpoints.length} endpoints, ${res.js.reduce((n, j) => n + j.secrets.length, 0)} keys`
  })

  // 8. A short list of files that should not be public, on each host that answers.
  await step('exposed', 'Check a few files that should never be public', async () => {
    const live = [...hostMap.values()].filter((h) => h.live).slice(0, ctx.depth === 'deep' ? 40 : 12)
    let found = 0
    for (const h of live) {
      if (ctx.cancelled()) break
      const base = h.live!.url.replace(/\/$/, '')
      const nf = await get(`${base}/laramac-recon-${Date.now().toString(36)}-404`, 10000).then((r) => ({ status: r.status, length: r.text.length })).catch(() => null)
      for (const p of EXPOSURE_PATHS) {
        try {
          const r = await get(`${base}/${p}`, 10000, { Range: 'bytes=0-65535' })
          if (!exposureReal(p, r.status === 206 ? 200 : r.status, r.text, nf)) continue
          const [severity, title, fix] = EXPOSURE_RATING[p] ?? ['info', p, '']
          res.findings.push({ id: fid('exp', base, p), kind: 'exposure', severity, title: `${title} (${h.host})`, url: `${base}/${p}`, fix })
          found++
          ctx.line(`${base}/${p}: ${title}`)
        } catch {
          // Skip.
        }
        await new Promise((r2) => setTimeout(r2, 120))
      }
    }
    return `${found} found`
  })

  res.hosts = [...hostMap.values()].sort((a, b) => a.host.localeCompare(b.host))
  res.findings.push(...subdomainFindings(res.hosts))
  return res
}

/** Hosts that look like staging, admin or internal systems, flagged for a closer look. */
export function subdomainFindings(hosts: HostInfo[]): ReconFinding[] {
  const out: ReconFinding[] = []
  for (const h of hosts) {
    if (!/(^|[.-])(dev|stag(e|ing)?|test|qa|uat|preprod|beta|old|legacy|admin|internal|intranet|vpn|jenkins|gitlab|grafana|kibana|jira|confluence|sonar|argo|rancher|portainer|backup|db|phpmyadmin)([.-]|\d)/.test(h.host)) continue
    if (!h.ips.length && !h.cname) continue
    out.push({ id: fid('sd', h.host), kind: 'subdomain', severity: h.live && h.live.status < 400 ? 'low' : 'info', title: `${h.host} looks like a ${/admin|jenkins|gitlab|grafana|kibana|jira|confluence|sonar|argo|rancher|portainer|phpmyadmin/.test(h.host) ? 'tool or admin system' : 'non-production system'}`, url: h.live?.url ?? h.host, description: h.live ? `It answers (${h.live.status}${h.live.title ? `, "${h.live.title}"` : ''}). Systems like this are often less protected than production.` : 'It resolves but did not answer over the web.', fix: 'Put it behind sign-in or a VPN, or remove it if it is no longer used.' })
  }
  return out
}

/** The brief an AI reviewer reads: a map of the attack surface, never the raw data. */
export function reconBrief(r: ReconResult): string {
  const live = r.hosts.filter((h) => h.live)
  return `Recon of ${r.domain} (read-only).
Hosts: ${r.hosts.length} found, ${live.length} answer.
${live.slice(0, 60).map((h) => `- ${h.live!.url} ${h.live!.status} ${h.live!.title ?? ''} [${h.live!.tech.join(', ')}]${h.cname ? ` cname ${h.cname}` : ''}`).join('\n')}
Parameters seen in archived URLs (most common first): ${r.params.slice(0, 60).join(', ') || 'none'}
Endpoints named in JavaScript (${r.endpoints.length}): ${r.endpoints.slice(0, 120).join(', ')}
Source maps: ${r.js.filter((j) => j.sourceMap).map((j) => `${j.sourceMap!.url} (${j.sourceMap!.files} files: ${j.sourceMap!.sample.slice(0, 5).join(', ')})`).join('; ') || 'none'}
Findings:
${r.findings.slice(0, 150).map((f) => `- id=${f.id} [${f.severity}] ${f.title}${f.url ? ` at ${f.url}` : ''}`).join('\n')}`
}

export function reconPrompt(r: ReconResult): string {
  return `You are a senior offensive security engineer doing reconnaissance for an authorised, read-only assessment. Use the recon-methodology and attack-surface-report skills if you have them.
Do not attack, fuzz, guess passwords or exploit anything, and do not suggest commands that change data. Plan where a careful manual tester should look first.

${reconBrief(r)}

Write Markdown:
## Executive summary
The shape of the attack surface in 3 to 5 sentences and the most important thing to look at.
## Attack surface map
A table: | Host | What it is | Why it matters |, the most interesting first.
## Leads for manual testing
For each lead, "### [SEVERITY] Title" with **Where**, **What the recon shows**, **Why it is interesting**, **What to check by hand** (read-only checks or what to try in Burp Suite, with authorisation), and **Fix if confirmed**.
## Source maps and JavaScript
What the front end reveals: internal APIs, admin routes, feature flags, third-party services.
## Probably harmless
Noise, and why.

End with one fenced json block: {"verdicts":[{"id":"<id>","verdict":"confirmed" or "false-positive","severity":"high","reason":"one sentence"}]} for findings you can judge from this data.`
}
