/**
 * Control confirmations: active checks that PROVE a problem is real, so a report has no false
 * positives. They only run when the person turns them on for a scan (see CLAUDE.md for the rules).
 *
 *   Discovery   hidden pages and parameters, with a check for sites that answer "yes" to everything
 *   Login       whether the login reveals which users exist, and whether it limits wrong guesses
 *   Access      whether another account can open what belongs to a different account
 *   Firewall    which web firewall answers, what it blocks, and whether a harmless marker gets past it
 *
 * Every request goes through ConfirmClient: same site only, no redirects followed off the site, a
 * request limit, a pause between requests, and a stop when the server starts to struggle. Only
 * harmless markers are sent. Nothing is reported until a second request has repeated it.
 */
import { createHash, randomBytes } from 'crypto'
import type { Finding, Severity } from '../shared/types'
import { fid } from './scanners/parse'
import { pathSeverity } from './scanners/web'
import { detectWaf, dirListing, fileShows, proofOf } from './seckit/confirm'
import { CONTENT_WORDS, PARAM_WORDS } from './wordlists'

// ---------------------------------------------------------------- A careful client

export class Stop extends Error {}

export interface Reply {
  status: number
  headers: Headers
  body: string
  url: string
  method: string
  ms: number
}

export interface ClientOptions {
  /** What the signed-in account sends (cookie, token). Never logged and never put in a proof. */
  headers?: Record<string, string>
  cap?: number
  delayMs?: number
  cancelled?: () => boolean
  fetchImpl?: typeof fetch
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))
const sha = (s: string): string => createHash('sha256').update(s).digest('hex')
const token = (): string => `macsec-${randomBytes(4).toString('hex')}`

export class ConfirmClient {
  count = 0
  stopped: string | null = null
  private bad = 0
  readonly origin: string

  constructor(readonly base: string, private o: ClientOptions = {}) {
    this.origin = new URL(base).origin
  }

  left(): number {
    return (this.o.cap ?? 1500) - this.count
  }

  /** The address, if it is on the site being tested. Anything else is refused. */
  resolve(path: string): string {
    const u = new URL(path, this.base.endsWith('/') ? this.base : `${this.base}/`)
    if (u.origin !== this.origin) throw new Error('That address is not on the site being tested.')
    return u.href
  }

  /** `headers: 'none'` sends the request signed out; an object sends that account instead. */
  async send(method: 'GET' | 'POST', path: string, o: { headers?: Record<string, string> | 'none'; form?: Record<string, string>; cookie?: string } = {}): Promise<Reply> {
    if (this.stopped) throw new Stop(this.stopped)
    if (this.o.cancelled?.()) throw new Stop('Cancelled')
    if (this.count >= (this.o.cap ?? 1500)) throw new Stop('The request limit for control confirmations was reached.')
    const url = this.resolve(path)
    this.count++
    await sleep(this.o.delayMs ?? 120)
    const who = o.headers === 'none' ? {} : (o.headers ?? this.o.headers ?? {})
    const headers: Record<string, string> = { 'User-Agent': 'MacSec control confirmation', ...who, ...(o.cookie ? { Cookie: o.cookie } : {}) }
    let body: string | undefined
    if (o.form) {
      headers['Content-Type'] = 'application/x-www-form-urlencoded'
      body = new URLSearchParams(o.form).toString()
    }
    const t = Date.now()
    try {
      const r = await (this.o.fetchImpl ?? fetch)(url, { method, redirect: 'manual', headers, body, signal: AbortSignal.timeout(15000) })
      const text = r.status >= 300 && r.status < 400 ? '' : (await r.text()).slice(0, 200000)
      this.bad = r.status >= 500 ? this.bad + 1 : 0
      if (this.bad >= 5) this.stopped = 'The server started to struggle (several errors in a row), so the checks stopped to avoid harming it.'
      return { status: r.status, headers: r.headers, body: text, url, method, ms: Date.now() - t }
    } catch (e) {
      this.bad++
      if (this.bad >= 5) this.stopped = 'The server stopped answering, so the checks stopped to avoid harming it.'
      throw e
    }
  }

  get(path: string, o: { headers?: Record<string, string> | 'none' } = {}): Promise<Reply> {
    return this.send('GET', path, o)
  }

  post(path: string, form: Record<string, string>, o: { headers?: Record<string, string> | 'none'; cookie?: string } = {}): Promise<Reply> {
    return this.send('POST', path, { ...o, form })
  }
}

// ---------------------------------------------------------------- Comparing answers

const locOf = (r: Reply, seg = ''): string => {
  const l = r.headers.get('location') ?? ''
  return seg ? l.split(seg).join('*') : l
}

/** Whether two answers are, for our purposes, the same page. */
export function similar(a: Reply, b: Reply): boolean {
  if (a.status !== b.status) return false
  if (a.status >= 300 && a.status < 400) return locOf(a) === locOf(b)
  if (sha(a.body) === sha(b.body)) return true
  const d = Math.abs(a.body.length - b.body.length)
  return d <= Math.max(60, Math.max(a.body.length, b.body.length) * 0.03)
}

export function visibleText(html: string): string {
  return html
    .replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;|&#160;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

interface Calibration {
  seg: string
  reply: Reply
}

/** Asks for pages that cannot exist. A site that says "found" or redirects for all of them answers yes to everything. */
export async function calibrate(c: ConfirmClient): Promise<Calibration[]> {
  const out: Calibration[] = []
  for (const shape of [(t: string) => t, (t: string) => `${t}/`, (t: string) => `${t}.php`, (t: string) => `${t}.html`]) {
    const seg = token()
    out.push({ seg, reply: await c.get(shape(seg)) })
  }
  return out
}

export function isCatchAll(word: string, r: Reply, cal: Calibration[]): boolean {
  return cal.some((k) => {
    if (k.reply.status !== r.status) return false
    if (r.status >= 300 && r.status < 400) return locOf(k.reply, k.seg) === locOf(r, word)
    return similar(k.reply, r)
  })
}

const f = (x: Omit<Finding, 'id' | 'tool' | 'category' | 'confidence'> & { confidence?: 'confirmed' | 'possible' }, key: string): Finding => ({
  id: fid('confirm', x.title, x.url, key),
  tool: 'MacSec',
  category: 'web',
  confidence: 'confirmed',
  ...x
})

const pathOf = (u: string): string => {
  try {
    const p = new URL(u)
    return p.pathname + (p.search ? '?…' : '')
  } catch {
    return u
  }
}

// ---------------------------------------------------------------- Discovery: hidden pages

/** Hidden pages and folders. Every hit is asked for twice, and answers that match the "cannot exist" pages are dropped. */
export async function fuzzContent(c: ConfirmClient, note: (d: string) => void, words: string[] = CONTENT_WORDS): Promise<Finding[]> {
  const cal = await calibrate(c).catch((e) => {
    if (e instanceof Stop) return null
    throw e
  })
  if (!cal) return []
  const out: Finding[] = []
  const plain: string[] = []
  let catchAllHits = 0
  for (const [i, w] of words.entries()) {
    if (c.left() < 10) break
    if (i % 25 === 0) note(`Tried ${i} of ${words.length} names`)
    let r: Reply
    try {
      r = await c.get(w)
    } catch (e) {
      if (e instanceof Stop) {
        note(e.message)
        break
      }
      continue
    }
    const redirectToFolder = r.status >= 300 && r.status < 400 && /^[^?#]*\/$/.test(r.headers.get('location')?.replace(/^https?:\/\/[^/]+/, '') ?? '') && (r.headers.get('location') ?? '').replace(/\/$/, '').endsWith(w)
    const interesting = r.status === 200 || r.status === 206 || r.status === 401 || r.status === 403 || redirectToFolder
    if (!interesting) continue
    if (isCatchAll(w, r, cal)) {
      catchAllHits++
      continue
    }
    // Confirm: the same answer a second time.
    let again: Reply
    try {
      again = await c.get(w)
    } catch {
      continue
    }
    if (again.status !== r.status || !similar(r, again)) continue
    const open = r.status === 200 || r.status === 206
    const url = r.url
    const listing = open ? dirListing(r.body) : null
    const file = open ? fileShows(`/${w}`, r.body) : null
    if (listing) {
      out.push(f({ severity: 'medium', title: `Folder lists its files: /${w}`, url, file: url, cwe: 'CWE-548', description: 'The web server shows the contents of this folder to anyone.', fix: 'Turn directory listing off (Apache: Options -Indexes; Nginx: autoindex off) and keep private files out of the public folder.', proof: proofOf({ url, status: r.status, headers: r.headers, body: r.body, shows: listing.shows }) }, w))
      continue
    }
    if (file) {
      const sev = pathSeverity(w, 200)
      out.push(f({ severity: sev === 'info' ? 'low' : sev, title: `Public file found by discovery: /${w}`, url, file: url, cwe: 'CWE-538', description: 'It is not linked from the site, but anyone who asks for it gets it.', fix: 'Remove it from the public folder, or deny it in the web server configuration. If it held passwords or keys, change them.', proof: proofOf({ url, status: r.status, headers: r.headers, body: r.body, shows: file }) }, w))
      continue
    }
    const sev = pathSeverity(w, r.status)
    if (sev !== 'info') {
      out.push(f({ severity: sev, title: open ? `Hidden page found: /${w}` : `Hidden page exists but is protected: /${w}`, url, file: url, description: open ? 'It is not linked from the site, but it answers.' : `The server answers ${r.status}, so it exists.`, proof: proofOf({ url, status: r.status, headers: r.headers, body: r.body, shows: [`answered ${r.status} twice, and differently from a page that does not exist`] }) }, w))
    } else {
      plain.push(`${w} (${r.status})`)
    }
  }
  if (plain.length) {
    const first = plain[0].split(' ')[0]
    out.push(f({ severity: 'info', title: `${plain.length} other hidden page${plain.length === 1 ? '' : 's'} found`, url: c.resolve(first), description: `Not linked from the site but they answer: ${plain.slice(0, 40).join(', ')}${plain.length > 40 ? ', and more' : ''}. Worth a look by hand.`, proof: { request: `GET ${c.resolve(first)}`, reproduce: `curl -sS -i '${c.resolve(first)}'`, status: Number(/\((\d+)\)/.exec(plain[0])?.[1] ?? 200), bytes: 0, sha256: '', at: new Date().toISOString(), shows: plain.slice(0, 12) } }, 'plain'))
  }
  if (catchAllHits > 20) note(`This site answers "found" for names that cannot exist, so ${catchAllHits} matches were ignored`)
  return out
}

// ---------------------------------------------------------------- Discovery: hidden parameters

export interface ParamHit {
  name: string
  how: 'reflected' | 'changed'
  marker: string
  page: string
}

const mark = (i: number): string => `msq${i.toString(36)}z`

/** Parameters a page quietly accepts: a value we send comes back in the page, or changes the answer. Each hit is repeated. */
export async function fuzzParams(c: ConfirmClient, page: string, note: (d: string) => void, names: string[] = PARAM_WORDS): Promise<{ hits: ParamHit[]; findings: Finding[] }> {
  const hits: ParamHit[] = []
  const findings: Finding[] = []
  try {
    await paramsInner(c, page, note, names, hits, findings)
  } catch (e) {
    if (e instanceof Stop) note(e.message)
    else throw e
  }
  return { hits, findings }
}

async function paramsInner(c: ConfirmClient, page: string, note: (d: string) => void, names: string[], hits: ParamHit[], findings: Finding[]): Promise<void> {
  const withParams = (list: { name: string; value: string }[]): string => {
    const u = new URL(c.resolve(page))
    for (const p of list) u.searchParams.set(p.name, p.value)
    return u.href
  }
  const safe = names.filter((n) => /^[A-Za-z][\w.-]{0,40}$/.test(n))
  const base1 = await c.get(page)
  const base2 = await c.get(page)
  const stable = similar(base1, base2)
  const idx = new Map(safe.map((n, i) => [n, i]))
  let splits = 0

  const confirm = async (name: string, how: 'reflected' | 'changed'): Promise<boolean> => {
    const i = idx.get(name) ?? 0
    const a = await c.get(withParams([{ name, value: mark(i) }]))
    const b = await c.get(withParams([{ name, value: `${mark(i)}b` }]))
    if (how === 'reflected') return a.body.includes(mark(i)) && b.body.includes(`${mark(i)}b`)
    const after = await c.get(page)
    return stable && similar(base1, after) && !similar(base1, a) && !similar(base1, b) && a.status === b.status
  }

  const search = async (group: string[], depth = 0): Promise<void> => {
    if (!group.length || c.left() < 6) return
    const r = await c.get(withParams(group.map((n) => ({ name: n, value: mark(idx.get(n) ?? 0) }))))
    const reflected = group.filter((n) => r.body.includes(mark(idx.get(n) ?? 0)))
    if (reflected.length > 12) {
      findings.push(f({ severity: 'info', title: `Page echoes any parameter you send: ${pathOf(c.resolve(page))}`, url: c.resolve(page), description: 'Because every name comes back, parameter discovery by reflection would only produce noise here, so it was skipped for this page.', proof: proofOf({ url: r.url, status: r.status, headers: r.headers, body: r.body, shows: [`${reflected.length} different made-up parameter values came back in the page`] }) }, `echo${page}`))
      return
    }
    for (const n of reflected) if (await confirm(n, 'reflected')) hits.push({ name: n, how: 'reflected', marker: mark(idx.get(n) ?? 0), page })
    // Echoed names can make the page look different, so look for other changes without them.
    const rest = reflected.length ? group.filter((n) => !reflected.includes(n)) : group
    if (!rest.length || !stable) return
    const r2 = reflected.length ? await c.get(withParams(rest.map((n) => ({ name: n, value: mark(idx.get(n) ?? 0) })))) : r
    if (similar(base1, r2)) return
    if (rest.length === 1) {
      if (await confirm(rest[0], 'changed')) hits.push({ name: rest[0], how: 'changed', marker: mark(idx.get(rest[0]) ?? 0), page })
    } else if (depth < 6 && splits++ < 60) {
      const mid = Math.ceil(rest.length / 2)
      await search(rest.slice(0, mid), depth + 1)
      await search(rest.slice(mid), depth + 1)
    }
  }

  for (let i = 0; i < safe.length; i += 20) {
    if (i % 60 === 0) note(`Tried ${i} of ${safe.length} parameter names on ${pathOf(c.resolve(page))}`)
    await search(safe.slice(i, i + 20))
    if (findings.some((x) => x.title.startsWith('Page echoes'))) break
  }

  for (const h of hits) {
    const u = withParams([{ name: h.name, value: h.marker }])
    const r = await c.get(u)
    findings.push(
      f(
        {
          severity: h.how === 'reflected' ? 'low' : 'info',
          title: `Hidden parameter "${h.name}" on ${pathOf(c.resolve(page))}`,
          url: u,
          file: u,
          description: h.how === 'reflected' ? 'The page accepts this parameter and puts its value in the answer. That is where script injection is usually found, so it deserves a manual look. It is not proof of a flaw by itself.' : 'The page accepts this parameter and answers differently when it is present.',
          proof: proofOf({ url: u, status: r.status, headers: r.headers, body: r.body, shows: [h.how === 'reflected' ? `the value ${h.marker} was sent and came back in the page, twice, with two different values` : 'the answer changed when the parameter was present, twice, and the normal page stayed the same'] })
        },
        `${page}${h.name}`
      )
    )
  }
}

// ---------------------------------------------------------------- Firewall control tests

const BLOCK_PAGE = /access denied|request blocked|blocked by|attention required|incapsula|web application firewall|mod_security|not acceptable|reference #\d|your request was rejected|request rejected|support id|security policy/i

export function isBlocked(r: Reply, base: Reply): boolean {
  if (similar(r, base)) return false
  if ([403, 406, 418, 429, 501, 999].includes(r.status)) return true
  return r.status >= 400 ? BLOCK_PAGE.test(r.body) : BLOCK_PAGE.test(r.body) && !BLOCK_PAGE.test(base.body)
}

/** Inert test strings: they only look like attacks, and nothing here can run on the server or in a browser. */
const PROBES: { cls: string; value: string; reflects: boolean }[] = [
  { cls: 'script tag (cross-site scripting)', value: '<script>macsec</script>', reflects: true },
  { cls: 'template syntax', value: '{{macsec*7}}', reflects: true },
  { cls: 'SQL injection shape', value: "' OR 'macsec'='macsec' --", reflects: false },
  { cls: 'path traversal shape', value: '../../../../etc/passwd', reflects: false },
  { cls: 'command separator shape', value: '; cat /etc/passwd | macsec', reflects: false }
]

const VARIANTS: { how: string; value: (plain: string) => string; reflected: (plain: string) => string; query?: boolean }[] = [
  { how: 'mixed upper and lower case', value: (p) => p.replace(/script/i, 'ScRiPt').replace(/<\/script/i, '</sCrIpT'), reflected: (p) => p.replace(/script/i, 'ScRiPt').replace(/<\/script/i, '</sCrIpT') },
  { how: 'a slash where a space would be', value: (p) => p.replace('<script>', '<script/x>'), reflected: (p) => p.replace('<script>', '<script/x>') },
  { how: 'encoded twice', value: (p) => encodeURIComponent(encodeURIComponent(p)), reflected: (p) => p },
  { how: 'a different tag', value: () => '<svg/onload=macsec>', reflected: () => '<svg/onload=macsec>' }
]

/**
 * What the web firewall does. Harmless look-alike strings are sent; a bypass is reported only when
 * a string the firewall blocked in its plain form comes back in the page, unchanged, when sent another way.
 */
export async function wafControl(c: ConfirmClient, note: (d: string) => void, carrier?: string): Promise<Finding[]> {
  const out: Finding[] = []
  try {
    await wafInner(c, note, out, carrier)
  } catch (e) {
    if (e instanceof Stop) note(e.message)
    else throw e
  }
  return out
}

async function wafInner(c: ConfirmClient, note: (d: string) => void, out: Finding[], carrier?: string): Promise<Finding[]> {
  const home = await c.get('')
  const found = detectWaf(home.headers, home.headers.getSetCookie?.().join('; ') ?? '')
  const rand = `macsec_${randomBytes(3).toString('hex')}`
  const withValue = (param: string, v: string): string => {
    const u = new URL(c.resolve(''))
    u.searchParams.set(param, v)
    return u.href
  }
  const baseline = await c.get(withValue(rand, 'hello'))
  const baseline2 = await c.get(withValue(rand, 'hello'))
  if (!similar(baseline, baseline2)) {
    note('The firewall tests were skipped: the page changes on every visit, so a block could not be told from normal changes')
    return out
  }
  const carrierUrl = (v: string): string => {
    const [path, name] = (carrier ?? '').split('?')
    const u = new URL(c.resolve(path))
    u.searchParams.set(name, v)
    return u.href
  }
  const carrierBase = carrier ? await c.get(carrierUrl('hello')) : null
  const results: { cls: string; blocked: boolean; reply: Reply }[] = []
  for (const p of PROBES) {
    const r = await c.get(withValue(rand, p.value))
    const blocked = isBlocked(r, baseline)
    results.push({ cls: p.cls, blocked, reply: r })
    if (blocked) {
      // Second request, so one odd answer is not taken for a rule.
      const again = await c.get(withValue(rand, p.value))
      if (!isBlocked(again, baseline)) results[results.length - 1].blocked = false
    }
  }
  const blockedNow = results.filter((r) => r.blocked)
  const name = found[0]?.name ?? (blockedNow.length ? 'an unnamed web firewall' : null)
  if (name) {
    const first = blockedNow[0]?.reply ?? home
    out.push(
      f(
        {
          severity: 'info',
          title: `Web firewall in front of the site: ${name}`,
          url: c.resolve(''),
          description: blockedNow.length ? `It blocked ${blockedNow.length} of ${PROBES.length} harmless test strings (${blockedNow.map((b) => b.cls).join(', ')}).${results.length > blockedNow.length ? ` It let these through: ${results.filter((r) => !r.blocked).map((r) => r.cls).join(', ')}. That does not mean the site is open: the site itself may reject them.` : ''}` : 'It is present but did not block any of the harmless test strings.',
          proof: proofOf({ url: first.url, status: first.status, headers: first.headers, body: first.body, shows: [...(found[0]?.shows ?? []), ...blockedNow.map((b) => `blocked: ${b.cls} (answer ${b.reply.status})`)] })
        },
        'waf'
      )
    )
  }

  // Bypass control tests need a place where the page puts the value back, so that getting through can be proven.
  if (!carrier || !carrierBase) {
    if (blockedNow.some((b) => PROBES.find((p) => p.cls === b.cls)?.reflects)) note('The firewall blocks the script test, but no parameter that echoes values was found, so bypass tests could not be proven and were skipped')
    return out
  }
  for (const p of PROBES.filter((x) => x.reflects && x.value.startsWith('<'))) {
    const plain = await c.get(carrierUrl(p.value))
    const plainBlocked = isBlocked(plain, carrierBase)
    const plainReflected = plain.body.includes(p.value)
    if (!plainBlocked && plainReflected && /html/i.test(plain.headers.get('content-type') ?? '')) {
      const again = await c.get(carrierUrl(p.value))
      if (again.body.includes(p.value)) {
        out.push(f({ severity: 'high', title: `Input comes back in the page without escaping: ${pathOf(carrierUrl(p.value))}`, url: carrierUrl(p.value), file: carrierUrl(p.value), cwe: 'CWE-79', description: `A harmless ${p.cls} marker was sent in a parameter and came back in the HTML exactly as sent, so a browser would treat it as markup. This is how reflected cross-site scripting works.`, fix: 'Escape output for the place it is used (HTML text, attribute, JavaScript, URL). Most template engines do this by default: do not turn it off.', proof: proofOf({ url: plain.url, status: plain.status, headers: plain.headers, body: plain.body, shows: [`the marker ${p.value} is in the page unchanged, in two separate requests`, plainBlocked ? '' : 'no firewall blocked it'].filter(Boolean) }) }, p.value))
        note(`Reported at once: ${pathOf(carrierUrl(p.value))} puts the test marker back in the page unescaped`)
      }
    }
    if (!plainBlocked) continue
    for (const v of VARIANTS) {
      const sent = v.value(p.value)
      const target = v.reflected(p.value)
      const r = await c.get(carrierUrl(sent))
      if (isBlocked(r, carrierBase) || !r.body.includes(target)) continue
      const again = await c.get(carrierUrl(sent))
      if (isBlocked(again, carrierBase) || !again.body.includes(target)) continue
      out.push(
        f(
          {
            severity: 'high',
            title: `Firewall bypass confirmed: ${p.cls} sent as ${v.how}`,
            url: carrierUrl(sent),
            file: carrierUrl(sent),
            cwe: 'CWE-693',
            description: `The firewall blocks the plain test string, but the same string sent as ${v.how} was not blocked and came back in the page as markup. Whoever runs the firewall should tighten that rule. The string was harmless: nothing ran.`,
            fix: 'Tell the owner of the web firewall which variant got through, so the rule can decode and normalise input before matching. The real fix is still to escape output in the application.',
            proof: proofOf({ url: r.url, status: r.status, headers: r.headers, body: r.body, shows: [`plain string: answer ${plain.status} (blocked)`, `${v.how}: answer ${r.status}, and the marker is in the page unchanged`, 'repeated twice with the same result'] })
          },
          `${p.cls}${v.how}`
        )
      )
      note(`Reported at once: firewall bypass (${v.how})`)
    }
  }
  return out
}

// ---------------------------------------------------------------- Login checks

export interface LoginForm {
  action: string
  fields: Record<string, string>
  userField: string
  passField: string
}

const attr = (tag: string, name: string): string => new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag)?.slice(2, 5).find((x) => x !== undefined) ?? ''

export function parseForms(html: string): { action: string; method: string; inputs: { type: string; name: string; value: string }[] }[] {
  return [...html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)].map((m) => ({
    action: attr(m[1], 'action'),
    method: (attr(m[1], 'method') || 'get').toLowerCase(),
    inputs: [...m[2].matchAll(/<input\b[^>]*>/gi)].map((i) => ({ type: (attr(i[0], 'type') || 'text').toLowerCase(), name: attr(i[0], 'name'), value: attr(i[0], 'value') })).filter((i) => i.name)
  }))
}

/** A sign-in form: a POST form with a password box. */
export function findLoginForm(html: string, pageUrl: string): LoginForm | null {
  for (const fm of parseForms(html)) {
    const pass = fm.inputs.find((i) => i.type === 'password')
    const user = fm.inputs.find((i) => ['text', 'email', 'tel'].includes(i.type))
    if (!pass || !user || fm.method !== 'post') continue
    const fields: Record<string, string> = {}
    for (const i of fm.inputs) if (i.type === 'hidden') fields[i.name] = i.value
    return { action: new URL(fm.action || pageUrl, pageUrl).href, fields, userField: user.name, passField: pass.name }
  }
  return null
}

/** A "forgot password" form: a POST form with one text or email box and no password box. */
export function findResetForm(html: string, pageUrl: string): { action: string; fields: Record<string, string>; emailField: string } | null {
  for (const fm of parseForms(html)) {
    if (fm.method !== 'post' || fm.inputs.some((i) => i.type === 'password')) continue
    const em = fm.inputs.find((i) => ['text', 'email'].includes(i.type))
    if (!em) continue
    const fields: Record<string, string> = {}
    for (const i of fm.inputs) if (i.type === 'hidden') fields[i.name] = i.value
    return { action: new URL(fm.action || pageUrl, pageUrl).href, fields, emailField: em.name }
  }
  return null
}

const cookiesOf = (r: Reply): string => (r.headers.getSetCookie?.() ?? []).map((c0) => c0.split(';')[0]).join('; ')
const LOGIN_PAGES = ['login', 'signin', 'user/login', 'users/sign_in', 'account/login', 'auth/login', 'admin/login', 'wp-login.php']
const RESET_PAGES = ['forgot-password', 'password/reset', 'forgot', 'password/forgot', 'users/password/new', 'account/forgot-password', 'password_reset', 'reset-password']

async function findPage(c: ConfirmClient, pages: string[], pick: (html: string, url: string) => unknown): Promise<{ url: string; found: any } | null> {
  for (const p of pages) {
    if (c.left() < 5) break
    try {
      const r = await c.get(p, { headers: 'none' })
      if (r.status !== 200) continue
      const found = pick(r.body, r.url)
      if (found) return { url: r.url, found }
    } catch (e) {
      if (e instanceof Stop) throw e
    }
  }
  return null
}

const THROTTLE = /too many|try again (later|in)|temporarily (locked|blocked)|account (is )?locked|rate limit|slow down|captcha|recaptcha|hcaptcha|verify you are human/i

/** Why two answers differ, in a few words, without anything secret. */
function whyDiffers(a: string, b: string): string {
  let i = 0
  while (i < a.length && i < b.length && a[i] === b[i]) i++
  const cut = (s: string): string => s.slice(Math.max(0, i - 15), i + 70).trim()
  return `"${cut(a)}" compared with "${cut(b)}"`
}

/**
 * Login checks with made-up users, so no real account can be locked:
 *  - eight wrong guesses for a user that does not exist, to see whether anything slows or stops them
 *  - the answer for a real user (yours) with a wrong password, compared with a user that does not exist
 */
export async function loginChecks(c: ConfirmClient, o: { loginUrl?: string; knownUser?: string }, note: (d: string) => void): Promise<Finding[]> {
  const out: Finding[] = []
  try {
    await loginInner(c, o, note, out)
  } catch (e) {
    if (e instanceof Stop) note(e.message)
    else throw e
  }
  return out
}

async function loginInner(c: ConfirmClient, o: { loginUrl?: string; knownUser?: string }, note: (d: string) => void, out: Finding[]): Promise<Finding[]> {
  const page = await findPage(c, o.loginUrl ? [o.loginUrl] : LOGIN_PAGES, findLoginForm)
  if (!page) {
    note('No sign-in form was found, so login checks were skipped. Add its address if it is somewhere unusual.')
    return out
  }
  const form = page.found as LoginForm
  const attempt = async (user: string, pass: string): Promise<Reply> => {
    const fresh = await c.get(page.url, { headers: 'none' })
    const ff = findLoginForm(fresh.body, fresh.url) ?? form
    return c.post(ff.action, { ...ff.fields, [ff.userField]: user, [ff.passField]: pass }, { headers: 'none', cookie: cookiesOf(fresh) })
  }
  const nobody = (): string => `macsec.${randomBytes(4).toString('hex')}@example.invalid`
  const wrong = (): string => `Wr0ng-${randomBytes(5).toString('hex')}`

  // 1. Limits on wrong guesses.
  const rows: Reply[] = []
  let throttledAt = 0
  const first = nobody()
  for (let i = 1; i <= 8; i++) {
    const r = await attempt(first, wrong())
    rows.push(r)
    if (r.status === 429 || r.headers.get('retry-after') || THROTTLE.test(visibleText(r.body))) {
      throttledAt = i
      break
    }
  }
  if (!throttledAt) {
    const last = rows[rows.length - 1]
    out.push(f({ severity: 'medium', title: 'Login does not slow down or stop repeated wrong guesses', url: page.url, file: page.url, cwe: 'CWE-307', description: `Eight wrong passwords in a row were tried for a user that does not exist (so no real account was touched). Nothing slowed down, blocked, or asked for a captcha. A limit that starts after more than eight tries would not show here.`, fix: 'Limit failed sign-ins per account and per address (for example five tries, then a growing delay or a captcha), and alert on bursts.', proof: proofOf({ method: 'POST', url: form.action, status: last.status, headers: last.headers, body: last.body, shows: [`8 wrong guesses answered ${[...new Set(rows.map((r) => r.status))].join(', ')} with the same kind of page each time`, 'no 429, no Retry-After, no lock or captcha message'] }) }, 'throttle'))
    note('Reported at once: the login has no limit on wrong guesses')
  } else note(`The login reacted after ${throttledAt} wrong guesses (good)`)

  // 2. Does the login reveal which users exist?
  if (o.knownUser) {
    const u1 = await attempt(nobody(), wrong())
    const u2 = await attempt(nobody(), wrong())
    const k1 = await attempt(o.knownUser, wrong())
    const k2 = await attempt(o.knownUser, wrong())
    const t = (r: Reply, who: string): string => visibleText(r.body).split(who).join('').slice(0, 600)
    const stable = (a: Reply, b: Reply, wa: string, wb: string): boolean => a.status === b.status && locOf(a) === locOf(b) && t(a, wa) === t(b, wb)
    const sameUnknown = stable(u1, u2, '', '')
    const sameKnown = stable(k1, k2, o.knownUser, o.knownUser)
    const differs = u1.status !== k1.status || locOf(u1) !== locOf(k1) || t(u1, '') !== t(k1, o.knownUser)
    if (sameUnknown && sameKnown && differs) {
      out.push(f({ severity: 'medium', title: 'Login shows which usernames exist', url: page.url, file: page.url, cwe: 'CWE-204', description: 'The answer to a wrong password is different for a real user than for a user that does not exist, so anyone can build a list of valid accounts.', fix: 'Give the same message, status and timing whether the user exists or not, for example "The email or password is wrong".', proof: proofOf({ method: 'POST', url: form.action, status: k1.status, headers: k1.headers, body: k1.body, shows: [`user that does not exist: answer ${u1.status}${locOf(u1) ? ` to ${locOf(u1).slice(0, 60)}` : ''}`, `real user, wrong password: answer ${k1.status}${locOf(k1) ? ` to ${locOf(k1).slice(0, 60)}` : ''}`, t(u1, '') !== t(k1, o.knownUser) ? whyDiffers(t(u1, ''), t(k1, o.knownUser)) : 'the pages have the same text', 'each case was repeated and gave the same answer both times'] }) }, 'enum'))
      note('Reported at once: the login reveals which usernames exist')
    }
  }
  return out
}

/** Password reset: does the answer reveal whether an email has an account? Sends one reset email to the address you gave. */
export async function resetCheck(c: ConfirmClient, email: string, note: (d: string) => void): Promise<Finding[]> {
  const page = await findPage(c, RESET_PAGES, findResetForm)
  if (!page) {
    note('No password reset form was found, so that check was skipped')
    return []
  }
  const form = page.found as { action: string; fields: Record<string, string>; emailField: string }
  const ask = async (addr: string): Promise<Reply> => {
    const fresh = await c.get(page.url, { headers: 'none' })
    const ff = findResetForm(fresh.body, fresh.url) ?? form
    return c.post(ff.action, { ...ff.fields, [ff.emailField]: addr }, { headers: 'none', cookie: cookiesOf(fresh) })
  }
  const n1 = await ask(`macsec.${randomBytes(4).toString('hex')}@example.invalid`)
  const n2 = await ask(`macsec.${randomBytes(4).toString('hex')}@example.invalid`)
  const k = await ask(email)
  const t = (r: Reply, who = ''): string => visibleText(r.body).split(who).join('').slice(0, 600)
  const stable = n1.status === n2.status && locOf(n1) === locOf(n2) && t(n1) === t(n2)
  const differs = n1.status !== k.status || locOf(n1) !== locOf(k) || t(n1) !== t(k, email)
  if (!stable || !differs) return []
  return [f({ severity: 'medium', title: 'Password reset shows which emails have an account', url: page.url, file: page.url, cwe: 'CWE-204', description: 'The reset form answers differently for an email with an account than for one without, so anyone can find out who is registered.', fix: 'Always say "If that email has an account, we sent a link", with the same status and timing either way.', proof: proofOf({ method: 'POST', url: form.action, status: k.status, headers: k.headers, body: k.body, shows: [`email without an account: answer ${n1.status}, the same twice`, `email with an account: answer ${k.status}`, whyDiffers(t(n1), t(k, email))] }) }, 'reset')]
}

// ---------------------------------------------------------------- Access checks (two accounts)

/** Links that could sign someone out or change something when opened. Never requested by the confirmation checks. */
export const risky = (u: string): boolean => /log-?out|sign-?out|delete|remove|destroy|unsubscribe|revoke|cancel|disable|deactivate|reset|clear|wipe|purge/i.test(u)

const ASSET = /\.(png|jpe?g|gif|svg|ico|webp|css|js|map|woff2?|ttf|eot|mp4|mp3|pdf|zip)(\?|$)/i
const ID_LIKE = /\/(\d{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(\/|$|\?)|[?&](id|user_?id|account|order|invoice)=\d+/i
const ADMIN_LIKE = /(^|\/)(admin|administrator|manage|staff|backoffice|internal)(\/|$)/i
const ADMIN_PATHS = ['admin', 'admin/users', 'dashboard/admin', 'api/admin', 'api/users', 'manage']
const hasLoginBox = (html: string): boolean => /type\s*=\s*["']?password/i.test(html)

/**
 * Whether a second account can open what the first account can. It only reads. A finding is
 * "confirmed" when account A's own identifier shows up in the page that account B received.
 */
export async function accessChecks(c: ConfirmClient, urls: string[], o: { headersB: Record<string, string>; identityA?: string }, note: (d: string) => void): Promise<Finding[]> {
  const out: Finding[] = []
  const seen = new Set<string>()
  const list = [...urls, ...ADMIN_PATHS.map((p) => c.resolve(p))].filter((u) => {
    try {
      const k = new URL(u)
      if (k.origin !== c.origin || ASSET.test(k.pathname) || risky(k.pathname + k.search)) return false
      const key = k.pathname + k.search
      if (seen.has(key)) return false
      seen.add(key)
      return true
    } catch {
      return false
    }
  }).slice(0, 70)
  const cal = await calibrate(c).catch(() => [])
  for (const [i, u] of list.entries()) {
    if (c.left() < 8) break
    if (i % 10 === 0) note(`Compared ${i} of ${list.length} pages between two accounts`)
    try {
      const a = await c.get(u)
      if (a.status !== 200 || a.body.length < 150 || hasLoginBox(a.body)) continue
      const anon = await c.get(u, { headers: 'none' })
      if (anon.status === 200 && similar(a, anon) && !hasLoginBox(anon.body)) continue
      const anonDenied = [401, 403].includes(anon.status) || (anon.status >= 300 && anon.status < 400) || hasLoginBox(anon.body)
      if (!anonDenied) continue
      const b = await c.get(u, { headers: o.headersB })
      if (b.status !== 200 || hasLoginBox(b.body)) continue
      if (cal.length && isCatchAll(new URL(u).pathname.replace(/^\//, ''), b, cal)) continue
      const idLeak = !!o.identityA && a.body.includes(o.identityA) && b.body.includes(o.identityA)
      const same = similar(a, b)
      const path = pathOf(u)
      if (!idLeak && !(same && (ID_LIKE.test(u) || ADMIN_LIKE.test(new URL(u).pathname)))) continue
      const b2 = await c.get(u, { headers: o.headersB })
      if (b2.status !== 200 || (idLeak && !b2.body.includes(o.identityA!)) || (!idLeak && !similar(a, b2))) continue
      const admin = ADMIN_LIKE.test(new URL(u).pathname)
      out.push(
        f(
          {
            severity: idLeak ? 'high' : 'medium',
            confidence: idLeak ? 'confirmed' : 'possible',
            title: admin ? `Another account can open an admin page: ${path}` : `Another account can open this page: ${path}`,
            url: u,
            file: u,
            cwe: admin ? 'CWE-285' : 'CWE-639',
            description: idLeak ? `A page that belongs to the first account was served to the second account. The first account's identifier is in the page the second account received. Signed out, the page is refused.` : `The second account got the same page as the first, and signed out it is refused. Nothing in the page proves it belongs to the first account, so look at it by hand.`,
            fix: 'Check on the server, for every request, that the signed-in user is allowed to see that exact record or function. Do not rely on hidden links, ids that are hard to guess, or the menu.',
            proof: proofOf({ url: u, status: b.status, headers: b.headers, body: b.body, shows: [`signed out: answer ${anon.status}`, `account B: answer ${b.status}, repeated with the same result`, idLeak ? "account A's identifier is in the page account B received" : 'the page is the same for both accounts'] })
          },
          u
        )
      )
      note(`Reported at once: another account can open ${path}`)
    } catch (e) {
      if (e instanceof Stop) {
        note(e.message)
        break
      }
    }
  }
  return out
}
