/**
 * Injection checks on every input the scan can see, done the safe way. For each query parameter and
 * each field of every GET form, MacSec sends harmless markers and reads how the page reacts:
 *
 *   Unescaped output   a made-up tag comes back as a tag (cross-site scripting)
 *   Database errors    one quote makes the page show a database error and two quotes do not (SQL injection)
 *   Template maths     the server calculates 1337 x 7331 for us (server-side template injection)
 *   Header injection   a line break in a value ends up as a response header
 *
 * Nothing here runs code, reads files or touches other people's data: the markers are inert text and
 * one piece of arithmetic. Only GET is used, so nothing is changed, and pages that look like they
 * change state (logout, delete, pay) are skipped. Forms that send data (POST) are listed, never
 * submitted. Every hit is repeated once and kept with its proof. Tools that really exploit (sqlmap,
 * XSS payload fuzzers) are never run.
 */
import type { Finding } from '../shared/types'
import { ConfirmClient, parseForms, risky, Stop, type Reply } from './confirmtests'
import { fid } from './scanners/parse'
import { proofOf } from './seckit/confirm'

export interface Input {
  /** The page the input belongs to, without a query string. */
  page: string
  name: string
  /** Every parameter of that page and its normal value. */
  params: Record<string, string>
  from: 'address' | 'form'
}

export interface PostForm {
  page: string
  action: string
  fields: string[]
}

const SKIP_TYPES = new Set(['password', 'file', 'submit', 'button', 'image', 'reset', 'checkbox', 'radio', 'hidden'])
const TOKENISH = /^(_?csrf|_?token|authenticity_token|__requestverificationtoken|nonce|_wpnonce|state|signature|sig|hmac)$/i
const STATIC = /\.(png|jpe?g|gif|svg|ico|webp|css|js|map|woff2?|ttf|pdf|zip|mp4|mp3)(\?|$)/i

const safeUrl = (u: string, base?: string): URL | null => {
  try {
    return new URL(u, base)
  } catch {
    return null
  }
}

/** The inputs worth testing, and the forms that send data and are therefore only listed. */
export function inputsFrom(pages: { url: string; html: string }[], urls: string[], origin: string, cap = 120): { inputs: Input[]; posts: PostForm[] } {
  const inputs = new Map<string, Input>()
  const posts: PostForm[] = []
  const add = (page: URL, name: string, params: Record<string, string>, from: Input['from']): void => {
    if (!name || TOKENISH.test(name) || page.origin !== origin || STATIC.test(page.pathname) || risky(page.href)) return
    const key = `${page.pathname}|${name}`
    if (!inputs.has(key) && inputs.size < cap) inputs.set(key, { page: `${page.origin}${page.pathname}`, name, params, from })
  }
  for (const u of urls) {
    const p = safeUrl(u)
    if (!p || !p.search) continue
    const params = Object.fromEntries(p.searchParams)
    for (const k of Object.keys(params)) add(p, k, params, 'address')
  }
  for (const pg of pages) {
    for (const fm of parseForms(pg.html)) {
      const action = safeUrl(fm.action || pg.url, pg.url)
      if (!action) continue
      const html = pg.html
      const extra = [...html.matchAll(/<(?:textarea|select)\b[^>]*\bname=["']([^"']+)["']/gi)].map((m) => m[1])
      const fields = fm.inputs.filter((i) => !SKIP_TYPES.has(i.type) && !TOKENISH.test(i.name))
      const names = [...fields.map((i) => i.name), ...extra]
      if (fm.method !== 'get') {
        if (names.length || fm.inputs.length) posts.push({ page: pg.url, action: action.href, fields: [...new Set([...fm.inputs.map((i) => i.name), ...extra])].slice(0, 12) })
        continue
      }
      const params: Record<string, string> = {}
      for (const i of fm.inputs) if (!['submit', 'button', 'image', 'reset', 'file'].includes(i.type)) params[i.name] = i.value || (SKIP_TYPES.has(i.type) ? '' : '1')
      for (const n of extra) params[n] ??= '1'
      for (const n of names) add(action, n, { ...params }, 'form')
    }
  }
  return { inputs: [...inputs.values()], posts }
}

// ---------------------------------------------------------------- Probes

const PRODUCT = String(1337 * 7331)
const SQL_ERRORS: { db: string; re: RegExp }[] = [
  { db: 'MySQL or MariaDB', re: /You have an error in your SQL syntax|check the manual that corresponds to your (MySQL|MariaDB)|mysqli?_sql_exception|SQLSTATE\[42000\]|Unclosed quotation mark after the character string/i },
  { db: 'PostgreSQL', re: /unterminated quoted string at or near|syntax error at or near|PG::SyntaxError|pq: syntax error|org\.postgresql\.util\.PSQLException/i },
  { db: 'SQLite', re: /unrecognized token:|SQLITE_ERROR|near "[^"]*": syntax error|SQLite3::SQLException/i },
  { db: 'Microsoft SQL Server', re: /Unclosed quotation mark|Incorrect syntax near|Microsoft OLE DB Provider for SQL Server|System\.Data\.SqlClient\.SqlException/i },
  { db: 'Oracle', re: /ORA-0(1756|0933|0921)|quoted string not properly terminated/i },
  { db: 'a database layer', re: /SQL syntax.*error|syntax error.*SQL|java\.sql\.SQLSyntaxErrorException|Doctrine\\DBAL\\Exception|Illuminate\\Database\\QueryException/i }
]

export const sqlError = (body: string): string | null => SQL_ERRORS.find((e) => e.re.test(body))?.db ?? null

const rand = (): string => `msx${Math.random().toString(36).slice(2, 8)}`
const isHtml = (r: Reply): boolean => /html/i.test(r.headers.get('content-type') ?? '') || /<html|<body|<div|<p[ >]/i.test(r.body.slice(0, 2000))

function withValue(i: Input, value: string): string {
  const q = Object.entries({ ...i.params, [i.name]: value })
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&')
  return `${i.page}?${q}`
}

const pathOf = (u: string): string => safeUrl(u)?.pathname ?? u

/** A finding with its proof. */
function make(i: Input, kind: 'xss' | 'sqli' | 'ssti' | 'crlf', r: Reply, shows: string[], sent: string, extra: string): Finding {
  const where = `${i.name} on ${pathOf(i.page)}`
  const base = { tool: 'MacSec', category: 'web' as const, url: r.url, file: r.url, confidence: 'confirmed' as const, proof: proofOf({ url: r.url, status: r.status, headers: r.headers, body: r.body.slice(0, 300000), shows }) }
  const sentNote = `Sent: ${sent}`
  if (kind === 'xss')
    return { id: fid('inj-xss', i.page, i.name), ...base, severity: 'medium', title: `Input comes back in the page without escaping: ${where}`, cwe: 'CWE-79', description: `A made-up tag sent in "${i.name}" came back as a real tag, not as plain text. That is how cross-site scripting starts: an attacker can put a script in a link and run it in a visitor's browser. ${sentNote}. ${extra}`, fix: 'Escape every value when writing it into a page (your template engine does this by default: do not switch it off), and send a Content-Security-Policy header.' }
  if (kind === 'sqli')
    return { id: fid('inj-sqli', i.page, i.name), ...base, severity: 'high', title: `A quote in "${i.name}" makes the page show a database error: ${pathOf(i.page)}`, cwe: 'CWE-89', description: `One quote in "${i.name}" produced a ${extra} error message, and two quotes did not. Both times the page was otherwise the same. That means the value is put straight into a database query: the usual first sign of SQL injection. MacSec stopped there: it never tries to read or change data. ${sentNote}`, fix: 'Use parameterised queries (prepared statements) for every value that reaches the database, and turn off detailed error pages in production.' }
  if (kind === 'ssti')
    return { id: fid('inj-ssti', i.page, i.name), ...base, severity: 'high', title: `The server calculates an expression sent in "${i.name}": ${pathOf(i.page)}`, cwe: 'CWE-1336', description: `The text ${extra} sent in "${i.name}" came back as ${PRODUCT}, which is the result of the sum. So the server is running what it was given as a template. In many template engines that goes on to running commands on the server. MacSec only did the arithmetic. ${sentNote}`, fix: 'Never build a template from visitor input. Pass values in as data, not into the template text.' }
  return { id: fid('inj-crlf', i.page, i.name), ...base, severity: 'medium', title: `A line break in "${i.name}" is written into a response header: ${pathOf(i.page)}`, cwe: 'CWE-113', description: `A value with a line break and a made-up header name came back as a real header. An attacker can use that to set cookies, split the response or poison caches. ${sentNote}`, fix: 'Remove carriage returns and line feeds from any value before it is put into a header or a redirect address (current frameworks do this: update yours).' }
}

export interface InjectionOptions {
  cap?: number
  note?: (t: string) => void
}

/** Tests every input. A stop (cap, cancel, a struggling server) returns what was found until then. */
export async function injectionChecks(c: ConfirmClient, inputs: Input[], o: InjectionOptions = {}): Promise<Finding[]> {
  const out: Finding[] = []
  const note = o.note ?? (() => undefined)
  try {
    for (const [n, i] of inputs.entries()) {
      note(`${n + 1} of ${inputs.length}: ${i.name} on ${pathOf(i.page)}`)
      const normal = i.params[i.name] || '1'
      const base = await c.get(withValue(i, normal))
      if (base.status >= 500 || base.status === 429) continue
      const baseErr = sqlError(base.body)

      // 1. Markers for unescaped output, template maths and a header line break, in one request each time.
      const m = rand()
      const tag = `<${m}x>`
      const probe = `${m}${tag}"'{{1337*7331}}\${1337*7331}<%= 1337*7331 %>`
      const hit = async (): Promise<Reply> => c.get(withValue(i, probe))
      const r1 = await hit()
      const echoedTag = isHtml(r1) && r1.body.includes(tag) && !base.body.includes(tag)
      const evaluated = r1.body.includes(PRODUCT) && !base.body.includes(PRODUCT)
      if (echoedTag || evaluated) {
        const r2 = await hit()
        if (echoedTag && r2.body.includes(tag)) out.push(make(i, 'xss', r1, [`the made-up tag ${tag} came back as a tag, not as text`, 'the normal value does not contain it', 'it came back the same on a second try'], withValue(i, probe), ''))
        if (evaluated && r2.body.includes(PRODUCT)) out.push(make(i, 'ssti', r1, [`1337 x 7331 = ${PRODUCT} appears in the answer`, `${PRODUCT} is not in the answer to a normal value`, 'the same on a second try'], withValue(i, probe), '{{1337*7331}}'))
      }

      // 2. A single quote, then two quotes: a database error that only the single quote causes.
      if (!baseErr) {
        const q1 = await c.get(withValue(i, `${normal}'`))
        const db = sqlError(q1.body)
        if (db) {
          const q2 = await c.get(withValue(i, `${normal}''`))
          const again = await c.get(withValue(i, `${normal}'`))
          if (!sqlError(q2.body) && sqlError(again.body)) out.push(make(i, 'sqli', q1, [`one quote: a ${db} error message`, 'two quotes: no error', 'one quote again: the same error'], withValue(i, `${normal}'`), db))
        }
      }

      // 3. A line break and a made-up header name.
      const h = rand()
      const rc = await c.get(withValue(i, `${normal}\r\nX-Macsec-Inj: ${h}`))
      if (rc.headers.get('x-macsec-inj') === h) {
        const rc2 = await c.get(withValue(i, `${normal}\r\nX-Macsec-Inj: ${h}`))
        if (rc2.headers.get('x-macsec-inj') === h) out.push(make(i, 'crlf', rc, [`the header X-Macsec-Inj: ${h} appeared in the response`, 'it was not sent as a header, only inside a value', 'the same on a second try'], withValue(i, `${normal}\r\nX-Macsec-Inj: ${h}`), ''))
      }
    }
  } catch (e) {
    if (e instanceof Stop) note(e.message)
    else throw e
  }
  return out
}

/** Forms that send data: listed so the person knows they were not tested, with what to test by hand. */
export function postFormLead(posts: PostForm[]): Finding[] {
  if (!posts.length) return []
  const uniq = [...new Map(posts.map((p) => [`${p.action}|${p.fields.join(',')}`, p])).values()]
  return [{ id: fid('inj-posts', uniq.map((p) => p.action).join('|')), tool: 'MacSec', category: 'web', severity: 'info', confidence: 'possible', title: `${uniq.length} ${uniq.length === 1 ? 'form sends' : 'forms send'} data and ${uniq.length === 1 ? 'was' : 'were'} not tested`, description: `Sending a form can create or change records, so MacSec only reads. These forms need a hand test (on a test copy, or with a test account): ${uniq.slice(0, 10).map((p) => `${pathOf(p.action)} [${p.fields.join(', ')}]`).join('; ')}${uniq.length > 10 ? '; and more' : ''}. Try each field with a quote, a made-up tag and {{1337*7331}}, and watch for errors, echoes and the number ${PRODUCT}.`, fix: 'Test them with an intercepting proxy such as Burp or ZAP on a copy of the site, never on live data.' }]
}
