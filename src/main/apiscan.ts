/**
 * API security review. Two parts, both read-only:
 *
 *  1. The description file itself: endpoints with no sign-in, secrets in URLs, real keys saved in
 *     examples or in the collection, plain HTTP.
 *  2. Ordinary requests to the API's GET endpoints, signed in as you, to check what comes back:
 *     security headers, cross-origin settings, error pages that reveal internals, and sensitive
 *     fields in responses.
 *
 * Only GET requests are sent, only to the API's own address, slowly. Nothing is changed.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs'
import { randomBytes } from 'crypto'
import { join } from 'path'
import type { ApiAuth, ApiScanRequest, ApiSpecInfo, Finding, ScanMode, SessionInfo, Severity } from '../shared/types'
import { parseSpec, type Endpoint, type ParsedSpec } from './apispec'
import { beginOp, endOp, runTool, SessionRun } from './engine'
import { createSession, saveAiReport } from './sessions'
import { fid } from './scanners/parse'
import { parseNuclei } from './scanners/web'
import { installTool, isInstalled, nucleiTemplatesDir, toolDef } from './toolbox'
import { isLocalTarget, NOT_READ_ONLY } from './webscan'
import { dirs } from './paths'
import { log } from './logs'
import { summarizeWithAi, summaryPrompt } from './aisummary'

const specDir = (): string => join(dirs.config(), 'api-specs')

/** Keeps a copy of the file you chose, so a scan can be run again later. */
export function loadSpec(path: string): ApiSpecInfo {
  const text = readFileSync(path, 'utf8')
  const spec = parseSpec(text, path.split('/').pop())
  const id = randomBytes(6).toString('hex')
  mkdirSync(specDir(), { recursive: true })
  writeFileSync(join(specDir(), `${id}.txt`), text)
  return { id, name: spec.name, format: spec.format, baseUrl: spec.baseUrl, endpoints: spec.endpoints.map((e) => ({ method: e.method, url: e.url, name: e.name })) }
}

const SECRET_VALUE = /(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}|sk_live_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/
const SECRET_PARAM = /^(password|passwd|pwd|secret|token|access_?token|api_?key|apikey|auth|session|sessionid|client_secret|private_key)$/i

const f = (severity: Severity, title: string, x: Partial<Finding>): Finding => ({ id: fid('api', title, x.url, x.file), tool: 'MacSec', category: 'api', severity, title, ...x })

/** What the description file itself gives away. */
export function reviewSpec(spec: ParsedSpec): Finding[] {
  const out: Finding[] = []
  if (!spec.hasAuthScheme && spec.endpoints.length > 0) out.push(f('high', 'The API describes no way to sign in', { file: spec.baseUrl, cwe: 'CWE-306', description: 'No security scheme is defined, so every endpoint looks public.', fix: 'Add a security scheme (bearer token, OAuth or API key) and require it on every endpoint that is not meant to be public.' }))
  const open = spec.endpoints.filter((e) => e.secured === false && (e.method !== 'GET' || /\{[^}]+\}|:\w+|\/\d+(\/|$)/.test(e.path)))
  if (spec.hasAuthScheme)
    for (const e of open.slice(0, 50))
      out.push(f(e.method === 'GET' ? 'medium' : 'high', `${e.method} ${e.path} needs no sign-in`, { file: `${e.method} ${e.path}`, url: e.url, cwe: 'CWE-306', description: 'The file marks this endpoint as public. Check that it really should be.', fix: 'Require sign-in on this endpoint, and check the signed-in user may use the record it names.' }))
  if (/^http:\/\//.test(spec.baseUrl) && !isLocalTarget(spec.baseUrl)) out.push(f('medium', 'The API address uses plain HTTP', { file: spec.baseUrl, cwe: 'CWE-319', fix: 'Serve the API over HTTPS only.' }))
  for (const e of spec.endpoints)
    for (const p of e.params.filter((p) => p.in === 'query' && SECRET_PARAM.test(p.name))) out.push(f('medium', `Secret sent in the address: "${p.name}" on ${e.method} ${e.path}`, { file: `${e.method} ${e.path}`, cwe: 'CWE-598', description: 'Values in the address end up in browser history, server logs and proxies.', fix: 'Send it in a header or the request body instead.' }))
  for (const e of spec.endpoints) {
    const hit = e.examples.map((x) => SECRET_VALUE.exec(x)).find(Boolean)
    if (hit) out.push(f('high', `A real-looking key in the examples of ${e.method} ${e.path}`, { file: `${e.method} ${e.path}`, cwe: 'CWE-798', description: `Starts with ${hit[0].slice(0, 6)}…`, fix: 'Replace it with a placeholder. If it was ever real, revoke it.' }))
  }
  for (const s of spec.saved) out.push(f('high', `A token is saved in the collection (${s.where})`, { file: s.where, cwe: 'CWE-798', description: `Anyone with this file can use it. It starts with ${s.value.slice(0, 4)}…`, fix: 'Move it to a Postman environment variable that is not shared or exported, and replace the token.' }))
  return out
}

const SENSITIVE_KEY = /^(password|password_?hash|passwd|secret|client_?secret|api_?key|private_?key|ssn|social_?security|credit_?card|card_?number|cvv|pin|otp|mfa_?secret|reset_?token|remember_?token)$/i
const STACK = /(Traceback \(most recent call last\)|at [\w$.]+\([\w./-]+:\d+:\d+\)|Stack trace:|\.php on line \d+|Whoops!|Illuminate\\|SQLSTATE\[|ORA-\d{5}|PG::|Microsoft OLE DB|java\.lang\.\w+Exception|System\.\w+Exception|ActiveRecord::|Django Version:|DEBUG = True)/

function sensitiveKeys(value: unknown, path = '', out = new Set<string>(), depth = 0): Set<string> {
  if (depth > 6 || out.size > 20 || value === null || typeof value !== 'object') return out
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (SENSITIVE_KEY.test(k) && v !== null && v !== '' && typeof v !== 'object') out.add(path ? `${path}.${k}` : k)
    sensitiveKeys(v, Array.isArray(value) ? path : path ? `${path}.${k}` : k, out, depth + 1)
  }
  return out
}

function authHeaders(a: ApiAuth): Record<string, string> {
  if (a.kind === 'bearer' && a.value) return { Authorization: `Bearer ${a.value.replace(/^Bearer\s+/i, '')}` }
  if (a.kind === 'header' && a.value && a.header && /^[A-Za-z0-9-]+$/.test(a.header)) return { [a.header]: a.value }
  return {}
}

const LIMIT: Record<ScanMode, number> = { quick: 25, standard: 120, thorough: 500 }

/** One ordinary GET per endpoint, signed in as you, to see what the API sends back. */
async function probe(endpoints: Endpoint[], base: string, auth: ApiAuth, cancelled: () => boolean, note: (d: string) => void): Promise<Finding[]> {
  const host = new URL(base).host
  const out: Finding[] = []
  const hostIssues = new Map<string, Finding>()
  const headers = { 'User-Agent': 'MacSec API review', Accept: 'application/json', Origin: 'https://macsec-origin-check.example', ...authHeaders(auth) }
  for (const [i, e] of endpoints.entries()) {
    if (cancelled()) break
    note(`${i + 1} of ${endpoints.length}: ${e.method} ${e.path}`)
    let url: URL
    try {
      url = new URL(e.url.replace(/\{\{[^}]+\}\}/g, ''), base)
    } catch {
      continue
    }
    if (url.host !== host) continue
    try {
      const r = await fetch(url, { headers, redirect: 'manual', signal: AbortSignal.timeout(15000) })
      const body = (await r.text()).slice(0, 500_000)
      const where = { file: `${e.method} ${e.path}`, url: url.href }
      const acao = r.headers.get('access-control-allow-origin')
      if (acao === headers.Origin && r.headers.get('access-control-allow-credentials') === 'true') hostIssues.set('cors', f('high', 'Any website can read this API’s responses as the signed-in user', { ...where, cwe: 'CWE-942', description: 'The API copies any Origin into Access-Control-Allow-Origin and allows credentials.', fix: 'Allow only your own front-end origins.' }))
      else if (acao === '*' && Object.keys(authHeaders(auth)).length) hostIssues.set('cors-any', f('low', 'Cross-origin access is open to every site', { ...where, cwe: 'CWE-942', fix: 'List the origins that may call the API instead of *.' }))
      if (STACK.test(body)) out.push(f(r.status >= 500 ? 'medium' : 'low', `${e.method} ${e.path} shows internal error details`, { ...where, cwe: 'CWE-209', description: `Status ${r.status}. The response includes a stack trace or database error.`, fix: 'Turn off debug output in production and return a plain error message.' }))
      else if (r.status >= 500) out.push(f('low', `${e.method} ${e.path} fails with ${r.status}`, { ...where, description: 'An ordinary request makes the server fail.', fix: 'Check the server log for this endpoint.' }))
      if (/json/.test(r.headers.get('content-type') ?? '') && r.status < 300) {
        try {
          const keys = [...sensitiveKeys(JSON.parse(body))]
          if (keys.length) out.push(f(/password|secret|key|cvv|pin|otp/i.test(keys.join()) ? 'high' : 'medium', `${e.method} ${e.path} returns sensitive fields`, { ...where, cwe: 'CWE-200', description: `Fields: ${keys.slice(0, 8).join(', ')}`, fix: 'Leave these fields out of the response (an API resource or serializer with an explicit list of fields).' }))
        } catch {
          // Not valid JSON.
        }
      }
      if (url.protocol === 'https:' && !r.headers.get('strict-transport-security')) hostIssues.set('hsts', f('low', 'API responses have no Strict-Transport-Security', { ...where, cwe: 'CWE-319', fix: 'Send Strict-Transport-Security: max-age=31536000.' }))
      if (r.headers.get('x-content-type-options') !== 'nosniff') hostIssues.set('nosniff', f('low', 'API responses have no X-Content-Type-Options: nosniff', { ...where, fix: 'Send X-Content-Type-Options: nosniff.' }))
      const ver = [r.headers.get('server'), r.headers.get('x-powered-by')].filter((v): v is string => !!v && /\d/.test(v))
      if (ver.length) hostIssues.set('version', f('low', 'The API reveals software versions', { ...where, cwe: 'CWE-200', description: ver.join(', '), fix: 'Hide version numbers in Server and X-Powered-By.' }))
      if (Object.keys(authHeaders(auth)).length && r.status < 300 && !/no-store|private/.test(r.headers.get('cache-control') ?? '')) hostIssues.set('cache', f('low', 'Signed-in responses can be cached', { ...where, cwe: 'CWE-525', fix: 'Send Cache-Control: no-store on responses for signed-in users.' }))
    } catch {
      // Unreachable endpoint: nothing to report.
    }
    await new Promise((res) => setTimeout(res, 150))
  }
  return [...out, ...hostIssues.values()]
}

export function startApiScan(req: ApiScanRequest): SessionInfo {
  if (!/^[a-f0-9]{12}$/.test(req.spec) || !existsSync(join(specDir(), `${req.spec}.txt`))) throw new Error('Load the API file again.')
  const spec = parseSpec(readFileSync(join(specDir(), `${req.spec}.txt`), 'utf8'))
  const base = (req.baseUrl || spec.baseUrl).replace(/\/+$/, '')
  if (!/^https?:\/\/[^\s/]+/.test(base)) throw new Error('Enter the API’s address, like https://api.example.com.')
  if (!isLocalTarget(base) && !req.authorized) throw new Error('Confirm that you own this API or have permission to test it.')
  const info = createSession('api-scan', spec.name, base)
  info.mode = req.mode
  info.reviewer = req.reviewer
  void runApiScan(info.id, spec, base, req).catch((e) => log('error', `API review: ${(e as Error).message}`, info.id))
  return info
}

async function runApiScan(id: string, spec: ParsedSpec, base: string, req: ApiScanRequest): Promise<void> {
  const op = beginOp(id)
  const s = new SessionRun(id, op)
  s.info.files = spec.endpoints.length
  const gets = spec.endpoints.filter((e) => e.method === 'GET').slice(0, LIMIT[req.mode])
  const st = {
    spec: s.step('spec', `Review the ${spec.format === 'har' ? 'recorded traffic' : spec.format === 'postman' ? 'Postman collection' : 'API description'}: ${spec.endpoints.length} endpoints`),
    probe: s.step('probe', `Ordinary GET requests to ${gets.length} endpoints, signed in as you`),
    nuclei: req.mode !== 'quick' ? s.step('nuclei', 'Nuclei read-only checks for exposed docs, panels and settings') : null,
    ai: req.reviewer !== 'none' ? s.step('ai', 'AI: what matters most and how to fix it') : null
  }
  try {
    await s.run(st.spec, async () => reviewSpec(spec))
    await s.run(st.probe, (note) => probe(gets, base, req.auth, () => s.cancelled, note))
    if (st.nuclei)
      await s.run(st.nuclei, async () => {
        const d = toolDef('nuclei')
        if (d && !isInstalled(d)) await installTool('nuclei', () => undefined)
        const out = join(s.raw, 'nuclei.jsonl')
        await runTool({ name: 'nuclei', bin: 'nuclei', args: ['-u', base, '-t', nucleiTemplatesDir(), '-ud', nucleiTemplatesDir(), '-tags', 'api,exposure,misconfig,swagger,graphql,token,config', '-etags', NOT_READ_ONLY, '-duc', '-nc', '-silent', '-jsonl', '-o', out, '-rl', '20', '-c', '10', '-timeout', '10'], timeoutMs: 30 * 60_000, output: out }, op, s.raw).catch((e) => {
          if (!existsSync(out)) throw e
          return ''
        })
        return existsSync(out) ? parseNuclei(readFileSync(out, 'utf8')).map((x) => ({ ...x, category: 'api' as const })) : []
      })
    if (st.ai)
      await s.run(st.ai, async () => {
        const r = await summarizeWithAi(req.reviewer, summaryPrompt('api', base, `The API has ${spec.endpoints.length} endpoints (${spec.format}).`, s.findings), op, s.raw)
        for (const x of s.findings) {
          const d = r.details.get(x.id)
          if (d) {
            x.verdict = d.verdict
            x.aiNote = d.reason
          }
        }
        saveAiReport(id, r.report)
        return []
      })
    s.finish()
  } catch (e) {
    s.finish((e as Error).message)
  } finally {
    endOp(id)
    log('info', `API review of ${base} ${s.info.status}`, id)
  }
}
