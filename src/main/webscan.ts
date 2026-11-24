/**
 * A web scan. Every mode only reads the site: it looks, it does not attack or change anything.
 * Control confirmations (confirmtests.ts) are a separate, opt-in step that proves problems are real
 * with harmless markers. For hands-on testing, open the site in Burp Suite.
 *
 *   Quick      fingerprint, headers and cookies, the most important exposed files, and Nuclei's
 *              critical to medium checks for known problems on the main address
 *   Standard   a crawl of the site, every exposed-file check, and every read-only Nuclei check
 *   Thorough   a deeper crawl with JavaScript, and Nuclei's read-only checks on every page found
 *
 * Scans of anything not on this Mac need your confirmation that you own it or may test it.
 */
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'fs'
import { homedir } from 'os'
import { join } from 'path'
import type { Finding, ScanMode, SessionInfo, WebScanRequest } from '../shared/types'
import { beginOp, endOp, runTool, SessionRun } from './engine'
import { createSession, saveAiReport, saveChecklist, savePlan } from './sessions'
import { proofOf } from './seckit/confirm'
import { planContext, planMarkdown, profileSite } from './testplan'
import { checkHeaders, parseFfuf, parseHttpx, parseKatana, parseNuclei, pathSeverity, SENSITIVE_PATHS, type Fingerprint } from './scanners/web'
import { fid, parseZap } from './scanners/parse'
import { execFileSync } from 'child_process'
import { appPath, installTool, isInstalled, nucleiTemplatesDir, toolDef } from './toolbox'
import { parseWpscan } from './scanners/infra'
import { dirs } from './paths'
import { getSettings } from './settings'
import { log } from './logs'
import { askAi, summarizeWithAi, summaryPrompt } from './aisummary'
import { crawlJs } from './jsdeep'
import { cveFindings, epssFor, liveCves } from './cvelive'
import { devopsChecks, dnsChecks, protectionFinding } from './webposture'
import { groupDecoyFiles } from './decoys'
import { bannersOf, type Product } from './seckit/confirm'
import { checkTls, keysInJavaScript, signedOutCheck } from './webextra'
import { logicChecks } from './bizlogic'
import { applyAnswers, autoMark, BATCH, parseAnswers, walkPrompt } from './checklist'
import { PARAM_WORDS } from './wordlists'
import { injectionChecks, inputsFrom, postFormLead } from './injection'
import { getPaths, mapCode, paramNames, unguardedPrivate, fillPath } from './routemap'
import { discoveryWords, writeWordlist } from './wordlistfiles'
import { calibrate, isCatchAll, visibleText } from './confirmtests'
import { oauthChecks } from './oauth'
import { jwtChecks } from './jwt'
import { graphqlChecks } from './graphql'
import { sessionChecks } from './sessioncheck'
import { runAutopilot, type Action } from './autopilot'
import { corsChecks } from './sessioncheck'
import type { Reply } from './confirmtests'
import { accessChecks, ConfirmClient, risky, fuzzContent, fuzzParams, loginChecks, resetCheck, wafControl } from './confirmtests'

/** Laramac's sites, from the www folder, at their .test addresses. */
export function localSites(): { name: string; url: string }[] {
  let tld = 'test'
  try {
    tld = (JSON.parse(readFileSync(join(homedir(), '.laramac', 'settings.json'), 'utf8')) as { tld?: string }).tld || 'test'
  } catch {
    // Laramac not set up: .test is its default.
  }
  const www = getSettings().wwwPath
  if (!existsSync(www)) return []
  return readdirSync(www)
    .filter((n) => !n.startsWith('.') && statSync(join(www, n)).isDirectory())
    .map((n) => ({ name: n, url: `http://${n.toLowerCase().replace(/[^a-z0-9-]+/g, '-')}.${tld}` }))
}

/** Docker's command, when OrbStack, Docker Desktop or Colima is installed and running. */
export function dockerPath(): string | null {
  for (const p of ['/usr/local/bin/docker', '/opt/homebrew/bin/docker', join(homedir(), '.orbstack', 'bin', 'docker'), '/Applications/Docker.app/Contents/Resources/bin/docker']) if (existsSync(p)) return dockerUp(p) ? p : null
  return null
}

let dockerChecked: { at: number; ok: boolean } | null = null
function dockerUp(bin: string): boolean {
  if (dockerChecked && Date.now() - dockerChecked.at < 60_000) return dockerChecked.ok
  let ok = false
  try {
    execFileSync(bin, ['info', '--format', '{{.ServerVersion}}'], { timeout: 8000, stdio: 'ignore' })
    ok = true
  } catch {
    ok = false
  }
  dockerChecked = { at: Date.now(), ok }
  return ok
}

/** Addresses on this Mac (and Laramac's domains) need no confirmation. */
export function isLocalTarget(url: string): boolean {
  const h = new URL(url).hostname
  return /^(localhost|127\.\d+\.\d+\.\d+|\[::1\])$/.test(h) || /\.(test|localhost)$/.test(h)
}

/** Nuclei tags that send anything beyond ordinary requests are always left out. */
export const NOT_READ_ONLY = 'dos,fuzz,fuzzing,intrusive,brute-force,bruteforce,dast,headless,sqli,rce,xss,lfi,ssrf,oast,oob,default-login'

const MODE: Record<ScanMode, { depth: number; rate: number; crawlSecs: number; paths: number; everyPage: boolean }> = {
  quick: { depth: 0, rate: 15, crawlSecs: 0, paths: 45, everyPage: false },
  standard: { depth: 3, rate: 25, crawlSecs: 300, paths: SENSITIVE_PATHS.length, everyPage: false },
  thorough: { depth: 5, rate: 30, crawlSecs: 900, paths: SENSITIVE_PATHS.length, everyPage: true }
}

export function parseHeaders(raw: string | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of (raw ?? '').split('\n')) {
    const m = /^([A-Za-z0-9-]+):\s*(.+)$/.exec(line.trim())
    if (m) out[m[1]] = m[2]
  }
  return out
}
const headerArgs = (h: Record<string, string>, flag: string): string[] => Object.entries(h).flatMap(([k, v]) => [flag, `${k}: ${v}`])

const templatesFresh = (): boolean => {
  const d = nucleiTemplatesDir()
  try {
    return existsSync(d) && readdirSync(d).length > 3 && Date.now() - statSync(d).mtimeMs < 24 * 3600 * 1000
  } catch {
    return false
  }
}

/** What a real file looks like, so a site that answers 200 for everything is not reported. */
export function looksReal(path: string, body: string, notFound: { status: number; length: number; body: string } | null): boolean {
  const b = body.slice(0, 4000)
  if (notFound && notFound.status === 200 && Math.abs(notFound.length - body.length) < 60) return false
  if (/^\.git\/HEAD$/.test(path)) return /^ref: refs\//.test(b)
  if (/^\.git\/config$/.test(path)) return /\[core\]/.test(b)
  if (/^\.env/.test(path)) return /^[A-Z][A-Z0-9_]+=/m.test(b) && !/<html/i.test(b)
  if (/\.(sql|sql\.gz)$/.test(path)) return /(CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump)/i.test(b) || !/<html/i.test(b)
  if (/phpinfo|info\.php/.test(path)) return /phpinfo\(\)|PHP Version/i.test(b)
  if (/\.DS_Store$/.test(path)) return b.includes('Bud1')
  if (/(composer|package)(-lock)?\.json$/.test(path)) return /"(require|dependencies|packages)"/.test(b)
  if (/swagger|openapi|api-docs/.test(path)) return /"(openapi|swagger)"|openapi:|swagger:/.test(b)
  if (/actuator/.test(path)) return /"(status|_links|activeProfiles|propertySources)"/.test(b)
  if (/laravel\.log|debug\.log|error_log|\.log$/.test(path)) return /(Stack trace|\[\d{4}-\d{2}-\d{2}|PHP (Warning|Fatal|Notice)|Exception)/.test(b)
  return !/<title>[^<]*(404|not found|page not found)/i.test(b)
}

/** MacSec's own check for files that should never be public: one ordinary GET per path, slowly. */
async function exposedFiles(base: string, paths: string[], headers: Record<string, string>, cancelled: () => boolean, note: (d: string) => void): Promise<Finding[]> {
  const get = async (p: string): Promise<{ status: number; body: string; length: number }> => {
    const r = await fetch(`${base}/${p}`, { redirect: 'manual', headers: { 'User-Agent': 'MacSec exposure check', Range: 'bytes=0-65535', ...headers }, signal: AbortSignal.timeout(12000) })
    const body = r.status >= 300 && r.status < 400 ? '' : await r.text()
    return { status: r.status, body, length: body.length }
  }
  const notFound = await get(`macsec-${Math.random().toString(36).slice(2)}.html`).catch(() => null)
  const out: Finding[] = []
  for (const [i, p] of paths.entries()) {
    if (cancelled()) break
    if (i % 10 === 0) note(`Checked ${i} of ${paths.length}`)
    try {
      const r = await get(p)
      const open = (r.status === 200 || r.status === 206) && looksReal(p, r.body, notFound)
      const severity = open ? pathSeverity(p, 200) : r.status === 401 || r.status === 403 ? pathSeverity(p, 403) : 'info'
      if (severity === 'info') continue
      out.push({
        id: fid('exposed', base, p),
        tool: 'MacSec',
        category: 'web',
        severity,
        title: open ? `Public file: /${p}` : `Exists but protected: /${p}`,
        url: `${base}/${p}`,
        file: `${base}/${p}`,
        cwe: severity === 'critical' || severity === 'high' ? 'CWE-538' : undefined,
        description: open ? `Anyone can download it (${r.length.toLocaleString()} bytes read).` : `The server answers ${r.status}, so it exists.`,
        fix: severity === 'critical' || severity === 'high' ? 'Remove it from the public folder, or deny it in the web server configuration. If it held passwords or keys, change them.' : undefined
      })
    } catch {
      // Unreachable path: nothing to report.
    }
    await new Promise((res) => setTimeout(res, 120))
  }
  return out
}

async function ensure(id: string): Promise<void> {
  const d = toolDef(id)
  if (d && !isInstalled(d)) await installTool(id, () => undefined)
}

export function startWebScan(req: WebScanRequest): SessionInfo {
  const url = req.target.kind === 'local' ? localSites().find((s) => s.name === (req.target as { name: string }).name)?.url : req.target.url
  if (!url) throw new Error('That site was not found in your www folder.')
  if (!isLocalTarget(url) && !req.authorized) throw new Error('Confirm that you own this site or have permission to test it.')
  const info = createSession('web-scan', new URL(url).host, url)
  info.mode = req.mode
  info.reviewer = req.reviewer
  void runWebScan(info.id, url.replace(/\/+$/, ''), req).catch((e) => log('error', `Web scan: ${(e as Error).message}`, info.id))
  return info
}

async function runWebScan(id: string, url: string, req: WebScanRequest): Promise<void> {
  const op = beginOp(id)
  const s = new SessionRun(id, op)
  const m = MODE[req.mode]
  const host = new URL(url).host
  const headers = parseHeaders(req.headers)
  const headersB = parseHeaders(req.confirm?.headersB)
  const mk = (cap: number): ConfirmClient => new ConfirmClient(url, { headers, cap, cancelled: () => s.cancelled, paused: () => op.paused })
  let carrier: string | undefined
  let codeNames: string[] = []
  const urlsFile = join(s.raw, 'urls.txt')
  let urls: string[] = [url]
  let fp: Fingerprint[] = []
  writeFileSync(urlsFile, url)

  const st = {
    fp: s.step('httpx', 'Fingerprint the server and technologies'),
    headers: s.step('headers', 'Check security headers, cookies and HTTPS'),
    tls: url.startsWith('https://') ? s.step('tls', 'Check the certificate and TLS versions') : null,
    crawl: m.depth ? s.step('katana', `Map the site, ${m.depth} levels deep`) : null,
    files: s.step('exposed', `Look for files that should not be public (${m.paths})`),
    discover: req.confirm?.discover ? s.step('ffuf', 'Content discovery with ffuf, then each hit proved') : null,
    js: m.depth ? s.step('js', 'Look for keys in the site’s public JavaScript') : null,
    infra: s.step('infra', 'Firewall, CDN, hosting, DNS and mail settings'),
    devops: s.step('devops', 'DevOps and infrastructure left open (Jenkins, Grafana, registries, clusters, state files, Git)'),
    jsdeep: m.depth ? s.step('jsdeep', 'JavaScript analysis: routes, hidden chunks, source maps, risks') : null,
    cves: s.step('cves', 'Known flaws for the versions found (live count from NVD, CISA and EPSS)'),
    access: m.depth && Object.keys(headers).length ? s.step('access', 'Compare private pages signed in and signed out') : null,
    fuzz: req.confirm?.fuzz ? s.step('fuzz', 'Control confirmation: hidden pages and parameters') : null,
    waf: req.confirm?.waf ? s.step('waf', 'Control confirmation: web firewall tests') : null,
    logic: req.confirm?.logic ? s.step('logic', 'Control confirmation: business logic (redirects, host header, code limits, skipped steps)') : null,
    code: req.codePath ? s.step('code', 'White box: read the code, map its routes and parameters, test them live') : null,
    inject: req.confirm?.inject ? s.step('inject', 'Control confirmation: injection tests on every page, parameter and form') : null,
    proto: req.confirm?.proto ? s.step('proto', 'Control confirmation: OAuth, tokens (JWT), GraphQL, CORS, CSRF and session ids') : null,
    autopilot: req.autopilot && req.reviewer !== 'none' ? s.step('autopilot', 'AI autopilot: the AI picks the next checks from a safe menu, MacSec runs them') : null,
    login: req.confirm?.auth ? s.step('login', 'Control confirmation: login checks') : null,
    authz: req.confirm?.authz && Object.keys(headers).length && Object.keys(headersB).length ? s.step('authz', 'Control confirmation: what a second account can open') : null,
    wp: s.step('wpscan', 'WordPress: version, plugins and themes (when the site uses it)'),
    templates: s.step('templates', 'Update Nuclei’s community checks'),
    zap: req.mode === 'thorough' && dockerPath() ? s.step('zap', 'ZAP baseline: passive checks while it browses (it never attacks)') : null,
    nuclei: s.step('nuclei', m.everyPage ? 'Nuclei read-only checks on every page' : req.mode === 'quick' ? 'Nuclei checks for serious known problems' : 'Every read-only Nuclei check'),
    checklist: req.checklist && req.reviewer !== 'none' ? s.step('checklist', 'AI: walk your checklist item by item, from the evidence only') : null,
    ai: req.reviewer !== 'none' ? s.step('ai', 'AI: what matters most and how to fix it') : null
  }
  try {
    await s.run(st.fp, async (note, line) => {
      await ensure('httpx')
      const out = await runTool({ name: 'httpx', bin: 'httpx', args: ['-u', url, '-json', '-silent', '-tech-detect', '-title', '-status-code', '-web-server', '-follow-redirects', '-no-color', ...headerArgs(headers, '-H')], timeoutMs: 120_000 }, op, s.raw, line)
      fp = parseHttpx(out)
      const f = fp[0]
      if (!f) throw new Error('The site did not answer.')
      s.info.languages = f.tech.slice(0, 8)
      note([f.status && `Status ${f.status}`, f.server, ...f.tech.slice(0, 5)].filter(Boolean).join(', '))
    })

    await s.run(st.headers, async () => {
      const res = await fetch(url, { redirect: 'follow', headers: { 'User-Agent': 'MacSec header check', ...headers }, signal: AbortSignal.timeout(20000) })
      await res.body?.cancel()
      const found = checkHeaders(res.url || url, res.headers, res.headers.getSetCookie())
      if (url.startsWith('http://') && !isLocalTarget(url) && !res.url.startsWith('https://')) found.push({ id: fid('nohttps', host), tool: 'MacSec', category: 'web', severity: 'high', title: 'Visitors are not moved to HTTPS', url, file: url, cwe: 'CWE-319', fix: 'Redirect every http:// request to https:// and send Strict-Transport-Security.' })
      return found
    })

    if (st.crawl)
      await s.run(st.crawl, async (note, line) => {
        await ensure('katana')
        const out = join(s.raw, 'katana.jsonl')
        await runTool({ name: 'katana', bin: 'katana', args: ['-u', url, '-jsonl', '-silent', '-nc', '-d', String(m.depth), ...(req.mode === 'thorough' ? ['-jc'] : []), '-ct', `${m.crawlSecs}s`, '-rl', String(m.rate), '-c', '5', '-fs', 'rdn', '-o', out, ...headerArgs(headers, '-H')], timeoutMs: (m.crawlSecs + 120) * 1000, output: out }, op, s.raw, line).catch((e) => {
          if (!existsSync(out)) throw e
          return ''
        })
        urls = [url, ...parseKatana(existsSync(out) ? readFileSync(out, 'utf8') : '', host)].filter((u, i, a) => a.indexOf(u) === i).slice(0, 2000)
        writeFileSync(urlsFile, urls.join('\n'))
        note(`${urls.length} pages and endpoints`)
      })

    if (st.tls) await s.run(st.tls, () => checkTls(url))

    await s.run(st.files, async (note) => groupDecoyFiles(await exposedFiles(url, SENSITIVE_PATHS.slice(0, m.paths), headers, () => s.cancelled, note)))

    if (st.discover)
      await s.run(st.discover, async (note, line) => {
        await ensure('ffuf')
        const words = discoveryWords(req.mode === 'thorough' ? 435 : 200)
        const wl = writeWordlist(words, join(s.raw, 'ffuf-words.txt'))
        const out = join(s.raw, 'ffuf.json')
        const base = url.replace(/\/+$/, '')
        await runTool({ name: 'ffuf', bin: 'ffuf', args: ['-u', `${base}/FUZZ`, '-w', wl, '-of', 'json', '-o', out, '-mc', '200,204,301,302,401,403,405', '-t', '5', '-rate', '20', '-timeout', '10', '-s', '-ac', '-noninteractive'], timeoutMs: 10 * 60_000, output: out }, op, s.raw, line).catch((e) => {
          if (!existsSync(out)) throw e
          return ''
        })
        const hits = existsSync(out) ? parseFfuf(readFileSync(out, 'utf8'), host) : []
        note(`${words.length} paths asked at 20 a second, ${hits.length} answered`)
        if (!hits.length) return []
        const c = mk(60)
        const cal = await calibrate(c).catch(() => [])
        const found: Finding[] = []
        const plain: string[] = []
        for (const h of hits.slice(0, 25)) {
          if (s.cancelled) break
          const p2 = h.path.replace(/^\//, '')
          if (!p2 || risky(p2)) continue
          const r = await c.get(h.path, { headers: 'none' }).catch(() => null)
          if (!r) continue
          if (cal.length && isCatchAll(p2, r, cal)) continue
          if (r.status !== h.status) continue
          const sev = pathSeverity(p2, r.status)
          if (sev === 'info') {
            plain.push(`${p2} (${r.status})`)
            continue
          }
          urls.push(r.url)
          found.push({
            id: fid('ffuf', url, p2),
            tool: 'ffuf',
            category: 'web',
            severity: sev,
            confidence: 'confirmed',
            title: r.status >= 200 && r.status < 300 ? `Reachable and not linked: /${p2}` : `Exists but protected: /${p2}`,
            url: r.url,
            file: r.url,
            description: 'It is not linked from the site, but it answers. ffuf found it and MacSec asked again to be sure.',
            proof: proofOf({ url: r.url, status: r.status, headers: r.headers, body: r.body, shows: [`ffuf found /${p2} (HTTP ${h.status})`, `asking again answered HTTP ${r.status}, the same way`, 'it is not one of the answers a page that does not exist gives'] })
          })
        }
        if (plain.length) found.push({ id: fid('ffuf-plain', url), tool: 'ffuf', category: 'web', severity: 'info', confidence: 'possible', title: `${plain.length} more paths answer and look low-risk`, description: `Not linked from the site: ${plain.slice(0, 40).join(', ')}${plain.length > 40 ? ', and more' : ''}. Listed for a look, not reported one by one.` })
        note(`${found.length} worth reporting, ${urls.length} pages in the list now`)
        return found
      })

    if (st.js) await s.run(st.js, (note) => keysInJavaScript(urls, host, s.raw, op, headers, note))
    // Versions found anywhere in this scan are matched against the live vulnerability databases at the end of these steps.
    const found: { product: Product; host: string }[] = []

    await s.run(st.infra, async (note) => {
      const out: Finding[] = []
      note('Reading the site’s protection')
      const home = await mk(10).get('/').catch(() => null)
      if (home) {
        const cookies = home.headers.getSetCookie?.().join('; ') ?? home.headers.get('set-cookie') ?? ''
        out.push(protectionFinding(url, home.headers, cookies, home.status, home.body))
        for (const b of bannersOf(home.headers, home.body)) found.push({ product: { ...b, proof: proofOf({ url, status: home.status, headers: home.headers, body: home.body.slice(0, 200000), shows: [b.from] }) }, host })
      }
      note('Reading DNS and mail settings')
      out.push(...(await dnsChecks(host)))
      return out
    })

    await s.run(st.devops, async (note) => {
      const r = await devopsChecks(mk(110), host, { note })
      found.push(...r.products)
      if (r.stopped) note(`Stopped early: ${r.stopped}`)
      return r.findings
    })

    if (st.jsdeep)
      await s.run(st.jsdeep, async (note) => {
        const scripts = urls.filter((u) => /\.m?js(\?|$)/i.test(u))
        const r = await crawlJs({ scripts, allowed: (u) => { try { return new URL(u).host === host } catch { return false } }, headers, cancelled: () => s.cancelled, paused: () => op.paused, note, sourceDir: join(s.raw, 'sources') })
        writeFileSync(join(s.raw, 'js-map.json'), JSON.stringify({ scripts: r.scripts, endpoints: r.endpoints, routes: r.routes, graphql: r.graphql, envVars: r.envVars, hosts: r.hosts, refs: r.refs }, null, 1))
        // What the scripts name joins the pages the test plan is built from.
        urls = [...new Set([...urls, ...r.endpoints.filter((e) => e.startsWith('/')).map((e) => new URL(e, url).href), ...r.routes.map((x) => new URL(x, url).href)])].slice(0, 3000)
        for (const l of r.libs) if (l.proof) found.push({ product: l, host })
        note(`${r.scripts.length} scripts (${r.chunksFound} found through chunk lists), ${r.endpoints.length} endpoints, ${r.routes.length} routes, ${r.scripts.filter((x) => x.sourceMap).length} source maps`)
        return r.findings
      })

    if (st.code)
      await s.run(st.code, async (note) => {
        const map = mapCode(req.codePath!)
        note(`${map.files} files read, ${map.routes.length} routes${map.frameworks.length ? ` (${map.frameworks.join(', ')})` : ''}, ${Object.keys(map.params).length} parameters`)
        writeFileSync(join(s.raw, 'code-map.json'), JSON.stringify({ frameworks: map.frameworks, files: map.files, routes: map.routes, params: Object.keys(map.params) }, null, 1))
        codeNames = paramNames(map)
        const out: Finding[] = []
        const known = new Set(urls.map((u) => { try { return new URL(u).pathname.replace(/\/+$/, '') || '/' } catch { return u } }))
        const fromCode = getPaths(map).map((p) => ({ p, u: new URL(p, url).href }))
        const hidden = fromCode.filter((x) => !known.has(x.p.replace(/\/+$/, '') || '/'))
        urls = [...new Set([...urls, ...fromCode.map((x) => x.u)])].slice(0, 3000)
        if (hidden.length)
          out.push({ id: fid('code-hidden', hidden.map((x) => x.p).join('|')), tool: 'MacSec', category: 'web', severity: 'info', confidence: 'possible', title: `${hidden.length} ${hidden.length === 1 ? 'route in the code is' : 'routes in the code are'} not linked from the site`, description: `The code defines these routes, but nothing the crawl read links to them: ${hidden.slice(0, 25).map((x) => x.p).join(', ')}${hidden.length > 25 ? ', and more' : ''}. They were added to the pages tested below.`, fix: 'Check that each of them asks for the right kind of sign-in. Not being linked is not protection.' })
        // Private-looking routes with no access check in the code: ask the live site, signed out, and report only what it answers.
        const leads = unguardedPrivate(map)
        if (leads.length) {
          const c = mk(120)
          const cal = await calibrate(c).catch(() => [])
          for (const r of leads.slice(0, 25)) {
            if (s.cancelled) break
            const path = fillPath(r.path)
            const a = await c.get(path, { headers: 'none' }).catch(() => null)
            if (!a || a.status !== 200 || isCatchAll(path.replace(/^\//, ''), a, cal)) continue
            const text = visibleText(a.body)
            if (text.length < 200 || /<input[^>]+type=["']?password/i.test(a.body)) continue
            const b = await c.get(path, { headers: 'none' }).catch(() => null)
            if (!b || b.status !== 200) continue
            out.push({ id: fid('code-open', path), tool: 'MacSec', category: 'web', severity: /admin|billing|export|users?/i.test(path) ? 'high' : 'medium', confidence: 'confirmed', title: `A private-looking page opens without signing in: ${path}`, url: a.url, file: a.url, cwe: 'CWE-306', description: `The code defines ${r.method} ${r.path} (${r.file}:${r.line}) with no access check in the lines around it, and the live site gave a full page to a visitor who was not signed in. The code and the site agree: nothing asks who is asking.`, fix: 'Put the route behind your sign-in and role check (a middleware or a guard), and test it signed out.', proof: proofOf({ url: a.url, status: a.status, headers: a.headers, body: a.body.slice(0, 300000), shows: ['a request with no cookie or token got a full page', `the code at ${r.file}:${r.line} shows no access check`, 'the same on a second try'] }) })
          }
        }
        return out
      })

    await s.run(st.cves, async (note) => {
      if (!found.length) {
        note('No software versions were stated')
        return []
      }
      const live = await liveCves(found, { cancelled: () => s.cancelled, note, cap: req.mode === 'quick' ? 4 : 10 })
      const ids = live.results.flatMap((r) => r.matches.slice(0, 10).map((x) => x.id))
      const epss = await epssFor(ids)
      const list = cveFindings(live.results, epss)
      note(live.note || `${found.length} versions checked, ${list.reduce((n, x) => n + (x.cves?.count ?? 0), 0)} known flaws listed${list.some((x) => x.cves?.kev) ? ', some on CISA’s exploited list' : ''}`)
      return list
    })

    if (st.access) await s.run(st.access, (note) => signedOutCheck(urls, headers, () => s.cancelled, note))

    if (st.fuzz)
      await s.run(st.fuzz, async (note) => {
        const found = await fuzzContent(mk(1200), note)
        // Parameters on the home page and a few pages the crawl found, without query strings.
        const pages = [url, ...urls.filter((u) => !u.includes('?') && u !== url && !risky(u) && !/\.(png|jpe?g|gif|svg|ico|webp|css|js|map|woff2?|pdf|zip)$/i.test(u))].slice(0, 5)
        for (const p of pages) {
          if (s.cancelled) break
          const r = await fuzzParams(mk(150), p, note, codeNames.length ? [...new Set([...codeNames, ...PARAM_WORDS])] : undefined)
          found.push(...r.findings)
          const hit = r.hits.find((h) => h.how === 'reflected')
          if (hit && !carrier) carrier = `${new URL(p).pathname}?${hit.name}`
        }
        return found
      })

    if (st.waf) await s.run(st.waf, (note) => wafControl(mk(150), note, carrier))

    if (st.logic) await s.run(st.logic, (note) => logicChecks(mk(400), { urls, pages: urls.filter((u) => !/\.(png|jpe?g|gif|svg|ico|webp|css|js|map|woff2?|pdf|zip)$/i.test(u)).slice(0, 10) }, note))

    // The pages the injection, sign-in protocol and autopilot steps read, fetched once.
    let readPages: Reply[] | null = null
    const getPages = async (): Promise<Reply[]> => {
      if (readPages) return readPages
      const origin = new URL(url).origin
      const pageUrls = [...new Set([url, ...urls.filter((u) => { try { const p = new URL(u); return p.origin === origin && !/\.(png|jpe?g|gif|svg|ico|webp|css|js|map|woff2?|ttf|pdf|zip|mp4|mp3)$/i.test(p.pathname) && !risky(u) } catch { return false } }).map((u) => { const p = new URL(u); return `${p.origin}${p.pathname}` })])].slice(0, 30)
      const reader = mk(80)
      const got: Reply[] = []
      for (const u of pageUrls) {
        if (s.cancelled) break
        const r = await reader.get(u).catch(() => null)
        if (r) got.push(r)
      }
      readPages = got
      return got
    }

    if (st.inject)
      await s.run(st.inject, async (note) => {
        const origin = new URL(url).origin
        const pages = (await getPages()).filter((r) => r.status === 200 && /html/i.test(r.headers.get('content-type') ?? '')).map((r) => ({ url: r.url, html: r.body }))
        const { inputs, posts } = inputsFrom(pages, urls, origin)
        note(`${pages.length} pages read, ${inputs.length} inputs to test, ${posts.length} forms that send data (listed, not submitted)`)
        const found = await injectionChecks(mk(Math.min(2500, inputs.length * 9 + 60)), inputs, { note })
        return [...found, ...postFormLead(posts)]
      })

    if (st.proto)
      await s.run(st.proto, async (note) => {
        const pages = await getPages()
        const out: Finding[] = []
        note('Sign-in with OAuth and OpenID Connect')
        out.push(...(await oauthChecks(mk(120), { pages, urls }, note)))
        note('Tokens (JWT)')
        out.push(...(await jwtChecks(mk(80), { headers, replies: pages, urls }, note)))
        note('GraphQL')
        out.push(...(await graphqlChecks(mk(120), { extraPaths: codeNames.filter((n) => /graphql|gql/i.test(n)), note })))
        note('Cross-site requests and sessions')
        out.push(...(await sessionChecks(mk(150), { urls, pages, account: headers }, note)))
        return out
      })

    if (st.login)
      await s.run(st.login, async (note) => {
        const found = await loginChecks(mk(120), { loginUrl: req.confirm?.loginUrl, knownUser: req.confirm?.knownUser }, note)
        if (req.confirm?.allowReset && req.confirm.knownUser?.includes('@')) found.push(...(await resetCheck(mk(30), req.confirm.knownUser, note).catch(() => [])))
        return found
      })

    if (st.autopilot)
      await s.run(st.autopilot, async (note, line) => {
        const origin = new URL(url).origin
        const exec = async (a: Action): Promise<{ findings: Finding[]; page?: Reply }> => {
          const u = a.url
          switch (a.action) {
            case 'read':
              return { findings: [], page: await mk(20).get(u!) }
            case 'inject': {
              const r = await mk(30).get(u!)
              const { inputs, posts } = inputsFrom([{ url: r.url, html: r.body }], [u!], origin)
              return { findings: [...(await injectionChecks(mk(Math.min(600, inputs.length * 9 + 40)), inputs, { note })), ...postFormLead(posts)] }
            }
            case 'fuzz':
              return { findings: (await fuzzParams(mk(150), u!.split('?')[0], note, codeNames.length ? [...new Set([...codeNames, ...PARAM_WORDS])] : undefined)).findings }
            case 'cors':
              return { findings: await corsChecks(mk(60), [u!], { account: headers, note }) }
            case 'graphql':
              return { findings: await graphqlChecks(mk(80), { extraPaths: [new URL(u!).pathname], note }) }
            case 'oauth':
              return { findings: await oauthChecks(mk(80), { pages: [await mk(20).get(u!)], urls: [u!] }, note) }
            case 'jwt':
              return { findings: await jwtChecks(mk(60), { headers, replies: await getPages(), urls }, note) }
            case 'logic':
              return { findings: await logicChecks(mk(250), { urls, pages: [u!] }, note) }
          }
        }
        const r = await runAutopilot({ target: url, ask: (prompt) => askAi(req.reviewer, prompt, op, s.raw), exec, pages: await getPages(), findings: () => s.findings, note, line, cancelled: () => s.cancelled })
        const have = new Set(s.findings.map((f) => f.id))
        const fresh = r.findings.filter((f) => !have.has(f.id))
        note(`${r.done.length} checks chosen by the AI in ${r.rounds} ${r.rounds === 1 ? 'round' : 'rounds'}, ${fresh.length} new ${fresh.length === 1 ? 'finding' : 'findings'}. ${r.stopped}`)
        if (r.done.length)
          fresh.push({ id: fid('autopilot', id), tool: 'MacSec', category: 'web', severity: 'info', title: `The AI autopilot chose ${r.done.length} ${r.done.length === 1 ? 'check' : 'checks'} to run`, description: `${r.done.map((d) => `${d.action}${d.url ? ` ${new URL(d.url).pathname}` : ''}${d.why ? ` (${d.why})` : ''}: ${d.found} ${d.found === 1 ? 'finding' : 'findings'}`).join('; ')}. ${r.stopped} Every finding above came from a MacSec check with its own proof, not from the AI.` })
        return fresh
      })

    if (st.authz) await s.run(st.authz, (note) => accessChecks(mk(400), urls, { headersB, identityA: req.confirm?.identityA }, note))

    await s.run(st.wp, async (note, line) => {
      const isWp = fp.some((f) => f.tech.some((t) => /wordpress/i.test(t)))
      if (!isWp) return note('Not a WordPress site')
      const bin = appPath('wpscan')
      if (!bin) return note('Nuclei’s WordPress checks run below. Install WPScan for plugin and theme versions.')
      const out = join(s.raw, 'wpscan.json')
      // Passive plugin detection and read-only checks: no password guessing, no user lists.
      await runTool({ name: 'wpscan', bin, absolute: true, args: ['--url', url, '--format', 'json', '--output', out, '--no-banner', '--random-user-agent', '--plugins-detection', 'passive', '--enumerate', 'vp,vt,cb,dbe', '--throttle', '150', ...(Object.keys(headers).length ? ['--headers', Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('; ')] : [])], timeoutMs: 30 * 60_000, output: out }, op, s.raw, line).catch((e) => {
        if (!existsSync(out)) throw e
        return ''
      })
      return parseWpscan(readFileSync(out, 'utf8'), url)
    })

    await s.run(st.templates, async (note, line) => {
      await ensure('nuclei')
      if (templatesFresh()) return note('Up to date')
      await runTool({ name: 'nuclei-update', bin: 'nuclei', args: ['-update-templates', '-ud', nucleiTemplatesDir(), '-silent', '-nc'], timeoutMs: 10 * 60_000 }, op, s.raw, line).catch((e) => {
        if (!existsSync(nucleiTemplatesDir())) throw e
      })
      note('Updated')
    })

    await s.run(st.nuclei, async (_n, line) => {
      const out = join(s.raw, 'nuclei.jsonl')
      const custom = join(dirs.extensions(), 'nuclei-templates')
      const hasCustom = existsSync(custom) && readdirSync(custom).some((f) => /\.ya?ml$/.test(f))
      const args = [
        ...(m.everyPage ? ['-l', urlsFile] : ['-u', url]),
        '-t', nucleiTemplatesDir(),
        ...(hasCustom ? ['-t', custom] : []),
        '-ud', nucleiTemplatesDir(),
        '-etags', NOT_READ_ONLY,
        ...(req.mode === 'quick' ? ['-severity', 'critical,high,medium'] : []),
        '-duc', '-nc', '-silent', '-jsonl', '-o', out, '-stats', '-sj', '-si', '5',
        '-rl', String(m.rate), '-c', '10', '-timeout', '10', '-retries', '1',
        ...headerArgs(headers, '-H')
      ]
      await runTool({ name: 'nuclei', bin: 'nuclei', args, timeoutMs: (req.mode === 'thorough' ? 120 : 45) * 60_000, output: out }, op, s.raw, line).catch((e) => {
        if (!existsSync(out)) throw e
        return ''
      })
      return existsSync(out) ? parseNuclei(readFileSync(out, 'utf8')) : []
    })

    if (st.zap)
      await s.run(st.zap, async (_n, line) => {
        const out = join(s.raw, 'zap.json')
        const local = isLocalTarget(url)
        // The baseline scan spiders for a few minutes and only reads responses: no attacks.
        const args = ['run', '--rm', '-v', `${s.raw}:/zap/wrk:rw`, ...(local ? ['--add-host', `${new URL(url).hostname}:host-gateway`] : []), 'ghcr.io/zaproxy/zaproxy:stable', 'zap-baseline.py', '-t', local ? url.replace('://localhost', '://host.docker.internal').replace('://127.0.0.1', '://host.docker.internal') : url, '-J', 'zap.json', '-I', '-m', req.mode === 'thorough' ? '5' : '2']
        await runTool({ name: 'zap', bin: dockerPath()!, absolute: true, args, timeoutMs: 30 * 60_000, output: out }, op, s.raw, line).catch((e) => {
          if (!existsSync(out)) throw new Error(`ZAP did not run: ${(e as Error).message}. Docker (OrbStack, Docker Desktop or Colima) must be running.`)
          return ''
        })
        return existsSync(out) ? parseZap(readFileSync(out, 'utf8')) : []
      })

    // The test plan: what to try by hand on this site, from the pages the crawl found. Always saved, with or without an AI.
    const ran = [st.login && 'auth', st.fuzz && 'fuzz', st.waf && 'waf', st.authz && 'authz', st.logic && 'logic', st.inject && 'inject', st.proto && 'proto'].filter(Boolean) as string[]
    const profile = profileSite(urls)
    try {
      savePlan(id, planMarkdown(profile, url, ran))
    } catch (e) {
      log('warn', `Could not save the test plan: ${(e as Error).message}`, id)
    }

    // The checklist: every item of the person's web checklist, marked from what this scan ran, and (with an AI) judged from the evidence.
    const done = Object.entries(st).filter(([, v]) => v && v.status === 'done').map(([k]) => k)
    const list = autoMark(s.findings, done, profile)
    try {
      saveChecklist(id, list)
    } catch (e) {
      log('warn', `Could not save the checklist: ${(e as Error).message}`, id)
    }
    if (st.checklist)
      await s.run(st.checklist, async (note) => {
        const todo = list.sections.filter((x) => x.relevant).flatMap((x) => x.items.filter((i) => i.state === 'manual')).slice(0, BATCH * 6)
        const evidence = { findings: s.findings, ran: done, profileText: planContext(profile, ran, 0).split('\nChecklist items')[0] }
        let applied = 0
        for (let i = 0; i < todo.length && !s.cancelled; i += BATCH) {
          note(`Items ${i + 1} to ${Math.min(todo.length, i + BATCH)} of ${todo.length}`)
          try {
            const text = await askAi(req.reviewer, walkPrompt(url, evidence, todo.slice(i, i + BATCH)), op, s.raw)
            applied += applyAnswers(list, parseAnswers(text), s.findings)
          } catch (e) {
            note(`A batch failed: ${(e as Error).message}`)
          }
        }
        list.ai = true
        saveChecklist(id, list)
        note(`${applied} of ${todo.length} items judged from the evidence; the rest are for you to test`)
        return []
      })

    if (st.ai)
      await s.run(st.ai, async () => {
        const tech = `${fp[0] ? `Detected: ${[fp[0].server, ...fp[0].tech].filter(Boolean).join(', ')}.` : ''}\n${planContext(profile, ran)}`
        const r = await summarizeWithAi(req.reviewer, summaryPrompt('web', url, tech, s.findings.filter((f) => f.severity !== 'info')), op, s.raw)
        for (const f of s.findings) {
          const d = r.details.get(f.id)
          if (d) {
            f.verdict = d.verdict
            f.aiNote = d.reason
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
    log('info', `Web scan of ${host} ${s.info.status}`, id)
  }
}
