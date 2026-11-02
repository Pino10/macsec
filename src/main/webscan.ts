/**
 * A web scan. Every mode only reads the site: it looks, it does not attack, fuzz or change
 * anything. For hands-on testing, open the site in Burp Suite.
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
import { createSession, saveAiReport } from './sessions'
import { checkHeaders, parseHttpx, parseKatana, parseNuclei, pathSeverity, SENSITIVE_PATHS, type Fingerprint } from './scanners/web'
import { fid } from './scanners/parse'
import { installTool, isInstalled, nucleiTemplatesDir, toolDef } from './toolbox'
import { dirs } from './paths'
import { getSettings } from './settings'
import { log } from './logs'
import { summarizeWithAi, summaryPrompt } from './aisummary'

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
  const urlsFile = join(s.raw, 'urls.txt')
  let urls: string[] = [url]
  let fp: Fingerprint[] = []
  writeFileSync(urlsFile, url)

  const st = {
    fp: s.step('httpx', 'Fingerprint the server and technologies'),
    headers: s.step('headers', 'Check security headers, cookies and HTTPS'),
    crawl: m.depth ? s.step('katana', `Map the site, ${m.depth} levels deep`) : null,
    files: s.step('exposed', `Look for files that should not be public (${m.paths})`),
    templates: s.step('templates', 'Update Nuclei’s community checks'),
    nuclei: s.step('nuclei', m.everyPage ? 'Nuclei read-only checks on every page' : req.mode === 'quick' ? 'Nuclei checks for serious known problems' : 'Every read-only Nuclei check'),
    ai: req.reviewer !== 'none' ? s.step('ai', 'AI: what matters most and how to fix it') : null
  }
  try {
    await s.run(st.fp, async (note) => {
      await ensure('httpx')
      const out = await runTool({ name: 'httpx', bin: 'httpx', args: ['-u', url, '-json', '-silent', '-tech-detect', '-title', '-status-code', '-web-server', '-follow-redirects', '-no-color', ...headerArgs(headers, '-H')], timeoutMs: 120_000 }, op, s.raw)
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
      await s.run(st.crawl, async (note) => {
        await ensure('katana')
        const out = join(s.raw, 'katana.jsonl')
        await runTool({ name: 'katana', bin: 'katana', args: ['-u', url, '-jsonl', '-silent', '-nc', '-d', String(m.depth), ...(req.mode === 'thorough' ? ['-jc'] : []), '-ct', `${m.crawlSecs}s`, '-rl', String(m.rate), '-c', '5', '-fs', 'rdn', '-o', out, ...headerArgs(headers, '-H')], timeoutMs: (m.crawlSecs + 120) * 1000, output: out }, op, s.raw).catch((e) => {
          if (!existsSync(out)) throw e
          return ''
        })
        urls = [url, ...parseKatana(existsSync(out) ? readFileSync(out, 'utf8') : '', host)].filter((u, i, a) => a.indexOf(u) === i).slice(0, 2000)
        writeFileSync(urlsFile, urls.join('\n'))
        note(`${urls.length} pages and endpoints`)
      })

    await s.run(st.files, (note) => exposedFiles(url, SENSITIVE_PATHS.slice(0, m.paths), headers, () => s.cancelled, note))

    await s.run(st.templates, async (note) => {
      await ensure('nuclei')
      if (templatesFresh()) return note('Up to date')
      await runTool({ name: 'nuclei-update', bin: 'nuclei', args: ['-update-templates', '-ud', nucleiTemplatesDir(), '-silent', '-nc'], timeoutMs: 10 * 60_000 }, op, s.raw).catch((e) => {
        if (!existsSync(nucleiTemplatesDir())) throw e
      })
      note('Updated')
    })

    await s.run(st.nuclei, async () => {
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
        '-duc', '-nc', '-silent', '-jsonl', '-o', out,
        '-rl', String(m.rate), '-c', '10', '-timeout', '10', '-retries', '1',
        ...headerArgs(headers, '-H')
      ]
      await runTool({ name: 'nuclei', bin: 'nuclei', args, timeoutMs: (req.mode === 'thorough' ? 120 : 45) * 60_000, output: out }, op, s.raw).catch((e) => {
        if (!existsSync(out)) throw e
        return ''
      })
      return existsSync(out) ? parseNuclei(readFileSync(out, 'utf8')) : []
    })

    if (st.ai)
      await s.run(st.ai, async () => {
        const tech = fp[0] ? `Detected: ${[fp[0].server, ...fp[0].tech].filter(Boolean).join(', ')}.` : ''
        const r = await summarizeWithAi(req.reviewer, summaryPrompt('web', url, tech, s.findings.filter((f) => f.severity !== 'info')), op, s.raw)
        for (const f of s.findings) if (r.verdicts.has(f.id)) f.verdict = r.verdicts.get(f.id)
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
