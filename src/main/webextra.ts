/**
 * Extra read-only web checks: TLS settings, keys left in public JavaScript, and pages that show
 * the same content whether you are signed in or not.
 */
import { connect, type PeerCertificate } from 'tls'
import { mkdirSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import type { Finding } from '../shared/types'
import { fid } from './scanners/parse'
import { parseGitleaks } from './scanners/parse'
import { runTool, type Op } from './engine'
import { installTool, isInstalled, toolDef } from './toolbox'

const f = (x: Omit<Finding, 'id' | 'tool' | 'category'> & { tool?: string }): Finding => ({ id: fid('webextra', x.title, x.url), tool: x.tool ?? 'MacSec', category: 'web', ...x })

function handshake(host: string, port: number, opts: { minVersion?: 'TLSv1' | 'TLSv1.1' | 'TLSv1.2'; maxVersion?: 'TLSv1' | 'TLSv1.1' | 'TLSv1.2' | 'TLSv1.3' }): Promise<{ ok: boolean; cert?: PeerCertificate; authorized?: boolean; error?: string; protocol?: string | null }> {
  return new Promise((resolve) => {
    const sock = connect({ host, port, servername: host, rejectUnauthorized: false, ciphers: 'DEFAULT:@SECLEVEL=0', ...opts, timeout: 10000 }, () => {
      const r = { ok: true, cert: sock.getPeerCertificate(), authorized: sock.authorized, error: sock.authorizationError ? String(sock.authorizationError) : undefined, protocol: sock.getProtocol() }
      sock.end()
      resolve(r)
    })
    sock.on('error', (e) => resolve({ ok: false, error: e.message }))
    sock.on('timeout', () => {
      sock.destroy()
      resolve({ ok: false, error: 'timeout' })
    })
  })
}

/** Certificate, trust and protocol versions, with ordinary TLS handshakes. */
export async function checkTls(url: string): Promise<Finding[]> {
  const u = new URL(url)
  if (u.protocol !== 'https:') return []
  const port = Number(u.port || 443)
  const out: Finding[] = []
  const main = await handshake(u.hostname, port, {})
  if (!main.ok) return [f({ severity: 'medium', title: 'HTTPS connection failed', url, description: main.error })]
  const c = main.cert
  if (c?.valid_to) {
    const days = Math.floor((new Date(c.valid_to).getTime() - Date.now()) / 86400000)
    if (days < 0) out.push(f({ severity: 'high', title: 'The HTTPS certificate has expired', url, description: `Expired on ${c.valid_to}.`, fix: 'Renew the certificate (for example with Let’s Encrypt and automatic renewal).', cwe: 'CWE-298' }))
    else if (days < 21) out.push(f({ severity: 'medium', title: `The HTTPS certificate expires in ${days} days`, url, description: `Valid until ${c.valid_to}.`, fix: 'Renew it now and turn on automatic renewal.' }))
  }
  if (!main.authorized && !/\.(test|localhost)$/.test(u.hostname)) out.push(f({ severity: 'high', title: 'Browsers will not trust this certificate', url, description: main.error, fix: 'Use a certificate from a trusted authority that covers this exact name, and send the full chain.', cwe: 'CWE-295' }))
  for (const v of ['TLSv1', 'TLSv1.1'] as const) {
    const old = await handshake(u.hostname, port, { minVersion: v, maxVersion: v })
    if (old.ok) out.push(f({ severity: 'medium', title: `The server still accepts ${v.replace('TLSv', 'TLS ')}`, url, description: 'Old protocol versions have known weaknesses and are refused by modern browsers.', fix: 'Allow TLS 1.2 and 1.3 only (Nginx: ssl_protocols TLSv1.2 TLSv1.3; Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3).', cwe: 'CWE-327' }))
  }
  return out
}

/** Downloads the site's own JavaScript (as any browser does) and looks for keys in it with Gitleaks. */
export async function keysInJavaScript(urls: string[], host: string, rawDir: string, op: Op, headers: Record<string, string>, note: (d: string) => void): Promise<Finding[]> {
  const js = urls.filter((u) => /\.m?js(\?|$)/i.test(u)).filter((u) => new URL(u).host === host).slice(0, 150)
  if (js.length === 0) return []
  const d = toolDef('gitleaks')
  if (d && !isInstalled(d)) await installTool('gitleaks', () => undefined)
  const dir = join(rawDir, 'javascript')
  mkdirSync(dir, { recursive: true })
  const map: Record<string, string> = {}
  for (const [i, u] of js.entries()) {
    if (op.cancelled) break
    note(`Downloading script ${i + 1} of ${js.length}`)
    try {
      const r = await fetch(u, { headers: { 'User-Agent': 'MacSec', ...headers }, signal: AbortSignal.timeout(15000) })
      if (!r.ok) continue
      const name = `${i}.js`
      writeFileSync(join(dir, name), (await r.text()).slice(0, 5_000_000))
      map[name] = u
    } catch {
      // Unreachable script.
    }
    await new Promise((res) => setTimeout(res, 100))
  }
  const report = join(rawDir, 'gitleaks-js.json')
  await runTool({ name: 'gitleaks-js', bin: 'gitleaks', args: ['dir', dir, '--report-format', 'json', '--report-path', report, '--no-banner', '--redact', '--exit-code', '0', '--log-level', 'error'], timeoutMs: 10 * 60_000, output: report }, op, rawDir)
  return parseGitleaks(readFileSync(report, 'utf8'), dir).map((x) => ({
    ...x,
    category: 'web' as const,
    title: x.title.replace(/ in code$/, ' in public JavaScript'),
    url: map[x.file?.split('/').pop() ?? ''] ?? x.file,
    file: map[x.file?.split('/').pop() ?? ''] ?? x.file,
    description: 'Anyone who opens the site can read this file. Keys meant for servers must never be in front-end code.',
    fix: 'Revoke the key, move the call that needs it to your server, and expose only public, restricted keys (for example a publishable key limited to your domain).'
  }))
}

const PRIVATE = /(account|dashboard|admin|profile|settings|order|invoice|billing|user|member|my|portal|manage|api\/)/i

/**
 * Visits pages found while signed in, once more without your login, and flags private-looking
 * pages that show the same content to everyone. Ordinary GET requests only.
 */
export async function signedOutCheck(urls: string[], headers: Record<string, string>, cancelled: () => boolean, note: (d: string) => void): Promise<Finding[]> {
  const pages = urls.filter((u) => PRIVATE.test(new URL(u).pathname) && !/\.(js|css|png|jpe?g|gif|svg|woff2?|ico|map)(\?|$)/i.test(u)).slice(0, 40)
  const out: Finding[] = []
  for (const [i, u] of pages.entries()) {
    if (cancelled()) break
    note(`Comparing ${i + 1} of ${pages.length}`)
    try {
      const a = await fetch(u, { headers: { 'User-Agent': 'MacSec', ...headers }, redirect: 'manual', signal: AbortSignal.timeout(15000) })
      const inBody = await a.text()
      const b = await fetch(u, { headers: { 'User-Agent': 'MacSec' }, redirect: 'manual', signal: AbortSignal.timeout(15000) })
      const outBody = await b.text()
      const same = a.status === 200 && b.status === 200 && inBody.length > 500 && Math.abs(inBody.length - outBody.length) / inBody.length < 0.05
      if (same && !/(log ?in|sign ?in|password)/i.test(outBody.slice(0, 20000))) {
        out.push(f({ severity: 'high', title: `Shows the same content when signed out: ${new URL(u).pathname}`, url: u, file: u, cwe: 'CWE-862', description: 'This page looked private when signed in, and returned nearly the same page without your login.', fix: 'Require sign-in for this route (auth middleware or guard), and check the user may see this record.' }))
      }
    } catch {
      // Unreachable page.
    }
    await new Promise((res) => setTimeout(res, 150))
  }
  return out
}
