/**
 * Self-test: MacSec checks its own checks. It starts two tiny web apps on this Mac only (127.0.0.1,
 * a random port, closed again afterwards): one with known weaknesses and one that looks similar but is
 * built correctly (the decoy). The checks must find every planted weakness and must report nothing
 * at all on the decoy. A result that fails either way means a check cannot be trusted, and says which.
 * Nothing leaves this Mac and nothing is written to disk.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'http'
import type { AddressInfo } from 'net'
import type { Finding, SelfTestResult } from '../shared/types'
import { ConfirmClient, fuzzContent } from './confirmtests'
import { logicChecks } from './bizlogic'

export type { SelfTestResult }
type SelfTestItem = SelfTestResult['items'][number]

const page = (body: string): string => `<!doctype html><html><head><title>Shop</title></head><body><h1>Shop</h1>${body}<p>Welcome to the shop. Browse our products, read our story and contact us.</p></body></html>`

/** The app with planted weaknesses. */
function weakApp(req: IncomingMessage, res: ServerResponse): void {
  const url = new URL(req.url ?? '/', 'http://x')
  const html = (b: string, status = 200): void => {
    res.writeHead(status, { 'content-type': 'text/html' })
    res.end(page(b))
  }
  if (url.pathname === '/') return html('<a href="/login?next=/home">Sign in</a> <a href="/verify">Verify</a> <a href="/cart">Cart</a> <a href="/invoice/1">Invoice</a>')
  if (url.pathname === '/login' && url.searchParams.get('next')) {
    res.writeHead(302, { location: url.searchParams.get('next') ?? '/' })
    return void res.end()
  }
  if (url.pathname === '/login') return html('<form method="post" action="/login"><input name="user"><input type="password" name="pass"></form>')
  if (url.pathname === '/forgot') {
    const host = String(req.headers['x-forwarded-host'] ?? req.headers.host)
    res.writeHead(302, { location: `https://${host}/reset-sent` })
    return void res.end()
  }
  if (url.pathname === '/verify' && req.method === 'GET') return html('<form method="post" action="/verify"><input name="otp_code" type="text"><button>Check</button></form>')
  if (url.pathname === '/verify') return html('<p>That code is not right.</p>')
  if (url.pathname === '/cart') return html('<form method="post" action="/cart"><input type="hidden" name="price" value="19.99"><input type="hidden" name="role" value="user"><button>Buy</button></form>')
  if (url.pathname === '/admin/' || url.pathname === '/admin') return html('<h2>Admin panel</h2><p>Users, orders and settings are managed here. Total orders: 412.</p>')
  return html('<p>Page not found.</p>', 404)
}

/** The decoy: it looks alike, but a correct site. Nothing here is a problem. */
function decoyApp(req: IncomingMessage, res: ServerResponse): void {
  const url = new URL(req.url ?? '/', 'http://x')
  let tries = decoyApp.tries
  const html = (b: string, status = 200): void => {
    res.writeHead(status, { 'content-type': 'text/html' })
    res.end(page(b))
  }
  if (url.pathname === '/') return html('<a href="/login?next=/home">Sign in</a> <a href="/verify">Verify</a> <a href="/cart">Cart</a>')
  if (url.pathname === '/login' && url.searchParams.get('next')) {
    const n = url.searchParams.get('next') ?? '/'
    res.writeHead(302, { location: n.startsWith('/') && !n.startsWith('//') ? n : '/' })
    return void res.end()
  }
  if (url.pathname === '/forgot') {
    res.writeHead(302, { location: 'https://shop.example.com/reset-sent' })
    return void res.end()
  }
  if (url.pathname === '/verify' && req.method === 'GET') return html('<form method="post" action="/verify"><input name="otp_code" type="text"><button>Check</button></form>')
  if (url.pathname === '/verify') {
    tries = ++decoyApp.tries
    if (tries > 5) {
      res.writeHead(429, { 'content-type': 'text/html', 'retry-after': '60' })
      return void res.end(page('<p>Too many tries. Please wait.</p>'))
    }
    return html('<p>That code is not right.</p>')
  }
  if (url.pathname === '/cart') return html('<form method="post" action="/cart"><input type="hidden" name="csrf" value="abc123"><button>Buy</button></form>')
  // A catch-all: every other address answers the same page with 200, which fuzzing must not mistake for hidden pages.
  return html('<p>Welcome back. Nothing to see here.</p>')
}
decoyApp.tries = 0

function listen(h: (q: IncomingMessage, s: ServerResponse) => void): Promise<{ server: Server; url: string }> {
  return new Promise((resolve, reject) => {
    const server = createServer(h)
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` }))
  })
}

const has = (fs: Finding[], re: RegExp): boolean => fs.some((f) => re.test(f.title))

/** What each planted weakness should produce. */
export const EXPECTED: { name: string; re: RegExp; confirmed?: boolean }[] = [
  { name: 'Open redirect', re: /Open redirect/i, confirmed: true },
  { name: 'Forwarded host trusted', re: /forwarded host/i, confirmed: true },
  { name: 'No limit on wrong codes', re: /ten wrong codes/i },
  { name: 'Price and role sent by the browser', re: /values the server should decide/i },
  { name: 'Hidden admin page found', re: /admin/i }
]

export async function runSelfTest(note: (t: string) => void = () => undefined, cancelled: () => boolean = () => false): Promise<SelfTestResult> {
  const items: SelfTestItem[] = []
  decoyApp.tries = 0
  const weak = await listen(weakApp)
  const decoy = await listen(decoyApp)
  try {
    const run = async (base: string): Promise<Finding[]> => {
      const c = () => new ConfirmClient(base, { cap: 1500, delayMs: 0, cancelled })
      const out: Finding[] = []
      out.push(...(await fuzzContent(c(), note, ['admin', 'backup', 'login', 'staging'])))
      out.push(...(await logicChecks(c(), { urls: [`${base}/login?next=/home`, `${base}/forgot`], pages: ['/', '/verify', '/cart'] }, note)))
      return out
    }
    note('Checking the weak app')
    const found = await run(weak.url)
    for (const e of EXPECTED) {
      const hit = found.find((f) => e.re.test(f.title))
      const okConf = !e.confirmed || (hit && hit.confidence === 'confirmed' && !!hit.proof)
      items.push({ name: e.name, ok: !!hit && !!okConf, detail: hit ? (okConf ? 'Found' + (e.confirmed ? ' with proof' : '') : 'Found but without proof') : 'Missed: this check cannot be trusted' })
    }
    if (cancelled()) return { ok: false, at: new Date().toISOString(), items }
    note('Checking the decoy')
    const clean = await run(decoy.url)
    items.push({ name: 'Decoy site gives no false alarms', ok: clean.length === 0, detail: clean.length === 0 ? 'Nothing reported, as it should be' : `False alarm: ${clean.map((f) => f.title).slice(0, 3).join('; ')}` })
    // A server with an unlimited code form must be flagged, but a decoy that limits it must not be.
    items.push({ name: 'A code limit is respected', ok: !has(clean, /wrong codes/i), detail: has(clean, /wrong codes/i) ? 'The limit was missed' : 'Limit noticed' })
  } finally {
    weak.server.close()
    decoy.server.close()
  }
  return { ok: items.every((i) => i.ok), at: new Date().toISOString(), items }
}
