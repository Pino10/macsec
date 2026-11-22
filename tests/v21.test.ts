import { createServer, type Server } from 'http'
import type { AddressInfo } from 'net'
import { describe, expect, it } from 'vitest'
import { ConfirmClient } from '../src/main/confirmtests'
import { codeLimit, guessableIds, hostPoisoning, logicChecks, openRedirect, skippedSteps, trustedFields } from '../src/main/bizlogic'
import { retestFinding } from '../src/main/retest'
import { createGithubIssue, ticketJira, ticketTitle, ticketMarkdown, validRepo } from '../src/main/tickets'
import { buildAssets, remediationPlan, riskScore } from '../src/main/assets'
import { chainsOf } from '../src/main/chains'
import { checkIdOf } from '../src/main/checks'
import { inWindow } from '../src/main/watch'
import { beginOp, endOp, isPaused, pauseOp } from '../src/main/engine'
import { executiveHtml } from '../src/main/report'
import { runSelfTest } from './helpers/selftest'
import type { Finding, SessionDetail, SessionInfo } from '../src/shared/types'

const serve = (h: Parameters<typeof createServer>[1]): Promise<{ server: Server; url: string }> =>
  new Promise((r) => {
    const server = createServer(h)
    server.listen(0, '127.0.0.1', () => r({ server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` }))
  })
const client = (url: string): ConfirmClient => new ConfirmClient(url, { cap: 3000, delayMs: 0 })
const f = (x: Partial<Finding>): Finding => ({ id: Math.random().toString(36).slice(2), tool: 'MacSec', category: 'web', severity: 'high', title: 't', ...x })
const page = (b: string): string => `<html><head><title>x</title></head><body>${b} ${'Some ordinary words on the page. '.repeat(20)}</body></html>`

describe('the self-test', () => {
  it('finds every planted weakness and reports nothing on the decoy', async () => {
    const r = await runSelfTest()
    expect(r.items.filter((i) => !i.ok)).toEqual([])
    expect(r.ok).toBe(true)
  }, 60000)
})

describe('business logic checks: negative controls', () => {
  it('a redirect that stays on the site is not an open redirect', async () => {
    const s = await serve((req, res) => {
      const u = new URL(req.url ?? '/', 'http://x')
      const n = u.searchParams.get('next') ?? '/'
      res.writeHead(302, { location: n.startsWith('/') && !n.startsWith('//') ? n : '/' })
      res.end()
    })
    const out = await openRedirect(client(s.url), [`${s.url}/login?next=/home`], () => undefined)
    s.server.close()
    expect(out).toEqual([])
  })
  it('a site that ignores the forwarded host is not flagged, and a reflected one is', async () => {
    const safe = await serve((_q, res) => {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end(page('<a href="https://shop.example.com/x">x</a>'))
    })
    const weak = await serve((req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end(page(`<a href="https://${req.headers['x-forwarded-host'] ?? 'real.example.com'}/reset">reset</a>`))
    })
    expect(await hostPoisoning(client(safe.url))).toEqual([])
    const hit = await hostPoisoning(client(weak.url))
    safe.server.close()
    weak.server.close()
    expect(hit).toHaveLength(1)
    expect(hit[0].confidence).toBe('confirmed')
    expect(hit[0].proof).toBeTruthy()
  })
  it('a code form that slows down is not flagged', async () => {
    let n = 0
    const s = await serve((req, res) => {
      if (req.method === 'GET') {
        res.writeHead(200, { 'content-type': 'text/html' })
        return void res.end(page('<form method="post" action="/v"><input name="otp_code" type="text"></form>'))
      }
      n++
      res.writeHead(n > 4 ? 429 : 200, { 'content-type': 'text/html' })
      res.end(page(n > 4 ? 'Too many tries' : 'Wrong code'))
    })
    const out = await codeLimit(client(s.url), ['/'], () => undefined)
    s.server.close()
    expect(out).toEqual([])
  })
  it('an unlimited code form is a possible finding, never confirmed', async () => {
    const s = await serve((req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end(req.method === 'GET' ? page('<form method="post" action="/v"><input name="pin" type="text"></form>') : page('Wrong code'))
    })
    const out = await codeLimit(client(s.url), ['/'], () => undefined)
    s.server.close()
    expect(out).toHaveLength(1)
    expect(out[0].confidence).toBe('possible')
  })
  it('a login form with a password is not treated as a code form', async () => {
    const s = await serve((req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end(req.method === 'GET' ? page('<form method="post" action="/v"><input name="pin" type="text"><input name="pw" type="password"></form>') : page('No'))
    })
    expect(await codeLimit(client(s.url), ['/'], () => undefined)).toEqual([])
    s.server.close()
  })
  it('a catch-all site shows no skipped steps', async () => {
    const s = await serve((_q, res) => {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end(page('Your order payment receipt confirmation total'))
    })
    const out = await skippedSteps(client(s.url), [], () => undefined)
    s.server.close()
    expect(out).toEqual([])
  })
  it('hidden fields: a price is a lead, a csrf token is nothing', () => {
    expect(trustedFields([{ url: 'http://a.example.com/cart', html: '<form><input type="hidden" name="csrf" value="abc"></form>' }])).toEqual([])
    const out = trustedFields([{ url: 'http://a.example.com/cart', html: '<form method="post"><input type="hidden" name="price" value="9.99"></form>' }])
    expect(out).toHaveLength(1)
    expect(out[0].confidence).toBe('possible')
    expect(out[0].proof).toBeUndefined()
  })
  it('numbered records are only an info lead', () => {
    const out = guessableIds(['http://a.example.com/invoice/12', 'http://a.example.com/invoice/13'])
    expect(out.every((x) => x.severity === 'info' && x.confidence === 'possible')).toBe(true)
  })
  it('a stopped scan returns what it had and does not throw', async () => {
    const s = await serve((_q, res) => {
      res.writeHead(500)
      res.end('no')
    })
    await expect(logicChecks(client(s.url), { urls: [], pages: [] }, () => undefined)).resolves.toBeDefined()
    s.server.close()
  })
})

describe('re-test', () => {
  const proofFor = (url: string, status: number, body: string): Finding['proof'] => ({ request: `GET ${url}`, status, bytes: Buffer.byteLength(body), sha256: require('crypto').createHash('sha256').update(body).digest('hex'), shows: [], reproduce: `curl ${url}` }) as unknown as Finding['proof']
  const fake = (status: number, body: string): typeof fetch => (async () => new Response(body, { status })) as unknown as typeof fetch
  const url = 'http://a.example.com/.env'
  it('says still, gone, changed, unreachable and unsupported correctly', async () => {
    const body = 'A=1\n'.repeat(50)
    const fnd = f({ proof: proofFor(url, 200, body) })
    expect((await retestFinding(fnd, fake(200, body))).state).toBe('still')
    expect((await retestFinding(fnd, fake(404, 'nope'))).state).toBe('gone')
    expect((await retestFinding(fnd, fake(200, 'x'.repeat(5000)))).state).toBe('changed')
    expect((await retestFinding(fnd, (async () => { throw new Error('down') }) as unknown as typeof fetch)).state).toBe('unreachable')
    expect((await retestFinding(f({}), fake(200, body))).state).toBe('unsupported')
  })
})

describe('tickets', () => {
  const s: Pick<SessionInfo, 'title' | 'target' | 'createdAt'> = { title: 'Shop', target: 'https://a.example.com', createdAt: '2026-01-02T00:00:00Z' }
  const fnd = f({ title: 'Public file', severity: 'high', url: 'https://a.example.com/.env', description: 'It is public.', fix: 'Remove it.' })
  it('makes Markdown and Jira text without secrets', () => {
    expect(ticketTitle(fnd)).toBe('[High] Public file')
    expect(ticketMarkdown(fnd, s)).toContain('It is public.')
    expect(ticketJira(fnd, s)).toContain('h3. How to fix it')
  })
  it('checks repository names', () => {
    expect(validRepo('acme/shop')).toBe(true)
    for (const bad of ['', 'acme', '../x', 'a/b/c', 'acme/shop?x=1', 'ac me/shop', '-a/b']) expect(validRepo(bad)).toBe(false)
  })
  it('creates an issue only on api.github.com, with the token in a header, and maps errors', async () => {
    let seen: { url: string; auth: string } | null = null
    const ok: typeof fetch = (async (u: string, o: RequestInit) => {
      seen = { url: String(u), auth: String((o.headers as Record<string, string>).Authorization) }
      return new Response(JSON.stringify({ html_url: 'https://github.com/acme/shop/issues/7', number: 7 }), { status: 201 })
    }) as unknown as typeof fetch
    const r = await createGithubIssue('acme/shop', fnd, s, 'tok', ok)
    expect(r.number).toBe(7)
    expect(seen!.url).toBe('https://api.github.com/repos/acme/shop/issues')
    expect(seen!.url).not.toContain('tok')
    await expect(createGithubIssue('acme/shop', fnd, s, 'tok', (async () => new Response('', { status: 404 })) as unknown as typeof fetch)).rejects.toThrow(/does not exist/)
    await expect(createGithubIssue('acme/shop', fnd, s, 'tok', (async () => new Response('', { status: 403 })) as unknown as typeof fetch)).rejects.toThrow(/refused/)
    await expect(createGithubIssue('acme/shop', fnd, s, 'tok', (async () => new Response(JSON.stringify({ html_url: 'https://evil.example/x', number: 1 }), { status: 201 })) as unknown as typeof fetch)).rejects.toThrow()
    await expect(createGithubIssue('../x', fnd, s, 'tok', ok)).rejects.toThrow()
    await expect(createGithubIssue('acme/shop', fnd, s, '', ok)).rejects.toThrow()
  })
})

describe('risk, plan and chains', () => {
  it('scores stay between 0 and 100 and rise with more findings', () => {
    expect(riskScore([])).toBe(0)
    const one = riskScore([f({ severity: 'high' })])
    const many = riskScore(Array.from({ length: 50 }, () => f({ severity: 'critical' })))
    expect(one).toBeGreaterThan(0)
    expect(many).toBeGreaterThan(one)
    expect(many).toBeLessThanOrEqual(100)
    expect(riskScore([f({ severity: 'high', triage: 'fixed' }), f({ severity: 'high', verdict: 'false-positive' }), f({ severity: 'info' })])).toBe(0)
  })
  it('the plan groups the same fix and never raises the score', () => {
    const list = [f({ title: 'a', fix: 'Turn on HSTS everywhere.', severity: 'medium' }), f({ title: 'b', fix: 'Turn on HSTS everywhere.', severity: 'medium' }), f({ title: 'c', fix: 'Remove the file.', severity: 'high' })]
    const p = remediationPlan(list)
    expect(p.actions).toHaveLength(2)
    expect(p.after).toBeLessThanOrEqual(p.before)
    expect(p.actions[0].drop).toBeGreaterThanOrEqual(p.actions[1].drop)
  })
  it('a chain needs every part, each from a different finding', () => {
    expect(chainsOf([f({ title: 'Open redirect: /login sends visitors to any address in "next"' })])).toEqual([])
    const both = chainsOf([f({ title: 'Open redirect: /go sends visitors', severity: 'medium' }), f({ title: 'Login form has no limit', severity: 'low' })])
    expect(both.some((c) => c.id === 'redirect-phish')).toBe(true)
    expect(both.find((c) => c.id === 'redirect-phish')!.severity).toBe('high')
    // A finding that was triaged away no longer joins a chain.
    expect(chainsOf([f({ title: 'Open redirect: /go', triage: 'fixed' }), f({ title: 'Login form' })])).toEqual([])
  })
  it('assets group one host and track the trend and fix time', () => {
    const sessions = [
      { id: 'a', kind: 'web-scan', target: 'https://a.example.com', title: 'a', createdAt: '2026-01-01T00:00:00Z', status: 'done' },
      { id: 'b', kind: 'web-scan', target: 'https://a.example.com', title: 'a', createdAt: '2026-01-11T00:00:00Z', status: 'done' }
    ] as unknown as SessionInfo[]
    const by: Record<string, Finding[]> = { a: [f({ title: 'Hole', file: '/x', severity: 'high' })], b: [] }
    const [asset] = buildAssets(sessions, (id) => by[id])
    expect(buildAssets(sessions, (id) => by[id])).toHaveLength(1)
    expect(asset.scans).toBe(2)
    expect(asset.trend.map((t) => t.risk)[1]).toBe(0)
    expect(asset.fixed).toBe(1)
    expect(asset.mttrDays).toBe(10)
  })
})

describe('check ids', () => {
  it('are the same for the same kind of finding on any target, and differ between kinds', () => {
    const a = checkIdOf({ title: 'Open redirect: /a sends visitors to any address in "next"', tool: 'MacSec', category: 'web' })
    const b = checkIdOf({ title: 'Open redirect: /zzz sends visitors to any address in "url"', tool: 'MacSec', category: 'web' })
    expect(a).toBe(b)
    expect(checkIdOf({ title: 'Something else entirely', tool: 'X', category: 'web' })).toMatch(/^MS-GEN-[0-9A-F]{6}$/)
    expect(checkIdOf({ title: 'Some rule 12 on /a', tool: 'X', category: 'web' })).toBe(checkIdOf({ title: 'Some rule 99 on /b', tool: 'X', category: 'web' }))
  })
})

describe('pause, resume and quiet hours', () => {
  it('pausing a running test is remembered and undone, and a missing test cannot be paused', () => {
    beginOp('v21-op')
    expect(pauseOp('v21-op', true)).toBe(true)
    expect(isPaused('v21-op')).toBe(true)
    pauseOp('v21-op', false)
    expect(isPaused('v21-op')).toBe(false)
    endOp('v21-op')
    expect(pauseOp('v21-op', true)).toBe(false)
  })
  it('MacSec’s own requests wait while paused and carry on after', async () => {
    let paused = true
    let hits = 0
    const s = await serve((_q, res) => {
      hits++
      res.end('ok')
    })
    const c = new ConfirmClient(s.url, { cap: 10, delayMs: 0, paused: () => paused })
    const p = c.get('/')
    await new Promise((r) => setTimeout(r, 700))
    expect(hits).toBe(0)
    paused = false
    await p
    s.server.close()
    expect(hits).toBe(1)
  })
  it('the quiet-hours window works inside a day and across midnight', () => {
    expect(inWindow({ on: false, from: 1, to: 6 }, 12)).toBe(true)
    expect(inWindow({ on: true, from: 1, to: 6 }, 3)).toBe(true)
    expect(inWindow({ on: true, from: 1, to: 6 }, 6)).toBe(false)
    expect(inWindow({ on: true, from: 22, to: 5 }, 23)).toBe(true)
    expect(inWindow({ on: true, from: 22, to: 5 }, 2)).toBe(true)
    expect(inWindow({ on: true, from: 22, to: 5 }, 12)).toBe(false)
  })
})

describe('executive summary', () => {
  it('escapes text from findings', () => {
    const d = { id: 's', title: '<b>Shop</b>', target: 'x', kind: 'web-scan', status: 'done', createdAt: '2026-01-01T00:00:00Z', counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, findings: [f({ title: '<script>alert(1)</script>' })], steps: [] } as unknown as SessionDetail
    const html = executiveHtml(d, { actions: [{ title: '<img src=x>', fix: '<i>fix</i>', count: 1, worst: 'high', drop: 10 }], before: 40, after: 10 }, [])
    expect(html).not.toContain('<script>alert')
    expect(html).not.toContain('<img src=x>')
    expect(html).toContain('&lt;img')
  })
})
