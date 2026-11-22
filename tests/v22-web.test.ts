import { createServer, type Server } from 'http'
import type { AddressInfo } from 'net'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterAll, describe, expect, it } from 'vitest'
import { applyAnswers, autoMark, counts, parseAnswers, walkPrompt } from '../src/main/checklist'
import { fillPath, getPaths, mapCode, paramNames, unguardedPrivate } from '../src/main/routemap'
import { deepHosts, mergeByTitle } from '../src/main/recondeep'
import { profileSite } from '../src/main/testplan'
import type { Finding } from '../src/shared/types'

const dir = mkdtempSync(join(tmpdir(), 'macsec-v22-'))
afterAll(() => rmSync(dir, { recursive: true, force: true }))
const f = (x: Partial<Finding>): Finding => ({ id: Math.random().toString(36).slice(2), tool: 'MacSec', category: 'web', severity: 'high', title: 't', ...x })
const serve = (h: Parameters<typeof createServer>[1]): Promise<{ server: Server; url: string }> =>
  new Promise((r) => {
    const server = createServer(h)
    server.listen(0, '127.0.0.1', () => r({ server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` }))
  })

describe('white box: reading the code', () => {
  it('maps Laravel, Express, Flask, Next.js and plain PHP routes, and the parameters the code reads', () => {
    const w = (rel: string, text: string): void => {
      mkdirSync(join(dir, rel, '..'), { recursive: true })
      writeFileSync(join(dir, rel), text)
    }
    w('routes/web.php', "<?php\nRoute::get('/admin/users', [UserController::class, 'index']);\nRoute::middleware('auth')->group(function () {\n  Route::get('/account/{id}', fn() => 1);\n});\nRoute::post('/buy', fn() => 1);\n")
    w('server/app.js', "const app = require('express')()\napp.get('/api/items/:id', (req, res) => res.json(req.query.sort))\napp.post('/login', auth, (req) => req.body.email)\n")
    w('svc/main.py', "@app.route('/reports/<int:rid>')\ndef r(rid):\n  return request.args.get('format')\n")
    w('pages/shop/[slug].tsx', 'export default function P(){}')
    w('public/old/export.php', "<?php echo $_GET['table'];")
    w('node_modules/x/ignored.js', "app.get('/never', f)")
    const m = mapCode(dir)
    const paths = m.routes.map((r) => `${r.method} ${r.path}`)
    expect(paths).toEqual(expect.arrayContaining(['GET /admin/users', 'POST /buy', 'GET /api/items/:id', 'POST /login', 'GET /reports/<int:rid>', 'GET /shop/[slug]', 'GET /old/export.php']))
    expect(paths.join()).not.toContain('/never')
    expect(m.frameworks).toEqual(expect.arrayContaining(['Laravel', 'Express', 'Flask', 'Next.js']))
    expect(paramNames(m)).toEqual(expect.arrayContaining(['sort', 'email', 'format', 'table']))
    expect(getPaths(m)).toEqual(expect.arrayContaining(['/admin/users', '/api/items/1', '/reports/1', '/shop/1']))
    expect(getPaths(m)).not.toContain('/buy')
    const priv = unguardedPrivate(m).map((r) => r.path)
    expect(priv).toContain('/admin/users')
    expect(priv).not.toContain('/account/{id}')
  })
  it('fills in route placeholders so a route can be requested', () => {
    expect(fillPath('/u/{id}/edit')).toBe('/u/1/edit')
    expect(fillPath('/u/:id')).toBe('/u/1')
    expect(fillPath('items/<int:pk>/')).toBe('/items/1/')
    expect(fillPath('/blog/[slug]')).toBe('/blog/1')
  })
})

describe('the checklist walk', () => {
  const profile = profileSite(['https://a.example.com/login'])
  it('marks tested items found or clear, and leaves the rest for you', () => {
    const found = [f({ title: 'Input comes back in the page without escaping: q on /search' })]
    const c = autoMark(found, ['inject', 'tls'], profile)
    const items = c.sections.flatMap((s) => s.items)
    expect(items.some((i) => i.state === 'found' && /xss|cross-site|injection|reflected/i.test(i.text))).toBe(true)
    expect(items.some((i) => i.state === 'clear')).toBe(true)
    expect(items.filter((i) => i.state === 'manual').length).toBeGreaterThan(300)
    // A check that did not run is never marked clear.
    const none = autoMark([], [], profile).sections.flatMap((s) => s.items)
    expect(none.filter((i) => /sql ?injection|xss/i.test(i.text)).every((i) => i.state === 'manual')).toBe(true)
    expect(counts(c).total).toBe(items.length)
  })
  it('a problem the scan found does not appear as clear on any item it covers', () => {
    const c = autoMark([f({ title: 'Cookie "sid" is missing the Secure flag' })], [], profile)
    const cookieItems = c.sections.flatMap((s) => s.items).filter((i) => i.covered === 'Cookie flags')
    expect(cookieItems.length).toBeGreaterThan(0)
    expect(cookieItems.every((i) => i.state === 'found')).toBe(true)
  })
  it('the AI cannot invent a problem or a pass: both need evidence that exists', () => {
    const real = f({ title: 'Cookie "sid" is missing the Secure flag' })
    const c = autoMark([], [], profile)
    const manual = c.sections.flatMap((s) => s.items).filter((i) => i.state === 'manual').slice(0, 4)
    const [a, b, d, e] = manual
    const n = applyAnswers(c, [
      { id: a.id, state: 'issue', evidence: [real.id], note: 'seen' },
      { id: b.id, state: 'issue', evidence: ['made-up-id'], first: 'check it' },
      { id: d.id, state: 'ok', evidence: [] , first: 'look'},
      { id: e.id, state: 'ok', evidence: ['profile'], note: 'no login page' }
    ], [real])
    expect(n).toBe(2)
    expect(a.state).toBe('ai-issue')
    expect(b.state).toBe('manual')
    expect(d.state).toBe('manual')
    expect(e.state).toBe('ai-ok')
    expect(b.note).toContain('Try by hand')
  })
  it('reads the AI answer from a fenced block and ignores nonsense', () => {
    expect(parseAnswers('Here:\n```json\n[{"id":"1.2","state":"unknown","first":"try x"},{"id":"bad","state":"ok"}]\n```')).toHaveLength(1)
    expect(parseAnswers('no json here')).toEqual([])
    expect(parseAnswers('```json\n{"id":"1.1"}\n```')).toEqual([])
  })
  it('the prompt carries only the evidence and forbids guessing', () => {
    const p = walkPrompt('https://a.example.com', { findings: [f({ id: 'abc123', title: 'Open redirect: /go' })], ran: ['logic'], profileText: 'Pages: none' }, [{ id: '1.1', text: 'Check x' }])
    expect(p).toContain('id=abc123')
    expect(p).toMatch(/Never invent a finding id/)
    expect(p).toContain('1.1 Check x')
  })
})

describe('deeper recon over live hosts', () => {
  it('merges the same weakness on many hosts into one finding, and keeps single ones', () => {
    const a = f({ title: 'Missing header X', description: 'd' })
    const out = mergeByTitle([{ host: 'a.example.com', findings: [a] }, { host: 'b.example.com', findings: [{ ...a, id: 'z' }] }, { host: 'c.example.com', findings: [f({ title: 'Only on c' })] }])
    expect(out).toHaveLength(2)
    expect(out.find((x) => /hosts\)/.test(x.title))?.description).toContain('b.example.com')
  })
  it('reads headers and DevOps tools of each host, and finds nothing on a plain correct host', async () => {
    const good = await serve((_q, res) => {
      res.writeHead(200, { 'content-type': 'text/html', 'strict-transport-security': 'max-age=63072000', 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'content-security-policy': "default-src 'self'", 'referrer-policy': 'no-referrer', 'permissions-policy': 'geolocation=()', server: 'cloudflare' })
      res.end('<html><body>Welcome. '.concat('word '.repeat(100), '</body></html>'))
    })
    const weak = await serve((req, res) => {
      if ((req.url ?? '').startsWith('/.git/config')) {
        res.writeHead(404)
        return void res.end('no')
      }
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end('<html><body>Hello '.concat('word '.repeat(100), '</body></html>'))
    })
    const hosts = [{ host: 'good.example.com', url: good.url, status: 200 }, { host: 'weak.example.com', url: weak.url, status: 200 }]
    const out = await deepHosts(hosts, { baseOf: (h) => (h.host.startsWith('good') ? good.url : weak.url), skipDns: true, skipTls: true, skipCves: true })
    good.server.close()
    weak.server.close()
    const text = out.map((x) => `${x.title} ${x.description ?? ''}`).join('\n')
    expect(text).toMatch(/weak\.example\.com|header|Content-Security/i)
    expect(text).not.toContain('good.example.com')
    const onlyGood = await (async () => {
      const g = await serve((_q, res) => {
        res.writeHead(200, { 'content-type': 'text/html', 'strict-transport-security': 'max-age=63072000', 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'content-security-policy': "default-src 'self'", 'referrer-policy': 'no-referrer', 'permissions-policy': 'geolocation=()', server: 'cloudflare' })
        res.end('<html><body>Welcome '.concat('word '.repeat(100), '</body></html>'))
      })
      const r = await deepHosts([{ host: 'good.example.com', url: g.url, status: 200 }], { baseOf: () => g.url, skipDns: true, skipTls: true, skipCves: true })
      g.server.close()
      return r
    })()
    expect(onlyGood.filter((x) => x.severity !== 'info')).toEqual([])
  })
})
