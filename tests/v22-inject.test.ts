import { createServer, type Server } from 'http'
import type { AddressInfo } from 'net'
import { describe, expect, it } from 'vitest'
import { ConfirmClient } from '../src/main/confirmtests'
import { injectionChecks, inputsFrom, postFormLead, sqlError } from '../src/main/injection'

const serve = (h: Parameters<typeof createServer>[1]): Promise<{ server: Server; url: string }> =>
  new Promise((r) => {
    const server = createServer(h)
    server.listen(0, '127.0.0.1', () => r({ server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` }))
  })
const client = (url: string): ConfirmClient => new ConfirmClient(url, { cap: 4000, delayMs: 0 })
const esc = (s: string): string => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!)
const html = (b: string): string => `<html><body><h1>Shop</h1>${b}</body></html>`
const q = (req: { url?: string }, name: string): string => new URL(req.url ?? '/', 'http://x').searchParams.get(name) ?? ''

describe('injection checks find real weaknesses', () => {
  it('finds unescaped output, a database error, template maths and header injection, each with proof', async () => {
    const s = await serve((req, res) => {
      const u = new URL(req.url ?? '/', 'http://x')
      if (u.pathname === '/search') {
        res.writeHead(200, { 'content-type': 'text/html' })
        return void res.end(html(`<p>Results for ${q(req, 'q')}</p>`))
      }
      if (u.pathname === '/item') {
        const id = q(req, 'id')
        res.writeHead(200, { 'content-type': 'text/html' })
        const quotes = (id.match(/'/g) ?? []).length
        return void res.end(html(quotes % 2 === 1 ? `<pre>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near '${esc(id)}'</pre>` : '<p>Item</p>'))
      }
      if (u.pathname === '/greet') {
        const n = q(req, 'name')
        res.writeHead(200, { 'content-type': 'text/html' })
        return void res.end(html(`<p>Hello ${n.replace(/\{\{(\d+)\*(\d+)\}\}/g, (_m, a, b) => String(Number(a) * Number(b)))}</p>`))
      }
      if (u.pathname === '/go') {
        // A server that splits the value at the line break and writes the rest out as a header.
        const hdr = /\r\nX-Macsec-Inj: (\S+)/.exec(q(req, 'lang'))?.[1]
        res.writeHead(200, { 'content-type': 'text/html', ...(hdr ? { 'x-macsec-inj': hdr } : {}) })
        return void res.end(html('ok'))
      }
      res.writeHead(404)
      res.end('no')
    })
    const urls = [`${s.url}/search?q=a`, `${s.url}/item?id=1`, `${s.url}/greet?name=bob`, `${s.url}/go?lang=en`]
    const { inputs } = inputsFrom([], urls, s.url)
    expect(inputs).toHaveLength(4)
    const out = await injectionChecks(client(s.url), inputs)
    s.server.close()
    const titles = out.map((f) => f.title).join('\n')
    expect(titles).toMatch(/without escaping: q on \/search/)
    expect(titles).toMatch(/database error: \/item/)
    expect(titles).toMatch(/calculates an expression sent in "name"/)
    expect(titles).toMatch(/line break in "lang"/)
    for (const f of out) {
      expect(f.confidence).toBe('confirmed')
      expect(f.proof?.reproduce).toContain('curl')
    }
  })
})

describe('injection checks stay quiet on correct sites', () => {
  it('an app that escapes everything and hides errors reports nothing', async () => {
    const s = await serve((req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end(html(`<p>Results for ${esc(q(req, 'q'))} ${esc(q(req, 'id'))}</p>`))
    })
    const { inputs } = inputsFrom([], [`${s.url}/search?q=a&id=1`], s.url)
    const out = await injectionChecks(client(s.url), inputs)
    s.server.close()
    expect(out).toEqual([])
  })
  it('a page that always shows a database error (even with a normal value) is not reported', async () => {
    const s = await serve((_q, res) => {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end(html('<pre>You have an error in your SQL syntax near x</pre>'))
    })
    const { inputs } = inputsFrom([], [`${s.url}/x?id=1`], s.url)
    expect(await injectionChecks(client(s.url), inputs)).toEqual([])
    s.server.close()
  })
  it('a page that errors on any odd value (one quote and two quotes alike) is not reported as SQL injection', async () => {
    const s = await serve((req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end(html(/'/.test(q(req, 'id')) ? '<pre>You have an error in your SQL syntax</pre>' : 'fine'))
    })
    const { inputs } = inputsFrom([], [`${s.url}/x?id=1`], s.url)
    expect(await injectionChecks(client(s.url), inputs)).toEqual([])
    s.server.close()
  })
  it('a page that already contains the product number or the tag is not reported', async () => {
    const s = await serve((_q, res) => {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end(html('<p>Order 9801547 shipped</p>'))
    })
    const { inputs } = inputsFrom([], [`${s.url}/x?id=1`], s.url)
    expect(await injectionChecks(client(s.url), inputs)).toEqual([])
    s.server.close()
  })
  it('a JSON answer that echoes the tag is not cross-site scripting', async () => {
    const s = await serve((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ q: q(req, 'q') }))
    })
    const { inputs } = inputsFrom([], [`${s.url}/api?q=a`], s.url)
    expect(await injectionChecks(client(s.url), inputs)).toEqual([])
    s.server.close()
  })
  it('random content on every request gives nothing', async () => {
    const s = await serve((_q, res) => {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end(html(`${Math.random()} ${'x'.repeat(Math.floor(Math.random() * 300))}`))
    })
    const { inputs } = inputsFrom([], [`${s.url}/x?id=1&q=2`], s.url)
    expect(await injectionChecks(client(s.url), inputs)).toEqual([])
    s.server.close()
  })
})

describe('what is tested and what is only listed', () => {
  it('reads query strings and GET forms, lists POST forms, skips risky addresses, tokens and other sites', () => {
    const pages = [{ url: 'http://a.example.com/', html: '<form action="/s" method="get"><input name="q"><input type="hidden" name="csrf" value="x"><input type="submit" name="go"></form><form method="post" action="/buy"><input name="qty"><textarea name="note"></textarea></form>' }]
    const { inputs, posts } = inputsFrom(pages, ['http://a.example.com/list?page=2&token=abc', 'http://a.example.com/logout?next=/', 'http://a.example.com/delete?id=3', 'http://other.example.com/x?id=1', 'http://a.example.com/logo.png?v=2'], 'http://a.example.com')
    const names = inputs.map((i) => `${new URL(i.page).pathname}:${i.name}`)
    expect(names).toEqual(expect.arrayContaining(['/s:q', '/list:page']))
    expect(names.join()).not.toMatch(/csrf|token|logout|delete|other|logo/)
    expect(posts).toHaveLength(1)
    expect(posts[0].fields).toEqual(expect.arrayContaining(['qty', 'note']))
    const lead = postFormLead(posts)
    expect(lead[0].severity).toBe('info')
    expect(lead[0].confidence).toBe('possible')
    expect(postFormLead([])).toEqual([])
  })
  it('knows common database errors and ignores ordinary text', () => {
    expect(sqlError('You have an error in your SQL syntax')).toBe('MySQL or MariaDB')
    expect(sqlError('ERROR: syntax error at or near "\'"')).toBe('PostgreSQL')
    expect(sqlError('Welcome to our SQL tutorial blog')).toBeNull()
  })
})
