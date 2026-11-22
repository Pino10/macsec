import { createServer, type Server } from 'http'
import type { AddressInfo } from 'net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { accessChecks, ConfirmClient, risky, fuzzContent, fuzzParams, findLoginForm, findResetForm, loginChecks, resetCheck, similar, Stop, wafControl } from '../src/main/confirmtests'

/** A small fake site with known weaknesses, so each check can be proven against something real. */
function site(opts: { catchAll?: boolean } = {}): Promise<{ server: Server; url: string }> {
  const server = createServer((req, res) => {
    const u = new URL(req.url ?? '/', 'http://x')
    const cookie = req.headers.cookie ?? ''
    const html = (body: string, status = 200): void => {
      res.writeHead(status, { 'Content-Type': 'text/html' })
      res.end(`<html><body>${body}</body></html>`)
    }
    // A firewall that blocks the plain lowercase script tag and an SQL shape, and nothing else.
    const decoded = decodeURIComponent(u.search)
    if (/<script>/.test(decoded) || /' or '.*'='/i.test(decoded)) return html('Access Denied - request blocked. Reference #18.2', 403)
    if (opts.catchAll) return html(`Welcome. This page answers everything. ${'x'.repeat(300)}`)
    const pad = 'This is a page with enough text to look like a real page. '.repeat(4)
    if (u.pathname === '/') return html(`Home ${pad}<a href="/login">Sign in</a>`)
    if (u.pathname === '/.env') {
      res.writeHead(200, { 'Content-Type': 'text/plain' })
      return res.end('APP_NAME=Demo\nAPP_KEY=base64:topsecretvalue\nDB_PASSWORD=hunter2hunter2\n')
    }
    if (u.pathname === '/backup/') return html('<title>Index of /backup/</title><h1>Index of /backup/</h1><a href="db.sql">db.sql</a><a href="site.zip">site.zip</a>')
    if (u.pathname === '/admin') return html('Forbidden', 403)
    if (u.pathname === '/secret-page') return html(`A page nobody links to. ${pad}`)
    if (u.pathname === '/search') {
      const q = u.searchParams.get('q')
      const dbg = u.searchParams.get('debug')
      return html(`Results ${pad}${q !== null ? `for: ${q}` : ''}${dbg !== null ? ' DEBUG MODE ON with a lot of extra detail that changes the page size a lot. '.repeat(5) : ''}`)
    }
    if (u.pathname === '/login') {
      const token = Math.random().toString(36).slice(2)
      if (req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/html', 'Set-Cookie': `sid=${token}; Path=/` })
        return res.end(`<html><body><form method="post" action="/login"><input type="hidden" name="csrf" value="${token}"><input type="text" name="email"><input type="password" name="pw"><input type="submit"></form></body></html>`)
      }
      let body = ''
      req.on('data', (d) => (body += d))
      req.on('end', () => {
        const p = new URLSearchParams(body)
        html(p.get('email') === 'alice@example.com' ? 'Wrong password for this account.' : 'No account with that email address.', 200)
      })
      return
    }
    if (u.pathname === '/forgot-password') {
      if (req.method === 'GET') return html('<form method="post" action="/forgot-password"><input type="hidden" name="t" value="1"><input type="email" name="email"></form>')
      let body = ''
      req.on('data', (d) => (body += d))
      req.on('end', () => html(new URLSearchParams(body).get('email') === 'alice@example.com' ? 'We sent you a reset link.' : 'No user has that email.'))
      return
    }
    if (u.pathname.startsWith('/orders/')) {
      if (!/s=(A|B)/.test(cookie)) return html('Please sign in', 401)
      // The flaw: any signed-in user can open any order.
      return html(`Order ${u.pathname.split('/')[2]} for alice@example.com. ${pad}`)
    }
    if (u.pathname === '/public') return html(`Public page. ${pad}`)
    return html('Not found', 404)
  })
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` })))
}

let s: { server: Server; url: string }
let all: { server: Server; url: string }
beforeAll(async () => {
  s = await site()
  all = await site({ catchAll: true })
})
afterAll(() => {
  s.server.close()
  all.server.close()
})

const client = (url: string, headers?: Record<string, string>, cap = 2000): ConfirmClient => new ConfirmClient(url, { delayMs: 0, cap, headers })
const quiet = (): void => undefined

describe('the careful client', () => {
  it('refuses addresses outside the site', () => {
    const c = client(s.url)
    expect(() => c.resolve('http://evil.example/x')).toThrow(/not on the site/)
    expect(c.resolve('admin')).toBe(`${s.url}/admin`)
  })
  it('stops at its request limit', async () => {
    const c = client(s.url, undefined, 3)
    await c.get('')
    await c.get('')
    await c.get('')
    await expect(c.get('')).rejects.toBeInstanceOf(Stop)
  })
  it('stops when the server keeps failing', async () => {
    const c = new ConfirmClient('http://x.test', { delayMs: 0, fetchImpl: (async () => new Response('oops', { status: 500 })) as typeof fetch })
    for (let i = 0; i < 5; i++) await c.get('a')
    await expect(c.get('a')).rejects.toThrow(/struggle/)
  })
  it('does not follow redirects', async () => {
    const c = new ConfirmClient('http://x.test', { delayMs: 0, fetchImpl: (async (_u: string, init: RequestInit) => new Response('', { status: init.redirect === 'manual' ? 302 : 200, headers: { Location: 'http://elsewhere.test/' } })) as unknown as typeof fetch })
    expect((await c.get('a')).status).toBe(302)
  })
})

describe('hidden pages', () => {
  it('finds what is really there, with proof and no secret values', async () => {
    const out = await fuzzContent(client(s.url), quiet, ['.env', 'backup/', 'admin', 'secret-page', 'nothing-here', 'public'])
    const titles = out.map((x) => x.title)
    expect(titles.some((t) => t.includes('/.env'))).toBe(true)
    expect(titles.some((t) => t.startsWith('Folder lists its files: /backup/'))).toBe(true)
    expect(out.some((x) => /hidden page/.test(x.title) && x.description?.includes('admin (403)'))).toBe(true)
    const env = out.find((x) => x.title.includes('/.env'))!
    expect(env.confidence).toBe('confirmed')
    expect(env.proof?.shows.join(' ')).toMatch(/APP_NAME/)
    expect(JSON.stringify(env)).not.toMatch(/topsecretvalue|hunter2/)
    expect(env.proof?.reproduce).toContain('curl')
    expect(titles.some((t) => t.includes('nothing-here'))).toBe(false)
  })
  it('reports nothing on a site that answers "found" to everything', async () => {
    const out = await fuzzContent(client(all.url), quiet, ['.env', 'admin', 'backup/', 'secret-page', 'login'])
    expect(out).toEqual([])
  })
  it('never puts the account cookie in a proof', async () => {
    const out = await fuzzContent(client(s.url, { Cookie: 's=A-private-cookie' }), quiet, ['.env'])
    expect(JSON.stringify(out)).not.toContain('A-private-cookie')
  })
})

describe('hidden parameters', () => {
  it('finds one that is echoed and one that changes the page, each repeated', async () => {
    const { hits, findings } = await fuzzParams(client(s.url), 'search', quiet, ['page', 'q', 'sort', 'debug', 'lang'])
    expect(hits.map((h) => `${h.name}:${h.how}`).sort()).toEqual(['debug:changed', 'q:reflected'])
    expect(findings.every((x) => x.confidence === 'confirmed')).toBe(true)
    expect(findings.find((x) => x.title.includes('"q"'))?.severity).toBe('low')
  })
  it('does not call every name a hit on a site that echoes everything', async () => {
    const echo = createServer((req, res) => {
      const u = new URL(req.url ?? '/', 'http://x')
      res.writeHead(200, { 'Content-Type': 'text/html' })
      res.end(`<html><body>${[...u.searchParams.values()].join(' ')} some page text</body></html>`)
    })
    await new Promise<void>((r) => echo.listen(0, '127.0.0.1', () => r()))
    const url = `http://127.0.0.1:${(echo.address() as AddressInfo).port}`
    const names = Array.from({ length: 30 }, (_, i) => `name${i}`)
    const { hits, findings } = await fuzzParams(client(url), '', quiet, names)
    echo.close()
    expect(hits).toEqual([])
    expect(findings[0].title).toMatch(/echoes any parameter/)
  })
})

describe('web firewall control tests', () => {
  it('names the firewall behaviour and proves a bypass only when the marker comes back', async () => {
    const notes: string[] = []
    const out = await wafControl(client(s.url), (d) => notes.push(d), 'search?q')
    const titles = out.map((x) => x.title)
    expect(titles.some((t) => t.startsWith('Web firewall in front of the site'))).toBe(true)
    const bypass = out.filter((x) => x.title.startsWith('Firewall bypass confirmed'))
    expect(bypass.length).toBeGreaterThanOrEqual(2)
    expect(bypass.every((x) => x.confidence === 'confirmed' && x.proof!.shows.some((l) => /repeated twice/.test(l)))).toBe(true)
    expect(bypass.map((x) => x.title).join(' ')).toMatch(/mixed upper and lower case/)
    expect(notes.some((n) => n.startsWith('Reported at once'))).toBe(true)
  })
  it('does not claim a bypass without a parameter that echoes', async () => {
    const out = await wafControl(client(s.url), quiet)
    expect(out.some((x) => x.title.startsWith('Firewall bypass'))).toBe(false)
  })
  it('reports unescaped output when nothing blocks the marker', async () => {
    const open = createServer((req, res) => {
      const q = new URL(req.url ?? '/', 'http://x').searchParams.get('q') ?? ''
      res.writeHead(200, { 'Content-Type': 'text/html' })
      res.end(`<html><body>Results for ${q}. ${'filler text '.repeat(20)}</body></html>`)
    })
    await new Promise<void>((r) => open.listen(0, '127.0.0.1', () => r()))
    const url = `http://127.0.0.1:${(open.address() as AddressInfo).port}`
    const out = await wafControl(client(url), quiet, 'search?q')
    open.close()
    const x = out.find((y) => y.title.startsWith('Input comes back in the page without escaping'))
    expect(x?.cwe).toBe('CWE-79')
    expect(x?.confidence).toBe('confirmed')
  })
})

describe('login checks', () => {
  it('finds the sign-in form with its hidden token', () => {
    const f = findLoginForm('<form method="post" action="/in"><input type="hidden" name="t" value="9"><input name="user" type="text"><input name="p" type="password"></form>', 'http://a.test/login')!
    expect(f).toMatchObject({ action: 'http://a.test/in', userField: 'user', passField: 'p', fields: { t: '9' } })
    expect(findLoginForm('<form method="get"><input type="text" name="q"></form>', 'http://a.test/')).toBeNull()
    expect(findResetForm('<form method="post"><input type="email" name="email"></form>', 'http://a.test/forgot')?.emailField).toBe('email')
  })
  it('proves there is no limit on wrong guesses and that usernames can be told apart', async () => {
    const out = await loginChecks(client(s.url), { knownUser: 'alice@example.com' }, quiet)
    const t = out.find((x) => x.title.startsWith('Login does not slow down'))
    expect(t?.cwe).toBe('CWE-307')
    expect(t?.description).toMatch(/does not exist/)
    const e = out.find((x) => x.title === 'Login shows which usernames exist')
    expect(e?.confidence).toBe('confirmed')
    expect(e?.proof?.shows.join(' ')).toMatch(/Wrong password|No account/)
  })
  it('never sends the known user more than twice', async () => {
    let known = 0
    const c = new ConfirmClient(s.url, {
      delayMs: 0,
      fetchImpl: (async (u: string, init: RequestInit) => {
        if (typeof init.body === 'string' && init.body.includes('alice')) known++
        return fetch(u, init)
      }) as typeof fetch
    })
    await loginChecks(c, { knownUser: 'alice@example.com' }, quiet)
    expect(known).toBe(2)
  })
  it('does not report enumeration when the answers are the same', async () => {
    const same = createServer((req, res) => {
      if (req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/html' })
        return res.end('<form method="post"><input type="text" name="u"><input type="password" name="p"></form>')
      }
      req.resume()
      req.on('end', () => {
        res.writeHead(429, { 'Content-Type': 'text/html', 'Retry-After': '30' })
        res.end('Too many attempts, try again later')
      })
    })
    await new Promise<void>((r) => same.listen(0, '127.0.0.1', () => r()))
    const url = `http://127.0.0.1:${(same.address() as AddressInfo).port}`
    const out = await loginChecks(client(url), { loginUrl: url, knownUser: 'bob' }, quiet)
    same.close()
    expect(out).toEqual([])
  })
  it('finds that password reset shows who has an account', async () => {
    const out = await resetCheck(client(s.url), 'alice@example.com', quiet)
    expect(out[0]?.title).toMatch(/Password reset shows which emails/)
  })
})

describe('access checks between two accounts', () => {
  it('proves account B can open account A\'s order, and skips public pages', async () => {
    const c = client(s.url, { Cookie: 's=A' })
    const out = await accessChecks(c, [`${s.url}/orders/1`, `${s.url}/public`, `${s.url}/`], { headersB: { Cookie: 's=B' }, identityA: 'alice@example.com' }, quiet)
    expect(out).toHaveLength(1)
    expect(out[0]).toMatchObject({ confidence: 'confirmed', severity: 'high', cwe: 'CWE-639' })
    expect(out[0].proof?.shows.join(' ')).toMatch(/signed out: answer 401/)
    expect(JSON.stringify(out)).not.toMatch(/s=A|s=B/)
  })
  it('calls it only possible when nothing proves the page is account A\'s', async () => {
    const c = client(s.url, { Cookie: 's=A' })
    const out = await accessChecks(c, [`${s.url}/orders/1`], { headersB: { Cookie: 's=B' } }, quiet)
    expect(out[0].confidence).toBe('possible')
  })
})

describe('links that are never opened', () => {
  it('skips anything that could sign out or change data', () => {
    for (const u of ['/logout', '/account/delete?id=3', '/sign-out', '/cart/remove/4', '/unsubscribe']) expect(risky(u)).toBe(true)
    for (const u of ['/orders/1', '/profile', '/search?q=a']) expect(risky(u)).toBe(false)
  })
  it('leaves them out of the two-account comparison', async () => {
    const seen: string[] = []
    const c = new ConfirmClient(s.url, { delayMs: 0, fetchImpl: (async (u: string, init: RequestInit) => {
      seen.push(u)
      return fetch(u, init)
    }) as typeof fetch })
    await accessChecks(c, [`${s.url}/logout`, `${s.url}/orders/delete/1`], { headersB: { Cookie: 's=B' } }, quiet)
    expect(seen.some((u) => /logout|delete/.test(u))).toBe(false)
  })
})

describe('comparing answers', () => {
  it('treats small differences as the same page', () => {
    const mk = (body: string): any => ({ status: 200, headers: new Headers(), body, url: '', method: 'GET', ms: 0 })
    expect(similar(mk('a'.repeat(1000)), mk('a'.repeat(1010)))).toBe(true)
    expect(similar(mk('a'.repeat(1000)), mk('b'.repeat(1500)))).toBe(false)
  })
})
