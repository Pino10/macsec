import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'http'
import type { AddressInfo } from 'net'
import { createHmac } from 'crypto'
import { afterAll, describe, expect, it } from 'vitest'
import { ConfirmClient, type Reply } from '../src/main/confirmtests'
import { authRequestsFrom, callbackVariants, discoveryChecks, leadsTo, oauthChecks, oauthPassive, redirectUriChecks, stateChecks, tokensInAddresses } from '../src/main/oauth'
import { decodeJwt, jwtChecks, signatureChecks, tokenChecks, tokensInHeaders, weakSecret } from '../src/main/jwt'
import { endpointChecks, findEndpoints, graphqlChecks, ideChecks } from '../src/main/graphql'
import { adoptsSessionId, cookieSamesite, corsChecks, csrfLeads, sessionsInUrls } from '../src/main/sessioncheck'

const servers: Server[] = []
afterAll(() => servers.forEach((s) => s.close()))
const serve = (h: (req: IncomingMessage, res: ServerResponse, body: string) => void): Promise<string> =>
  new Promise((resolve) => {
    const s = createServer((req, res) => {
      let b = ''
      req.on('data', (d) => (b += d))
      req.on('end', () => h(req, res, b))
    })
    servers.push(s)
    s.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${(s.address() as AddressInfo).port}`))
  })
const client = (base: string, headers?: Record<string, string>): ConfirmClient => new ConfirmClient(base, { delayMs: 0, cap: 500, headers })
const reply = (url: string, body = '', status = 200, headers: Record<string, string> = {}): Reply => ({ status, url, body, headers: new Headers({ 'content-type': 'text/html', ...headers }), method: 'GET', ms: 1 })
const b64u = (s: string | Buffer): string => Buffer.from(s).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
const sign = (payload: object, secret: string, alg = 'HS256'): string => {
  const h = b64u(JSON.stringify({ alg, typ: 'JWT' }))
  const p = b64u(JSON.stringify(payload))
  return `${h}.${p}.${b64u(createHmac('sha256', secret).update(`${h}.${p}`).digest())}`
}

// ---------------------------------------------------------------- OAuth

describe('OAuth from the links a site sends', () => {
  const link = 'https://idp.example/authorize?client_id=abc&response_type=code&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&state=xyz123&code_challenge=zzz&code_challenge_method=S256'
  it('finds the request in a page and in a redirect, including &amp; forms', () => {
    const a = authRequestsFrom([reply('https://app.example/login', `<a href="${link.replace(/&/g, '&amp;')}">Sign in</a>`), reply('https://app.example/go', '', 302, { location: link })])
    expect(a).toHaveLength(1)
    expect(a[0].params.client_id).toBe('abc')
    expect(authRequestsFrom([reply('https://app.example/', '<a href="https://x.example/page?client_id=1">x</a>')])).toEqual([])
  })
  it('a correct request produces nothing', () => {
    expect(oauthPassive(authRequestsFrom([reply('https://app.example/login', `<a href="${link}">x</a>`)]))).toEqual([])
  })
  it('flags no state, implicit flow, no PKCE (as a lead) and an http callback, each with the proof or as a lead', () => {
    const bad = 'https://idp.example/authorize?client_id=abc&response_type=token&redirect_uri=http%3A%2F%2Fapp.example%2Fcb'
    const f = oauthPassive(authRequestsFrom([reply('https://app.example/login', `<a href="${bad}">x</a>`)]))
    const titles = f.map((x) => x.title).join('\n')
    expect(titles).toMatch(/without a state value/)
    expect(titles).toMatch(/implicit flow/)
    expect(titles).toMatch(/plain http/)
    expect(f.find((x) => /state value/.test(x.title))?.proof?.shows.join()).toContain('no state')
    const code = oauthPassive(authRequestsFrom([reply('https://app.example/login', `<a href="https://idp.example/authorize?client_id=a&response_type=code&state=s&redirect_uri=https%3A%2F%2Fa.example%2Fcb">x</a>`)]))
    expect(code).toHaveLength(1)
    expect(code[0]).toMatchObject({ confidence: 'possible', severity: 'low' })
    expect(code[0].proof).toBeUndefined()
  })
  it('does not call localhost callbacks insecure', () => {
    const u = 'https://idp.example/authorize?client_id=a&response_type=code&state=s&code_challenge=c&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb'
    expect(oauthPassive(authRequestsFrom([reply('https://app.example/', `<a href="${u}">x</a>`)]))).toEqual([])
  })
  it('finds tokens in addresses and hides the value', () => {
    const f = tokensInAddresses([reply('https://app.example/cb?access_token=abcdefghijklmnop1234&x=1'), reply('https://app.example/ok?token=short')])
    expect(f).toHaveLength(1)
    expect(JSON.stringify(f)).not.toContain('abcdefghijklmnop1234')
  })
})

describe('the provider settings document', () => {
  const doc = (o: Record<string, unknown>) => ({ reply: reply('https://app.example/.well-known/openid-configuration', JSON.stringify(o), 200, { 'content-type': 'application/json' }), doc: o })
  it('flags none, plain PKCE, implicit, password grant and open registration, and passes a good one', () => {
    const bad = discoveryChecks(doc({ issuer: 'https://app.example', authorization_endpoint: 'http://app.example/a', id_token_signing_alg_values_supported: ['RS256', 'none'], code_challenge_methods_supported: ['plain'], response_types_supported: ['code', 'id_token token'], grant_types_supported: ['password'], registration_endpoint: 'https://app.example/register' }))
    const t = bad.map((x) => x.title).join('\n')
    for (const re of [/unsigned ID tokens/, /weak PKCE/, /implicit flow/, /password grant/, /registered by address/, /plain http/]) expect(t).toMatch(re)
    expect(bad.find((x) => /registered by address/.test(x.title))?.confidence).toBe('possible')
    expect(discoveryChecks(doc({ issuer: 'https://app.example', authorization_endpoint: 'https://app.example/a', id_token_signing_alg_values_supported: ['RS256'], code_challenge_methods_supported: ['S256'], response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'] }))).toEqual([])
  })
})

describe('live OAuth checks against local servers', () => {
  const authorize = (strict: boolean) => async (req: IncomingMessage, res: ServerResponse) => {
    const u = new URL(req.url ?? '/', 'http://x')
    if (u.pathname === '/authorize') {
      const ru = u.searchParams.get('redirect_uri') ?? ''
      if (strict && ru !== 'https://app.example/cb') {
        res.writeHead(400, { 'content-type': 'text/html' })
        return res.end('<h1>Invalid redirect_uri</h1>')
      }
      // Both servers would normally ask for a login first; this one redirects straight to the callback with an error, like a sloppy one.
      res.writeHead(302, { location: `${ru}?error=login_required` })
      return res.end()
    }
    res.writeHead(404)
    res.end()
  }
  it('catches a server that redirects to any callback, and not one that checks it', async () => {
    const bad = await serve(authorize(false))
    const good = await serve(authorize(true))
    const mk = (base: string) => authRequestsFrom([reply(`${base}/login`, '', 302, { location: `${base}/authorize?client_id=abc&response_type=code&state=s&redirect_uri=${encodeURIComponent('https://app.example/cb')}` })])
    const f1 = await redirectUriChecks(client(bad), mk(bad))
    expect(f1).toHaveLength(1)
    expect(f1[0]).toMatchObject({ confidence: 'confirmed', severity: 'high' })
    expect(f1[0].proof?.shows.join()).toContain('.invalid')
    expect(await redirectUriChecks(client(good), mk(good))).toEqual([])
  })
  it('a signed-out request that is sent to the login page is not a hit', async () => {
    const base = await serve((req, res) => {
      res.writeHead(302, { location: `/login?next=${encodeURIComponent(req.url ?? '')}` })
      res.end()
    })
    const reqs = authRequestsFrom([reply(`${base}/x`, '', 302, { location: `${base}/authorize?client_id=abc&response_type=code&state=s&redirect_uri=${encodeURIComponent('https://app.example/cb')}` })])
    expect(await redirectUriChecks(client(base), reqs)).toEqual([])
  })
  it('callback variants end in .invalid and leadsTo reads the Location host, not the text', () => {
    const v = callbackVariants('https://app.example/cb')
    expect(v.length).toBeGreaterThanOrEqual(3)
    for (const x of v) expect(x.value).toContain('.invalid')
    expect(leadsTo(reply('https://a/x', '', 302, { location: '/login?redirect_uri=https%3A%2F%2Fmacsec-abc.invalid' }), 'macsec-abc')).toBeNull()
    expect(leadsTo(reply('https://a/x', '', 302, { location: 'https://macsec-abc.invalid/cb?code=1' }), 'macsec-abc')?.carries).toEqual(['code'])
  })
  it('a state that never changes is found, a random one is not', async () => {
    const mk = (fixed: boolean) =>
      serve((req, res) => {
        if (req.url === '/login/google') {
          res.writeHead(302, { location: `https://idp.example/authorize?client_id=abc&response_type=code&state=${fixed ? 'static' : Math.random().toString(36).slice(2)}` })
          return res.end()
        }
        res.writeHead(404)
        res.end()
      })
    for (const [fixed, count] of [[true, 1], [false, 0]] as const) {
      const base = await mk(fixed)
      const first = await client(base).get('/login/google', { headers: 'none' })
      const reqs = authRequestsFrom([first])
      reqs[0].starter = `${base}/login/google`
      expect(await stateChecks(client(base), reqs)).toHaveLength(count)
    }
  })
  it('oauthChecks runs end to end and does not stray off the site', async () => {
    const seen: string[] = []
    const base = await serve((req, res) => {
      seen.push(req.url ?? '')
      if (req.url === '/login/google') {
        res.writeHead(302, { location: 'https://accounts.example/o/authorize?client_id=abc&response_type=token&redirect_uri=https%3A%2F%2Fapp.example%2Fcb' })
        return res.end()
      }
      res.writeHead(404)
      res.end()
    })
    const f = await oauthChecks(client(base), { pages: [], urls: [base] })
    expect(f.map((x) => x.title).join('\n')).toMatch(/without a state value/)
    expect(f.map((x) => x.title).join('\n')).toMatch(/implicit flow/)
    expect(seen.every((u) => u.startsWith('/'))).toBe(true)
  })
})

// ---------------------------------------------------------------- JWT

describe('JWT checks', () => {
  const payload = { sub: '42', name: 'Ann', iat: 1700000000, exp: 1700003600 }
  it('decodes tokens and refuses things that are not tokens', () => {
    expect(decodeJwt(sign(payload, 'x'))?.payload.sub).toBe('42')
    expect(decodeJwt('a.b.c')).toBeNull()
    expect(decodeJwt('eyJhbGciOiJIUzI1NiJ9.bm90anNvbg.')).toBeNull()
  })
  it('finds tokens in the headers the person gave, in a cookie and in Authorization', () => {
    const t = sign(payload, 'x')
    const f = tokensInHeaders({ Cookie: `a=1; session=${t}; b=2`, Authorization: `Bearer ${t}` })
    expect(f.map((x) => x.where)).toEqual(['the cookie session', 'the Authorization header'])
    expect(f[0].put!({ Cookie: `a=1; session=${t}` }, 'NEW').Cookie).toBe('a=1; session=NEW')
  })
  it('a weak secret is found without writing the secret down, a strong one is not', () => {
    const weak = decodeJwt(sign(payload, 'secret'))!
    const strong = decodeJwt(sign(payload, 'k8Zq0vR2mX9wLpT4aBn7YdCe5HfJs1Gu'))!
    expect(weakSecret(weak)).toBe(6)
    expect(weakSecret(strong)).toBeNull()
    const f = tokenChecks({ ...weak, where: 'the cookie session' })
    const hit = f.find((x) => /weak secret/.test(x.title))!
    expect(hit.confidence).toBe('confirmed')
    expect(JSON.stringify(f)).not.toContain('"secret"')
    expect(JSON.stringify(f)).not.toContain(weak.token)
  })
  it('no signature, no expiry, long life and sensitive claims', () => {
    const none = { ...decodeJwt(`${b64u(JSON.stringify({ alg: 'none' }))}.${b64u(JSON.stringify({ sub: '1', password: 'x' }))}.`)!, where: 'the Authorization header' }
    const titles = tokenChecks(none).map((x) => x.title).join('\n')
    expect(titles).toMatch(/no signature/)
    expect(titles).toMatch(/never expires/)
    expect(titles).toMatch(/sensitive data/)
    const long = decodeJwt(sign({ sub: '1', iat: 1700000000, exp: 1700000000 + 86400 * 400 }, 'k8Zq0vR2mX9wLpT4aBn7YdCe5HfJs1Gu'))!
    expect(tokenChecks({ ...long, where: 'x' }).map((x) => x.title).join()).toMatch(/lives for/)
    const ok = decodeJwt(sign(payload, 'k8Zq0vR2mX9wLpT4aBn7YdCe5HfJs1Gu'))!
    expect(tokenChecks({ ...ok, where: 'x' })).toEqual([])
  })
  const SECRET = 'k8Zq0vR2mX9wLpT4aBn7YdCe5HfJs1Gu'
  const page = (verify: boolean) => (req: IncomingMessage, res: ServerResponse) => {
    const m = /^Bearer (\S+)/.exec(String(req.headers.authorization ?? ''))
    let who: string | null = null
    if (m) {
      const [h, p, sig] = m[1].split('.')
      try {
        const head = JSON.parse(Buffer.from(h, 'base64url').toString())
        const pay = JSON.parse(Buffer.from(p, 'base64url').toString())
        const good = b64u(createHmac('sha256', SECRET).update(`${h}.${p}`).digest()) === sig
        if (!verify || (good && head.alg === 'HS256')) who = pay.sub
      } catch {
        who = null
      }
    }
    if (!who) {
      res.writeHead(302, { location: '/login' })
      return res.end()
    }
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end(`<h1>Account of user ${who}</h1>${'<p>private details</p>'.repeat(20)}`)
  }
  it('a server that does not check the signature is caught; one that does is not', async () => {
    const token = sign({ sub: '42', iat: 1700000000, exp: 4100000000 }, SECRET)
    for (const [verify, count] of [[false, 1], [true, 0]] as const) {
      const base = await serve(page(verify))
      const headers = { Authorization: `Bearer ${token}` }
      const f = await signatureChecks(client(base, headers), tokensInHeaders(headers), headers, [`${base}/account`])
      expect(f).toHaveLength(count)
      if (count) {
        expect(f[0]).toMatchObject({ confidence: 'confirmed', severity: 'critical' })
        expect(JSON.stringify(f)).not.toContain(token)
      }
    }
  })
  it('skips the test when no page treats the token differently', async () => {
    const base = await serve((_q, res) => {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end('<h1>Same for everyone</h1>')
    })
    const token = sign({ sub: '1', exp: 4100000000, iat: 1 }, SECRET)
    const headers = { Authorization: `Bearer ${token}` }
    expect(await signatureChecks(client(base, headers), tokensInHeaders(headers), headers, [`${base}/x`])).toEqual([])
  })
  it('jwtChecks puts it together and flags a token cookie without HttpOnly', async () => {
    const token = sign({ sub: '1', iat: 1700000000, exp: 4100000000 }, SECRET)
    const r = reply('https://app.example/login', '', 200, { 'set-cookie': `session=${token}; Path=/; Secure` })
    const base = await serve((_q, res) => {
      res.writeHead(200)
      res.end('x')
    })
    const f = await jwtChecks(client(base), { headers: {}, replies: [r], urls: [] })
    expect(f.map((x) => x.title).join('\n')).toMatch(/not HttpOnly/)
    const ok = reply('https://app.example/login', '', 200, { 'set-cookie': `session=${token}; Path=/; Secure; HttpOnly` })
    expect((await jwtChecks(client(base), { headers: {}, replies: [ok], urls: [] })).map((x) => x.title).join()).not.toMatch(/not HttpOnly/)
  })
})

// ---------------------------------------------------------------- GraphQL

describe('GraphQL checks', () => {
  interface Cfg {
    introspection: boolean
    getMutation: boolean
    textPlain: boolean
    batching: boolean
    suggestions: boolean
    trace: boolean
    ide: boolean
  }
  const gql = (c: Cfg) => (req: IncomingMessage, res: ServerResponse, body: string) => {
    const u = new URL(req.url ?? '/', 'http://x')
    const send = (status: number, data: unknown, type = 'application/json'): void => {
      res.writeHead(status, { 'content-type': type })
      res.end(typeof data === 'string' ? data : JSON.stringify(data))
    }
    if (u.pathname === '/graphiql' && c.ide) return send(200, '<html><title>GraphiQL</title><div id="graphiql"></div></html>', 'text/html')
    if (u.pathname !== '/graphql') return send(404, 'nope', 'text/html')
    const run = (q: string): unknown => {
      if (/\{\s*$/.test(q.trim()) || q.trim() === '{') return { errors: [{ message: 'Syntax Error: Expected Name, found <EOF>.', ...(c.trace ? { extensions: { exception: { stacktrace: ['Error: x', 'at resolve (/usr/src/app/node_modules/graphql/execute.js:10:5)'] } } } : {}) }] }
      if (q.includes('__schema')) return c.introspection ? { data: { __schema: { queryType: { name: 'Query' }, mutationType: { name: 'Mutation' }, types: [{ name: 'Query', kind: 'OBJECT' }, { name: 'User', kind: 'OBJECT' }, { name: '__Schema', kind: 'OBJECT' }] } } } : { errors: [{ message: 'GraphQL introspection is not allowed' }] }
      if (q.includes('__typenam}') || q.includes('__typenam ')) return { errors: [{ message: c.suggestions ? 'Cannot query field "__typenam" on type "Query". Did you mean "__typename"?' : 'Cannot query field "__typenam" on type "Query".' }] }
      return { data: { __typename: q.includes('mutation') ? 'Mutation' : 'Query' } }
    }
    if (req.method === 'GET') {
      const q = u.searchParams.get('query') ?? ''
      if (q.includes('mutation') && !c.getMutation) return send(405, { errors: [{ message: 'GET supports only query operation' }] })
      return send(200, run(q))
    }
    const ct = String(req.headers['content-type'] ?? '')
    if (!ct.includes('json') && !c.textPlain) return send(415, { errors: [{ message: 'Unsupported content type' }] })
    try {
      const j = JSON.parse(body) as unknown
      if (Array.isArray(j)) return c.batching ? send(200, j.map((x: { query: string }) => run(x.query))) : send(400, { errors: [{ message: 'Batching is not allowed' }] })
      return send(200, run((j as { query: string }).query))
    } catch {
      return send(400, { errors: [{ message: 'bad json' }] })
    }
  }
  const open: Cfg = { introspection: true, getMutation: true, textPlain: true, batching: true, suggestions: true, trace: true, ide: true }
  const hard: Cfg = { introspection: false, getMutation: false, textPlain: false, batching: false, suggestions: false, trace: false, ide: false }
  it('an open server shows every weakness, each with proof', async () => {
    const base = await serve(gql(open))
    const f = await graphqlChecks(client(base))
    const t = f.map((x) => x.title).join('\n')
    for (const re of [/endpoint answers/, /read the whole GraphQL schema/, /server internals/, /mutations sent as a GET/, /accepts text\/plain/, /batched requests/, /IDE is open/]) expect(t).toMatch(re)
    expect(f.find((x) => /whole GraphQL schema/.test(x.title))?.description).toContain('User')
    for (const x of f.filter((y) => y.severity !== 'info')) expect(x.proof).toBeTruthy()
  })
  it('a hardened server shows only that an endpoint exists', async () => {
    const base = await serve(gql(hard))
    const f = await graphqlChecks(client(base))
    expect(f.map((x) => x.title)).toEqual([expect.stringMatching(/endpoint answers/)])
  })
  it('with introspection off, field suggestions are still reported', async () => {
    const base = await serve(gql({ ...hard, suggestions: true }))
    expect((await graphqlChecks(client(base))).map((x) => x.title).join()).toMatch(/suggests field names/)
  })
  it('a site with no GraphQL, and a single-page app that answers 200 to everything, produce nothing', async () => {
    const spa = await serve((_q, res) => {
      res.writeHead(200, { 'content-type': 'text/html' })
      res.end('<html><title>My app</title><div id="root"></div></html>')
    })
    expect(await graphqlChecks(client(spa))).toEqual([])
    expect(await findEndpoints(client(spa))).toEqual([])
    expect(await ideChecks(client(spa))).toEqual([])
  })
  it('never sends a mutation', async () => {
    const base = await serve(gql(open))
    const c = client(base)
    expect(() => c.query('/graphql', JSON.stringify({ query: 'mutation { deleteAll }' }))).toThrow(/no mutations/)
    expect(() => c.query('/graphql', JSON.stringify({ query: 'subscription { x }' }))).toThrow()
    const eps = await findEndpoints(c)
    expect(eps).toHaveLength(1)
    expect((await endpointChecks(c, eps[0])).length).toBeGreaterThan(3)
  })
})

// ---------------------------------------------------------------- CORS, CSRF, sessions

describe('CORS', () => {
  const cors = (mode: 'reflect' | 'list' | 'wild' | 'reflect-nocreds') => (req: IncomingMessage, res: ServerResponse) => {
    const o = String(req.headers.origin ?? '')
    const h: Record<string, string> = { 'content-type': 'application/json' }
    if (mode === 'reflect' && o) Object.assign(h, { 'access-control-allow-origin': o, 'access-control-allow-credentials': 'true' })
    if (mode === 'reflect-nocreds' && o) h['access-control-allow-origin'] = o
    if (mode === 'list' && o === 'https://app.example') Object.assign(h, { 'access-control-allow-origin': o, 'access-control-allow-credentials': 'true' })
    if (mode === 'wild') h['access-control-allow-origin'] = '*'
    res.writeHead(200, h)
    res.end('{"ok":true}')
  }
  it('catches reflection with credentials, and not an allow-list, a wildcard or reflection without credentials', async () => {
    for (const [mode, count] of [['reflect', 1], ['list', 0], ['wild', 0], ['reflect-nocreds', 0]] as const) {
      const base = await serve(cors(mode))
      const f = await corsChecks(client(base), [`${base}/api/me`])
      expect(f.length > 0).toBe(count > 0)
      if (count) {
        expect(f[0]).toMatchObject({ confidence: 'confirmed' })
        expect(f[0].proof?.shows.join()).toContain('Access-Control-Allow-Credentials: true')
      }
    }
  })
  it('signed in, the same flaw is rated higher', async () => {
    const base = await serve(cors('reflect'))
    const f = await corsChecks(client(base), [`${base}/api/me`], { account: { Cookie: 'sid=abc' } })
    expect(f.some((x) => x.severity === 'high')).toBe(true)
  })
})

describe('CSRF leads and session ids', () => {
  const sc = (s: string): Reply => reply('https://app.example/', '', 200, { 'set-cookie': s })
  it('lists a form with no token and says it is a lead, and leaves tokened, search and login forms alone', () => {
    const cookies = cookieSamesite([sc('sid=1; Path=/; HttpOnly')])
    const bad = csrfLeads([{ url: 'https://app.example/profile', html: '<form method="post" action="/profile/update"><input name="email"><input name="name"></form>' }], cookies)
    expect(bad).toHaveLength(1)
    expect(bad[0]).toMatchObject({ confidence: 'possible', severity: 'medium' })
    expect(bad[0].proof).toBeUndefined()
    const good = csrfLeads([{ url: 'https://app.example/profile', html: '<form method="post" action="/profile/update"><input type="hidden" name="_token" value="x"><input name="email"></form>' }], cookies)
    expect(good).toEqual([])
    expect(csrfLeads([{ url: 'https://app.example/', html: '<form method="post" action="/search"><input name="q"></form><form method="get" action="/x"><input name="a"></form>' }], cookies)).toEqual([])
    expect(csrfLeads([{ url: 'https://app.example/', html: '<form method="post" action="/login"><input name="email"><input type="password" name="password"></form>' }], cookies)).toEqual([])
  })
  it('with SameSite set the lead is only low', () => {
    const f = csrfLeads([{ url: 'https://app.example/p', html: '<form method="post" action="/p/save"><input name="email"></form>' }], cookieSamesite([sc('sid=1; SameSite=Lax')]))
    expect(f[0].severity).toBe('low')
  })
  it('a session id in an address is found and its value hidden', () => {
    const f = sessionsInUrls([reply('https://app.example/home;jsessionid=ABCDEF1234567890'), reply('https://app.example/other?page=2')], [])
    expect(f).toHaveLength(1)
    expect(JSON.stringify(f)).not.toContain('ABCDEF1234567890')
  })
  const sessionServer = (mode: 'adopt' | 'regenerate' | 'none' | 'ignore') => (req: IncomingMessage, res: ServerResponse) => {
    const cookie = String(req.headers.cookie ?? '')
    const have = /PHPSESSID=([^;]+)/.exec(cookie)?.[1]
    const fresh = `PHPSESSID=${Math.random().toString(36).slice(2)}; Path=/; HttpOnly`
    const h: Record<string, string | string[]> = { 'content-type': 'text/html' }
    if (mode === 'adopt' && !have) h['set-cookie'] = fresh // PHP: gives one when there is none, keeps whatever the visitor sent
    if (mode === 'regenerate') h['set-cookie'] = have && have.startsWith('macsec') ? fresh : fresh
    if (mode === 'ignore') h['set-cookie'] = fresh // sets a new one every time, even for a visitor that sent one
    res.writeHead(200, h)
    res.end('<h1>home</h1>')
  }
  it('finds a server that keeps a made-up id, and not one that replaces it or never hands one out', async () => {
    for (const [mode, count] of [['adopt', 1], ['regenerate', 0], ['ignore', 0], ['none', 0]] as const) {
      const base = await serve(sessionServer(mode))
      const first = await client(base).get('/', { headers: {} })
      const r = mode === 'none' ? [reply(`${base}/`, '', 200, { 'set-cookie': 'PHPSESSID=abc123abc; Path=/' })] : [first]
      const f = await adoptsSessionId(client(base), r)
      expect(f).toHaveLength(count)
      if (count) expect(f[0].proof?.shows.join()).toContain('no sign-in was attempted')
    }
  })
})
