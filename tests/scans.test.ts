import { createServer, type Server } from 'http'
import { mkdtempSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { parseSpec } from '../src/main/apispec'
import { reviewSpec } from '../src/main/apiscan'
import { checkHeaders, parseHttpx, parseKatana, parseNuclei, pathSeverity } from '../src/main/scanners/web'
import { isLocalTarget, looksReal, NOT_READ_ONLY, parseHeaders } from '../src/main/webscan'
import { newer } from '../src/main/toolbox'
import { ensureDirs, setRoot } from '../src/main/paths'

describe('reading API files', () => {
  it('OpenAPI 3 with sign-in, public endpoints and secrets in the address', () => {
    const spec = parseSpec(
      JSON.stringify({
        openapi: '3.0.1',
        info: { title: 'Shop' },
        servers: [{ url: 'http://api.shop.example/v1' }],
        components: { securitySchemes: { bearer: { type: 'http', scheme: 'bearer' } } },
        security: [{ bearer: [] }],
        paths: {
          '/orders/{id}': { get: { parameters: [{ name: 'id', in: 'path', example: 42 }] }, delete: { security: [] } },
          '/search': { get: { security: [], parameters: [{ name: 'api_key', in: 'query', example: 'x' }] } },
          '/me': { get: { responses: { 200: { content: { 'application/json': { example: { token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk' } } } } } } }
        }
      })
    )
    expect(spec.format).toBe('openapi')
    expect(spec.endpoints.find((e) => e.path === '/orders/{id}' && e.method === 'GET')!.url).toBe('http://api.shop.example/v1/orders/42')
    expect(spec.endpoints.find((e) => e.method === 'DELETE')!.secured).toBe(false)
    const f = reviewSpec(spec).map((x) => x.title)
    expect(f).toContain('DELETE /orders/{id} needs no sign-in')
    expect(f).toContain('The API address uses plain HTTP')
    expect(f.some((t) => t.includes('"api_key"'))).toBe(true)
    expect(f.some((t) => t.startsWith('A real-looking key'))).toBe(true)
  })
  it('Swagger 2 in YAML', () => {
    const spec = parseSpec('swagger: "2.0"\ninfo: {title: Old}\nhost: api.example.com\nbasePath: /v2\nschemes: [https]\npaths:\n  /users:\n    get: {}\n')
    expect(spec.baseUrl).toBe('https://api.example.com/v2')
    expect(spec.endpoints[0].url).toBe('https://api.example.com/v2/users')
    expect(reviewSpec(spec).map((x) => x.title)).toContain('The API describes no way to sign in')
  })
  it('Postman, with folders, variables and a saved token', () => {
    const spec = parseSpec(
      JSON.stringify({
        info: { name: 'Shop API', schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json' },
        variable: [{ key: 'baseUrl', value: 'https://api.shop.example' }],
        auth: { type: 'bearer', bearer: [{ key: 'token', value: 'eyJhbGciOiJIUzI1NiJ9.real.token' }] },
        item: [{ name: 'Orders', item: [{ name: 'Get order', request: { method: 'GET', url: { raw: '{{baseUrl}}/orders/:id' } } }, { name: 'Health', request: { method: 'GET', auth: { type: 'noauth' }, url: '{{baseUrl}}/health' } }] }]
      })
    )
    expect(spec.format).toBe('postman')
    expect(spec.baseUrl).toBe('https://api.shop.example')
    expect(spec.endpoints.map((e) => e.url)).toEqual(['https://api.shop.example/orders/1', 'https://api.shop.example/health'])
    expect(reviewSpec(spec).some((x) => x.title.startsWith('A token is saved in the collection'))).toBe(true)
  })
  it('HAR', () => {
    const spec = parseSpec(JSON.stringify({ log: { entries: [{ request: { method: 'GET', url: 'https://a.example/x?id=1', headers: [{ name: 'Authorization', value: 'b' }] } }, { request: { method: 'GET', url: 'https://a.example/x?id=2' } }] } }))
    expect(spec.endpoints).toHaveLength(1)
    expect(spec.endpoints[0].params[0].name).toBe('id')
  })
})

describe('web checks', () => {
  it('reads Nuclei, httpx and Katana', () => {
    const n = parseNuclei(JSON.stringify({ 'template-id': 'git-config', info: { name: 'Git Config Disclosure', severity: 'medium', classification: { 'cwe-id': ['cwe-200'] }, remediation: 'Block .git' }, 'matched-at': 'https://a.example/.git/config', host: 'https://a.example' }) + '\n{bad\n')
    expect(n[0]).toMatchObject({ severity: 'medium', cwe: 'CWE-200', url: 'https://a.example/.git/config', fix: 'Block .git' })
    expect(parseHttpx(JSON.stringify({ url: 'https://a.example', status_code: 200, webserver: 'nginx/1.25.3', tech: ['Laravel', 'PHP:8.3'] }))[0].tech).toEqual(['Laravel', 'PHP:8.3'])
    const k = parseKatana([{ request: { endpoint: 'https://a.example/x' } }, { request: { endpoint: 'https://cdn.other/y' } }, { request: { endpoint: 'https://a.example/x#top' } }].map((x) => JSON.stringify(x)).join('\n'), 'a.example')
    expect(k).toEqual(['https://a.example/x'])
  })
  it('checks headers and cookies', () => {
    const h = new Headers({ server: 'Apache/2.4.58', 'x-powered-by': 'PHP/8.3.1' })
    const f = checkHeaders('https://a.example', h, ['laravel_session=abc; path=/', 'theme=dark; Secure; HttpOnly; SameSite=Lax'])
    const t = f.map((x) => x.title)
    expect(t).toEqual(expect.arrayContaining(['No Strict-Transport-Security header', 'No Content-Security-Policy', 'Server reveals software versions', 'Cookie "laravel_session" is missing Secure, HttpOnly, SameSite']))
    expect(t.some((x) => x.includes('"theme"'))).toBe(false)
  })
  it('judges exposed files by their content, not just the status', () => {
    expect(looksReal('.git/HEAD', 'ref: refs/heads/main\n', null)).toBe(true)
    expect(looksReal('.git/HEAD', '<html>home page</html>', null)).toBe(false)
    expect(looksReal('.env', 'APP_KEY=base64:x\nDB_PASSWORD=y', null)).toBe(true)
    expect(looksReal('admin', '<html>x</html>', { status: 200, length: 15, body: '' })).toBe(false)
    expect(pathSeverity('.env', 200)).toBe('critical')
    expect(pathSeverity('phpinfo.php', 200)).toBe('high')
    expect(pathSeverity('admin', 403)).toBe('info')
  })
  it('keeps every intrusive Nuclei tag out', () => {
    for (const t of ['dos', 'fuzz', 'intrusive', 'brute-force', 'dast', 'sqli', 'rce', 'default-login']) expect(NOT_READ_ONLY.split(',')).toContain(t)
  })
  it('knows what is on this Mac', () => {
    expect(isLocalTarget('http://shop.test')).toBe(true)
    expect(isLocalTarget('http://127.0.0.1:8000')).toBe(true)
    expect(isLocalTarget('https://shop.example.com')).toBe(false)
    expect(parseHeaders('Cookie: a=b\nbad line\nAuthorization: Bearer x')).toEqual({ Cookie: 'a=b', Authorization: 'Bearer x' })
  })
  it('compares tool versions', () => {
    expect(newer('3.4.10', '3.4.9')).toBe(true)
    expect(newer('v1.183.0', '1.183.0')).toBe(false)
    expect(newer('0.65.0', '0.66.1')).toBe(false)
  })
})

describe('scans against a real local server', () => {
  let srv: Server
  let base = ''
  beforeAll(async () => {
    setRoot(mkdtempSync(join(tmpdir(), 'ms-scan-')))
    ensureDirs()
    srv = createServer((req, res) => {
      const u = req.url ?? '/'
      if (u === '/.env') return res.writeHead(200, { 'content-type': 'text/plain' }).end('APP_KEY=base64:abc\nDB_PASSWORD=secret\n')
      if (u === '/phpinfo.php') return res.writeHead(200).end('<title>phpinfo()</title>PHP Version 8.3')
      if (u.startsWith('/api/users')) return res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': String(req.headers.origin), 'access-control-allow-credentials': 'true' }).end(JSON.stringify([{ id: 1, email: 'a@b.c', password_hash: '$2y$x' }]))
      if (u.startsWith('/api/crash')) return res.writeHead(500, { 'content-type': 'text/html' }).end('Whoops! SQLSTATE[42S22]: Column not found in /var/www/app.php on line 12')
      res.writeHead(u === '/' ? 200 : 404, { 'content-type': 'text/html', server: 'nginx/1.25.3', 'set-cookie': 'laravel_session=x; path=/' }).end('<html><title>Home</title></html>')
    })
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()))
    base = `http://127.0.0.1:${(srv.address() as { port: number }).port}`
  })
  afterAll(() => srv.close())

  const wait = async (id: string): Promise<import('../src/shared/types').SessionDetail> => {
    const { readSession, sessionDetail } = await import('../src/main/sessions')
    for (let i = 0; i < 300 && readSession(id).status === 'running'; i++) await new Promise((r) => setTimeout(r, 200))
    return sessionDetail(id)
  }

  it('a web scan finds the exposed .env, phpinfo and missing headers', async () => {
    const { startWebScan } = await import('../src/main/webscan')
    const s = startWebScan({ target: { kind: 'url', url: base }, mode: 'quick', authorized: false, reviewer: 'none' })
    const d = await wait(s.id)
    const t = d.findings.map((f) => `${f.severity} ${f.title}`)
    expect(t).toContain('critical Public file: /.env')
    expect(t).toContain('high Public file: /phpinfo.php')
    expect(t.some((x) => x.includes('Content-Security-Policy'))).toBe(true)
    expect(d.steps.find((x) => x.id === 'exposed')!.status).toBe('done')
  }, 120_000)

  it('refuses an outside site without your confirmation', async () => {
    const { startWebScan } = await import('../src/main/webscan')
    expect(() => startWebScan({ target: { kind: 'url', url: 'https://example.com' }, mode: 'quick', authorized: false, reviewer: 'none' })).toThrow(/permission/)
  })

  it('an API review flags open CORS, sensitive fields and leaked errors', async () => {
    const { loadSpec, startApiScan } = await import('../src/main/apiscan')
    const file = join(mkdtempSync(join(tmpdir(), 'ms-spec-')), 'api.json')
    writeFileSync(file, JSON.stringify({ openapi: '3.0.0', info: { title: 'Local API' }, servers: [{ url: base }], paths: { '/api/users': { get: {} }, '/api/crash': { get: {} } } }))
    const spec = loadSpec(file)
    const s = startApiScan({ spec: spec.id, baseUrl: '', auth: { kind: 'bearer', value: 'tok' }, mode: 'quick', authorized: false, reviewer: 'none' })
    const d = await wait(s.id)
    const t = d.findings.map((f) => `${f.severity} ${f.title}`)
    expect(t).toContain('high Any website can read this API’s responses as the signed-in user')
    expect(t).toContain('high GET /api/users returns sensitive fields')
    expect(t).toContain('medium GET /api/crash shows internal error details')
    expect(t).toContain('high The API describes no way to sign in')
  }, 120_000)
})
