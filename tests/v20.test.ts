import { createServer, type Server } from 'http'
import type { AddressInfo } from 'net'
import { mkdtempSync, readFileSync, rmSync, existsSync, readdirSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterAll, describe, expect, it } from 'vitest'
import { accessChecks, ConfirmClient, fuzzContent, fuzzParams, loginChecks, wafControl } from '../src/main/confirmtests'
import { analyzeJs, chunkUrls, crawlJs, recoverSources, safeSourcePath } from '../src/main/jsdeep'
import { devopsChecks, dnsChecks, gitRemote, PROBES, protectionFinding, rootDomain, type Resolver } from '../src/main/webposture'
import { cveFindings, epssFor, liveCves } from '../src/main/cvelive'
import { honest, label, labelExploit } from '../src/main/risk'
import type { Finding } from '../src/shared/types'
import type { Product } from '../src/main/seckit/confirm'

const dir = mkdtempSync(join(tmpdir(), 'macsec-v20-'))
afterAll(() => rmSync(dir, { recursive: true, force: true }))

const serve = (h: Parameters<typeof createServer>[1]): Promise<{ server: Server; url: string }> =>
  new Promise((r) => {
    const server = createServer(h)
    server.listen(0, '127.0.0.1', () => r({ server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` }))
  })
const client = (url: string, cap = 3000): ConfirmClient => new ConfirmClient(url, { cap, delayMs: 0 })
const f = (x: Partial<Finding>): Finding => ({ id: 'x', tool: 'MacSec', category: 'web', severity: 'high', title: 't', ...x })

// ---------------------------------------------------------------- The control confirmations must not claim what they cannot show

describe('control confirmations against sites built to fool them', () => {
  it('a site that answers every path with different random content gets no findings', async () => {
    const s = await serve((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' })
      res.end(`<html><body>${'Welcome '.repeat(20 + Math.floor(Math.random() * 400))}${Math.random()}</body></html>`)
    })
    const out: Finding[] = []
    // Random pages can look alike by chance once in a while, so it is tried many times: not one false report is allowed.
    for (let i = 0; i < 25; i++) {
      out.push(...(await fuzzContent(client(s.url), () => undefined, ['admin', 'backup', 'config', 'old', 'test', 'dev', 'api', 'login', 'console', 'staging'])))
      out.push(...(await fuzzParams(client(s.url), '/', () => undefined, ['debug', 'test', 'admin', 'id'])).findings)
    }
    s.server.close()
    expect(out.filter((x) => x.severity !== 'info')).toEqual([])
  })

  it('a site that refuses everything with 403 reports nothing above info', async () => {
    const s = await serve((_req, res) => {
      res.writeHead(403, { 'Content-Type': 'text/html' })
      res.end('<html><body>Forbidden</body></html>')
    })
    const out = await fuzzContent(client(s.url), () => undefined, ['admin', 'backup', 'config'])
    s.server.close()
    expect(out.filter((x) => x.severity !== 'info')).toEqual([])
  })

  it('a site that sends everyone to the login page shows no private pages', async () => {
    const s = await serve((_req, res) => {
      res.writeHead(302, { Location: '/login' })
      res.end()
    })
    const out = await accessChecks(client(s.url), [`${s.url}/account`, `${s.url}/orders/1`], { headersB: { Cookie: 's=B' } }, () => undefined)
    s.server.close()
    expect(out).toEqual([])
  })

  it('a site that echoes everything back does not produce a high finding, and a firewall is not invented', async () => {
    const s = await serve((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' })
      res.end(`<html><body>You asked for ${req.url}</body></html>`)
    })
    const a = await fuzzParams(client(s.url), '/', () => undefined, ['q', 'debug', 'id'])
    const w = await wafControl(client(s.url), () => undefined)
    s.server.close()
    expect(a.findings.filter((x) => x.severity === 'high' || x.severity === 'critical')).toEqual([])
    expect(w.filter((x) => /bypass/i.test(x.title) && x.confidence === 'confirmed')).toEqual([])
  })

  it('a site with no login form gets no login findings', async () => {
    const s = await serve((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' })
      res.end('<html><body>Hello, nothing to sign in to.</body></html>')
    })
    const out = await loginChecks(client(s.url, 200), {}, () => undefined)
    s.server.close()
    expect(out).toEqual([])
  })

  it('a server that starts failing stops the scan quietly and keeps what it had', async () => {
    let n = 0
    const s = await serve((_req, res) => {
      n++
      res.writeHead(n > 12 ? 503 : 404, { 'Content-Type': 'text/html' })
      res.end('<html><body>nope</body></html>')
    })
    const c = client(s.url)
    const out = await fuzzContent(c, () => undefined, Array.from({ length: 80 }, (_, i) => `word${i}`))
    s.server.close()
    expect(Array.isArray(out)).toBe(true)
    expect(c.stopped).toBeTruthy()
    expect(n).toBeLessThan(40)
  })
})

// ---------------------------------------------------------------- The honesty guard and the exploit labels

describe('what a report may claim', () => {
  it('turns "confirmed" without a proof into "possible"', () => {
    expect(honest(f({ confidence: 'confirmed' })).confidence).toBe('possible')
    const proof = { request: 'GET x', reproduce: 'curl x', status: 200, bytes: 1, sha256: 'a', at: 'now', shows: ['it showed'] }
    expect(honest(f({ confidence: 'confirmed', proof })).confidence).toBe('confirmed')
  })
  it('labels proven, known exploited, likely and not proven, and leaves info and code alone', () => {
    const proof = { request: 'GET x', reproduce: 'curl x', status: 200, bytes: 1, sha256: 'a', at: 'now', shows: ['the file is public'] }
    expect(labelExploit(f({ confidence: 'confirmed', proof }))?.state).toBe('proven')
    expect(labelExploit(f({ confidence: 'possible', cves: { count: 3, kev: 1, topEpss: 0.9, top: [] } }))?.state).toBe('known-exploited')
    expect(labelExploit(f({ confidence: 'possible', cves: { count: 3, kev: 0, topEpss: 0.4, top: [] } }))?.state).toBe('likely')
    expect(labelExploit(f({ confidence: 'possible' }))?.state).toBe('unproven')
    expect(labelExploit(f({ severity: 'info' }))).toBeUndefined()
    expect(labelExploit(f({ category: 'code' }))).toBeUndefined()
    const l = label([f({ confidence: 'confirmed', severity: 'critical' })])[0]
    expect(l.confidence).toBe('possible')
    expect(l.exploit?.state).toBe('unproven')
  })
  it('never calls a matched rule from another scanner proven', () => {
    const e = labelExploit(f({ tool: 'Nuclei' }))
    expect(e?.state).toBe('unproven')
    expect(e?.why).toMatch(/Nuclei/)
  })
})

// ---------------------------------------------------------------- JavaScript analysis

const APP = `
const routes=[{path:"/admin/users",component:A},{path:"/account/billing"}];
const q = 'mutation DeleteUser($id: ID!) { deleteUser(id: $id) }';
fetch("/api/v1/orders/" + id); const base="https://api.example.test/v2/users";
const k = process.env.STRIPE_SECRET; const p = process.env.NEXT_PUBLIC_API_URL;
el.innerHTML = html; eval(code);
window.addEventListener("message", function(e){ run(e.data) });
window.addEventListener("message", function(e){ if(e.origin!=="https://x.test") return; run(e.data) });
const dev = "http://192.168.1.20:8080/api"; const u2 = "stage.corp.internal";
const fb = "https://demo-app-1.firebaseio.com"; // TODO remove admin bypass before launch
`
describe('JavaScript analysis', () => {
  const d = analyzeJs(APP, 'https://x.test/static/js/main.abc.js')
  it('finds routes, GraphQL operations and build variables', () => {
    expect(d.routes).toContain('/admin/users')
    expect(d.graphql).toContain('mutation DeleteUser')
    expect(d.envVars).toEqual(expect.arrayContaining(['STRIPE_SECRET', 'NEXT_PUBLIC_API_URL']))
  })
  it('finds risky functions, unchecked message listeners and internal addresses', () => {
    expect(d.sinks.map((s) => s.kind)).toEqual(expect.arrayContaining(['eval()', 'innerHTML']))
    expect(d.messages).toEqual({ listeners: 2, unchecked: 1 })
    expect(d.internal).toEqual(expect.arrayContaining(['192.168.1.20:8080', 'stage.corp.internal']))
    expect(d.refs.firebase).toEqual(['demo-app-1.firebaseio.com'])
    expect(d.notes.join(' ')).toMatch(/admin bypass/)
  })
  it('does not judge vendor bundles', () => {
    const v = analyzeJs(APP, 'https://x.test/static/js/vendor.abc.js')
    expect(v.sinks).toEqual([])
    expect(v.messages.unchecked).toBe(0)
  })
  it('names the lazy chunks a webpack runtime lists', () => {
    const rt = 'r.u=function(e){return"static/js/"+e+"."+{12:"a1b2c3d4",34:"0f9e8d7c",56:"deadbeef01"}[e]+".chunk.js"}'
    expect(chunkUrls(rt, 'https://x.test/static/js/runtime.js')).toEqual(expect.arrayContaining(['https://x.test/static/js/12.a1b2c3d4.chunk.js', 'https://x.test/static/js/56.deadbeef01.chunk.js']))
    expect(chunkUrls('nothing here', 'https://x.test/a.js')).toEqual([])
  })
})

describe('source maps', () => {
  it('keeps every written file inside the folder and skips libraries', () => {
    expect(safeSourcePath('webpack:///./src/app/admin.js')).toBe('src/app/admin.js')
    expect(safeSourcePath('webpack:///../../../etc/passwd')).toBe('etc/passwd')
    expect(safeSourcePath('webpack:///node_modules/react/index.js')).toBeNull()
    const out = join(dir, 'rec')
    const map = JSON.stringify({ version: 3, sources: ['webpack:///./src/a.js', 'webpack:///../../../../tmp/evil.js', 'webpack:///node_modules/x/y.js'], sourcesContent: ['const k="AKIAABCDEFGHIJKLMNOP"', 'x', 'y'] })
    const r = recoverSources(map, out)
    expect(r.written).toBe(2)
    expect(existsSync(join(out, 'src', 'a.js'))).toBe(true)
    expect(existsSync('/tmp/evil.js')).toBe(false)
    expect(readdirSync(out)).toContain('src')
    expect(r.keys[0]).toMatchObject({ kind: 'AWS access key id', file: 'src/a.js' })
    expect(JSON.stringify(r)).not.toContain('AKIAABCDEFGHIJKLMNOP')
  })
})

describe('reading all of a site’s scripts', () => {
  const files: Record<string, { type?: string; body: string }> = {
    '/static/js/main.js': { body: `${APP}\n//# sourceMappingURL=main.js.map` },
    '/static/js/main.js.map': { type: 'application/json', body: JSON.stringify({ version: 3, sources: ['webpack:///./src/admin.js'], sourcesContent: ['const k="AKIAABCDEFGHIJKLMNOP"'] }) },
    '/static/js/runtime.js': { body: 'r.u=function(e){return"static/js/"+e+"."+{7:"a1b2c3d4",8:"b2c3d4e5",9:"c3d4e5f6"}[e]+".chunk.js"}' },
    '/static/js/7.a1b2c3d4.chunk.js': { body: 'var x = { path: "/hidden/console" }' }
  }
  const fetchImpl = (async (u: string) => {
    const p = new URL(u).pathname
    const hit = files[p]
    if (!hit) return new Response('nf', { status: 404 })
    return new Response(hit.body, { status: 200, headers: { 'content-type': hit.type ?? 'application/javascript' } })
  }) as unknown as typeof fetch
  it('follows chunk lists, finds the map and reports keys in the original source', async () => {
    const r = await crawlJs({ scripts: ['https://x.test/static/js/main.js', 'https://x.test/static/js/runtime.js'], allowed: (u) => new URL(u).host === 'x.test', fetchImpl, delayMs: 0, sourceDir: join(dir, 'crawl') })
    expect(r.scripts.map((s) => s.url)).toContain('https://x.test/static/js/7.a1b2c3d4.chunk.js')
    expect(r.routes).toContain('/hidden/console')
    const titles = r.findings.map((x) => x.title).join('|')
    expect(titles).toMatch(/Source map public/)
    expect(titles).toMatch(/AWS access key id in the original source/)
    expect(titles).toMatch(/front end names/)
    const map = r.findings.find((x) => x.title.startsWith('Source map public'))!
    expect(map.confidence).toBe('confirmed')
    expect(map.proof?.reproduce).toMatch(/curl/)
    const key = r.findings.find((x) => /original source/.test(x.title))!
    expect(key.confidence).toBe('possible')
    expect(JSON.stringify(r.findings)).not.toContain('AKIAABCDEFGHIJKLMNOP')
  })
  it('never reads a script on another site', async () => {
    let other = 0
    const f2 = (async (u: string) => {
      if (new URL(u).host !== 'x.test') other++
      return new Response('x', { status: 200 })
    }) as unknown as typeof fetch
    await crawlJs({ scripts: ['https://evil.test/a.js', 'https://x.test/b.js'], allowed: (u) => new URL(u).host === 'x.test', fetchImpl: f2, delayMs: 0 })
    expect(other).toBe(0)
  })
})

// ---------------------------------------------------------------- Protection, DNS and DevOps

describe('protection and DNS', () => {
  const h = (o: Record<string, string>): Headers => new Headers(o)
  it('names the firewall or says none was recognised, with proof either way', () => {
    const a = protectionFinding('https://x.test', h({ 'cf-ray': '1-AMS', server: 'cloudflare' }), '', 200, '')
    expect(a.title).toMatch(/Cloudflare/)
    expect(a.proof?.shows.join(' ')).toMatch(/cf-ray/)
    const b = protectionFinding('https://x.test', h({ server: 'nginx' }), '', 200, '')
    expect(b.title).toMatch(/No web firewall/)
    expect(b.severity).toBe('info')
  })
  it('finds missing SPF and DMARC, an open SPF, and a dangling CNAME', async () => {
    const none = async (): Promise<never> => {
      throw Object.assign(new Error('x'), { code: 'ENOTFOUND' })
    }
    const r: Resolver = { resolveTxt: async (n) => (n.startsWith('_dmarc') ? [] : [['v=spf1 +all']]), resolveCname: async (n) => (n === 'blog.example.com' ? ['old-app.herokuapp.com'] : none()), resolve4: none, resolveMx: async () => [{ exchange: 'mx.example.com', priority: 10 }], resolveCaa: async () => [] }
    const out = await dnsChecks('blog.example.com', r)
    const t = out.map((x) => x.title).join('|')
    expect(t).toMatch(/points at Heroku/)
    expect(t).toMatch(/allows every sender/)
    expect(t).toMatch(/no DMARC/)
    expect(t).toMatch(/no CAA/)
    expect(out.find((x) => /Heroku/.test(x.title))?.confidence).toBe('possible')
    expect(await dnsChecks('127.0.0.1', r)).toEqual([])
    expect(rootDomain('a.b.example.co.uk')).toBe('example.co.uk')
  })
})

describe('DevOps exposure', () => {
  it('finds a real open Jenkins console and an open Elasticsearch, and nothing on a catch-all', async () => {
    const real = await serve((req, res) => {
      const p = new URL(req.url ?? '/', 'http://x').pathname
      if (p === '/script') {
        res.writeHead(200, { 'Content-Type': 'text/html' })
        return res.end('<html><title>Script Console [Jenkins]</title>Type in an arbitrary Groovy script and execute it on the server</html>')
      }
      if (p === '/') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        return res.end('{"name":"n1","cluster_name":"prod","version":{"number":"7.10.2"},"tagline":"You Know, for Search"}')
      }
      res.writeHead(404)
      res.end('no')
    })
    const r = await devopsChecks(client(real.url), '127.0.0.1')
    real.server.close()
    const t = r.findings.map((x) => x.title).join('|')
    expect(t).toMatch(/Jenkins Script Console/)
    expect(t).toMatch(/Elasticsearch is open/)
    expect(r.findings.every((x) => x.confidence === 'confirmed' && x.proof?.shows.includes('the same answer came twice'))).toBe(true)
    expect(r.products.map((p) => `${p.product.name} ${p.product.version}`)).toContain('Elasticsearch 7.10.2')

    const trap = await serve((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' })
      res.end('<html><body>Jenkins Grafana Kibana Prometheus Script Console Groovy cluster_name tagline etcdserver gitVersion "repositories": [ ' + 'x'.repeat(500) + '</body></html>')
    })
    const none = await devopsChecks(client(trap.url), '127.0.0.1')
    trap.server.close()
    expect(none.findings).toEqual([])
  })
  it('drops a hit that does not repeat', async () => {
    let n = 0
    const s = await serve((req, res) => {
      if (new URL(req.url ?? '/', 'http://x').pathname === '/script') {
        n++
        res.writeHead(200, { 'Content-Type': 'text/html' })
        return res.end(n === 1 ? 'Script Console Groovy' : 'gone')
      }
      res.writeHead(404)
      res.end('no')
    })
    const r = await devopsChecks(client(s.url), 'x', { probes: PROBES.filter((p) => p.path === 'script') })
    s.server.close()
    expect(r.findings).toEqual([])
  })
  it('finds the GitHub repository in a public .git folder, and a token in its address', async () => {
    expect(gitRemote('[remote "origin"]\n\turl = git@github.com:acme/shop.git\n')).toEqual({ host: 'github.com', repo: 'acme/shop', credential: false })
    expect(gitRemote('[remote "origin"]\n\turl = https://deploy:ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/acme/shop.git\n')?.credential).toBe(true)
    const s = await serve((req, res) => {
      if (req.url === '/.git/config') {
        res.writeHead(200, { 'Content-Type': 'text/plain' })
        return res.end('[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://github.com/acme/shop.git\n')
      }
      res.writeHead(404)
      res.end('no')
    })
    const r = await devopsChecks(client(s.url), 'x', { probes: [] })
    s.server.close()
    expect(r.findings[0].title).toMatch(/github\.com\/acme\/shop/)
  })
  it('has probes with real signatures, unique paths and no em dashes', () => {
    const paths = PROBES.map((p) => p.path)
    expect(new Set(paths).size).toBe(paths.length)
    for (const p of PROBES) {
      expect(p.test(200, '<html>hello</html>', new Headers({ 'content-type': 'text/html' })), p.path).toBeNull()
      expect(`${p.title}${p.description}${p.fix}`).not.toContain('—')
    }
  })
})

// ---------------------------------------------------------------- Live counts

const nvd = (id: string, kev: boolean): unknown => ({ cve: { id, ...(kev ? { cisaExploitAdd: '2022-01-01' } : {}), descriptions: [{ lang: 'en', value: 'A flaw.' }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8 } }] }, configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*', versionEndExcluding: '1.20.0' }] }] }] } })
const nginx: Product = { name: 'nginx', version: '1.18.0', cpe: [['f5', 'nginx']], from: 'Server: nginx/1.18.0' }

describe('live vulnerability counts', () => {
  it('counts the flaws whose range covers the version, marks the exploited ones and adds EPSS', async () => {
    const calls: string[] = []
    const fetchImpl = (async (u: string) => {
      calls.push(u)
      if (u.includes('nvd.nist.gov')) return new Response(JSON.stringify({ vulnerabilities: [nvd('CVE-2021-23017', true), nvd('CVE-2020-0001', false)] }), { status: 200 })
      return new Response(JSON.stringify({ data: [{ cve: 'CVE-2021-23017', epss: '0.45', percentile: '0.97' }] }), { status: 200 })
    }) as unknown as typeof fetch
    const live = await liveCves([{ product: nginx, host: 'x.test' }], { fetchImpl, pauseMs: 0 })
    expect(live.results[0].matches.map((m) => m.id)).toEqual(['CVE-2021-23017', 'CVE-2020-0001'])
    const epss = await epssFor(['CVE-2021-23017', 'not-a-cve'], fetchImpl)
    expect(calls.some((c) => c.includes('not-a-cve'))).toBe(false)
    const out = cveFindings(live.results, epss)
    expect(out[0].title).toMatch(/nginx 1\.18\.0 matches 2 known flaws, 1 on CISA/)
    expect(out[0].confidence).toBe('possible')
    expect(out[0].cves?.kev).toBe(1)
    expect(out[0].description).toMatch(/45\.0% chance/)
    expect(label(out)[0].exploit?.state).toBe('known-exploited')
  })
  it('does not match a version outside the range', async () => {
    const fetchImpl = (async () => new Response(JSON.stringify({ vulnerabilities: [nvd('CVE-2021-23017', true)] }), { status: 200 })) as unknown as typeof fetch
    const live = await liveCves([{ product: { ...nginx, version: '1.25.0' }, host: 'x' }], { fetchImpl, pauseMs: 0 })
    expect(live.results).toEqual([])
  })
  it('stops politely when the database asks it to slow down, and when it cannot be reached', async () => {
    const slow = (async () => new Response('', { status: 429 })) as unknown as typeof fetch
    expect((await liveCves([{ product: nginx, host: 'x' }, { product: { ...nginx, name: 'php', version: '7.4.0', cpe: [['php', 'php']] }, host: 'x' }], { fetchImpl: slow, pauseMs: 0 })).note).toMatch(/slow down/)
    const down = (async () => {
      throw new Error('offline')
    }) as unknown as typeof fetch
    expect((await liveCves([{ product: nginx, host: 'x' }], { fetchImpl: down, pauseMs: 0 })).note).toMatch(/could not be reached/)
    expect((await epssFor(['CVE-2021-23017'], down)).size).toBe(0)
  })
})

describe('the new data is clean', () => {
  it('sources contain no em dashes', () => {
    for (const file of ['jsdeep.ts', 'webposture.ts', 'cvelive.ts', 'risk.ts']) expect(readFileSync(join(__dirname, '..', 'src', 'main', file), 'utf8')).not.toContain('—')
  })
})
