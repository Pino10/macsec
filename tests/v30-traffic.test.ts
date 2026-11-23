import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { analyzeHar } from '../src/main/traffic'
import { captureArgs, lanAddresses, validListen } from '../src/main/trafficcapture'
import { controlsOf } from '../src/main/masvs'

const har = (entries: unknown[]): string => JSON.stringify({ log: { entries } })
const req = (url: string, o: Record<string, unknown> = {}, res: Record<string, unknown> = { status: 200 }): unknown => ({
  request: { method: 'GET', url, headers: [], queryString: [...new URL(url).searchParams].map(([name, value]) => ({ name, value })), ...o },
  response: res
})

describe('traffic check on a real mitmproxy capture', () => {
  const real = readFileSync(join(__dirname, 'fixtures', 'mitmproxy-capture.har'), 'utf8')
  const r = analyzeHar(real)
  it('finds plain http, a token in the address and a header sent in the clear', () => {
    const t = r.findings.map((x) => x.title).join('|')
    expect(t).toMatch(/example\.com unencrypted \(plain http\)/)
    expect(t).toMatch(/A token is sent in the web address to example\.com/)
    expect(t).toMatch(/authorization header is sent unencrypted/)
  })
  it('never copies the secret values anywhere', () => {
    expect(JSON.stringify(r.findings)).not.toMatch(/abc123|xyz/)
  })
  it('keeps a replayable proof with the address cut off at the ?', () => {
    const p = r.findings.find((x) => /plain http/.test(x.title))!.proof!
    expect(p.request).toBe('GET http://example.com/?…')
    expect(r.findings.every((x) => x.severity === 'info' || x.confidence === 'confirmed')).toBe(true)
  })
  it('counts servers', () => {
    expect(r.hosts).toEqual(['example.com'])
    expect(r.requests).toBe(1)
  })
})

describe('traffic check rules', () => {
  it('stays quiet for https, localhost and the mitm.it page', () => {
    const r = analyzeHar(har([req('https://api.shop.example/v1/items?page=2'), req('http://127.0.0.1:8080/x'), req('http://mitm.it/cert/pem')]))
    expect(r.findings.filter((x) => x.severity !== 'info')).toEqual([])
  })
  it('does not treat look-alike names as secrets', () => {
    const r = analyzeHar(har([req('https://a.example/x?tokenizer=1&pinned=2&author=3&passenger=4')]))
    expect(r.findings.filter((x) => x.severity !== 'info')).toEqual([])
  })
  it('a secret in an https address is medium, over http it is high', () => {
    expect(analyzeHar(har([req('https://a.example/x?api_key=SECRETVALUE')])).findings.find((x) => /api_key/.test(x.title))!.severity).toBe('medium')
    expect(analyzeHar(har([req('http://a.example/x?api_key=SECRETVALUE')])).findings.find((x) => /api_key/.test(x.title))!.severity).toBe('high')
  })
  it('finds secrets in plain http form and JSON bodies, by name only', () => {
    const r = analyzeHar(har([
      req('http://a.example/login', { method: 'POST', postData: { mimeType: 'application/x-www-form-urlencoded', params: [{ name: 'password', value: 'hunter2' }, { name: 'user', value: 'bob' }] } }),
      req('http://a.example/pay', { method: 'POST', postData: { mimeType: 'application/json', text: '{"card":{"cvv":"123","number":"4111"}}' } })
    ]))
    const t = r.findings.map((x) => x.title).join('|')
    expect(t).toMatch(/A password is sent unencrypted/)
    expect(t).toMatch(/A cvv is sent unencrypted/)
    expect(JSON.stringify(r.findings)).not.toMatch(/hunter2|4111/)
  })
  it('reports a cookie without Secure on https only', () => {
    const r = analyzeHar(har([req('https://a.example/', {}, { status: 200, cookies: [{ name: 'sid', secure: false }, { name: 'ok', secure: true }] })]))
    expect(r.findings.filter((x) => /cookie/.test(x.title)).map((x) => x.title)).toEqual(['The cookie sid from a.example has no Secure flag'])
  })
  it('says why an empty capture may be empty', () => {
    const r = analyzeHar(har([]))
    expect(r.findings[0].severity).toBe('info')
    expect(r.findings[0].description).toMatch(/pinning/)
  })
  it('refuses a file that is not a HAR', () => {
    expect(() => analyzeHar('hello')).toThrow(/HAR/)
  })
  it('reports each problem once per server, not once per request', () => {
    const many = Array.from({ length: 20 }, () => req('http://a.example/x?token=1'))
    expect(analyzeHar(har(many)).findings.filter((x) => /plain http/.test(x.title))).toHaveLength(1)
  })
  it('plain http findings land in the MASVS network control', () => {
    const f = analyzeHar(har([req('http://a.example/')])).findings.find((x) => /plain http/.test(x.title))!
    expect(controlsOf(f)).toContain('MASVS-NETWORK-1')
  })
})

describe('capture listener', () => {
  it('listens only on this Mac or its own local addresses', () => {
    const lan = ['192.168.1.20']
    expect(validListen('127.0.0.1', lan)).toBe(true)
    expect(validListen('192.168.1.20', lan)).toBe(true)
    for (const bad of ['0.0.0.0', '8.8.8.8', '192.168.1.21', '127.0.0.1; rm -rf /', '::', '', undefined, 5]) expect(validListen(bad, lan)).toBe(false)
  })
  it('ignores public and loopback interface addresses', () => {
    const ifs = { en0: [{ family: 'IPv4', internal: false, address: '192.168.1.20' }, { family: 'IPv4', internal: false, address: '8.8.4.4' }], lo0: [{ family: 'IPv4', internal: true, address: '127.0.0.1' }] }
    expect(lanAddresses(ifs as never)).toEqual(['192.168.1.20'])
  })
  it('keeps the local-only guard on and passes arguments as a list', () => {
    const a = captureArgs('127.0.0.1', 8123, '/x/c.har', '/x/conf')
    expect(a).toContain('block_global=true')
    expect(a.join(' ')).toContain('hardump=/x/c.har')
    expect(a.some((x) => /listen-host/.test(x))).toBe(true)
  })
})
