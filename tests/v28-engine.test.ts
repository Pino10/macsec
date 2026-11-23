import { describe, expect, it } from 'vitest'
import { NetGuard, classify, isRestricted } from '../src/main/netguard'
import { correlate } from '../src/main/correlate'
import { asvsOf, verificationOf } from '../src/shared/verification'
import { score } from '../src/main/benchmark'
import { scanCode } from '../src/main/mobilestatic'
import { ConfirmClient } from '../src/main/confirmtests'
import type { Finding } from '../src/shared/types'

const f = (o: Partial<Finding>): Finding =>
  ({ id: o.title ?? 'x', tool: 'a', category: 'code', severity: 'medium', title: 'T', description: '', ...o }) as Finding

describe('netguard', () => {
  it('classifies addresses', () => {
    expect(classify('8.8.8.8')).toBe('public')
    expect(isRestricted(classify('127.0.0.1'))).toBe(true)
    expect(isRestricted(classify('10.1.2.3'))).toBe(true)
    expect(isRestricted(classify('169.254.169.254'))).toBe(true)
  })
  it('refuses cloud metadata addresses', async () => {
    const g = new NetGuard(async () => ['169.254.169.254'])
    await expect(g.check('evil.example')).rejects.toThrow()
  })
  it('refuses a name that mixes public and private answers', async () => {
    const g = new NetGuard(async () => ['8.8.8.8', '10.0.0.5'])
    await expect(g.check('mixed.example')).rejects.toThrow()
  })
  it('refuses a name that moves from public to private (rebinding)', async () => {
    let now = 0
    let ans = ['8.8.8.8']
    const g = new NetGuard(async () => ans, 10_000, () => now)
    await g.check('site.example')
    ans = ['127.0.0.1']
    now = 60_000
    await expect(g.check('site.example')).rejects.toThrow()
  })
  it('does not guard a client with an injected fetch', () => {
    expect(() => new ConfirmClient('https://x.example', { fetchImpl: (async () => new Response('')) as never })).not.toThrow()
  })
})

describe('verification', () => {
  it('names the state', () => {
    expect(verificationOf(f({ confidence: 'confirmed', proof: { request: 'GET /' } as never }))).toBe('confirmed')
    expect(verificationOf(f({ verdict: 'false-positive' }))).toBe('ruled-out')
    expect(verificationOf(f({ alsoFoundBy: ['b'] }))).toBe('likely')
    expect(verificationOf(f({ severity: 'info' }))).toBe('unverified')
    expect(verificationOf(f({ confidence: 'confirmed' }))).not.toBe('confirmed')
  })
  it('maps CWE to an ASVS chapter and stays quiet when unsure', () => {
    expect(asvsOf('CWE-89')).toMatch(/^V5/)
    expect(asvsOf(798)).toMatch(/^V2/)
    expect(asvsOf('CWE-99999')).toBeNull()
    expect(asvsOf(undefined)).toBeNull()
  })
})

describe('correlate', () => {
  const a = f({ tool: 'semgrep', title: 'SQL injection', cwe: 'CWE-89', file: 'a.js', line: 4 })
  const b = f({ tool: 'opengrep', title: 'SQL injection', cwe: 'CWE-89', file: 'a.js', line: 4, id: 'y' })
  it('merges the same problem at the same place from two tools', () => {
    const out = correlate([a, b])
    expect(out).toHaveLength(1)
    expect(out[0].alsoFoundBy?.length).toBe(1)
  })
  it('keeps different places and same-tool findings apart', () => {
    expect(correlate([a, { ...b, line: 9 }])).toHaveLength(2)
    expect(correlate([a, { ...b, tool: 'semgrep' }])).toHaveLength(2)
  })
  it('never merges two findings that both carry proof', () => {
    const p = { request: 'GET /' } as never
    expect(correlate([{ ...a, proof: p }, { ...b, proof: p }])).toHaveLength(2)
  })
  it('keeps findings with no place', () => {
    expect(correlate([f({ tool: 'x', title: 'Z' }), f({ tool: 'y', title: 'Z', id: 'q' })])).toHaveLength(2)
  })
  it('is safe to run twice', () => {
    const once = correlate([a, b])
    expect(correlate(once)[0].alsoFoundBy).toEqual(once[0].alsoFoundBy)
  })
})

describe('benchmark score', () => {
  it('counts hits, misses and extras', () => {
    const s = score([{ name: 'a', title: /alpha/ }, { name: 'b', title: /beta/ }], [f({ title: 'alpha bug' }), f({ title: 'gamma' }), f({ title: 'note', severity: 'info' })])
    expect([s.tp, s.fp, s.fn]).toEqual([1, 1, 1])
    expect(s.precision).toBe(0.5)
    expect(s.missed).toEqual(['b'])
  })
  it('scores the mobile code check on a bad and a good sample', () => {
    const bad = scanCode('setJavaScriptEnabled addJavascriptInterface http://api.shop.example/v1 TrustAllCerts', 'android')
    const good = scanCode('https://api.shop.example/v1 CertificatePinner root detection', 'android')
    const badScore = score([{ name: 'plain http', title: /Plain http/ }], bad.findings)
    expect(badScore.recall).toBe(1)
    expect(score([], good.findings.filter((x) => /Plain http/.test(x.title))).fp).toBe(0)
  })
})
