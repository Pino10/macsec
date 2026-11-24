/** WAF honeypots: tell the noise from a finding, and never report the noise as a problem. */
import { describe, expect, it } from 'vitest'
import { assessPortDeception, assessWebDeception, deceptionFinding, sameStructure, structureOf, WAF_DECEPTION_NOTE } from '../src/main/wafdeception'

const page = (body: string): string => `<!doctype html><html><head><title>Shop</title><script>var a=${Math.random()}</script></head><body><h1>Shop</h1>${body}<p>Welcome to our shop. Browse the products, read our story and contact us any time.</p></body></html>`
const sample = (path: string, status: number, body: string, ms = 80): { url: string; status: number; length: number; body: string; ms: number } => ({ url: `http://shop.example.test${path}`, status, length: body.length, body, ms })

describe('structure, not size', () => {
  it('ignores scripts, numbers and whitespace when it compares two pages', () => {
    const a = structureOf('<div>Order 12345 at 12:01</div><script>x=1</script>')
    const b = structureOf('<div>Order 99999 at 23:59</div><script>y=2</script>')
    expect(a).toBe(b)
    expect(a).not.toContain('12345')
  })

  it('calls a padded copy the same page, and a different page different', () => {
    const base = structureOf(page('<p>Product list</p>'))
    const padded = structureOf(page('<p>Product list</p>' + ' '.repeat(120)))
    const other = structureOf('<html><body><h2>Admin console</h2><table><tr><td>users</td></tr></table><form action="/x"><input name="q"></form></body></html>')
    expect(sameStructure(base, padded)).toBe(true)
    expect(sameStructure(base, other)).toBe(false)
  })
})

describe('dynamic path spoofing', () => {
  it('flags a site that answers every made-up path with the same page', () => {
    const random = Array.from({ length: 6 }, (_, i) => sample(`/msq${i}`, 200, page(`<p>Result ${i}</p>`)))
    const v = assessWebDeception({ home: sample('/', 200, page('<p>Home</p>')), random, vendors: [] })
    expect(v.deceptive).toBe(true)
    expect(v.sameStructure).toBe(true)
    expect(v.confidence).toBe('strong')
    expect(v.reasons.join(' ')).toMatch(/cannot exist/)
    expect(v.advice).toMatch(/not .*findings|Do not send/)
  })

  it('says an honest site is honest', () => {
    const random = Array.from({ length: 6 }, () => sample('/nope', 404, 'Not found'))
    const v = assessWebDeception({ home: sample('/', 200, page('<p>Home</p>')), random, vendors: [] })
    expect(v.deceptive).toBe(false)
    expect(v.advice).toMatch(/answers honestly/)
  })

  it('flags decoy files and a tarpit even when the pages differ', () => {
    const random = Array.from({ length: 6 }, (_, i) => sample(`/x${i}`, 200, `<html><body>different ${'z'.repeat(i * 30)} page ${i}</body></html>`, 4000))
    const v = assessWebDeception({ home: sample('/', 200, page('<p>Home</p>')), random, decoyHits: 6, vendors: ['Cloudflare'] })
    expect(v.deceptive).toBe(true)
    expect(v.reasons.join(' ')).toMatch(/sensitive file names/)
    expect(v.reasons.join(' ')).toMatch(/tarpit|slow/)
    expect(v.vendor).toBe('Cloudflare')
  })
})

describe('port mimics', () => {
  it('flags a great many open ports, and a crowd with the same banner', () => {
    const all = Array.from({ length: 30 }, (_, i) => ({ port: 1000 + i }))
    expect(assessPortDeception(all, 100).spoofed).toBe(true)
    const same = Array.from({ length: 9 }, (_, i) => ({ port: 8000 + i, service: 'http' }))
    const v = assessPortDeception(same, 1000)
    expect(v.spoofed).toBe(true)
    expect(v.mimic).toBe(true)
    expect(v.reason).toMatch(/port mimic|same way/)
    expect(assessPortDeception([{ port: 80, service: 'http' }, { port: 443, service: 'https' }], 100).spoofed).toBe(false)
  })

  it('writes one note that says it is defence, not a finding', () => {
    const f = deceptionFinding('https://shop.example.test', { deceptive: true, confidence: 'strong', reasons: ['6 of 6 paths answered.'], vendor: 'Imperva (Incapsula)', sameStructure: true, everyPathAnswers: true, tarpit: false, advice: 'Treat this as deception.' }, 'web')
    expect(f.severity).toBe('info')
    expect(f.title).toMatch(/honeypot|decoy/)
    expect(f.description).toMatch(/Imperva/)
    expect(f.description).toMatch(/defend|not .*findings|deception/i)
    expect(WAF_DECEPTION_NOTE).toMatch(/deception rather than findings/)
  })
})
