/** 1.24: Burp XML import, PHP taint parsers, and the independent verifier's answer format. */
import { describe, expect, it } from 'vitest'
import { parseSpec } from '../src/main/apispec'
import { parsePhpstan, parsePsalm } from '../src/main/scanners/parse'
import { parseOpinion, secondOpinionPrompt } from '../src/main/secondopinion'
import type { Finding } from '../src/shared/types'

const b64 = (s: string): string => Buffer.from(s, 'utf8').toString('base64')

const burp = `<?xml version="1.0"?>
<items>
  <item>
    <url>https://shop.test/orders</url>
    <request base64="true">${b64('GET /orders?page=2 HTTP/1.1\r\nHost: shop.test\r\nCookie: session=abc\r\n\r\n')}</request>
  </item>
  <item>
    <request>POST /login HTTP/1.1
Host: shop.test
Authorization: Bearer xyz

username=a</request>
  </item>
</items>`

describe('the Burp import', () => {
  it('reads requests, keeps the sign-in as a fact, and never keeps the token', () => {
    const spec = parseSpec(burp, 'burp.xml')
    expect(spec.format).toBe('burp')
    expect(spec.endpoints.map((e) => `${e.method} ${e.path}`).sort()).toEqual(['GET /orders', 'POST /login'])
    expect(spec.endpoints.every((e) => e.secured === true)).toBe(true)
    expect(spec.saved).toEqual([])
    expect(JSON.stringify(spec)).not.toContain('abc')
    expect(JSON.stringify(spec)).not.toContain('xyz')
  })
  it('refuses an export with no usable request', () => {
    expect(() => parseSpec('<items><item><url>https://x</url></item></items>', 'x.xml')).toThrow(/no requests/)
  })
})

describe('the PHP analysers', () => {
  it('keeps PHPStan to security messages', () => {
    const text = JSON.stringify({
      files: {
        '/p/app/Search.php': {
          messages: [
            { message: 'Query built with a variable: possible SQL injection.', line: 12, identifier: 'macsec.sql' },
            { message: 'Variable $x might not be defined.', line: 20 }
          ]
        }
      }
    })
    const found = parsePhpstan(text, '/p')
    expect(found).toHaveLength(1)
    expect(found[0]).toMatchObject({ tool: 'PHPStan', file: 'app/Search.php', line: 12 })
  })
  it('reads Psalm taint issues as high when they reach a sink', () => {
    const text = JSON.stringify({
      issues: [
        { type: 'TaintedSql', file_name: '/p/app/Repo.php', line_from: 9, message: 'Detected tainted SQL' },
        { type: 'TaintedHtml', file_name: '/p/app/View.php', line_from: 4, message: 'Detected tainted HTML' }
      ]
    })
    const found = parsePsalm(text, '/p')
    expect(found.map((f) => f.severity)).toEqual(['high', 'medium'])
    expect(found[0].snippet).toContain('TaintedSql')
  })
})

describe('the second opinion', () => {
  const f: Finding = { id: 'x', tool: 'Semgrep', category: 'code', severity: 'high', title: 'SQL injection in search', file: 'app/Search.php', line: 12, description: 'User input reaches the query.' }
  it('asks the verifier to disprove, with the excerpt and a fixed answer', () => {
    const p = secondOpinionPrompt(f, '12: $q = $_GET["q"];')
    expect(p).toContain('DISPROVE')
    expect(p).toContain('VERDICT: seconded or refuted or uncertain')
    expect(p).toContain('app/Search.php:12')
  })
  it('parses the two lines and refuses anything else', () => {
    expect(parseOpinion('VERDICT: refuted\nREASON: The value is escaped with a constant.')).toEqual({ verdict: 'refuted', reason: 'The value is escaped with a constant.' })
    expect(() => parseOpinion('Looks fine to me.')).toThrow(/did not give a verdict/)
  })
})
