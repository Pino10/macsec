import { execFileSync } from 'child_process'
import { mkdtempSync, readFileSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { parse as parseYaml } from 'yaml'
import { leakKit, GITLEAKS, CHECKOUT } from '../src/main/leakkit'
import { testsOf, sessionOwasp } from '../src/main/owaspmap'
import { parseGitleaks, parseSemgrep, parseZap } from '../src/main/scanners/parse'
import { cookiesOf, formsOf, pageInfo } from '../src/main/seckit/recon'
import { OWASP_TOP10, owaspCategory, owaspChecklist, owaspMarkdown } from '../src/main/seckit/owasp'
import type { SessionDetail } from '../src/shared/types'

const fx = (f: string): string => readFileSync(join(__dirname, 'fixtures', f), 'utf8')
/** Real response headers saved with curl -D (values of cookies and tokens replaced). */
const headersOf = (f: string): Headers => {
  const h = new Headers()
  const blocks = fx(f).split(/\r?\n\r?\n/).filter((b) => /^HTTP\/[\d.]+ \d+/.test(b.trim()) && !/Connection Established/.test(b))
  for (const line of blocks[blocks.length - 1].split(/\r?\n/).slice(1)) {
    const i = line.indexOf(':')
    if (i > 0) h.append(line.slice(0, i).trim(), line.slice(i + 1).trim())
  }
  return h
}

describe('OWASP Top 10 (2025)', () => {
  it('has the ten categories of 2025, in order', () => {
    expect(OWASP_TOP10.map((c) => `${c.id} ${c.name}`)).toEqual([
      'A01 Broken Access Control',
      'A02 Security Misconfiguration',
      'A03 Software Supply Chain Failures',
      'A04 Cryptographic Failures',
      'A05 Injection',
      'A06 Insecure Design',
      'A07 Authentication Failures',
      'A08 Software or Data Integrity Failures',
      'A09 Security Logging and Alerting Failures',
      'A10 Mishandling of Exceptional Conditions'
    ])
  })
  it('sorts real Semgrep findings by their CWE', () => {
    const f = parseSemgrep(fx('v11/semgrep.json'), '/tmp/demo')
    expect(f.length).toBeGreaterThan(0)
    expect(f.map((x) => owaspCategory({ title: x.title, cwe: x.cwe ? [x.cwe] : [], text: x.description }))).toEqual(f.map(() => 'A05'))
  })
  it('sorts real ZAP and Gitleaks findings', () => {
    const zap = parseZap(fx('zap.json'))
    expect(zap.length).toBeGreaterThan(0)
    for (const z of zap) expect(owaspCategory({ title: z.title, cwe: z.cwe ? [z.cwe] : [], text: z.description })).not.toBeNull()
    const leaks = parseGitleaks(fx('v11/gitleaks.json'), '/tmp/gl/repo')
    expect(leaks).toHaveLength(1)
    expect(owaspCategory({ title: leaks[0].title, cwe: [798] })).toBe('A07')
  })
  it('uses the words when there is no CWE, and the reviewer’s own category first', () => {
    const c = (title: string, text?: string): string | null => owaspCategory({ title, text })
    expect(c('Missing CSRF token on the transfer form')).toBe('A01')
    expect(c('Raw SQL built from the request in OrderController')).toBe('A05')
    expect(c('Passwords hashed with md5')).toBe('A04')
    expect(c('Login has no rate limit')).toBe('A07')
    expect(c('APP_DEBUG is true in production')).toBe('A02')
    expect(c('Stack trace shown on error pages')).toBe('A10')
    expect(c('unserialize() on a cookie')).toBe('A08')
    expect(c('CVE-2024-4577 in PHP 8.1.2')).toBe('A03')
    expect(c('Failed logins are not logged')).toBe('A09')
    expect(c('Sensitive data written to the logs')).toBe('A09')
    expect(c('Something odd', 'A06 Insecure Design, CWE-840')).toBe('A06')
    expect(c('A broken thing', 'OWASP: A01 Broken Access Control, CWE-639')).toBe('A01')
    expect(c('The page is slow')).toBeNull()
  })
  it('marks what was checked, what had problems and what no test covered', () => {
    const list = owaspChecklist(
      [
        { title: 'SQL injection in search', severity: 'high', cwe: ['CWE-89'] },
        { title: 'Reflected XSS', severity: 'medium', cwe: [79] },
        { title: 'Server version shown', severity: 'info' }
      ],
      ['web-scan']
    )
    const by = Object.fromEntries(list.items.map((i) => [i.id, i]))
    expect(by.A05).toMatchObject({ status: 'issues', count: 2, worst: 'high', examples: ['SQL injection in search', 'Reflected XSS'] })
    expect(by.A02.status).toBe('checked') // info only: listed, not red
    expect(by.A06.status).toBe('not-checked')
    expect(by.A09.status).toBe('not-checked')
    expect(list.covered).toBe(7)
    expect(owaspMarkdown(list)).toContain('| A05 | Injection | 2 to fix (worst: high) |')
  })
  it('works out what a session could see from its steps', () => {
    const s = (kind: SessionDetail['kind'], ids: string[], reviewer = 'none'): Pick<SessionDetail, 'kind' | 'reviewer' | 'steps'> => ({ kind, reviewer: reviewer as never, steps: ids.map((id) => ({ id, label: id, status: 'done' })) as never })
    expect(testsOf(s('code-review', ['semgrep', 'gitleaks', 'osv-scanner']))).toEqual(['sast', 'secrets', 'dependencies'])
    expect(testsOf(s('code-review', ['semgrep', 'ai'], 'claude'))).toContain('code-review')
    expect(testsOf(s('web-scan', ['headers', 'nuclei', 'ai'], 'claude'))).toEqual(['headers', 'web-scan'])
    const d = { ...s('code-review', ['gitleaks']), findings: [{ title: 'AWS key', severity: 'high', category: 'secret', tool: 'gitleaks', verdict: 'confirmed' }, { title: 'x', severity: 'high', category: 'code', tool: 'semgrep', verdict: 'false-positive', cwe: 89 }] } as unknown as SessionDetail
    const o = sessionOwasp(d)
    expect(o.items.find((i) => i.id === 'A07')).toMatchObject({ status: 'issues', count: 1 })
    expect(o.items.find((i) => i.id === 'A05')!.status).toBe('not-checked')
  })
})

describe('Stop leaking keys', () => {
  const kit = leakKit('/Users/me/MacSec/tools/bin')
  it('writes a hook that is valid shell and uses MacSec’s Gitleaks as a fallback', () => {
    const dir = mkdtempSync(join(tmpdir(), 'kit-'))
    writeFileSync(join(dir, 'pre-commit'), kit.hook)
    execFileSync('sh', ['-n', join(dir, 'pre-commit')])
    expect(kit.hook).toContain("'/Users/me/MacSec/tools/bin/gitleaks'")
    expect(kit.hook).toContain('git --pre-commit --staged --redact')
  })
  it('the hook blocks a commit with a key, with the real Gitleaks', () => {
    const bin = '/tmp/gl/gitleaks'
    let have = false
    try {
      execFileSync(bin, ['version'])
      have = true
    } catch {
      /* not downloaded here */
    }
    if (!have) return
    const repo = mkdtempSync(join(tmpdir(), 'leak-'))
    const git = (...a: string[]): string => execFileSync('git', ['-C', repo, '-c', 'user.email=a@b', '-c', 'user.name=a', '-c', 'commit.gpgsign=false', ...a], { encoding: 'utf8' })
    git('init', '-q')
    writeFileSync(join(repo, 'pre-commit'), kit.hook.replaceAll("/Users/me/MacSec/tools/bin/gitleaks", bin), { mode: 0o755 })
    execFileSync('cp', [join(repo, 'pre-commit'), join(repo, '.git', 'hooks', 'pre-commit')])
    writeFileSync(join(repo, 'ok.txt'), 'hello\n')
    git('add', 'ok.txt')
    git('commit', '-qm', 'fine')
    writeFileSync(join(repo, 'config.env'), 'aws_access_key_id=AKIAIOSFODNN7ABCDEFG\n')
    git('add', 'config.env')
    expect(() => execFileSync('git', ['-C', repo, '-c', 'user.email=a@b', '-c', 'user.name=a', '-c', 'commit.gpgsign=false', 'commit', '-qm', 'leak'], { env: { ...process.env, PATH: '/usr/bin:/bin' }, stdio: 'pipe' })).toThrow()
  })
  it('the Action is valid YAML, read-only, pinned and checks the download', () => {
    const y = parseYaml(kit.action) as { permissions: Record<string, string>; jobs: { gitleaks: { steps: { uses?: string; run?: string; with?: Record<string, unknown> }[] } } }
    expect(y.permissions).toEqual({ contents: 'read' })
    const steps = y.jobs.gitleaks.steps
    expect(steps[0].uses).toBe(`actions/checkout@${CHECKOUT.sha}`)
    expect(steps[0].with).toMatchObject({ 'fetch-depth': 0, 'persist-credentials': false })
    expect(steps[1].run).toContain(`${GITLEAKS.linuxX64Sha256}  gitleaks.tar.gz`)
    expect(steps[1].run).toContain('sha256sum --check --strict')
    expect(parseYaml(kit.preCommit)).toMatchObject({ repos: [{ repo: 'https://github.com/gitleaks/gitleaks', rev: `v${GITLEAKS.version}`, hooks: [{ id: 'gitleaks' }] }] })
  })
})

describe('Recon: pages one by one', () => {
  it('breaks down a real login page (RubyGems): form, CSRF token, cookies and headers', () => {
    const p = pageInfo('https://rubygems.org/sign_in', 200, headersOf('v11/rubygems-signin.headers.txt'), fx('v11/rubygems-signin.html'), 210)
    const login = p.forms.find((f) => f.password)!
    expect(login).toMatchObject({ method: 'post', action: 'https://rubygems.org/session', csrf: true, offsite: false, insecure: false })
    expect(login.inputs.map((i) => i.name)).toEqual(expect.arrayContaining(['authenticity_token', 'session[who]', 'session[password]']))
    expect(p.forms.find((f) => f.action.endsWith('/search'))?.method).toBe('get')
    expect(p.cookies).toEqual([{ name: '_rubygems_session', secure: true, httpOnly: true, sameSite: 'strict' }])
    expect(p.headers.filter((h) => h.present).map((h) => h.name)).toEqual(expect.arrayContaining(['content-security-policy', 'strict-transport-security', 'x-frame-options']))
    expect(p.notes.filter((n) => n.severity !== 'info')).toEqual([])
    expect(JSON.stringify(p)).not.toContain('REDACTED')
  })
  it('notices a login form with no CSRF field (Packagist)', () => {
    const p = pageInfo('https://packagist.org/login/', 200, headersOf('v11/packagist-login.headers.txt'), fx('v11/packagist-login.html'), 180)
    const logins = p.forms.filter((f) => f.password)
    expect(logins.length).toBe(2)
    expect(logins.every((f) => f.action === 'https://packagist.org/login/')).toBe(true)
    expect(p.notes.some((n) => /login form posting to \/login\/ has no CSRF token/.test(n.text))).toBe(logins.some((f) => !f.csrf))
    expect(p.tech).toContain('BunnyCDN-IL1-871')
  })
  it('reads PyPI: a deleted cookie does not count, and the session cookie is safe', () => {
    const h = headersOf('v11/pypi-login.headers.txt')
    expect(cookiesOf(h)).toEqual([{ name: 'session_id', secure: true, httpOnly: true, sameSite: 'lax' }])
    const p = pageInfo('https://pypi.org/account/login/', 200, h, fx('v11/pypi-login.html'), 95)
    expect(p.title).toBeTruthy()
    expect(p.scripts.total).toBeGreaterThan(0)
  })
  it('flags what a weak page does wrong', () => {
    const h = new Headers({ 'content-type': 'text/html' })
    h.append('set-cookie', 'PHPSESSID=abc; path=/')
    const html = '<form method="post" action="http://shop.test/login"><input name="email"><input type="password" name="pw"></form><script src="https://cdn.other.net/a.js"></script><img src="http://shop.test/x.png"><a href="/p?id=1&amp;sort=asc">x</a>'
    const p = pageInfo('https://shop.test/', 200, h, html, 10)
    expect(p.notes.map((n) => n.severity)).toEqual(['high', 'medium', 'medium', 'medium', 'low', 'low', 'low', 'low', 'info'])
    expect(p.params).toEqual(['id', 'sort'])
    expect(p.scripts).toEqual({ total: 1, inline: 0, external: ['cdn.other.net'], withoutSri: 1 })
    expect(formsOf('<form><input name=q></form>', 'https://a.test/x')[0]).toMatchObject({ method: 'get', action: 'https://a.test/x', inputs: [{ name: 'q', type: 'text' }] })
  })
})
