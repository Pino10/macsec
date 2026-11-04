import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { endpointsIn, exposureReal, interestingUrls, normalizeTarget, paramsOf, parseCrtSh, parseSourceMap, parseSubfinder, parseWayback, secretsIn, sourceMapUrl, subdomainFindings, takeoverService, techOf } from '../src/main/seckit/recon'
import { anthropicBase, localModelEnv, reviewerRun } from '../src/main/seckit/reviewers'
import { SKILLS, skillText, writePlugin } from '../src/main/seckit/skills'
import { mkdtempSync, existsSync } from 'fs'
import { tmpdir } from 'os'

const fx = (n: string): string => readFileSync(join(__dirname, 'fixtures', n), 'utf8')

describe('recon: passive sources', () => {
  it('reads crt.sh, keeping names in scope only', () => {
    expect(parseCrtSh(fx('crtsh.json'), 'example.com')).toEqual(['example.com', 'shop.example.com', 'staging-api.example.com', 'www.shop.example.com'])
  })
  it('reads the Wayback Machine, with parameters and interesting files', () => {
    const urls = parseWayback(fx('wayback.json'), 'example.com')
    expect(urls).toHaveLength(6)
    expect(urls).toContain('http://example.com/')
    expect(paramsOf(urls)).toEqual(['next', 'lang', 'q', 'page', 'id'])
    expect(interestingUrls(urls)).toEqual(['https://example.com/backup/site.zip'])
  })
  it('reads subfinder JSON lines and plain lines', () => {
    expect(parseSubfinder('{"host":"a.example.com","input":"example.com","source":"crtsh"}\nb.example.com\nother.org\n', 'example.com')).toEqual(['a.example.com', 'b.example.com'])
  })
  it('understands what was typed', () => {
    expect(normalizeTarget('https://www.Shop.example.com/path?x=1')).toEqual({ domain: 'shop.example.com', url: 'https://www.shop.example.com/path?x=1' })
    expect(normalizeTarget('myapp.test').domain).toBe('myapp.test')
    expect(() => normalizeTarget('-oX /tmp/x')).toThrow()
  })
})

describe('recon: hosts', () => {
  it('names takeover-prone services', () => {
    expect(takeoverService('shop-old.azurewebsites.net')).toBe('Azure App Service')
    expect(takeoverService('acme.github.io')).toBe('GitHub Pages')
    expect(takeoverService('example.com')).toBeNull()
  })
  it('flags staging and admin hosts that resolve', () => {
    const f = subdomainFindings([
      { host: 'staging.example.com', ips: ['1.2.3.4'], sources: [], live: { url: 'https://staging.example.com/', status: 200, title: 'Login', tech: [] } },
      { host: 'jenkins.example.com', ips: ['1.2.3.5'], sources: [] },
      { host: 'www.example.com', ips: ['1.2.3.6'], sources: [] },
      { host: 'dev.example.com', ips: [], sources: [] }
    ])
    expect(f.map((x) => [x.severity, x.title])).toEqual([
      ['low', 'staging.example.com looks like a non-production system'],
      ['info', 'jenkins.example.com looks like a tool or admin system']
    ])
  })
  it('recognises technologies', () => {
    const h = new Headers({ server: 'nginx/1.27', 'x-powered-by': 'PHP/8.4', 'set-cookie': 'laravel_session=x' })
    expect(techOf(h, '<script src="/_next/static/chunks/a.js"></script>')).toEqual(expect.arrayContaining(['nginx/1.27', 'PHP/8.4', 'Next.js', 'Laravel']))
  })
})

describe('recon: JavaScript', () => {
  it('reads a real indexed source map from the Next.js dev server', () => {
    const m = parseSourceMap(fx('next-dev.js.map'))!
    expect(m.files).toBeGreaterThan(10)
    expect(m.sample.some((s) => s.includes('next-devtools/dev-overlay'))).toBe(true)
    expect(m.hasContent).toBe(true)
  })
  it('finds where a source map is', () => {
    expect(sourceMapUrl('var a=1;\n//# sourceMappingURL=app.js.map', 'https://x.example.com/static/app.js')).toBe('https://x.example.com/static/app.js.map')
    expect(sourceMapUrl('x', 'https://x.example.com/a.js', '/maps/a.map')).toBe('https://x.example.com/maps/a.map')
    expect(sourceMapUrl('//# sourceMappingURL=data:application/json;base64,e30=', 'https://x.example.com/a.js')).toBeNull()
  })
  it('lists endpoints the front end calls', () => {
    const js = `fetch("/api/v2/orders/"+id);axios.get('/internal/admin/users');const u="https://api.example.com/v1/me";const img="/uploads/a.png";x("/graphql")`
    expect(endpointsIn(js)).toEqual(['/api/v2/orders/', '/graphql', '/internal/admin/users', 'https://api.example.com/v1/me'])
  })
  it('finds keys and masks them, with public keys at info', () => {
    const anon = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${Buffer.from('{"iss":"supabase-demo","role":"anon"}').toString('base64url')}.abcdefghijklmnop`
    const s = secretsIn(`const k="sk_live_${'a'.repeat(24)}";const g="AKIAIOSFODNN7EXAMPLE";const s="${anon}"`)
    expect(s.map((x) => [x.kind, x.masked, x.severity])).toEqual([
      ['AWS access key id', 'AKIA••••••••', 'high'],
      ['Stripe secret key', 'sk_l••••••••', 'critical'],
      ['Supabase anon key (public by design)', 'eyJh••••••••', 'info']
    ])
  })
})

describe('recon: exposed files', () => {
  it('counts only the real file, never a soft 404', () => {
    expect(exposureReal('.git/HEAD', 200, 'ref: refs/heads/main\n', null)).toBe(true)
    expect(exposureReal('.env', 200, '<html><title>Not found</title>', null)).toBe(false)
    expect(exposureReal('.env', 200, 'APP_KEY=base64:x\nDB_PASSWORD=y', { status: 200, length: 2000 })).toBe(true)
    expect(exposureReal('.env', 200, 'x'.repeat(1990), { status: 200, length: 2000 })).toBe(false)
  })
})

describe('reviewers', () => {
  it('points Claude Code at LM Studio', () => {
    expect(anthropicBase('http://localhost:1234/v1/')).toBe('http://127.0.0.1:1234')
    const env = localModelEnv({ baseUrl: 'http://127.0.0.1:1234/v1', model: 'qwen/qwen3-coder-30b' })
    expect(env).toMatchObject({ ANTHROPIC_BASE_URL: 'http://127.0.0.1:1234', ANTHROPIC_AUTH_TOKEN: 'lmstudio', ANTHROPIC_MODEL: 'qwen/qwen3-coder-30b', CLAUDE_CODE_ATTRIBUTION_HEADER: '0' })
    const run = reviewerRun('claude-local', '/bin/claude', 'Review', { plugins: ['/p'], local: { baseUrl: 'http://127.0.0.1:1234/v1', model: 'qwen/qwen3-coder-30b' }, name: 'Laramac review: shop' })
    expect(run.args).toEqual(expect.arrayContaining(['--permission-mode', 'plan', '--plugin-dir', '/p', '--model', 'qwen/qwen3-coder-30b', '--session-id', run.session!]))
    expect(run.args[run.args.indexOf('--allowedTools') + 1]).toBe('Read,Grep,Glob,Skill')
  })
  it('keeps every other reviewer read-only', () => {
    expect(reviewerRun('codex', 'codex', 'p').args.slice(0, 3)).toEqual(['exec', '--sandbox', 'read-only'])
    expect(reviewerRun('gemini', 'gemini', 'p').args).toEqual(expect.arrayContaining(['--approval-mode', 'plan']))
    expect(reviewerRun('coderabbit', 'coderabbit', 'p', { cwd: '/x' }).args).toEqual(['review', '--plain', '--no-color', '--type', 'all', '--cwd', '/x'])
  })
})

describe('skills', () => {
  it('writes a valid plugin with every skill, recon included', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ms-plugin-'))
    writePlugin(dir, 'macsec-security', 'x')
    for (const n of ['security-code-review', 'recon-methodology', 'js-recon', 'attack-surface-report', 'local-model-review']) {
      expect(existsSync(join(dir, 'skills', n, 'SKILL.md'))).toBe(true)
      expect(readFileSync(join(dir, 'skills', n, 'SKILL.md'), 'utf8')).toMatch(new RegExp(`^---\\nname: ${n}\\ndescription: .+\\n---\\n`))
    }
    expect(JSON.parse(readFileSync(join(dir, '.claude-plugin', 'plugin.json'), 'utf8')).name).toBe('macsec-security')
    expect(skillText(['js-recon'])).toContain('Source maps')
    expect(Object.keys(SKILLS)).toHaveLength(29)
  })
})

describe('MacSec recon sessions', () => {
  it('turns recon findings into MacSec findings', async () => {
    const { toFinding } = await import('../src/main/reconscan')
    expect(toFinding({ id: '1', kind: 'sourcemap', severity: 'medium', title: 'Source map public' })).toMatchObject({ category: 'web', tool: 'Source map check', severity: 'medium' })
    expect(toFinding({ id: '2', kind: 'secret', severity: 'critical', title: 'k' }).category).toBe('secret')
    expect(toFinding({ id: '3', kind: 'takeover', severity: 'high', title: 't' }).category).toBe('network')
  })
})
