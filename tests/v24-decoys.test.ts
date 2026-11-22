import { mkdtempSync, readdirSync, readFileSync, statSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { beforeAll, describe, expect, it } from 'vitest'
import { detectWaf, explainKey, groupDecoyFiles, isChallengePage, isPlaceholderKey, isPublicLibrary, plausibleVersion, seenLine, seriesNote, spoofedPorts } from '../src/main/decoys'
import { addRule, applyIgnored, isIgnored, kindOf, readRules, removeRule } from '../src/main/ignored'
import { setRoot } from '../src/main/paths'
import { libsIn } from '../src/main/seckit/confirm'
import type { Finding } from '../src/shared/types'

const base = (o: Partial<Finding>): Finding => ({ id: 'x', tool: 'MacSec', category: 'web', severity: 'high', confidence: 'confirmed', title: 't', ...o }) as Finding

describe('firewall knowledge', () => {
  it('recognises shields by header, cookie and block page', () => {
    expect(detectWaf({ 'cf-ray': 'abc' }).map((w) => w.name)).toContain('Cloudflare')
    expect(detectWaf({ 'set-cookie': 'visid_incap_123=abc; path=/' }).map((w) => w.name)).toContain('Imperva (Incapsula)')
    expect(detectWaf({}, 'Request unsuccessful. Incapsula incident ID: 123').map((w) => w.name)).toContain('Imperva (Incapsula)')
    expect(detectWaf({ server: 'nginx' }, '<html>hello</html>')).toEqual([])
  })
  it('knows a challenge page from a normal one', () => {
    expect(isChallengePage(200, '<title>Just a moment...</title>')).toBe(true)
    expect(isChallengePage(200, '<h1>Welcome</h1>')).toBe(false)
  })
})

describe('fake open ports', () => {
  it('flags an address with a crowd of open ports', () => {
    expect(spoofedPorts(Array.from({ length: 40 }, (_, i) => 100 + i), 1000).spoofed).toBe(true)
  })
  it('flags many risky services at once', () => {
    expect(spoofedPorts([21, 22, 23, 25, 3306, 5432, 6379], 100).spoofed).toBe(true)
  })
  it('leaves an ordinary server alone', () => {
    expect(spoofedPorts([22, 80, 443], 1000).spoofed).toBe(false)
    expect(spoofedPorts([22, 80, 443, 3306], 100).spoofed).toBe(false)
  })
})

describe('fake files', () => {
  const files = ['/trace.axd', '/db.sql', '/.env', '/backup.zip', '/phpinfo.php'].map((p) => base({ id: p, title: `Public file: ${p}`, file: 'https://a.test', url: `https://a.test${p}` }))
  it('turns many sensitive names down to info and says why', () => {
    const out = groupDecoyFiles(files)
    expect(out.filter((f) => f.title.startsWith('Probably a decoy')).every((f) => f.severity === 'info')).toBe(true)
    expect(out.some((f) => /probably a firewall decoy/.test(f.title))).toBe(true)
    expect(out.length).toBe(files.length + 1)
  })
  it('keeps one real-looking file as it is', () => {
    const out = groupDecoyFiles(files.slice(0, 1))
    expect(out).toEqual(files.slice(0, 1))
    expect(out[0].severity).toBe('high')
  })
})

describe('keys', () => {
  it('knows example values', () => {
    for (const v of ['YOUR_API_KEY_HERE', 'xxxxxxxxxxxxxxxx', 'AKIAIOSFODNN7EXAMPLE', 'AAAAAAAAAAAAAAAA1', 'changeme123456']) expect(isPlaceholderKey(v)).toBe(true)
    expect(isPlaceholderKey('sk_live_51Hq8vXk2LmZpQ7rTn4Wd')).toBe(false)
  })
  it('shows what was seen without the full value', () => {
    const seen = seenLine('const key = "sk_live_51Hq8vXk2LmZpQ7rTn4Wd";')
    expect(seen).toContain('sk_l…')
    expect(seen).not.toContain('51Hq8vXk2LmZpQ7rTn4Wd')
  })
  it('turns an example down and keeps a real-looking one', () => {
    const f = base({ title: 'Generic API Key in public JavaScript', description: 'x' })
    expect(explainKey(f, 'apiKey: "YOUR_API_KEY_HERE"').severity).toBe('info')
    const real = explainKey(f, 'apiKey: "sk_live_51Hq8vXk2LmZpQ7rTn4Wd"')
    expect(real.severity).toBe('high')
    expect(real.description).toContain('What MacSec saw')
    expect(real.description).not.toContain('51Hq8vXk2LmZpQ7rTn4Wd')
  })
})

describe('libraries', () => {
  it('knows public libraries and their maps', () => {
    expect(isPublicLibrary('https://cdn.jsdelivr.net/npm/foo/dist/x.js.map')).toBe(true)
    expect(isPublicLibrary('https://a.test/static/jquery.min.js.map')).toBe(true)
    expect(isPublicLibrary('https://a.test/static/app.4f2a.js.map')).toBe(false)
  })
  it('checks that a version fits a series that exists', () => {
    expect(plausibleVersion('Bootstrap', '4.6.2')).toBe(true)
    expect(plausibleVersion('Bootstrap', '2025.1.2')).toBe(false)
    expect(seriesNote('Bootstrap', '3.3.7')).toContain('Bootstrap 3.x')
    expect(seriesNote('Bootstrap', '5.3.0')).toContain('still maintained')
  })
  it('says so when the file name and the code disagree, and uses the code', () => {
    const l = libsIn('https://a.test/bootstrap-3.3.7.min.js', '/*! Bootstrap v4.1.0 (https://getbootstrap.com) */')
    expect(l[0].version).toBe('4.1.0')
    expect(l[0].note).toContain('3.3.7')
  })
})

describe('what you told MacSec to ignore', () => {
  beforeAll(() => setRoot(mkdtempSync(join(tmpdir(), 'macsec-ign-'))))
  it('remembers a finding on one site and forgets it when asked', () => {
    const f = base({ id: 'abc', title: 'Generic API Key in public JavaScript', file: 'https://a.test/app.js' })
    addRule(f, 'site')
    expect(isIgnored(f)).toBe(true)
    expect(isIgnored(base({ id: 'zzz', title: f.title }))).toBe(false)
    const list = [base({ id: 'abc', title: f.title }), base({ id: 'def', title: 'Other' })]
    expect(applyIgnored(list)).toBe(1)
    expect(list[0].triage).toBe('not-a-problem')
    expect(list[0].remembered).toBe(true)
    expect(list[1].triage).toBeUndefined()
    removeRule(readRules()[0].key)
    expect(readRules()).toEqual([])
  })
  it('remembers a kind of finding everywhere, ignoring counts', () => {
    addRule(base({ id: 'q', title: 'Source map public: 12 original files' }), 'everywhere')
    expect(isIgnored(base({ id: 'other', title: 'Source map public: 40 original files' }))).toBe(true)
    expect(kindOf('Source map public: 12 original files')).toBe('source map public: # original files')
  })
})

describe('the AI agents do not load your own MCP servers', () => {
  it('every run in plan mode also says --strict-mcp-config', () => {
    const files: string[] = []
    const walk = (d: string): void => {
      for (const n of readdirSync(d)) {
        const p = join(d, n)
        if (statSync(p).isDirectory()) walk(p)
        else if (/\.ts$/.test(n)) files.push(p)
      }
    }
    walk(join(__dirname, '..', 'src', 'main'))
    const bad: string[] = []
    for (const f of files) {
      const text = readFileSync(f, 'utf8')
      for (const m of text.matchAll(/'--permission-mode'[^\n]*/g)) {
        const around = text.slice(Math.max(0, (m.index ?? 0) - 300), (m.index ?? 0) + m[0].length + 300)
        if (!around.includes('--strict-mcp-config')) bad.push(f)
      }
    }
    expect(bad).toEqual([])
  })
})
