import { mkdtempSync, readFileSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { describe, expect, it, vi } from 'vitest'

vi.mock('electron', () => ({ app: { getVersion: () => '0.5.0', getPath: () => '/Applications/MacSec.app/Contents/MacOS/MacSec' } }))

import { ensureDirs, setRoot } from '../src/main/paths'
import { pickUpdate, type Release } from '../src/main/updater'
import { postureOf, postureScore } from '../src/renderer/src/components/ThreatCore'

const rel = (tag: string, assets: string[], extra: Partial<Release> = {}): Release => ({ tag_name: tag, draft: false, body: `Notes ${tag}`, published_at: '2026-11-04T12:00:00Z', html_url: `https://github.com/Pino10/macsec/releases/tag/${tag}`, assets: assets.map((name) => ({ name, browser_download_url: `https://example.invalid/${name}` })), ...extra })

describe('MacSec updates itself', () => {
  it('offers the newest release that has this Mac’s DMG and checksums', () => {
    const list = [rel('v0.4.0', ['MacSec-0.4.0-arm64.dmg', 'SHA256SUMS.txt']), rel('v0.6.0', ['MacSec-0.6.0-arm64.dmg', 'MacSec-0.6.0-x64.dmg', 'SHA256SUMS.txt']), rel('v0.7.0', ['MacSec-0.7.0-arm64.dmg', 'SHA256SUMS.txt'], { draft: true })]
    const u = pickUpdate(list, '0.5.0', 'arm64')!
    expect(u.info).toMatchObject({ version: '0.6.0', current: '0.5.0' })
    expect(u.dmg).toContain('MacSec-0.6.0-arm64.dmg')
  })
  it('never offers a release it cannot verify, or an older one', () => {
    expect(pickUpdate([rel('v0.6.0', ['MacSec-0.6.0-arm64.dmg'])], '0.5.0', 'arm64')).toBeNull()
    expect(pickUpdate([rel('v0.5.0', ['MacSec-0.5.0-arm64.dmg', 'SHA256SUMS.txt'])], '0.5.0', 'arm64')).toBeNull()
    expect(pickUpdate([rel('v0.6.0', ['MacSec-0.6.0-x64.dmg', 'SHA256SUMS.txt'])], '0.5.0', 'arm64')).toBeNull()
  })
})

describe('the posture core moves', () => {
  it('averages targets, so fixing one project changes it', () => {
    const bad = { critical: 3, high: 8, medium: 10, low: 5, info: 0 }
    const good = { critical: 0, high: 0, medium: 1, low: 2, info: 4 }
    expect(postureScore(bad)).toBeLessThan(5)
    const before = postureOf([bad, bad, good])
    const after = postureOf([bad, good, good])
    expect(after).toBeGreaterThan(before + 20)
    expect(postureOf([])).toBe(100)
  })
})

describe('triage and testing again', () => {
  it('marking a finding fixed takes it out of the counts, and it can be opened again', async () => {
    setRoot(mkdtempSync(join(tmpdir(), 'ms-triage-')))
    ensureDirs()
    const { createSession, saveFindings, triageFinding, readSession } = await import('../src/main/sessions')
    const s = createSession('code-review', 'shop', '/x/shop')
    saveFindings(s.id, [
      { id: 'a', tool: 'Semgrep', category: 'code', severity: 'critical', title: 'SQL injection' },
      { id: 'b', tool: 'Semgrep', category: 'code', severity: 'high', title: 'XSS' }
    ])
    let d = triageFinding(s.id, 'a', 'fixed')
    expect(d.counts).toMatchObject({ critical: 0, high: 1 })
    expect(d.findings.find((f) => f.id === 'a')?.triage).toBe('fixed')
    expect(readSession(s.id).counts.critical).toBe(0)
    d = triageFinding(s.id, 'a', null)
    expect(d.counts.critical).toBe(1)
    expect(() => triageFinding(s.id, 'zzz', 'fixed')).toThrow()
  })
  it('keeps the request to test again, without cookies or keys', async () => {
    const { createSession, saveRequest, readRequest, stripSecrets, sessionDir } = await import('../src/main/sessions')
    const s = createSession('web-scan', 'shop.test', 'http://shop.test')
    saveRequest(s.id, 'web:start', stripSecrets({ target: { kind: 'url', url: 'http://shop.test' }, mode: 'standard', headers: 'Cookie: session=SECRET', reviewer: 'none' }))
    saveRequest(s.id, 'api:start', stripSecrets({ spec: 'x', auth: { kind: 'bearer', value: 'TOKEN123' } }))
    const text = readFileSync(join(sessionDir(s.id), 'request.json'), 'utf8')
    expect(text).not.toMatch(/SECRET|TOKEN123/)
    expect(readRequest(s.id)?.channel).toBe('api:start')
    writeFileSync(join(sessionDir(s.id), 'request.json'), 'not json')
    expect(readRequest(s.id)).toBeNull()
  })
})
