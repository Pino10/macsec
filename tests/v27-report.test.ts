import { describe, expect, it } from 'vitest'
import { masvsReportHtml, reproduction, top10Of } from '../src/main/masvsreport'
import type { Finding, SessionDetail } from '../src/shared/types'

const f = (o: Partial<Finding>): Finding => ({ id: o.title ?? 'x', tool: 'MacSec manifest check', category: 'mobile', severity: 'medium', confidence: 'possible', title: 't', ...o }) as Finding
const session = (findings: Finding[]): SessionDetail =>
  ({ id: 's1', kind: 'mobile-scan', title: 'Bank <app>', target: '/x/app.apk', status: 'done', steps: [{ id: 'settings', label: 'Check the manifest', status: 'done' }, { id: 'deep', label: 'Read the code', status: 'done' }], findings }) as unknown as SessionDetail

describe('MASVS report', () => {
  const html = masvsReportHtml(
    session([
      f({ title: 'The app is built as debuggable', severity: 'high', file: 'AndroidManifest.xml', fix: 'Remove android:debuggable.' }),
      f({ title: 'Generic API Key in <script>', category: 'secret', tool: 'gitleaks', severity: 'high', file: 'a.js', line: 3 }),
      f({ title: 'Marked fine', triage: 'not-a-problem', severity: 'high' }),
      f({ title: 'Servers named in the app: 3', severity: 'info' })
    ]),
    '1.10.0',
    undefined,
    new Date('2026-11-23T10:00:00Z')
  )
  it('has every section an auditor looks for', () => {
    for (const h of ['Summary', 'What was checked', 'OWASP MASVS 2.0', 'Findings', 'Still to test by hand', 'MASVS-NETWORK-1']) expect(html).toContain(h)
    expect(html).toContain('MacSec 1.10.0 on 2026-11-23')
    expect(html).toContain('See it again')
    expect(html).toContain('Remove android:debuggable.')
    expect(html).toContain('Confidence')
  })
  it('keeps out what is marked not a problem and information items from the findings list', () => {
    expect(html).not.toContain('Marked fine')
    expect(html).not.toContain('Servers named in the app')
  })
  it('escapes what comes from the app', () => {
    expect(html).toContain('Bank &lt;app&gt;')
    expect(html).toContain('Generic API Key in &lt;script&gt;')
    expect(html).not.toContain('<script>')
  })
  it('says clear is not a pass mark', () => {
    expect(html).toMatch(/not a pass mark/)
  })
  it('names the Mobile Top 10 and gives reproduction steps', () => {
    expect(top10Of('MASVS-CRYPTO-2')).toMatch(/^M1/)
    expect(top10Of('MASVS-STORAGE-2')).toMatch(/^M9/)
    expect(reproduction(f({ tool: 'MacSec binary check', file: 'lib/a.so' }))[0]).toMatch(/readelf|otool/)
    expect(reproduction(f({ proof: { request: 'r', reproduce: 'curl -s https://x', status: 200, bytes: 1, sha256: 'a', at: 'now', shows: ['a key'] } }))[0]).toBe('Run: curl -s https://x')
  })
})
