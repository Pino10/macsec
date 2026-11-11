import { describe, expect, it } from 'vitest'
import { deltaIsEmpty, deltaText, reconDelta } from '../src/main/seckit/recondelta'
import { SKILLS, skillText } from '../src/main/seckit/skills'
import { METHOD } from '../src/main/aisummary'

const prev = { session: 'a', at: '2026-10-01T10:00:00Z', hosts: ['a.x.com', 'old.x.com'], endpoints: ['/api/a'], findings: [{ id: '1', title: 'Open .env', severity: 'high' }] }

describe('recon delta', () => {
  it('finds what is new and what is gone', () => {
    const d = reconDelta(prev, { hosts: ['a.x.com', 'new.x.com'], endpoints: ['/api/a', '/api/b'], findings: [{ id: '2', title: 'Listing', severity: 'low' }] })
    expect(d.newHosts).toEqual(['new.x.com'])
    expect(d.goneHosts).toEqual(['old.x.com'])
    expect(d.newEndpoints).toEqual(['/api/b'])
    expect(d.newFindings.map((f) => f.id)).toEqual(['2'])
    expect(d.fixedFindings.map((f) => f.id)).toEqual(['1'])
    expect(deltaText(d)).toContain('1 new host')
  })
  it('says so when nothing changed', () => {
    const d = reconDelta(prev, { hosts: prev.hosts, endpoints: prev.endpoints, findings: prev.findings })
    expect(deltaIsEmpty(d)).toBe(true)
    expect(deltaText(d)).toContain('Nothing changed')
  })
})

describe('new skills', () => {
  it('exist and every method list points at real skills', () => {
    for (const n of ['cicd-pipeline-review', 'smart-contract-review', 'identity-surface-review', 'evidence-gate-review', 'standards-mapping-catalog', 'untrusted-content-guard', 'file-upload-review', 'http-cache-review']) expect(SKILLS[n]).toBeTruthy()
    for (const list of Object.values(METHOD)) for (const n of list) expect(SKILLS[n], n).toBeTruthy()
  })
  it('the guard rides along in every method and has no em dashes', () => {
    for (const list of Object.values(METHOD)) expect(list).toContain('untrusted-content-guard')
    expect(skillText(['untrusted-content-guard'])).toContain('data')
    for (const s of Object.values(SKILLS)) expect(s.body).not.toContain('—')
  })
})
