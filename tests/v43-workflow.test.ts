/** The workflow release: saved profiles, bulk triage with an owner and a due date, and CSV. */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { setRoot } from '../src/main/paths'
import { deleteProfile, listProfiles, saveProfile } from '../src/main/profiles'
import { triageBulk } from '../src/main/sessions'
import { sessionCsv } from '../src/main/exports'
import type { Finding, SessionDetail, SessionInfo } from '../src/shared/types'

let dir = ''
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'macsec-work-'))
  setRoot(dir)
  mkdirSync(join(dir, 'config'), { recursive: true })
  mkdirSync(join(dir, 'sessions'), { recursive: true })
})
afterEach(() => rmSync(dir, { recursive: true, force: true }))

const finding = (id: string, extra: Partial<Finding> = {}): Finding => ({ id, tool: 'Semgrep', category: 'code', severity: 'high', title: `Finding ${id}`, checkId: `c-${id}`, file: 'src/app.ts', line: 4, ...extra })

function sessionWith(findings: Finding[]): string {
  const id = 'sess-1234'
  const info: SessionInfo = { id, kind: 'code-review', title: 'Shop', target: '/tmp/shop', createdAt: '2026-11-24T10:00:00.000Z', status: 'done', counts: { critical: 0, high: 2, medium: 0, low: 0, info: 0 }, steps: [] }
  mkdirSync(join(dir, 'sessions', id), { recursive: true })
  writeFileSync(join(dir, 'sessions', id, 'session.json'), JSON.stringify(info))
  writeFileSync(join(dir, 'sessions', id, 'findings.json'), JSON.stringify(findings))
  return id
}

describe('saved profiles', () => {
  it('saves choices, replaces by name and never holds a secret', () => {
    saveProfile({ name: 'Staging gentle', kind: 'web', options: { mode: 'standard', pacing: 'gentle', confirm: { fuzz: true } } })
    expect(listProfiles().map((p) => p.name)).toEqual(['Staging gentle'])
    saveProfile({ name: 'staging gentle', kind: 'web', options: { mode: 'quick' } })
    const list = listProfiles()
    expect(list).toHaveLength(1)
    expect(list[0].options).toMatchObject({ mode: 'quick' })
    expect(() => saveProfile({ name: 'Leak', kind: 'web', options: { headers: 'Cookie: x' } })).toThrow(/cannot hold/)
    expect(() => saveProfile({ name: '', kind: 'web', options: {} })).toThrow(/name/)
    expect(() => saveProfile({ name: 'Bad', kind: 'mobile', options: {} })).toThrow(/web scan or a code review/)
    const id = list[0].id
    expect(deleteProfile(id)).toEqual([])
  })
})

describe('bulk triage', () => {
  it('marks several findings, keeps an owner and a due date, and clears them together', () => {
    const id = sessionWith([finding('a'), finding('b'), finding('c')])
    const d = triageBulk(id, ['a', 'b'], 'accepted', { owner: '  Ada  ', due: '2026-12-01' })
    const a = d.findings.find((f) => f.id === 'a')!
    expect(a.triage).toBe('accepted')
    expect(a.owner).toBe('Ada')
    expect(a.due).toBe('2026-12-01')
    expect(d.findings.find((f) => f.id === 'c')?.triage).toBeUndefined()
    expect(d.counts.high).toBe(1) // the two accepted findings no longer count
    const cleared = triageBulk(id, ['a', 'b'], null)
    expect(cleared.findings.find((f) => f.id === 'a')?.owner).toBeUndefined()
    expect(cleared.findings.find((f) => f.id === 'b')?.triage).toBeUndefined()
  })
  it('ignores a bad due date and refuses no ids', () => {
    const id = sessionWith([finding('a')])
    const d = triageBulk(id, ['a'], 'fixed', { owner: 'Ada', due: 'tomorrow' })
    expect(d.findings[0].due).toBeUndefined()
    expect(d.findings[0].owner).toBe('Ada')
    expect(() => triageBulk(id, [], 'fixed')).toThrow(/at least one/)
  })
})

describe('the CSV export', () => {
  it('quotes commas and quotes, and defuses a formula', () => {
    const d = { findings: [finding('a', { title: 'Redirect, open "wide"', owner: 'Ada', triage: 'accepted', due: '2026-12-01' }), finding('b', { title: '=1+1' })] } as unknown as SessionDetail
    const csv = sessionCsv(d)
    const lines = csv.trim().split('\n')
    expect(lines[0]).toContain('severity,tool,category,title')
    expect(lines[1]).toContain('"Redirect, open ""wide"""')
    expect(lines[1]).toContain(',accepted,Ada,2026-12-01,')
    expect(lines[2]).toContain("'=1+1")
    expect(csv.endsWith('\n')).toBe(true)
  })
})
