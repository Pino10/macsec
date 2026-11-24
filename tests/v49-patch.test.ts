/** 1.31: patch generation in a scratch copy, tests, typed apply, rollback. */
import { afterAll, beforeEach, describe, expect, it } from 'vitest'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { setRoot } from '../src/main/paths'
import { applyPatch, proposePatch, rollbackPatch } from '../src/main/patch'
import type { Finding, SessionInfo } from '../src/shared/types'

let root = ''
let project = ''
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'macsec-patch-'))
  setRoot(root)
  project = join(root, 'project')
  mkdirSync(join(project, 'src'), { recursive: true })
  mkdirSync(join(root, 'sessions', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'), { recursive: true })
  writeFileSync(join(project, 'package.json'), JSON.stringify({ name: 'shop', scripts: { test: 'node -e "process.exit(0)"' } }))
  writeFileSync(join(project, 'src', 'search.js'), "const sql = 'SELECT * FROM users WHERE name = ' + name\n")
  const info: SessionInfo = { id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', kind: 'code-review', title: 'Shop', target: project, createdAt: new Date().toISOString(), status: 'done', codePath: project, counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, steps: [] }
  writeFileSync(join(root, 'sessions', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'session.json'), JSON.stringify(info))
  const f: Finding = { id: 'f1', tool: 'Semgrep', category: 'code', severity: 'high', title: 'SQL injection in search', file: 'src/search.js', line: 1, description: 'Input reaches the query.' }
  writeFileSync(join(root, 'sessions', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'findings.json'), JSON.stringify([f]))
})
afterAll(() => rmSync(root, { recursive: true, force: true }))

const editor = async (scratch: string): Promise<void> => {
  writeFileSync(join(scratch, 'src', 'search.js'), "const sql = 'SELECT * FROM users WHERE name = ?'\n")
}

describe('patch generation', () => {
  it('changes only the scratch copy, shows the diff, and records passing tests', async () => {
    const r = await proposePatch('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'f1', { editor, testRunner: async () => ({ code: 0, out: 'ok', err: '' }) })
    expect(r.error).toBeUndefined()
    expect(r.files).toEqual(['src/search.js'])
    expect(r.diff).toContain('-const sql')
    expect(r.tests).toMatchObject({ ran: true, passed: true })
    expect(readFileSync(join(project, 'src', 'search.js'), 'utf8')).toContain('+ name')
    expect(existsSync(join(r.scratch, 'src', 'search.js'))).toBe(true)
  })

  it('applies only with the exact phrase and rolls back to the original', async () => {
    const r = await proposePatch('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'f1', { editor, testRunner: async () => ({ code: 0, out: 'ok', err: '' }) })
    await expect(applyPatch(r.id, 'APPLY wrong')).rejects.toThrow(/Type "APPLY/)
    const applied = await applyPatch(r.id, `APPLY ${r.id}`)
    expect(applied.applied).toBe(true)
    expect(readFileSync(join(project, 'src', 'search.js'), 'utf8')).toContain('name = ?')
    const back = await rollbackPatch(r.id)
    expect(back.applied).toBe(false)
    expect(back.rolledBack).toBe(true)
    expect(readFileSync(join(project, 'src', 'search.js'), 'utf8')).toContain('+ name')
  })

  it('refuses to apply when the tests failed', async () => {
    const r = await proposePatch('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', 'f1', { editor, testRunner: async () => ({ code: 1, out: 'boom', err: '' }) })
    expect(r.tests.passed).toBe(false)
    await expect(applyPatch(r.id, `APPLY ${r.id}`)).rejects.toThrow(/tests did not pass/)
  })
})
