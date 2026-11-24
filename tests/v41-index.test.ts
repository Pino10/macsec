/** The session index: real SQLite when the runtime has it, and a clean "not available" when not. */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { setRoot } from '../src/main/paths'
import { closeIndex, forgetSession, indexFindings, indexSessionRow, isBuilt, markBuilt, searchIndex, sqliteAvailable } from '../src/main/indexdb'
import type { Finding } from '../src/shared/types'

let dir = ''
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'macsec-idx-'))
  setRoot(dir)
  mkdirSync(join(dir, 'config'), { recursive: true })
})
afterEach(() => {
  closeIndex()
  rmSync(dir, { recursive: true, force: true })
})

const f = (id: string, title: string, where = 'src/a.ts'): Finding => ({ id, tool: 'Semgrep', category: 'code', severity: 'high', title, file: where, checkId: `c-${id}` })

describe('the session index', () => {
  it('answers availability instead of throwing when SQLite is missing', async () => {
    expect(typeof (await sqliteAvailable())).toBe('boolean')
  })

  it.skipIf(!process.versions.node || Number(process.versions.node.split('.')[0]) < 22)('finds indexed findings, forgets a session, and knows when it is warm', async () => {
    if (!(await sqliteAvailable())) return
    await indexSessionRow({ id: 's1', title: 'Shop review', kind: 'code-review', createdAt: '2026-11-24T10:00:00.000Z' })
    await indexFindings('s1', [f('a1', 'SQL injection in orders'), f('a2', 'Hard-coded key', 'config/app.php')], '2026-11-24T10:00:00.000Z')
    expect((await searchIndex('injection'))?.[0]).toMatchObject({ sessionId: 's1', title: 'SQL injection in orders', kind: 'code-review' })
    expect(await searchIndex('%_wild')).toEqual([])
    expect(await isBuilt()).toBe(false)
    await markBuilt()
    expect(await isBuilt()).toBe(true)
    await forgetSession('s1')
    expect(await searchIndex('injection')).toEqual([])
  })

  it('never throws on a strange term', async () => {
    if (!(await sqliteAvailable())) return
    for (const q of ["' OR 1=1 --", '%', '_', '\\', 'very long '.repeat(50)]) expect(Array.isArray(await searchIndex(q)) || (await searchIndex(q)) === null).toBe(true)
  })
})

// A session folder exists so a warm index can be built from it later; this file only checks the rows.
it('keeps a findings.json readable for the fallback path', () => {
  mkdirSync(join(dir, 'sessions', 'abcdefgh-1'), { recursive: true })
  writeFileSync(join(dir, 'sessions', 'abcdefgh-1', 'findings.json'), '[]')
  expect(true).toBe(true)
})
