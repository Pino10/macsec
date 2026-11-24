/** The CI door: argument rules, the baseline comparison, exit codes, and the accuracy gate. */
import { afterAll, describe, expect, it } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { parseCli } from '../src/main/cli'
import { baselineOf, exitCodeFor, findingKey, newFindings, readBaseline, writeBaseline } from '../src/main/baseline'
import { runBenchmarks } from '../src/main/benchmarks'
import type { Finding } from '../src/shared/types'

const f = (id: string, severity: Finding['severity'], extra: Partial<Finding> = {}): Finding => ({ id, tool: 'Semgrep', category: 'code', severity, title: `Finding ${id}`, checkId: `check-${id}`, file: 'src/a.ts', ...extra })

describe('the command line rules', () => {
  const dir = tmpdir()
  it('accepts a scan with sensible defaults, and --headless first', () => {
    const o = parseCli(['--headless', 'scan', '--path', dir])
    expect('error' in o).toBe(false)
    if (!('error' in o)) {
      expect(o.command).toBe('scan')
      expect(o.depth).toBe('standard')
      expect(o.failOn).toBe('high')
      expect(o.baseline).toBe(true)
    }
  })
  it('refuses nonsense plainly', () => {
    expect(parseCli(['scan'])).toMatchObject({ error: expect.stringContaining('--path') })
    expect(parseCli(['scan', '--path', dir, '--depth', 'fast'])).toMatchObject({ error: expect.stringContaining('--depth') })
    expect(parseCli(['scan', '--path', '/does/not/exist'])).toMatchObject({ error: expect.stringContaining('not a folder') })
    expect(parseCli(['dance'])).toMatchObject({ error: expect.stringContaining('Unknown command') })
  })
  it('has a bench command and a help text', () => {
    expect(parseCli(['bench'])).toMatchObject({ command: 'bench' })
    const h = parseCli(['--help'])
    expect('error' in h).toBe(false)
  })
})

describe('the baseline', () => {
  const dir = mkdtempSync(join(tmpdir(), 'macsec-base-'))
  afterAll(() => rmSync(dir, { recursive: true, force: true }))
  it('keeps identity across scans, and only new findings are new', () => {
    const before = [f('a', 'high'), f('b', 'critical')]
    const file = join(dir, '.macsec-baseline.json')
    writeBaseline(file, baselineOf(before, '/p'))
    const loaded = readBaseline(file)
    expect(loaded?.findings).toHaveLength(2)
    const after = [f('a', 'high'), f('c', 'medium'), f('b', 'critical', { file: 'src/b.ts' })]
    const fresh = newFindings(after, loaded)
    expect(fresh.map((x) => x.id).sort()).toEqual(['b', 'c'])
    expect(findingKey(f('x', 'high'))).toBe('check-x|src/a.ts')
  })
  it('fails only at the threshold, and never on info or triaged findings', () => {
    expect(exitCodeFor([f('a', 'medium')], 'high')).toBe(0)
    expect(exitCodeFor([f('a', 'high')], 'high')).toBe(1)
    expect(exitCodeFor([f('a', 'critical')], 'none')).toBe(0)
    expect(exitCodeFor([f('a', 'critical', { triage: 'not-a-problem' })], 'low')).toBe(0)
  })
  it('reads an unreadable or foreign baseline as none', () => {
    const bad = join(dir, 'bad.json')
    writeFileSync(bad, '{"version":2}')
    expect(readBaseline(bad)).toBeNull()
    expect(readBaseline(join(dir, 'missing.json'))).toBeNull()
  })
})

describe('the accuracy gate', () => {
  it('every built-in check is at 0.8 precision and recall or better', () => {
    const rows = runBenchmarks()
    expect(rows.map((r) => r.name)).toEqual(['exposed files', 'key values', 'deception', 'attack paths'])
    for (const r of rows) {
      expect(r.precision, `${r.name} precision`).toBeGreaterThanOrEqual(0.8)
      expect(r.recall, `${r.name} recall`).toBeGreaterThanOrEqual(0.8)
    }
  })
})
