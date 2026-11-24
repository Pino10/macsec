/** 1.25.0: the install harness and the cross-engine runner. */
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'fs'
import { join } from 'path'
import { CATALOG } from '../src/main/toolbox'
import { checkCatalog, checkLatestReleases } from '../src/main/qa/installcheck'
import { runEngineCases, type EngineCase } from '../src/main/qa/crossengine'

const ROOT = join(__dirname, 'fixtures', 'crossengine')
const read = (name: string): string => readFileSync(join(ROOT, name), 'utf8')

const CASES: EngineCase[] = [
  {
    engine: 'semgrep',
    root: '/p',
    output: read('semgrep-vulnerable.json'),
    expected: [{ name: 'sql-injection', title: /sql injection/i }]
  },
  {
    engine: 'psalm',
    root: '/p',
    output: read('psalm-vulnerable.json'),
    expected: [{ name: 'tainted sql', title: /tainted sql/i }]
  },
  {
    engine: 'phpstan',
    root: '/p',
    output: read('phpstan-vulnerable.json'),
    expected: [{ name: 'sql built from a variable', title: /sql injection/i }]
  },
  { engine: 'semgrep', root: '/p', output: read('semgrep-clean.json'), expected: [] },
  { engine: 'psalm', root: '/p', output: read('psalm-clean.json'), expected: [] }
]

describe('the install harness', () => {
  it('every catalogue entry passes the static rules', () => {
    const issues = checkCatalog()
    expect(issues, issues.map((i) => `${i.id}: ${i.problem}`).join('\n')).toEqual([])
  })
  it('every downloaded tool has a real latest release, when the live half is asked for', async () => {
    if (process.env.MACSEC_LIVE !== '1') return
    const issues = await checkLatestReleases(fetch)
    expect(issues, issues.map((i) => `${i.id}: ${i.problem}`).join('\n')).toEqual([])
  }, 240_000)
  it('refuses a catalogue entry that would install from nowhere', () => {
    const bad = [
      { ...CATALOG.find((t) => t.id === 'semgrep')!, id: 'Not A Slug' },
      { ...CATALOG.find((t) => t.id === 'bearer')!, repo: 'not-a-repo', homepage: 'http://x' }
    ]
    const issues = checkCatalog(bad as typeof CATALOG)
    expect(issues.map((i) => i.problem).join(' ')).toMatch(/slug|owner\/name|https/)
  })
})

describe('the cross-engine runner', () => {
  it('finds the labelled problem with each engine, and nothing on the clean files', () => {
    const rows = runEngineCases(CASES)
    for (const row of rows) {
      expect(row.score.precision, `${row.engine} precision`).toBe(1)
      expect(row.score.recall, `${row.engine} recall`).toBe(1)
    }
  })
  it('deduplicates the same place reported twice', () => {
    const dup = JSON.parse(read('semgrep-vulnerable.json'))
    dup.results.push({ ...dup.results[0], check_id: 'php.lang.security.other-sqli-rule' })
    const row = runEngineCases([{ engine: 'semgrep', root: '/p', output: JSON.stringify(dup), expected: [{ name: 'sql-injection', title: /sql injection/i }] }])[0]
    expect(row.found).toHaveLength(1)
    expect(row.score.fp).toBe(0)
  })
})
