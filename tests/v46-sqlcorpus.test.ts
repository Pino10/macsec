/** 1.25.1: the SQL corpus, its scoring, and the live measurement against Semgrep. */
import { describe, expect, it } from 'vitest'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { fileURLToPath } from 'url'
import { loadCorpus, parseJoernJson, runSemgrepCorpus, scoreSqlCorpus, semgrepBin } from '../src/main/qa/sqlcorpus'

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..', 'corpus', 'sql')

describe('the SQL corpus', () => {
  const corpus = loadCorpus(ROOT)
  it('every file and every labelled line exists, and the clean files stay clean', () => {
    expect(corpus.cases.length).toBeGreaterThanOrEqual(8)
    for (const c of corpus.cases) {
      const text = readFileSync(join(ROOT, c.file), 'utf8')
      const lines = text.split('\n')
      expect(lines.length, c.file).toBeGreaterThan(3)
      for (const e of c.expect) expect(lines[e.line - 1], `${c.file}:${e.line}`).toBeTruthy()
      if (!c.expect.length) expect(text).not.toMatch(/\+\s*(name|req|request|user)|\$\{|%[ \t]*name|\.[ \t]*\$name/)
    }
    expect(corpus.cases.filter((c) => c.split === 'holdout').length).toBeGreaterThanOrEqual(2)
  })

  it('scores a hit inside the tolerance, a miss, and a finding at the wrong line', () => {
    const s = scoreSqlCorpus(corpus, [
      { file: 'php/vulnerable.php', line: 5 },
      { file: 'python/vulnerable.py', line: 20 },
      { file: 'javascript/clean.js', line: 8 }
    ])
    const php = s.cases.find((c) => c.id === 'php-request-to-query')!
    expect(php.tp).toBe(1)
    const py = s.cases.find((c) => c.id === 'python-format-to-execute')!
    expect(py.fn).toBe(1)
    const js = s.cases.find((c) => c.id === 'javascript-parameterised')!
    expect(js.fp).toBe(1)
    expect(s.all.precision).toBeLessThan(1)
    expect(s.all.recall).toBeLessThan(1)
  })

  it('reads Joern rows without inventing any', () => {
    expect(parseJoernJson('[{"file":"php/vulnerable.php","line":6,"message":"sql"}]')).toEqual([{ file: 'php/vulnerable.php', line: 6, tool: 'Joern', checkId: 'sql' }])
    expect(parseJoernJson('[]')).toEqual([])
  })

  it('measures Semgrep for real when asked', async () => {
    if (process.env.MACSEC_SQL_EVAL !== '1') return
    const bin = semgrepBin()
    expect(bin, 'Semgrep should be installed in ~/MacSec/tools').toBeTruthy()
    const home = mkdtempSync(join(tmpdir(), 'macsec-sql-'))
    const findings = await runSemgrepCorpus(ROOT, bin!, home).finally(() => rmSync(home, { recursive: true, force: true }))
    const s = scoreSqlCorpus(corpus, findings)
    const report = { at: new Date().toISOString(), engine: 'semgrep', config: 'p/sql-injection', bin, corpus: corpus.cases.length, findings: findings.length, raw: findings, score: s }
    writeFileSync(join(ROOT, 'report.json'), JSON.stringify(report, null, 2))
    console.log(`Semgrep on the SQL corpus: precision ${s.all.precision}, recall ${s.all.recall} (train ${s.train.precision}/${s.train.recall}, holdout ${s.holdout.precision}/${s.holdout.recall})`)
    expect(findings).toBeDefined()
  }, 300_000)
})
