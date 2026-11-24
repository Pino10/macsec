/**
 * The SQL corpus and its measurement. The corpus is labelled, includes clean code that must stay
 * clean, and keeps a holdout split that rules are not allowed to be written against. A finding counts
 * for a case when it is in that file within a couple of lines of the labelled query; the same
 * finding cannot count twice.
 */
import { execFile } from 'child_process'
import { existsSync, mkdirSync, readFileSync } from 'fs'
import { join } from 'path'

export interface SqlExpectation {
  line: number
  kind: string
}

export interface SqlCase {
  id: string
  language: string
  file: string
  split: 'train' | 'holdout'
  expect: SqlExpectation[]
}

export interface SqlCorpus {
  version: number
  toleranceLines: number
  cases: SqlCase[]
}

export interface CorpusFinding {
  file: string
  line?: number
  checkId?: string
  tool?: string
}

export interface CaseScore {
  id: string
  split: 'train' | 'holdout'
  tp: number
  fp: number
  fn: number
  missed: string[]
  extra: CorpusFinding[]
}

export interface CorpusScore {
  cases: CaseScore[]
  train: { tp: number; fp: number; fn: number; precision: number; recall: number }
  holdout: { tp: number; fp: number; fn: number; precision: number; recall: number }
  all: { tp: number; fp: number; fn: number; precision: number; recall: number }
}

const ratio = (a: number, b: number): number => (b === 0 ? 1 : Math.round((a / b) * 1000) / 1000)
const norm = (p: string): string => p.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '')

export function loadCorpus(root: string): SqlCorpus {
  return JSON.parse(readFileSync(join(root, 'cases.json'), 'utf8')) as SqlCorpus
}

export function scoreSqlCorpus(corpus: SqlCorpus, findingsInput: CorpusFinding[], tolerance = corpus.toleranceLines): CorpusScore {
  let findings = findingsInput
  const files = new Set(corpus.cases.map((c) => norm(c.file)))
  const byFile = new Map<string, CorpusFinding[]>()
  const loose: CorpusFinding[] = []
  const seenPlace = new Set<string>()
  // Two rules naming the same line are one problem, not a hit and a false positive.
  findings = findings.filter((f) => {
    const k = `${norm(f.file)}|${f.line ?? ''}`
    if (seenPlace.has(k)) return false
    seenPlace.add(k)
    return true
  })
  for (const f of findings) {
    const key = norm(f.file)
    if (!files.has(key)) {
      loose.push(f)
      continue
    }
    const list = byFile.get(key) ?? []
    list.push(f)
    byFile.set(key, list)
  }
  const scores: CaseScore[] = corpus.cases.map((c) => {
    const got = byFile.get(norm(c.file)) ?? []
    const used = new Set<number>()
    const missed: string[] = []
    let tp = 0
    for (const e of c.expect) {
      const i = got.findIndex((f, k) => !used.has(k) && typeof f.line === 'number' && Math.abs(f.line - e.line) <= tolerance)
      if (i < 0) missed.push(`${e.kind} at ${c.file}:${e.line}`)
      else {
        used.add(i)
        tp++
      }
    }
    // Every rule that points at the same labelled query is that one problem, not a false positive.
    const extra = got.filter((f, k) => !used.has(k) && !c.expect.some((e) => typeof f.line === 'number' && Math.abs(f.line - e.line) <= tolerance))
    return { id: c.id, split: c.split, tp, fp: extra.length, fn: missed.length, missed, extra }
  })
  const sum = (split?: 'train' | 'holdout') => {
    const list = split ? scores.filter((s) => s.split === split) : scores
    const tp = list.reduce((n, s) => n + s.tp, 0)
    const fp = list.reduce((n, s) => n + s.fp, 0)
    const fn = list.reduce((n, s) => n + s.fn, 0)
    return { tp, fp, fn, precision: ratio(tp, tp + fp), recall: ratio(tp, tp + fn) }
  }
  // A finding outside every corpus file cannot be judged, so it is not counted as a false positive.
  return { cases: scores, train: sum('train'), holdout: sum('holdout'), all: sum() }
}

/** Joern's own JSON, as produced by the template in scripts/joern-sql.sc. */
export function parseJoernJson(text: string): CorpusFinding[] {
  const rows = JSON.parse(text) as { file?: string; line?: number; lineNumber?: number; message?: string; code?: string }[]
  return (Array.isArray(rows) ? rows : []).map((r) => ({ file: r.file ?? '', line: r.line ?? r.lineNumber, tool: 'Joern', checkId: r.message ?? r.code }))
}

/** The Semgrep binary MacSec installed, or the one on PATH. */
export function semgrepBin(): string | null {
  const local = join(process.env.HOME ?? '', 'MacSec', 'tools', 'bin', 'semgrep')
  return existsSync(local) ? local : null
}

export function runSemgrepCorpus(root: string, bin = semgrepBin(), home = join(process.env.HOME ?? '', 'MacSec', 'tools', 'home')): Promise<CorpusFinding[]> {
  if (!bin) return Promise.reject(new Error('Semgrep is not installed in ~/MacSec/tools.'))
  // A private home, so nothing is written to the person's ~/.semgrep (the app uses tools/home).
  const cache = join(home, '.cache')
  try {
    mkdirSync(cache, { recursive: true })
  } catch {
    // Already there, or the sandbox says no; Semgrep will report it.
  }
  const toolEnv = { ...process.env, HOME: home, XDG_CACHE_HOME: cache, SEMGREP_SEND_METRICS: 'off', SEMGREP_SETTINGS_FILE: join(cache, 'semgrep-settings.yml'), SEMGREP_LOG_FILE: join(cache, 'semgrep.log'), SEMGREP_VERSION_CACHE_PATH: join(cache, 'version-check') }
  return new Promise((resolve, reject) => {
    execFile(bin, ['--config', 'p/sql-injection', '--json', '--quiet', '--metrics=off', '--disable-version-check', root], { timeout: 240_000, maxBuffer: 32 * 1024 * 1024, env: toolEnv }, (e, out, err) => {
      if (e && !out.trim()) return reject(new Error(`Semgrep failed: ${String(err).trim().split('\n').slice(-2).join(' ')}`))
      try {
        const d = JSON.parse(out) as { results?: { check_id: string; path: string; start: { line: number } }[] }
        resolve(
          (d.results ?? []).map((r) => ({
            file: norm(r.path).slice(norm(root).length).replace(/^\/+/, ''),
            line: r.start.line,
            checkId: r.check_id,
            tool: 'Semgrep'
          }))
        )
      } catch (x) {
        reject(new Error(`Semgrep's JSON could not be read: ${(x as Error).message}`))
      }
    })
  })
}
