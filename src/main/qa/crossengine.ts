/**
 * The cross-engine runner: the same labelled case through every engine's own output format, so a
 * parser change or an engine upgrade cannot quietly change what is reported. It uses recorded tool
 * output (the formats do not change with an install) and the real parsers, so it runs in CI with no
 * scanners installed. Live runs are a separate, opt-in harness.
 */
import type { Finding } from '../../shared/types'
import type { Expected, Score } from '../benchmark'
import { score } from '../benchmark'
import { parsePhpstan, parsePsalm, parseSemgrep } from '../scanners/parse'

export type EngineId = 'semgrep' | 'psalm' | 'phpstan'

export interface EngineCase {
  engine: EngineId
  /** The file the recorded output came from, for the parser's relative paths. */
  root: string
  output: string
  expected: Expected[]
}

const PARSE: Record<EngineId, (text: string, root: string) => Finding[]> = {
  semgrep: parseSemgrep,
  psalm: parsePsalm,
  phpstan: parsePhpstan
}

/** Deduplicate by the check that made it and where, so two rule ids at one line count once. */
const keyOf = (f: Finding): string => `${f.file ?? f.url ?? ''}|${f.line ?? ''}`

export function runEngineCases(cases: EngineCase[]): { engine: EngineId; found: Finding[]; score: Score }[] {
  return cases.map((c) => {
    const seen = new Set<string>()
    const all = PARSE[c.engine](c.output, c.root)
    const found = all.filter((f) => {
      const k = keyOf(f)
      if (seen.has(k)) return false
      seen.add(k)
      return true
    })
    return { engine: c.engine, found, score: score(c.expected, found) }
  })
}
