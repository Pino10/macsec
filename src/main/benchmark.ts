/**
 * Accuracy score for a check: run it on a sample that is known to be bad and on one that is known to be fine,
 * then count what it got right. Read-only: it only compares lists, it never sends a request.
 *
 *   True positive   a known problem that the check reported
 *   False negative  a known problem that the check missed
 *   False positive  something reported that is not on the known list (only counted at the level you choose)
 */
import type { Finding } from '../shared/types'

export interface Expected {
  /** A short name for the known problem. */
  name: string
  /** Matches the finding title. */
  title: RegExp
}

export interface Score {
  tp: number
  fp: number
  fn: number
  /** tp / (tp + fp), or 1 when nothing was reported. */
  precision: number
  /** tp / (tp + fn), or 1 when nothing was expected. */
  recall: number
  missed: string[]
  extra: string[]
}

const ratio = (a: number, b: number): number => (b === 0 ? 1 : Math.round((a / b) * 1000) / 1000)

/** Findings below this level are notes, not problems, so they never count as false positives. */
const NOTE = new Set(['info'])

export function score(expected: Expected[], found: Finding[]): Score {
  const real = found.filter((f) => !NOTE.has(f.severity) && f.verdict !== 'false-positive' && f.triage !== 'not-a-problem')
  const used = new Set<number>()
  const missed: string[] = []
  let tp = 0
  for (const e of expected) {
    const i = real.findIndex((f, k) => !used.has(k) && e.title.test(f.title))
    if (i < 0) missed.push(e.name)
    else {
      used.add(i)
      tp++
    }
  }
  const extra = real.filter((_, k) => !used.has(k)).map((f) => f.title)
  return { tp, fp: extra.length, fn: missed.length, precision: ratio(tp, tp + extra.length), recall: ratio(tp, tp + missed.length), missed, extra }
}
